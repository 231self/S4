use bytes::Bytes;
use csv_core::{ReadRecordResult, Reader as CsvReader};
use s4_error::{S4Error, codes};

use crate::Format;

pub const DEFAULT_MAX_SOURCE_FRAME_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_JSON_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_CSV_FIELDS: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub payload: Bytes,
    pub separator: Bytes,
}

impl Record {
    pub fn new(payload: impl Into<Bytes>, separator: impl Into<Bytes>) -> Self {
        Self {
            payload: payload.into(),
            separator: separator.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecoderLimits {
    pub max_source_frame_bytes: usize,
    pub max_record_bytes: usize,
    pub max_json_document_bytes: usize,
    pub max_csv_fields: usize,
}

impl Default for DecoderLimits {
    fn default() -> Self {
        Self {
            max_source_frame_bytes: DEFAULT_MAX_SOURCE_FRAME_BYTES,
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
            max_json_document_bytes: DEFAULT_MAX_JSON_DOCUMENT_BYTES,
            max_csv_fields: DEFAULT_MAX_CSV_FIELDS,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum CsvState {
    #[default]
    FieldStart,
    Unquoted,
    Quoted,
    QuoteClosed,
}

#[derive(Debug)]
pub struct RecordDecoder {
    format: Format,
    limits: DecoderLimits,
    pending: Vec<u8>,
    ready: Option<Record>,
    scan_offset: usize,
    csv_state: CsvState,
    csv_fields: usize,
    finished: bool,
    complete: bool,
    input_seen: bool,
    records_emitted: usize,
}

impl RecordDecoder {
    pub fn new(format: Format, limits: DecoderLimits) -> Result<Self, S4Error> {
        if limits.max_source_frame_bytes == 0
            || limits.max_record_bytes == 0
            || limits.max_json_document_bytes == 0
            || limits.max_csv_fields == 0
        {
            return Err(S4Error::new(
                codes::CONFIG_INVALID,
                "decoder limits must be greater than zero",
            ));
        }
        Ok(Self {
            format,
            limits,
            pending: Vec::new(),
            ready: None,
            scan_offset: 0,
            csv_state: CsvState::FieldStart,
            csv_fields: 1,
            finished: false,
            complete: false,
            input_seen: false,
            records_emitted: 0,
        })
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<(), S4Error> {
        if self.finished {
            return Err(S4Error::new(
                codes::INTERNAL,
                "cannot push after decoder finish",
            ));
        }
        if self.ready.is_some() {
            return Err(S4Error::new(
                codes::INTERNAL,
                "drain the ready record before pushing another source frame",
            ));
        }
        if chunk.len() > self.limits.max_source_frame_bytes {
            return Err(limit_error(
                codes::LIMIT_INPUT_BYTES,
                "source frame",
                chunk.len(),
                self.limits.max_source_frame_bytes,
            ));
        }
        self.input_seen |= !chunk.is_empty();
        self.pending.extend_from_slice(chunk);
        self.prepare_next(false)
    }

    pub fn next_record(&mut self) -> Result<Option<Record>, S4Error> {
        if self.ready.is_none() {
            self.prepare_next(self.finished)?;
        }
        let record = self.ready.take();
        if record.is_some() {
            self.records_emitted += 1;
        }
        Ok(record)
    }

    pub fn finish(&mut self) -> Result<(), S4Error> {
        if self.finished {
            return Ok(());
        }
        if self.ready.is_some() {
            return Err(S4Error::new(
                codes::INTERNAL,
                "drain the ready record before finishing the decoder",
            ));
        }
        self.finished = true;
        self.prepare_next(true)?;
        if self.format == Format::Csv && self.ready.is_none() && self.records_emitted == 0 {
            return Err(S4Error::new(codes::DECODE_CSV, "no CSV records found"));
        }
        Ok(())
    }

    pub fn buffered_bytes(&self) -> usize {
        self.pending.len()
            + self
                .ready
                .as_ref()
                .map(|record| record.payload.len() + record.separator.len())
                .unwrap_or(0)
    }

    /// Signals the end of a discrete source segment (e.g. one multipart part).
    ///
    /// Whole-document formats (JSON) emit a complete document immediately and
    /// reset so the next segment decodes independently; a document that spans
    /// segment boundaries stays buffered until it completes. Line/TSV/CSV
    /// formats emit incrementally and need no per-segment handling.
    pub fn end_of_segment(&mut self) -> Result<(), S4Error> {
        if self.format != Format::Json || self.pending.is_empty() || self.ready.is_some() {
            return Ok(());
        }
        match serde_json::from_slice::<serde_json::Value>(&self.pending) {
            Ok(_) => {
                self.ready = Some(Record::new(
                    Bytes::from(std::mem::take(&mut self.pending)),
                    Bytes::new(),
                ));
                self.input_seen = true;
                self.scan_offset = 0;
            }
            Err(error) if error.is_eof() => {}
            Err(error) => return Err(S4Error::new(codes::DECODE_JSON, error.to_string())),
        }
        Ok(())
    }

    fn prepare_next(&mut self, at_eof: bool) -> Result<(), S4Error> {
        if self.ready.is_some() || self.complete {
            return Ok(());
        }
        match self.format {
            Format::Text | Format::Jsonl | Format::Tsv => self.prepare_line(at_eof),
            Format::Csv => self.prepare_csv(at_eof),
            Format::Json => self.prepare_json(at_eof),
        }
    }

    fn prepare_line(&mut self, at_eof: bool) -> Result<(), S4Error> {
        if let Some(relative_end) = self.pending[self.scan_offset..]
            .iter()
            .position(|byte| *byte == b'\n')
        {
            let end = self.scan_offset + relative_end;
            let (payload_end, separator_start) = if end > 0 && self.pending[end - 1] == b'\r' {
                (end - 1, end - 1)
            } else {
                (end, end)
            };
            self.emit(
                payload_end,
                separator_start,
                end + 1,
                codes::DECODE_ENCODING,
            )?;
            return Ok(());
        }
        self.scan_offset = self.pending.len();
        self.ensure_pending_limit(self.limits.max_record_bytes, "record")?;
        if at_eof && (!self.pending.is_empty() || !self.input_seen) {
            validate_utf8(&self.pending, codes::DECODE_ENCODING)?;
            self.emit_final();
        } else if at_eof {
            self.complete = true;
        }
        Ok(())
    }

    fn prepare_json(&mut self, at_eof: bool) -> Result<(), S4Error> {
        self.ensure_pending_limit(self.limits.max_json_document_bytes, "JSON document")?;
        if !at_eof {
            return Ok(());
        }
        if self.pending.is_empty() {
            self.complete = true;
            return Ok(());
        }
        validate_utf8(&self.pending, codes::DECODE_ENCODING)?;
        serde_json::from_slice::<serde_json::Value>(&self.pending)
            .map_err(|error| S4Error::new(codes::DECODE_JSON, error.to_string()))?;
        self.emit_final();
        Ok(())
    }

    fn prepare_csv(&mut self, at_eof: bool) -> Result<(), S4Error> {
        while self.scan_offset < self.pending.len() {
            let byte = self.pending[self.scan_offset];
            match self.csv_state {
                CsvState::FieldStart => match byte {
                    b'"' => self.csv_state = CsvState::Quoted,
                    b',' => self.increment_csv_fields()?,
                    b'\n' | b'\r' => {
                        if let Some((payload_end, separator_end)) =
                            self.csv_boundary(self.scan_offset, at_eof)
                        {
                            if payload_end == 0 {
                                self.consume_csv_empty(separator_end);
                                continue;
                            }
                            self.emit_csv(payload_end, separator_end)?;
                            return Ok(());
                        }
                        break;
                    }
                    _ => self.csv_state = CsvState::Unquoted,
                },
                CsvState::Unquoted => match byte {
                    b',' => {
                        self.increment_csv_fields()?;
                        self.csv_state = CsvState::FieldStart;
                    }
                    b'"' => {
                        return Err(S4Error::new(
                            codes::DECODE_CSV,
                            "quote inside an unquoted CSV field",
                        ));
                    }
                    b'\n' | b'\r' => {
                        if let Some((payload_end, separator_end)) =
                            self.csv_boundary(self.scan_offset, at_eof)
                        {
                            self.emit_csv(payload_end, separator_end)?;
                            return Ok(());
                        }
                        break;
                    }
                    _ => {}
                },
                CsvState::Quoted => {
                    if byte == b'"' {
                        self.csv_state = CsvState::QuoteClosed;
                    }
                }
                CsvState::QuoteClosed => match byte {
                    b'"' => self.csv_state = CsvState::Quoted,
                    b',' => {
                        self.increment_csv_fields()?;
                        self.csv_state = CsvState::FieldStart;
                    }
                    b'\n' | b'\r' => {
                        if let Some((payload_end, separator_end)) =
                            self.csv_boundary(self.scan_offset, at_eof)
                        {
                            self.emit_csv(payload_end, separator_end)?;
                            return Ok(());
                        }
                        break;
                    }
                    _ => {
                        return Err(S4Error::new(
                            codes::DECODE_CSV,
                            "unexpected byte after closing CSV quote",
                        ));
                    }
                },
            }
            self.scan_offset += 1;
        }

        self.ensure_pending_limit(self.limits.max_record_bytes, "CSV record")?;
        if at_eof {
            if self.csv_state == CsvState::Quoted {
                return Err(S4Error::new(
                    codes::DECODE_CSV,
                    "unterminated quoted CSV field",
                ));
            }
            if !self.pending.is_empty() {
                let payload_end = self.pending.len();
                self.validate_csv(payload_end)?;
                validate_utf8(&self.pending, codes::DECODE_ENCODING)?;
                self.emit_final();
                self.reset_csv_state();
            } else {
                self.complete = true;
            }
        }
        Ok(())
    }

    fn csv_boundary(&self, at: usize, at_eof: bool) -> Option<(usize, usize)> {
        if self.pending[at] == b'\n' {
            return Some((at, at + 1));
        }
        if at + 1 < self.pending.len() {
            return if self.pending[at + 1] == b'\n' {
                Some((at, at + 2))
            } else {
                Some((at, at + 1))
            };
        }
        at_eof.then_some((at, at + 1))
    }

    fn emit_csv(&mut self, payload_end: usize, separator_end: usize) -> Result<(), S4Error> {
        self.validate_csv(payload_end)?;
        validate_utf8(&self.pending[..payload_end], codes::DECODE_ENCODING)?;
        self.emit(payload_end, payload_end, separator_end, codes::DECODE_CSV)?;
        self.reset_csv_state();
        Ok(())
    }

    fn validate_csv(&self, payload_end: usize) -> Result<(), S4Error> {
        let mut input = Vec::with_capacity(payload_end + 1);
        input.extend_from_slice(&self.pending[..payload_end]);
        input.push(b'\n');
        let mut output = vec![0; payload_end.saturating_add(1)];
        let mut ends = vec![0; self.limits.max_csv_fields];
        let mut reader = CsvReader::new();
        let (result, consumed, _, fields) = reader.read_record(&input, &mut output, &mut ends);
        if !matches!(result, ReadRecordResult::Record) || consumed != input.len() {
            return Err(S4Error::new(
                codes::DECODE_CSV,
                "CSV parser did not produce one complete record",
            ));
        }
        if fields > self.limits.max_csv_fields {
            return Err(limit_error(
                codes::RECORD_TOO_LARGE,
                "CSV field count",
                fields,
                self.limits.max_csv_fields,
            ));
        }
        Ok(())
    }

    fn emit(
        &mut self,
        payload_end: usize,
        separator_start: usize,
        consumed: usize,
        utf8_code: &'static str,
    ) -> Result<(), S4Error> {
        if payload_end > self.limits.max_record_bytes {
            return Err(limit_error(
                codes::RECORD_TOO_LARGE,
                "record",
                payload_end,
                self.limits.max_record_bytes,
            ));
        }
        validate_utf8(&self.pending[..payload_end], utf8_code)?;
        let payload = Bytes::copy_from_slice(&self.pending[..payload_end]);
        let separator = Bytes::copy_from_slice(&self.pending[separator_start..consumed]);
        self.pending.drain(..consumed);
        self.ready = Some(Record::new(payload, separator));
        self.scan_offset = 0;
        Ok(())
    }

    fn emit_final(&mut self) {
        self.ready = Some(Record::new(
            Bytes::from(std::mem::take(&mut self.pending)),
            Bytes::new(),
        ));
        self.input_seen = true;
        self.complete = true;
        self.scan_offset = 0;
    }

    fn consume_csv_empty(&mut self, consumed: usize) {
        self.pending.drain(..consumed);
        self.reset_csv_state();
    }

    fn reset_csv_state(&mut self) {
        self.csv_state = CsvState::FieldStart;
        self.csv_fields = 1;
        self.scan_offset = 0;
    }

    fn increment_csv_fields(&mut self) -> Result<(), S4Error> {
        self.csv_fields += 1;
        if self.csv_fields > self.limits.max_csv_fields {
            return Err(limit_error(
                codes::RECORD_TOO_LARGE,
                "CSV field count",
                self.csv_fields,
                self.limits.max_csv_fields,
            ));
        }
        Ok(())
    }

    fn ensure_pending_limit(&self, max: usize, kind: &str) -> Result<(), S4Error> {
        if self.pending.len() > max {
            return Err(limit_error(
                codes::RECORD_TOO_LARGE,
                kind,
                self.pending.len(),
                max,
            ));
        }
        Ok(())
    }
}

fn validate_utf8(input: &[u8], code: &'static str) -> Result<(), S4Error> {
    std::str::from_utf8(input)
        .map(|_| ())
        .map_err(|error| S4Error::new(code, error.to_string()))
}

/// Validates a complete set of output records against the selected record
/// format before they are committed downstream.
///
/// Custom filter components are untrusted: their `Emit` and `finish` output
/// must still form a well-formed record stream in the target format. Re-decoding
/// the output with a fresh [`RecordDecoder`] proves structure and encoding
/// (UTF-8, JSON documents, CSV fields, line/TSV framing) without ever
/// committing malformed data.
pub fn validate_output_records(
    format: Format,
    records: &[Record],
    limits: DecoderLimits,
) -> Result<(), S4Error> {
    // A pipeline may legitimately drop every record (e.g. PII redaction on an
    // empty or all-sensitive stream); empty output is always well-formed.
    if records.is_empty() {
        return Ok(());
    }
    let mut decoder = RecordDecoder::new(format, limits)?;
    for record in records {
        if !record.payload.is_empty() {
            decoder.push(&record.payload)?;
            while decoder.next_record()?.is_some() {}
        }
        if !record.separator.is_empty() {
            decoder.push(&record.separator)?;
            while decoder.next_record()?.is_some() {}
        }
    }
    decoder.finish()?;
    while decoder.next_record()?.is_some() {}
    // The line decoder validates framing and UTF-8 but not per-line JSON
    // structure; prove JSONL/JSON documents parse before commit.
    if format == Format::Jsonl {
        for record in records {
            validate_utf8(&record.payload, codes::DECODE_ENCODING)?;
            serde_json::from_slice::<serde_json::Value>(&record.payload)
                .map_err(|error| S4Error::new(codes::DECODE_JSONL, error.to_string()))?;
        }
    }
    Ok(())
}

fn limit_error(code: &'static str, kind: &str, actual: usize, limit: usize) -> S4Error {
    S4Error::new(code, format!("{kind} size {actual} exceeds limit {limit}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_segments_emit_one_document_each() {
        let mut decoder = RecordDecoder::new(Format::Json, DecoderLimits::default()).unwrap();
        decoder.push(br#"{"a":1}"#).unwrap();
        assert!(decoder.next_record().unwrap().is_none());
        decoder.end_of_segment().unwrap();
        let record = decoder.next_record().unwrap().expect("first document");
        assert_eq!(record.payload.as_ref(), br#"{"a":1}"#);
        assert_eq!(record.separator.as_ref(), b"");

        decoder.push(br#"{"b":2}"#).unwrap();
        assert!(decoder.next_record().unwrap().is_none());
        decoder.end_of_segment().unwrap();
        let record = decoder.next_record().unwrap().expect("second document");
        assert_eq!(record.payload.as_ref(), br#"{"b":2}"#);

        decoder.finish().unwrap();
        assert!(decoder.next_record().unwrap().is_none());
    }

    #[test]
    fn json_document_spanning_segments_stays_buffered_until_complete() {
        let mut decoder = RecordDecoder::new(Format::Json, DecoderLimits::default()).unwrap();
        decoder.push(br#"{"a":"#).unwrap();
        decoder.end_of_segment().unwrap();
        assert!(decoder.next_record().unwrap().is_none());
        decoder.push(br#"1}"#).unwrap();
        decoder.finish().unwrap();
        let record = decoder.next_record().unwrap().expect("completed document");
        assert_eq!(record.payload.as_ref(), br#"{"a":1}"#);
        assert!(decoder.next_record().unwrap().is_none());
    }

    #[test]
    fn json_empty_stream_finishes_cleanly() {
        let mut decoder = RecordDecoder::new(Format::Json, DecoderLimits::default()).unwrap();
        decoder.finish().unwrap();
        assert!(decoder.next_record().unwrap().is_none());
    }

    #[test]
    fn validate_output_accepts_well_formed_records_per_format() {
        let limits = DecoderLimits::default();
        let text = vec![Record::new("first", "\n"), Record::new("second", "\n")];
        validate_output_records(Format::Text, &text, limits).unwrap();

        let jsonl = vec![
            Record::new(r#"{"a":1}"#, "\n"),
            Record::new(r#"{"b":2}"#, "\n"),
        ];
        validate_output_records(Format::Jsonl, &jsonl, limits).unwrap();

        let json_doc = vec![Record::new(b"{\"a\":1}".to_vec(), "")];
        validate_output_records(Format::Json, &json_doc, limits).unwrap();
    }

    #[test]
    fn validate_output_rejects_malformed_structured_records() {
        let limits = DecoderLimits::default();

        let bad_utf8 = vec![Record::new(vec![0xff, 0xfe, 0x01], "\n")];
        assert_eq!(
            validate_output_records(Format::Text, &bad_utf8, limits)
                .unwrap_err()
                .code(),
            codes::DECODE_ENCODING
        );

        let bad_jsonl = vec![Record::new(b"{\"a\":".to_vec(), "\n")];
        assert_eq!(
            validate_output_records(Format::Jsonl, &bad_jsonl, limits)
                .unwrap_err()
                .code(),
            codes::DECODE_JSONL
        );

        let bad_json = vec![Record::new(b"{\"a\":1".to_vec(), "")];
        assert_eq!(
            validate_output_records(Format::Json, &bad_json, limits)
                .unwrap_err()
                .code(),
            codes::DECODE_JSON
        );
    }
}
