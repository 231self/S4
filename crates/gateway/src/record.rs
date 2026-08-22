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

fn limit_error(code: &'static str, kind: &str, actual: usize, limit: usize) -> S4Error {
    S4Error::new(code, format!("{kind} size {actual} exceeds limit {limit}"))
}
