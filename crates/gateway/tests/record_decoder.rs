use proptest::prelude::*;
use s4_error::codes;
use s4_gateway::Format;
use s4_gateway::record::{DecoderLimits, Record, RecordDecoder, decode_all};

fn small_limits() -> DecoderLimits {
    DecoderLimits {
        max_source_frame_bytes: 32,
        max_record_bytes: 64,
        max_json_document_bytes: 64,
        max_csv_fields: 8,
    }
}

fn decode_chunks(
    input: &[u8],
    format: Format,
    limits: DecoderLimits,
    chunk_sizes: &[usize],
) -> Result<Vec<Record>, s4_error::S4Error> {
    let mut decoder = RecordDecoder::new(format, limits)?;
    let mut records = Vec::new();
    let mut offset = 0;
    let mut chunk_index = 0;
    while offset < input.len() {
        let requested = chunk_sizes
            .get(chunk_index % chunk_sizes.len())
            .copied()
            .unwrap_or(1)
            .max(1);
        let end = (offset + requested).min(input.len());
        decoder.push(&input[offset..end])?;
        while let Some(record) = decoder.next_record()? {
            records.push(record);
        }
        assert!(
            decoder.buffered_bytes() <= limits.max_record_bytes + limits.max_source_frame_bytes,
            "decoder retained unbounded source data"
        );
        offset = end;
        chunk_index += 1;
    }
    decoder.finish()?;
    while let Some(record) = decoder.next_record()? {
        records.push(record);
    }
    Ok(records)
}

fn reconstruct(records: &[Record]) -> Vec<u8> {
    let mut output = Vec::new();
    for record in records {
        output.extend_from_slice(&record.payload);
        output.extend_from_slice(&record.separator);
    }
    output
}

fn assert_every_split(input: &[u8], format: Format) {
    let limits = DecoderLimits {
        max_source_frame_bytes: input.len().max(1),
        max_record_bytes: input.len().max(1),
        max_json_document_bytes: input.len().max(1),
        max_csv_fields: 32,
    };
    let baseline = decode_all(input, format, limits).unwrap();
    for split in 0..=input.len() {
        let mut decoder = RecordDecoder::new(format, limits).unwrap();
        let mut actual = Vec::new();
        decoder.push(&input[..split]).unwrap();
        while let Some(record) = decoder.next_record().unwrap() {
            actual.push(record);
        }
        decoder.push(&input[split..]).unwrap();
        while let Some(record) = decoder.next_record().unwrap() {
            actual.push(record);
        }
        decoder.finish().unwrap();
        while let Some(record) = decoder.next_record().unwrap() {
            actual.push(record);
        }
        assert_eq!(actual, baseline, "split at byte {split}");
    }
}

#[test]
fn text_preserves_payloads_and_separators() {
    let input = b"alpha\r\n\nbeta\ngamma";
    let records = decode_chunks(input, Format::Text, small_limits(), &[1]).unwrap();
    assert_eq!(
        records,
        vec![
            Record::new(&b"alpha"[..], &b"\r\n"[..]),
            Record::new(&b""[..], &b"\n"[..]),
            Record::new(&b"beta"[..], &b"\n"[..]),
            Record::new(&b"gamma"[..], &b""[..]),
        ]
    );
    assert_eq!(reconstruct(&records), input);
}

#[test]
fn empty_text_is_one_empty_record() {
    let records = decode_all(b"", Format::Text, small_limits()).unwrap();
    assert_eq!(records, vec![Record::new(&b""[..], &b""[..])]);
}

#[test]
fn trailing_separator_does_not_create_extra_record() {
    let records = decode_all(b"alpha\n", Format::Text, small_limits()).unwrap();
    assert_eq!(records, vec![Record::new(&b"alpha"[..], &b"\n"[..])]);
}

#[test]
fn utf8_code_point_can_cross_every_chunk_boundary() {
    let input = "before 日 after\r\n次".as_bytes();
    assert_every_split(input, Format::Text);
}

#[test]
fn invalid_utf8_is_rejected() {
    let error = decode_chunks(b"ok\n\xff", Format::Text, small_limits(), &[1]).unwrap_err();
    assert_eq!(error.code(), codes::DECODE_ENCODING);
}

#[test]
fn source_frame_limit_is_enforced_before_buffering() {
    let mut decoder = RecordDecoder::new(Format::Text, small_limits()).unwrap();
    let error = decoder.push(&[b'x'; 33]).unwrap_err();
    assert_eq!(error.code(), codes::LIMIT_INPUT_BYTES);
    assert_eq!(decoder.buffered_bytes(), 0);
}

#[test]
fn record_limit_accepts_boundary_and_rejects_next_byte() {
    let limits = DecoderLimits {
        max_source_frame_bytes: 8,
        max_record_bytes: 4,
        max_json_document_bytes: 4,
        max_csv_fields: 4,
    };
    assert!(decode_chunks(b"1234", Format::Text, limits, &[2]).is_ok());
    let error = decode_chunks(b"12345", Format::Text, limits, &[2]).unwrap_err();
    assert_eq!(error.code(), codes::RECORD_TOO_LARGE);
}

#[test]
fn caller_must_drain_before_push_or_finish() {
    let mut decoder = RecordDecoder::new(Format::Text, small_limits()).unwrap();
    decoder.push(b"one\ntwo").unwrap();
    assert_eq!(decoder.push(b"three").unwrap_err().code(), codes::INTERNAL);
    assert_eq!(decoder.finish().unwrap_err().code(), codes::INTERNAL);
    assert_eq!(decoder.next_record().unwrap().unwrap().payload, "one");
    assert_eq!(decoder.next_record().unwrap(), None);
    decoder.finish().unwrap();
    assert_eq!(decoder.next_record().unwrap().unwrap().payload, "two");
}

#[test]
fn complete_json_is_validated_only_at_finish() {
    let input = br#"{"message":"split value","items":[1,2,3]}"#;
    let records = decode_chunks(input, Format::Json, small_limits(), &[1, 2, 3]).unwrap();
    assert_eq!(records, vec![Record::new(&input[..], &b""[..])]);

    let error = decode_chunks(b"{\"missing\":", Format::Json, small_limits(), &[2]).unwrap_err();
    assert_eq!(error.code(), codes::DECODE_JSON);
}

#[test]
fn complete_json_limit_is_enforced_incrementally() {
    let limits = DecoderLimits {
        max_json_document_bytes: 4,
        ..small_limits()
    };
    let error = decode_chunks(b"[123]", Format::Json, limits, &[2]).unwrap_err();
    assert_eq!(error.code(), codes::RECORD_TOO_LARGE);
}

#[test]
fn csv_preserves_quoted_newlines_escaped_quotes_and_crlf() {
    let input = b"name,note\r\nAlice,\"line one\nline \"\"two\"\"\"\r\nBob,plain";
    let records = decode_chunks(input, Format::Csv, small_limits(), &[1]).unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0], Record::new(&b"name,note"[..], &b"\r\n"[..]));
    assert_eq!(
        records[1],
        Record::new(&b"Alice,\"line one\nline \"\"two\"\"\""[..], &b"\r\n"[..])
    );
    assert_eq!(records[2], Record::new(&b"Bob,plain"[..], &b""[..]));
    assert_eq!(reconstruct(&records), input);
}

#[test]
fn csv_rejects_malformed_quotes_and_excess_fields() {
    let error = decode_chunks(b"a,\"unterminated", Format::Csv, small_limits(), &[2]).unwrap_err();
    assert_eq!(error.code(), codes::DECODE_CSV);

    let limits = DecoderLimits {
        max_csv_fields: 2,
        ..small_limits()
    };
    let error = decode_chunks(b"a,b,c\n", Format::Csv, limits, &[2]).unwrap_err();
    assert_eq!(error.code(), codes::RECORD_TOO_LARGE);
}

#[test]
fn empty_csv_is_rejected() {
    let error = decode_all(b"\r\n\n", Format::Csv, small_limits()).unwrap_err();
    assert_eq!(error.code(), codes::DECODE_CSV);
}

#[test]
fn every_split_point_is_invariant() {
    assert_every_split(b"alpha\r\nbeta\ngamma", Format::Text);
    assert_every_split(b"one\ttwo\r\nthree\tfour", Format::Tsv);
    assert_every_split(b"{\"a\":1}\n{\"b\":2}\r\n", Format::Jsonl);
    assert_every_split(
        b"name,note\r\nAlice,\"quoted\nvalue\"\r\nBob,\"escaped \"\"quote\"\"\"",
        Format::Csv,
    );
    assert_every_split(br#"{"message":"hello","ok":true}"#, Format::Json);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn randomized_chunk_partitions_match_single_frame(
        format_index in 0usize..5,
        chunk_sizes in prop::collection::vec(1usize..16, 1..32),
    ) {
        let (format, input): (Format, &[u8]) = match format_index {
            0 => (Format::Text, "first 日\r\nsecond\nthird".as_bytes()),
            1 => (Format::Jsonl, "{\"a\":1}\n{\"b\":\"日\"}\n{\"c\":3}".as_bytes()),
            2 => (Format::Tsv, b"a\tb\r\nc\td\ne\tf"),
            3 => (Format::Csv, b"a,b\r\n\"quoted\nvalue\",c\r\nd,\"escaped \"\"quote\"\"\""),
            _ => (Format::Json, "{\"nested\":{\"value\":\"日\"},\"items\":[1,2,3]}".as_bytes()),
        };
        let limits = DecoderLimits {
            max_source_frame_bytes: 64,
            max_record_bytes: 256,
            max_json_document_bytes: 256,
            max_csv_fields: 32,
        };
        let baseline = decode_all(input, format, limits).unwrap();
        let chunked = decode_chunks(input, format, limits, &chunk_sizes).unwrap();
        prop_assert_eq!(chunked, baseline);
    }
}
