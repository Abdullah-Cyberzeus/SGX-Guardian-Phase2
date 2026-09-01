use sgx_guardian_client::advisory::{AdvisoryError, AdvisoryResult};
use std::io::{Error, ErrorKind};

#[test]
fn io_error_display_includes_io_prefix() {
    let err = AdvisoryError::from(Error::new(ErrorKind::NotFound, "missing"));
    assert_eq!(err.to_string(), "io: missing");
}

#[test]
fn json_error_display_includes_json_prefix() {
    let err = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
    assert!(AdvisoryError::from(err).to_string().starts_with("json: "));
}

#[test]
fn invalid_rules_display_includes_reason() {
    let err = AdvisoryError::InvalidRules("bad signature".into());
    assert_eq!(err.to_string(), "invalid advisory rules: bad signature");
}

#[test]
fn result_alias_accepts_ok_value() {
    let value: AdvisoryResult<u8> = Ok(7);
    assert_eq!(value.unwrap(), 7);
}

#[test]
fn result_alias_accepts_error_value() {
    let value: AdvisoryResult<()> = Err(AdvisoryError::InvalidRules("x".into()));
    assert!(value.is_err());
}

macro_rules! io_kind_tests {
    ($($name:ident => $kind:expr),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                let err = AdvisoryError::from(Error::new($kind, "io-case"));
                assert_eq!(err.to_string(), "io: io-case");
            }
        )+
    };
}

io_kind_tests! {
    io_error_not_found_is_wrapped => ErrorKind::NotFound,
    io_error_permission_denied_is_wrapped => ErrorKind::PermissionDenied,
    io_error_connection_refused_is_wrapped => ErrorKind::ConnectionRefused,
    io_error_connection_reset_is_wrapped => ErrorKind::ConnectionReset,
    io_error_connection_aborted_is_wrapped => ErrorKind::ConnectionAborted,
    io_error_not_connected_is_wrapped => ErrorKind::NotConnected,
    io_error_addr_in_use_is_wrapped => ErrorKind::AddrInUse,
    io_error_addr_not_available_is_wrapped => ErrorKind::AddrNotAvailable,
    io_error_broken_pipe_is_wrapped => ErrorKind::BrokenPipe,
    io_error_already_exists_is_wrapped => ErrorKind::AlreadyExists,
    io_error_would_block_is_wrapped => ErrorKind::WouldBlock,
    io_error_invalid_input_is_wrapped => ErrorKind::InvalidInput,
    io_error_invalid_data_is_wrapped => ErrorKind::InvalidData,
    io_error_timed_out_is_wrapped => ErrorKind::TimedOut,
    io_error_write_zero_is_wrapped => ErrorKind::WriteZero,
    io_error_interrupted_is_wrapped => ErrorKind::Interrupted,
    io_error_unsupported_is_wrapped => ErrorKind::Unsupported,
    io_error_unexpected_eof_is_wrapped => ErrorKind::UnexpectedEof,
    io_error_other_is_wrapped => ErrorKind::Other,
}

macro_rules! json_error_tests {
    ($($name:ident => $payload:expr),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                let err = serde_json::from_str::<serde_json::Value>($payload).unwrap_err();
                assert!(AdvisoryError::from(err).to_string().starts_with("json: "));
            }
        )+
    };
}

json_error_tests! {
    json_error_empty_payload_is_wrapped => "",
    json_error_truncated_object_is_wrapped => "{\"a\"",
    json_error_trailing_comma_is_wrapped => "{\"a\":1,}",
}
