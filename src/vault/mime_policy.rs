use crate::vault::errors::VaultError;

/// MIME prefixes/exact types accepted for Vault and chat-attachment uploads.
/// Anything outside this list is rejected before any bytes are persisted.
const ALLOWED_PREFIXES: &[&str] = &["image/", "text/", "video/", "audio/"];

const ALLOWED_EXACT: &[&str] = &[
    "application/pdf",
    "application/json",
    "application/xml",
    "application/zip",
    "application/octet-stream",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
];

pub fn ensure_mime_allowed(mime: &str) -> Result<(), VaultError> {
    let normalized = mime.trim().to_ascii_lowercase();
    let allowed = ALLOWED_PREFIXES
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
        || ALLOWED_EXACT.iter().any(|exact| normalized == *exact);
    if allowed {
        Ok(())
    } else {
        Err(VaultError::InvalidStructure(format!(
            "content type not allowed: {}",
            mime
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_common_document_and_media_types() {
        for mime in [
            "image/png",
            "image/jpeg",
            "text/plain",
            "text/csv",
            "video/mp4",
            "audio/mpeg",
            "application/pdf",
            "application/json",
            "application/zip",
            "application/octet-stream",
        ] {
            assert!(ensure_mime_allowed(mime).is_ok(), "expected {mime} allowed");
        }
    }

    #[test]
    fn rejects_disallowed_types() {
        for mime in [
            "application/x-msdownload",
            "application/x-sh",
            "application/vnd.microsoft.portable-executable",
        ] {
            assert!(
                ensure_mime_allowed(mime).is_err(),
                "expected {mime} rejected"
            );
        }
    }

    #[test]
    fn normalizes_case_and_surrounding_whitespace() {
        for mime in [
            " IMAGE/PNG ",
            "\tText/Plain\n",
            "Video/MP4",
            "AUDIO/MPEG",
            " Application/PDF ",
            "APPLICATION/VND.OPENXMLFORMATS-OFFICEDOCUMENT.WORDPROCESSINGML.DOCUMENT",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/msword",
            "application/xml",
        ] {
            assert!(
                ensure_mime_allowed(mime).is_ok(),
                "expected {mime:?} allowed"
            );
        }
    }

    #[test]
    fn prefix_types_allow_parameters_but_exact_application_types_do_not() {
        assert!(ensure_mime_allowed("text/plain; charset=utf-8").is_ok());
        assert!(ensure_mime_allowed("image/svg+xml; charset=utf-8").is_ok());
        assert!(ensure_mime_allowed("application/pdf; charset=utf-8").is_err());
        assert!(ensure_mime_allowed("application/json-patch+json").is_err());
    }

    #[test]
    fn rejects_empty_boundary_and_near_miss_values() {
        for mime in [
            "",
            "   ",
            "image",
            "text",
            "video",
            "audio",
            "application/",
            "application/pdfx",
            "x-image/png",
            "multipart/form-data",
            "message/rfc822",
        ] {
            let error = ensure_mime_allowed(mime).expect_err("mime should be rejected");
            assert!(error.to_string().contains("content type not allowed"));
            assert!(error.to_string().contains(mime));
        }
    }
}
