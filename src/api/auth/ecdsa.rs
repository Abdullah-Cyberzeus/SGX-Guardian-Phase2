use anyhow::{Result, anyhow};
use p256::ecdsa::Signature as P256Signature;

// Some signing backends emit ASN.1 DER while our wire formats require fixed
// width P-256 signatures encoded as R||S.
pub(crate) fn normalize_p256_signature(signature: &[u8]) -> Result<Vec<u8>> {
    if signature.len() == 64 {
        return Ok(signature.to_vec());
    }

    let signature = P256Signature::from_der(signature).map_err(|e| {
        anyhow!(
            "signature must be raw 64-byte or DER-encoded P-256: {:?}",
            e
        )
    })?;
    Ok(signature.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::SignatureEncoding;

    fn sample_raw_signature() -> [u8; 64] {
        let mut raw = [0u8; 64];
        raw[0] = 0x01;
        raw[32] = 0x80;
        raw
    }

    #[test]
    fn der_signature_normalizes_to_raw_rs() {
        let raw = sample_raw_signature();
        let der = P256Signature::try_from(raw.as_slice())
            .expect("build raw signature")
            .to_der()
            .to_vec();

        assert_eq!(der[0], 0x30);
        assert_eq!(der.len(), 71);
        assert_eq!(normalize_p256_signature(&der).expect("normalize"), raw);
    }

    #[test]
    fn raw_signature_stays_unchanged() {
        let raw = sample_raw_signature();
        assert_eq!(normalize_p256_signature(&raw).expect("normalize"), raw);
    }
}
