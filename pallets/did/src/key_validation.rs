use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use crate::constants::*;
use sp_std::vec::Vec;

pub(crate) enum KeyValidationError {
    InvalidMultikey,
}

// Validates Multikey lexical/encoding structure:
// - multibase base64url prefix 'u'
// - decodable base64url payload
// - leading unsigned varint multicodec code
// - non-empty key bytes after codec prefix
//
// Returns (multicodec_code, raw_public_key_bytes).
pub(crate) fn validate_multikey(multikey: &[u8]) -> Result<(u64, Vec<u8>), KeyValidationError> {
    if multikey.is_empty() || multikey[0] != b'u' || multikey.len() <= 1 {
        return Err(KeyValidationError::InvalidMultikey);
    }

    let decoded = URL_SAFE_NO_PAD
        .decode(&multikey[1..])
        .map_err(|_| KeyValidationError::InvalidMultikey)?;
    if decoded.is_empty() {
        return Err(KeyValidationError::InvalidMultikey);
    }

    let (codec, codec_len) = decode_uvarint(&decoded).ok_or(KeyValidationError::InvalidMultikey)?;
    if codec_len >= decoded.len() {
        return Err(KeyValidationError::InvalidMultikey);
    }
    let key_bytes = decoded[codec_len..].to_vec();
    if key_bytes.is_empty() {
        return Err(KeyValidationError::InvalidMultikey);
    }

    Ok((codec, key_bytes))
}

// For known codecs, enforce expected raw public key length.
// Unknown codecs are allowed (method-level policy), as long as Multikey syntax is valid.
pub(crate) fn validate_known_codec_length(codec: u64, key_bytes: &[u8]) -> bool {
    match codec {
        MULTICODEC_ML_DSA_44 => key_bytes.len() == 1312,
        MULTICODEC_ML_DSA_65 => key_bytes.len() == 1952,
        MULTICODEC_ML_DSA_87 => key_bytes.len() == 2592,
        MULTICODEC_ED25519_PUB => key_bytes.len() == 32,
        MULTICODEC_SECP256K1_PUB | MULTICODEC_P256_PUB => {
            key_bytes.len() == 33 || key_bytes.len() == 65
        }
        _ => true,
    }
}

pub(crate) fn decode_uvarint(input: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;

    for (idx, byte) in input.iter().copied().enumerate() {
        let low = (byte & 0x7f) as u64;
        value |= low.checked_shl(shift)?;
        if (byte & 0x80) == 0 {
            return Some((value, idx + 1));
        }
        shift = shift.saturating_add(7);
        if shift >= 64 {
            return None;
        }
    }
    None
}
