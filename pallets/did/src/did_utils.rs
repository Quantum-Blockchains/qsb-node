use crate::constants::{DID_MATERIAL_PREFIX, DID_PREFIX};
use crate::pallet::{Config, Error};
use frame_system::pallet_prelude::BlockNumberFor;
use sp_io::hashing::blake2_256;
use sp_runtime::traits::Zero;
use sp_std::vec::Vec;

pub(crate) fn did_id_from_public_key<T: Config>(public_key: &[u8]) -> [u8; 32] {
    let genesis = frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero());
    let mut material =
        Vec::with_capacity(DID_MATERIAL_PREFIX.len() + genesis.as_ref().len() + public_key.len());
    material.extend_from_slice(DID_MATERIAL_PREFIX);
    material.extend_from_slice(genesis.as_ref());
    material.extend_from_slice(public_key);
    blake2_256(&material)
}

pub(crate) fn did_string_from_did_id(did_id: &[u8; 32]) -> Vec<u8> {
    let did_id_b58 = bs58::encode(did_id).into_string();
    let mut did = Vec::with_capacity(DID_PREFIX.len() + did_id_b58.len());
    did.extend_from_slice(DID_PREFIX);
    did.extend_from_slice(did_id_b58.as_bytes());
    did
}

pub(crate) fn decode_did_id<T: Config>(input: &[u8]) -> Result<[u8; 32], Error<T>> {
    if !input.starts_with(DID_PREFIX) {
        return Err(Error::<T>::InvalidDidId);
    }
    let did_id_bytes = &input[DID_PREFIX.len()..];
    decode_did_id_body::<T>(did_id_bytes)
}

pub(crate) fn decode_did_id_legacy<T: Config>(input: &[u8]) -> Result<[u8; 32], Error<T>> {
    let did_id_bytes = if input.starts_with(DID_PREFIX) {
        &input[DID_PREFIX.len()..]
    } else {
        input
    };
    decode_did_id_body::<T>(did_id_bytes)
}

fn decode_did_id_body<T: Config>(did_id_bytes: &[u8]) -> Result<[u8; 32], Error<T>> {
    let decoded = bs58::decode(did_id_bytes)
        .into_vec()
        .map_err(|_| Error::<T>::InvalidDidId)?;
    let did_id: [u8; 32] = decoded.try_into().map_err(|_| Error::<T>::InvalidDidId)?;
    Ok(did_id)
}

pub(crate) fn build_full_key_id(did: &[u8], key_suffix: &[u8]) -> Vec<u8> {
    let mut key_id = did.to_vec();
    key_id.extend_from_slice(key_suffix);
    key_id
}

pub(crate) fn key_suffix_from_index(index: u32) -> Vec<u8> {
    let mut out = b"#key-".to_vec();

    if index == 0 {
        out.push(b'0');
        return out;
    }

    let mut digits = [0u8; 10];
    let mut n = index;
    let mut i = 0usize;
    while n > 0 {
        digits[i] = (n % 10) as u8;
        n /= 10;
        i += 1;
    }

    while i > 0 {
        i -= 1;
        out.push(b'0' + digits[i]);
    }

    out
}

pub(crate) fn is_valid_uri(value: &[u8]) -> bool {
    if value.is_empty() {
        return false;
    }
    if value.iter().any(|b| *b <= 0x20 || *b >= 0x7f) {
        return false;
    }

    let Some(colon_pos) = value.iter().position(|b| *b == b':') else {
        return false;
    };
    if colon_pos == 0 {
        return false;
    }

    let scheme = &value[..colon_pos];
    if !scheme[0].is_ascii_alphabetic() {
        return false;
    }
    scheme
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'-' || *b == b'.')
}

pub(crate) fn is_valid_key_id_suffix(suffix: &[u8]) -> bool {
    if suffix.len() <= 1 || suffix[0] != b'#' {
        return false;
    }
    if suffix[1..].iter().any(|b| *b == b'#') {
        return false;
    }
    suffix[1..].iter().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                *b,
                b'-' | b'.' | b'_' | b'~' | b'!' | b'$' | b'&' | b'\''
                    | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':' | b'@'
                    | b'/' | b'?' | b'%'
            )
    })
}

pub(crate) fn is_valid_did_url<T: Config>(value: &[u8]) -> bool {
    if !value.starts_with(DID_PREFIX) {
        return false;
    }
    if value.len() <= DID_PREFIX.len() {
        return false;
    }

    let mut base_end = value.len();
    for (idx, b) in value.iter().enumerate() {
        if *b == b'#' || *b == b'?' || *b == b'/' {
            base_end = idx;
            break;
        }
    }
    if base_end <= DID_PREFIX.len() {
        return false;
    }

    let base = &value[..base_end];
    if decode_did_id::<T>(base).is_err() {
        return false;
    }

    if let Some(hash_pos) = value.iter().position(|b| *b == b'#') {
        if hash_pos + 1 >= value.len() {
            return false;
        }
        let suffix = &value[hash_pos..];
        return is_valid_key_id_suffix(suffix);
    }
    true
}

pub(crate) fn is_strict_did_uri<T: Config>(value: &[u8]) -> bool {
    if !value.starts_with(DID_PREFIX) {
        return false;
    }
    if value.len() <= DID_PREFIX.len() {
        return false;
    }
    if value.iter().any(|b| *b == b'#' || *b == b'?' || *b == b'/') {
        return false;
    }
    decode_did_id::<T>(value).is_ok()
}
