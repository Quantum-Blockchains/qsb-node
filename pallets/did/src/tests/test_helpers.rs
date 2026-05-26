use super::mock_runtime::{Did, RuntimeOrigin, System};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use crate::{KeyRole, MetadataEntry};
use codec::Encode;
use frame_support::assert_ok;
use sp_core::mldsa44;
use sp_core::Pair as PairT;
use sp_io::hashing::blake2_256;

const DID_MATERIAL_PREFIX: &[u8] = b"QSB_DID";
const DID_PREFIX: &[u8] = b"did:qsb:";
const DID_CREATE_PREFIX: &[u8] = b"QSB_DID_CREATE";
const DID_ADD_KEY_PREFIX: &[u8] = b"QSB_DID_ADD_KEY";
const DID_REVOKE_KEY_PREFIX: &[u8] = b"QSB_DID_REVOKE_KEY";
const DID_DEACTIVATE_PREFIX: &[u8] = b"QSB_DID_DEACTIVATE";
const DID_SET_METADATA_PREFIX: &[u8] = b"QSB_DID_SET_METADATA";
const DID_ROTATE_KEY_PREFIX: &[u8] = b"QSB_DID_ROTATE_KEY";
const DID_UPDATE_ROLES_PREFIX: &[u8] = b"QSB_DID_UPDATE_ROLES";
const MULTICODEC_ML_DSA_44: u64 = 0x1210;

pub(super) fn keypair(seed: u8) -> mldsa44::Pair {
    <mldsa44::Pair as PairT>::from_seed(&[seed; 32])
}

pub(super) fn sign(pair: &mldsa44::Pair, payload: &[u8]) -> Vec<u8> {
    pair.sign(payload).0.to_vec()
}

pub(super) fn public_key(pair: &mldsa44::Pair) -> Vec<u8> {
    pair.public().0.to_vec()
}

pub(super) fn multikey_from_raw_mldsa44(raw_public_key: &[u8]) -> Vec<u8> {
    let mut prefixed = encode_uvarint(MULTICODEC_ML_DSA_44);
    prefixed.extend_from_slice(raw_public_key);
    let encoded = URL_SAFE_NO_PAD.encode(prefixed);
    let mut out = Vec::with_capacity(encoded.len() + 1);
    out.push(b'u');
    out.extend_from_slice(encoded.as_bytes());
    out
}

fn encode_uvarint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

fn did_id_from_public_key(public_key: &[u8]) -> [u8; 32] {
    let genesis = System::block_hash(0u64);
    let mut material =
        Vec::with_capacity(DID_MATERIAL_PREFIX.len() + genesis.as_ref().len() + public_key.len());
    material.extend_from_slice(DID_MATERIAL_PREFIX);
    material.extend_from_slice(genesis.as_ref());
    material.extend_from_slice(public_key);
    blake2_256(&material)
}

fn did_input_from_id(did_id: &[u8; 32]) -> Vec<u8> {
    let did_id_b58 = bs58::encode(did_id).into_string();
    let mut did = Vec::with_capacity(DID_PREFIX.len() + did_id_b58.len());
    did.extend_from_slice(DID_PREFIX);
    did.extend_from_slice(did_id_b58.as_bytes());
    did
}

pub(super) fn create_did(owner: u64, owner_pair: &mldsa44::Pair) -> ([u8; 32], Vec<u8>, Vec<u8>) {
    let owner_pk = public_key(owner_pair);
    let owner_multikey = multikey_from_raw_mldsa44(&owner_pk);
    let mut payload = DID_CREATE_PREFIX.to_vec();
    payload.extend_from_slice(&owner_multikey.encode());
    let signature = sign(owner_pair, &payload);

    assert_ok!(Did::create_did(
        RuntimeOrigin::signed(owner),
        owner_multikey,
        signature
    ));

    let did_id = did_id_from_public_key(&owner_pk);
    let did_input = did_input_from_id(&did_id);
    (did_id, did_input, owner_pk)
}

pub(super) fn add_key_signature(
    signer: &mldsa44::Pair,
    did_input: &[u8],
    key_id_suffix: &Option<Vec<u8>>,
    new_public_key: &[u8],
    roles: &[KeyRole],
    controller: &Option<Vec<u8>>,
) -> Vec<u8> {
    let mut payload = DID_ADD_KEY_PREFIX.to_vec();
    payload.extend_from_slice(&did_input.to_vec().encode());
    payload.extend_from_slice(&key_id_suffix.encode());
    payload.extend_from_slice(&new_public_key.to_vec().encode());
    payload.extend_from_slice(&roles.to_vec().encode());
    payload.extend_from_slice(&controller.encode());
    sign(signer, &payload)
}

pub(super) fn revoke_key_signature(
    signer: &mldsa44::Pair,
    did_input: &[u8],
    key_id: &[u8],
) -> Vec<u8> {
    let mut payload = DID_REVOKE_KEY_PREFIX.to_vec();
    payload.extend_from_slice(&did_input.to_vec().encode());
    payload.extend_from_slice(&key_id.to_vec().encode());
    sign(signer, &payload)
}

pub(super) fn rotate_key_signature(
    signer: &mldsa44::Pair,
    did_input: &[u8],
    old_key_id: &[u8],
    new_public_key: &[u8],
    new_key_id_suffix: &Option<Vec<u8>>,
    new_controller: &Option<Vec<u8>>,
    roles: &[KeyRole],
) -> Vec<u8> {
    let mut payload = DID_ROTATE_KEY_PREFIX.to_vec();
    payload.extend_from_slice(&did_input.to_vec().encode());
    payload.extend_from_slice(&old_key_id.to_vec().encode());
    payload.extend_from_slice(&new_public_key.to_vec().encode());
    payload.extend_from_slice(&new_key_id_suffix.encode());
    payload.extend_from_slice(&new_controller.encode());
    payload.extend_from_slice(&roles.to_vec().encode());
    sign(signer, &payload)
}

pub(super) fn update_roles_signature(
    signer: &mldsa44::Pair,
    did_input: &[u8],
    key_id: &[u8],
    roles: &[KeyRole],
) -> Vec<u8> {
    let mut payload = DID_UPDATE_ROLES_PREFIX.to_vec();
    payload.extend_from_slice(&did_input.to_vec().encode());
    payload.extend_from_slice(&key_id.to_vec().encode());
    payload.extend_from_slice(&roles.to_vec().encode());
    sign(signer, &payload)
}

pub(super) fn set_metadata_signature(
    signer: &mldsa44::Pair,
    did_input: &[u8],
    entry: &MetadataEntry,
) -> Vec<u8> {
    let mut payload = DID_SET_METADATA_PREFIX.to_vec();
    payload.extend_from_slice(&did_input.to_vec().encode());
    payload.extend_from_slice(&entry.encode());
    sign(signer, &payload)
}

pub(super) fn deactivate_signature(signer: &mldsa44::Pair, did_input: &[u8]) -> Vec<u8> {
    let mut payload = DID_DEACTIVATE_PREFIX.to_vec();
    payload.extend_from_slice(&did_input.to_vec().encode());
    sign(signer, &payload)
}
