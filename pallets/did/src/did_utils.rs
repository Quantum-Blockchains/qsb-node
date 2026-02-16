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
    let did_id_bytes = if input.starts_with(DID_PREFIX) {
        &input[DID_PREFIX.len()..]
    } else {
        input
    };

    let decoded = bs58::decode(did_id_bytes)
        .into_vec()
        .map_err(|_| Error::<T>::InvalidDidId)?;
    let did_id: [u8; 32] = decoded.try_into().map_err(|_| Error::<T>::InvalidDidId)?;
    Ok(did_id)
}
