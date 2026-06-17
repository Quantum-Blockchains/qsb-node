#![cfg(feature = "runtime-benchmarks")]

use crate::pallet::{Call, Config, DidRecords, Pallet};
use crate::{KeyMaterialInput, KeyRole, MetadataEntry, ServiceEndpoint};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use codec::Encode;
use frame_benchmarking::v1::{benchmarks, whitelisted_caller};
use frame_support::assert_ok;
use frame_system::{pallet_prelude::BlockNumberFor, RawOrigin};
use sp_core::{crypto::KeyTypeId, mldsa44};
use sp_io::{
    crypto::{mldsa44_generate, mldsa44_sign},
    hashing::blake2_256,
};
use sp_runtime::traits::Zero;
use sp_std::vec;
use sp_std::vec::Vec;

const DID_PREFIX: &[u8] = b"did:qsb:";
const DID_MATERIAL_PREFIX: &[u8] = b"QSB_DID";
const DID_CREATE_PREFIX: &[u8] = b"QSB_DID_CREATE";
const DID_ADD_KEY_PREFIX: &[u8] = b"QSB_DID_ADD_KEY";
const DID_REVOKE_KEY_PREFIX: &[u8] = b"QSB_DID_REVOKE_KEY";
const DID_DEACTIVATE_PREFIX: &[u8] = b"QSB_DID_DEACTIVATE";
const DID_ADD_SERVICE_PREFIX: &[u8] = b"QSB_DID_ADD_SERVICE";
const DID_REMOVE_SERVICE_PREFIX: &[u8] = b"QSB_DID_REMOVE_SERVICE";
const DID_SET_METADATA_PREFIX: &[u8] = b"QSB_DID_SET_METADATA";
const DID_REMOVE_METADATA_PREFIX: &[u8] = b"QSB_DID_REMOVE_METADATA";
const DID_ROTATE_KEY_PREFIX: &[u8] = b"QSB_DID_ROTATE_KEY";
const DID_UPDATE_ROLES_PREFIX: &[u8] = b"QSB_DID_UPDATE_ROLES";
const BENCH_KEY_TYPE: KeyTypeId = KeyTypeId(*b"did!");
const MULTICODEC_ML_DSA_44: u64 = 0x1210;

fn generate_key() -> mldsa44::Public {
    mldsa44_generate(BENCH_KEY_TYPE, None)
}

fn sign_payload(public: &mldsa44::Public, payload: &[u8]) -> Vec<u8> {
    mldsa44_sign(BENCH_KEY_TYPE, public, payload)
        .expect("benchmark key should be present")
        .0
        .to_vec()
}

fn did_id_from_public_key<T: crate::pallet::Config>(public_key: &[u8]) -> [u8; 32] {
    let genesis = frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero());
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

fn multikey_from_raw_mldsa44(raw_public_key: &[u8]) -> Vec<u8> {
    let mut prefixed = encode_uvarint(MULTICODEC_ML_DSA_44);
    prefixed.extend_from_slice(raw_public_key);
    let encoded = URL_SAFE_NO_PAD.encode(prefixed);
    let mut out = Vec::with_capacity(encoded.len() + 1);
    out.push(b'u');
    out.extend_from_slice(encoded.as_bytes());
    out
}

fn key_id_from_suffix(did_input: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut key_id = did_input.to_vec();
    key_id.extend_from_slice(b"#");
    key_id.extend_from_slice(suffix);
    key_id
}

fn setup_did<T: crate::pallet::Config>(
    caller: T::AccountId,
) -> (Vec<u8>, Vec<u8>, mldsa44::Public) {
    let owner_public = generate_key();
    let owner_pk = owner_public.0.to_vec();
    let owner_multikey = multikey_from_raw_mldsa44(&owner_pk);

    let mut payload = DID_CREATE_PREFIX.to_vec();
    payload.extend_from_slice(&owner_multikey.encode());
    let signature = sign_payload(&owner_public, &payload);

    assert_ok!(Pallet::<T>::create_did(
        RawOrigin::Signed(caller).into(),
        owner_multikey,
        signature
    ));

    let did_id = did_id_from_public_key::<T>(&owner_pk);
    let did_input = did_input_from_id(&did_id);
    (did_input, owner_pk, owner_public)
}

benchmarks! {
    create_did {
        let caller: T::AccountId = whitelisted_caller();
        let owner_public = generate_key();
        let owner_pk = owner_public.0.to_vec();
        let owner_multikey = multikey_from_raw_mldsa44(&owner_pk);
        let mut payload = DID_CREATE_PREFIX.to_vec();
        payload.extend_from_slice(&owner_multikey.encode());
        let signature = sign_payload(&owner_public, &payload);
        let did_id = did_id_from_public_key::<T>(&owner_pk);
    }: _(RawOrigin::Signed(caller), owner_multikey, signature)
    verify {
        let details = DidRecords::<T>::get(did_id)
            .expect("did should exist after create");
        assert_eq!(details.keys.len(), 1);
    }

    add_key {
        let caller: T::AccountId = whitelisted_caller();
        let (did_input, _owner_pk, owner_public) = setup_did::<T>(caller.clone());
        let new_public = generate_key();
        let new_pk = new_public.0.to_vec();
        let new_key_material = KeyMaterialInput::Multikey(multikey_from_raw_mldsa44(&new_pk));
        let roles = vec![KeyRole::AssertionMethod];
        let key_id_suffix = None;
        let controller = None;
        let mut payload = DID_ADD_KEY_PREFIX.to_vec();
        payload.extend_from_slice(&did_input.encode());
        payload.extend_from_slice(&key_id_suffix.encode());
        payload.extend_from_slice(&new_key_material.encode());
        payload.extend_from_slice(&roles.encode());
        payload.extend_from_slice(&controller.encode());
        let signature = sign_payload(&owner_public, &payload);
    }: _(RawOrigin::Signed(caller), did_input, key_id_suffix, new_key_material, roles, controller, signature)

    revoke_key {
        let caller: T::AccountId = whitelisted_caller();
        let (did_input, _owner_pk, owner_public) = setup_did::<T>(caller.clone());
        let target_public = generate_key();
        let target_pk = target_public.0.to_vec();
        let target_key_material = KeyMaterialInput::Multikey(multikey_from_raw_mldsa44(&target_pk));
        let add_roles = vec![KeyRole::AssertionMethod];
        let key_id_suffix = Some(b"bench-revoke".to_vec());
        let controller = None;
        let mut add_payload = DID_ADD_KEY_PREFIX.to_vec();
        add_payload.extend_from_slice(&did_input.encode());
        add_payload.extend_from_slice(&key_id_suffix.encode());
        add_payload.extend_from_slice(&target_key_material.encode());
        add_payload.extend_from_slice(&add_roles.encode());
        add_payload.extend_from_slice(&controller.encode());
        let add_signature = sign_payload(&owner_public, &add_payload);
        assert_ok!(Pallet::<T>::add_key(
            RawOrigin::Signed(caller.clone()).into(),
            did_input.clone(),
            key_id_suffix,
            target_key_material,
            add_roles,
            controller,
            add_signature,
        ));
        let target_key_id = key_id_from_suffix(&did_input, b"bench-revoke");
        let mut payload = DID_REVOKE_KEY_PREFIX.to_vec();
        payload.extend_from_slice(&did_input.encode());
        payload.extend_from_slice(&target_key_id.encode());
        let signature = sign_payload(&owner_public, &payload);
    }: _(RawOrigin::Signed(caller), did_input, target_key_id, signature)

    deactivate_did {
        let caller: T::AccountId = whitelisted_caller();
        let (did_input, _owner_pk, owner_public) = setup_did::<T>(caller.clone());
        let mut payload = DID_DEACTIVATE_PREFIX.to_vec();
        payload.extend_from_slice(&did_input.encode());
        let signature = sign_payload(&owner_public, &payload);
    }: _(RawOrigin::Signed(caller), did_input, signature)

    add_service {
        let caller: T::AccountId = whitelisted_caller();
        let (did_input, _owner_pk, owner_public) = setup_did::<T>(caller.clone());
        let service = ServiceEndpoint {
            id: b"svc-a".to_vec(),
            service_type: b"type".to_vec(),
            endpoint: b"https://example.org".to_vec(),
        };
        let mut payload = DID_ADD_SERVICE_PREFIX.to_vec();
        payload.extend_from_slice(&did_input.encode());
        payload.extend_from_slice(&service.encode());
        let signature = sign_payload(&owner_public, &payload);
    }: _(RawOrigin::Signed(caller), did_input, service, signature)

    remove_service {
        let caller: T::AccountId = whitelisted_caller();
        let (did_input, _owner_pk, owner_public) = setup_did::<T>(caller.clone());
        let service = ServiceEndpoint {
            id: b"svc-r".to_vec(),
            service_type: b"type".to_vec(),
            endpoint: b"https://example.org".to_vec(),
        };
        let mut add_payload = DID_ADD_SERVICE_PREFIX.to_vec();
        add_payload.extend_from_slice(&did_input.encode());
        add_payload.extend_from_slice(&service.encode());
        let add_signature = sign_payload(&owner_public, &add_payload);
        assert_ok!(Pallet::<T>::add_service(
            RawOrigin::Signed(caller.clone()).into(),
            did_input.clone(),
            service.clone(),
            add_signature,
        ));
        let mut payload = DID_REMOVE_SERVICE_PREFIX.to_vec();
        payload.extend_from_slice(&did_input.encode());
        payload.extend_from_slice(&service.id.encode());
        let signature = sign_payload(&owner_public, &payload);
    }: _(RawOrigin::Signed(caller), did_input, service.id, signature)

    set_metadata {
        let caller: T::AccountId = whitelisted_caller();
        let (did_input, _owner_pk, owner_public) = setup_did::<T>(caller.clone());
        let entry = MetadataEntry { key: b"k".to_vec(), value: b"v".to_vec() };
        let mut payload = DID_SET_METADATA_PREFIX.to_vec();
        payload.extend_from_slice(&did_input.encode());
        payload.extend_from_slice(&entry.encode());
        let signature = sign_payload(&owner_public, &payload);
    }: _(RawOrigin::Signed(caller), did_input, entry, signature)

    remove_metadata {
        let caller: T::AccountId = whitelisted_caller();
        let (did_input, _owner_pk, owner_public) = setup_did::<T>(caller.clone());
        let entry = MetadataEntry { key: b"k2".to_vec(), value: b"v2".to_vec() };
        let mut set_payload = DID_SET_METADATA_PREFIX.to_vec();
        set_payload.extend_from_slice(&did_input.encode());
        set_payload.extend_from_slice(&entry.encode());
        let set_signature = sign_payload(&owner_public, &set_payload);
        assert_ok!(Pallet::<T>::set_metadata(
            RawOrigin::Signed(caller.clone()).into(),
            did_input.clone(),
            entry.clone(),
            set_signature,
        ));
        let mut payload = DID_REMOVE_METADATA_PREFIX.to_vec();
        payload.extend_from_slice(&did_input.encode());
        payload.extend_from_slice(&entry.key.encode());
        let signature = sign_payload(&owner_public, &payload);
    }: _(RawOrigin::Signed(caller), did_input, entry.key, signature)

    rotate_key {
        let caller: T::AccountId = whitelisted_caller();
        let (did_input, _owner_pk, owner_public) = setup_did::<T>(caller.clone());
        let old_public = generate_key();
        let old_pk = old_public.0.to_vec();
        let old_key_material = KeyMaterialInput::Multikey(multikey_from_raw_mldsa44(&old_pk));
        let add_roles = vec![KeyRole::AssertionMethod];
        let old_key_id_suffix = Some(b"bench-rotate".to_vec());
        let add_controller = None;
        let mut add_payload = DID_ADD_KEY_PREFIX.to_vec();
        add_payload.extend_from_slice(&did_input.encode());
        add_payload.extend_from_slice(&old_key_id_suffix.encode());
        add_payload.extend_from_slice(&old_key_material.encode());
        add_payload.extend_from_slice(&add_roles.encode());
        add_payload.extend_from_slice(&add_controller.encode());
        let add_signature = sign_payload(&owner_public, &add_payload);
        assert_ok!(Pallet::<T>::add_key(
            RawOrigin::Signed(caller.clone()).into(),
            did_input.clone(),
            old_key_id_suffix,
            old_key_material,
            add_roles,
            add_controller,
            add_signature,
        ));
        let old_key_id = key_id_from_suffix(&did_input, b"bench-rotate");
        let new_public = generate_key();
        let new_pk = new_public.0.to_vec();
        let new_key_material = KeyMaterialInput::Multikey(multikey_from_raw_mldsa44(&new_pk));
        let new_roles = vec![KeyRole::AssertionMethod];
        let new_key_id_suffix = None;
        let new_controller = None;
        let mut payload = DID_ROTATE_KEY_PREFIX.to_vec();
        payload.extend_from_slice(&did_input.encode());
        payload.extend_from_slice(&old_key_id.encode());
        payload.extend_from_slice(&new_key_material.encode());
        payload.extend_from_slice(&new_key_id_suffix.encode());
        payload.extend_from_slice(&new_controller.encode());
        payload.extend_from_slice(&new_roles.encode());
        let signature = sign_payload(&owner_public, &payload);
    }: _(RawOrigin::Signed(caller), did_input, old_key_id, new_key_material, new_key_id_suffix, new_controller, new_roles, signature)

    update_roles {
        let caller: T::AccountId = whitelisted_caller();
        let (did_input, _owner_pk, owner_public) = setup_did::<T>(caller.clone());
        let target_public = generate_key();
        let target_pk = target_public.0.to_vec();
        let target_key_material = KeyMaterialInput::Multikey(multikey_from_raw_mldsa44(&target_pk));
        let add_roles = vec![KeyRole::AssertionMethod];
        let key_id_suffix = Some(b"bench-roles".to_vec());
        let controller = None;
        let mut add_payload = DID_ADD_KEY_PREFIX.to_vec();
        add_payload.extend_from_slice(&did_input.encode());
        add_payload.extend_from_slice(&key_id_suffix.encode());
        add_payload.extend_from_slice(&target_key_material.encode());
        add_payload.extend_from_slice(&add_roles.encode());
        add_payload.extend_from_slice(&controller.encode());
        let add_signature = sign_payload(&owner_public, &add_payload);
        assert_ok!(Pallet::<T>::add_key(
            RawOrigin::Signed(caller.clone()).into(),
            did_input.clone(),
            key_id_suffix,
            target_key_material,
            add_roles,
            controller,
            add_signature,
        ));
        let target_key_id = key_id_from_suffix(&did_input, b"bench-roles");
        let new_roles = vec![KeyRole::CapabilityInvocation];
        let mut payload = DID_UPDATE_ROLES_PREFIX.to_vec();
        payload.extend_from_slice(&did_input.encode());
        payload.extend_from_slice(&target_key_id.encode());
        payload.extend_from_slice(&new_roles.encode());
        let signature = sign_payload(&owner_public, &payload);
    }: _(RawOrigin::Signed(caller), did_input, target_key_id, new_roles, signature)

    impl_benchmark_test_suite!(
        Pallet,
        crate::tests::mock_runtime::new_test_ext(),
        crate::tests::mock_runtime::Test
    );
}
