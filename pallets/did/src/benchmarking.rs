#![cfg(feature = "runtime-benchmarks")]

use crate::pallet::{Call, Config, DidRecords, Pallet};
use crate::{KeyRole, MetadataEntry, ServiceEndpoint};
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

fn setup_did<T: crate::pallet::Config>(
    caller: T::AccountId,
) -> (Vec<u8>, Vec<u8>, mldsa44::Public) {
    let owner_public = generate_key();
    let owner_pk = owner_public.0.to_vec();

    let mut payload = DID_CREATE_PREFIX.to_vec();
    payload.extend_from_slice(&owner_pk.encode());
    let signature = sign_payload(&owner_public, &payload);

    assert_ok!(Pallet::<T>::create_did(
        RawOrigin::Signed(caller).into(),
        owner_pk.clone(),
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
        let mut payload = DID_CREATE_PREFIX.to_vec();
        payload.extend_from_slice(&owner_pk.encode());
        let signature = sign_payload(&owner_public, &payload);
        let did_id = did_id_from_public_key::<T>(&owner_pk);
    }: _(RawOrigin::Signed(caller), owner_pk, signature)
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
        let roles = vec![KeyRole::AssertionMethod];
        let mut payload = DID_ADD_KEY_PREFIX.to_vec();
        payload.extend_from_slice(&did_input.encode());
        payload.extend_from_slice(&new_pk.encode());
        payload.extend_from_slice(&roles.encode());
        let signature = sign_payload(&owner_public, &payload);
    }: _(RawOrigin::Signed(caller), did_input, new_pk, roles, signature)

    revoke_key {
        let caller: T::AccountId = whitelisted_caller();
        let (did_input, _owner_pk, owner_public) = setup_did::<T>(caller.clone());
        let target_public = generate_key();
        let target_pk = target_public.0.to_vec();
        let add_roles = vec![KeyRole::AssertionMethod];
        let mut add_payload = DID_ADD_KEY_PREFIX.to_vec();
        add_payload.extend_from_slice(&did_input.encode());
        add_payload.extend_from_slice(&target_pk.encode());
        add_payload.extend_from_slice(&add_roles.encode());
        let add_signature = sign_payload(&owner_public, &add_payload);
        assert_ok!(Pallet::<T>::add_key(
            RawOrigin::Signed(caller.clone()).into(),
            did_input.clone(),
            target_pk.clone(),
            add_roles,
            add_signature,
        ));
        let mut payload = DID_REVOKE_KEY_PREFIX.to_vec();
        payload.extend_from_slice(&did_input.encode());
        payload.extend_from_slice(&target_pk.encode());
        let signature = sign_payload(&owner_public, &payload);
    }: _(RawOrigin::Signed(caller), did_input, target_pk, signature)

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
        let add_roles = vec![KeyRole::AssertionMethod];
        let mut add_payload = DID_ADD_KEY_PREFIX.to_vec();
        add_payload.extend_from_slice(&did_input.encode());
        add_payload.extend_from_slice(&old_pk.encode());
        add_payload.extend_from_slice(&add_roles.encode());
        let add_signature = sign_payload(&owner_public, &add_payload);
        assert_ok!(Pallet::<T>::add_key(
            RawOrigin::Signed(caller.clone()).into(),
            did_input.clone(),
            old_pk.clone(),
            add_roles,
            add_signature,
        ));
        let new_public = generate_key();
        let new_pk = new_public.0.to_vec();
        let new_roles = vec![KeyRole::AssertionMethod];
        let mut payload = DID_ROTATE_KEY_PREFIX.to_vec();
        payload.extend_from_slice(&did_input.encode());
        payload.extend_from_slice(&old_pk.encode());
        payload.extend_from_slice(&new_pk.encode());
        payload.extend_from_slice(&new_roles.encode());
        let signature = sign_payload(&owner_public, &payload);
    }: _(RawOrigin::Signed(caller), did_input, old_pk, new_pk, new_roles, signature)

    update_roles {
        let caller: T::AccountId = whitelisted_caller();
        let (did_input, _owner_pk, owner_public) = setup_did::<T>(caller.clone());
        let target_public = generate_key();
        let target_pk = target_public.0.to_vec();
        let add_roles = vec![KeyRole::AssertionMethod];
        let mut add_payload = DID_ADD_KEY_PREFIX.to_vec();
        add_payload.extend_from_slice(&did_input.encode());
        add_payload.extend_from_slice(&target_pk.encode());
        add_payload.extend_from_slice(&add_roles.encode());
        let add_signature = sign_payload(&owner_public, &add_payload);
        assert_ok!(Pallet::<T>::add_key(
            RawOrigin::Signed(caller.clone()).into(),
            did_input.clone(),
            target_pk.clone(),
            add_roles,
            add_signature,
        ));
        let new_roles = vec![KeyRole::CapabilityInvocation];
        let mut payload = DID_UPDATE_ROLES_PREFIX.to_vec();
        payload.extend_from_slice(&did_input.encode());
        payload.extend_from_slice(&target_pk.encode());
        payload.extend_from_slice(&new_roles.encode());
        let signature = sign_payload(&owner_public, &payload);
    }: _(RawOrigin::Signed(caller), did_input, target_pk, new_roles, signature)

    impl_benchmark_test_suite!(
        Pallet,
        crate::tests::mock_runtime::new_test_ext(),
        crate::tests::mock_runtime::Test
    );
}
