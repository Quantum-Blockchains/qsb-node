use super::mock_runtime::{new_test_ext, Did, RuntimeOrigin, Test};
use super::test_helpers::{
    add_key_signature, create_did, keypair, public_key, set_metadata_signature,
};
use crate::{pallet::DidRecords, Error, KeyRole, MetadataEntry, VerificationMethodType};
use frame_support::{assert_noop, assert_ok};

#[test]
fn invalid_authentication_key_count_is_rejected_on_call() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let (did_id, did_input, _owner_pk) = create_did(1, &owner_pair);

        DidRecords::<Test>::mutate(did_id, |maybe_details| {
            let details = maybe_details.as_mut().expect("did should exist");
            details.keys[0].revoked = true;
        });

        let entry = MetadataEntry {
            key: b"k".to_vec(),
            value: b"v".to_vec(),
        };
        let sig = set_metadata_signature(&owner_pair, &did_input, &entry);
        assert_noop!(
            Did::set_metadata(RuntimeOrigin::signed(1), did_input, entry, sig),
            Error::<Test>::InvalidAuthenticationKeyCount
        );
    });
}

#[test]
fn invalid_authentication_key_count_with_two_active_auth_keys_is_rejected_on_call() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let (did_id, did_input, _owner_pk) = create_did(1, &owner_pair);

        let second_pair = keypair(2);
        let second_pk = public_key(&second_pair);
        DidRecords::<Test>::mutate(did_id, |maybe_details| {
            let details = maybe_details.as_mut().expect("did should exist");
            details.keys.push(crate::DidKey {
                key_id: b"did:qsb:test#extra-auth".to_vec(),
                vm_type: VerificationMethodType::Multikey,
                public_key: second_pk,
                roles: vec![KeyRole::Authentication],
                controller: None,
                revoked: false,
            });
        });

        let entry = MetadataEntry {
            key: b"k2".to_vec(),
            value: b"v2".to_vec(),
        };
        let sig = set_metadata_signature(&owner_pair, &did_input, &entry);
        assert_noop!(
            Did::set_metadata(RuntimeOrigin::signed(1), did_input, entry, sig),
            Error::<Test>::InvalidAuthenticationKeyCount
        );
    });
}

#[test]
fn invalid_public_key_is_rejected_in_create_did() {
    new_test_ext().execute_with(|| {
        let invalid_pk = vec![1u8; 32];
        let dummy_signature = vec![2u8; 1];

        assert_noop!(
            Did::create_did(RuntimeOrigin::signed(1), invalid_pk, dummy_signature),
            Error::<Test>::InvalidPublicKey
        );
    });
}

#[test]
fn invalid_create_signature_format_is_rejected() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let owner_pk = public_key(&owner_pair);

        assert_noop!(
            Did::create_did(RuntimeOrigin::signed(1), owner_pk, vec![0u8; 17]),
            Error::<Test>::InvalidDidSignature
        );
    });
}

#[test]
fn invalid_did_id_is_rejected_before_signature_verification() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let (_did_id, _did_input, _owner_pk) = create_did(1, &owner_pair);

        let entry = MetadataEntry {
            key: b"x".to_vec(),
            value: b"y".to_vec(),
        };

        assert_noop!(
            Did::set_metadata(
                RuntimeOrigin::signed(1),
                b"did:qsb:not_base58_id".to_vec(),
                entry,
                vec![0u8; 2420]
            ),
            Error::<Test>::InvalidDidId
        );
    });
}

#[test]
fn invalid_did_signature_format_is_rejected_on_mutation_call() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let (_did_id, did_input, _owner_pk) = create_did(1, &owner_pair);

        let entry = MetadataEntry {
            key: b"bad".to_vec(),
            value: b"sig".to_vec(),
        };

        assert_noop!(
            Did::set_metadata(RuntimeOrigin::signed(1), did_input, entry, vec![7u8; 10]),
            Error::<Test>::InvalidDidSignature
        );
    });
}

#[test]
fn add_key_rejects_duplicate_key_id_suffix() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let (_did_id, did_input, _owner_pk) = create_did(1, &owner_pair);

        let first_pair = keypair(2);
        let first_pk = public_key(&first_pair);
        let first_roles = vec![KeyRole::AssertionMethod];
        let first_suffix = Some(b"key-11".to_vec());
        let first_controller = None;
        let first_sig = add_key_signature(
            &owner_pair,
            &did_input,
            &first_suffix,
            VerificationMethodType::Multikey,
            &first_pk,
            &first_roles,
            &first_controller,
        );
        assert_ok!(Did::add_key(
            RuntimeOrigin::signed(1),
            did_input.clone(),
            first_suffix,
            VerificationMethodType::Multikey,
            first_pk,
            first_roles,
            first_controller,
            first_sig
        ));

        let second_pair = keypair(3);
        let second_pk = public_key(&second_pair);
        let second_roles = vec![KeyRole::CapabilityInvocation];
        let dup_suffix = Some(b"key-11".to_vec());
        let second_controller = None;
        let second_sig = add_key_signature(
            &owner_pair,
            &did_input,
            &dup_suffix,
            VerificationMethodType::Multikey,
            &second_pk,
            &second_roles,
            &second_controller,
        );
        assert_noop!(
            Did::add_key(
                RuntimeOrigin::signed(1),
                did_input,
                dup_suffix,
                VerificationMethodType::Multikey,
                second_pk,
                second_roles,
                second_controller,
                second_sig
            ),
            Error::<Test>::KeyIdAlreadyExists
        );
    });
}

#[test]
fn add_key_normalizes_suffix_without_hash() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let (_did_id, did_input, _owner_pk) = create_did(1, &owner_pair);

        let new_pair = keypair(2);
        let new_pk = public_key(&new_pair);
        let roles = vec![KeyRole::AssertionMethod];
        let key_suffix = Some(b"key-12".to_vec());
        let controller = None;
        let sig = add_key_signature(
            &owner_pair,
            &did_input,
            &key_suffix,
            VerificationMethodType::Multikey,
            &new_pk,
            &roles,
            &controller,
        );

        assert_ok!(Did::add_key(
            RuntimeOrigin::signed(1),
            did_input.clone(),
            key_suffix,
            VerificationMethodType::Multikey,
            new_pk.clone(),
            roles,
            controller,
            sig
        ));

        let details = Did::get_did(did_input).expect("did should exist");
        let key = details
            .keys
            .iter()
            .find(|k| k.public_key == new_pk)
            .expect("added key should exist");
        assert!(key.key_id.ends_with(b"#key-12"));
    });
}

#[test]
fn add_key_rejects_full_did_key_id_suffix() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let (_did_id, did_input, _owner_pk) = create_did(1, &owner_pair);

        let new_pair = keypair(2);
        let new_pk = public_key(&new_pair);
        let roles = vec![KeyRole::AssertionMethod];
        let invalid_suffix = Some(b"did:qsb:some#key-13".to_vec());
        let controller = None;
        let sig = add_key_signature(
            &owner_pair,
            &did_input,
            &invalid_suffix,
            VerificationMethodType::Multikey,
            &new_pk,
            &roles,
            &controller,
        );

        assert_noop!(
            Did::add_key(
                RuntimeOrigin::signed(1),
                did_input,
                invalid_suffix,
                VerificationMethodType::Multikey,
                new_pk,
                roles,
                controller,
                sig
            ),
            Error::<Test>::InvalidKeyIdSuffix
        );
    });
}

#[test]
fn auto_generated_key_id_skips_taken_index() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let (did_id, did_input, _owner_pk) = create_did(1, &owner_pair);

        DidRecords::<Test>::mutate(did_id, |maybe_details| {
            let details = maybe_details.as_mut().expect("did should exist");
            details.next_key_index = 1;
        });

        let first_pair = keypair(2);
        let first_pk = public_key(&first_pair);
        let first_roles = vec![KeyRole::AssertionMethod];
        let first_sig = add_key_signature(
            &owner_pair,
            &did_input,
            &None,
            VerificationMethodType::Multikey,
            &first_pk,
            &first_roles,
            &None,
        );
        assert_ok!(Did::add_key(
            RuntimeOrigin::signed(1),
            did_input.clone(),
            None,
            VerificationMethodType::Multikey,
            first_pk,
            first_roles,
            None,
            first_sig
        ));

        let second_pair = keypair(3);
        let second_pk = public_key(&second_pair);
        let second_roles = vec![KeyRole::CapabilityInvocation];
        let second_sig = add_key_signature(
            &owner_pair,
            &did_input,
            &None,
            VerificationMethodType::Multikey,
            &second_pk,
            &second_roles,
            &None,
        );
        assert_ok!(Did::add_key(
            RuntimeOrigin::signed(1),
            did_input.clone(),
            None,
            VerificationMethodType::Multikey,
            second_pk.clone(),
            second_roles,
            None,
            second_sig
        ));

        let details = Did::get_did(did_input).expect("did should exist");
        let second_key = details
            .keys
            .iter()
            .find(|k| k.public_key == second_pk)
            .expect("second key should exist");
        assert!(second_key.key_id.ends_with(b"#key-2"));
    });
}
