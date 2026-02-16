use super::mock_runtime::{new_test_ext, Did, RuntimeOrigin, Test};
use super::test_helpers::{create_did, keypair, public_key, set_metadata_signature};
use crate::{pallet::DidRecords, Error, KeyRole, MetadataEntry};
use frame_support::assert_noop;

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
                public_key: second_pk,
                roles: vec![KeyRole::Authentication],
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
