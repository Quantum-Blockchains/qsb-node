use super::mock_runtime::{new_test_ext, Did, RuntimeEvent, RuntimeOrigin, System, Test};
use super::test_helpers::*;
use crate::{pallet::DidRecords, Error, KeyRole, MetadataEntry};
use frame_support::{assert_noop, assert_ok};

#[test]
fn create_did_creates_single_active_authentication_key() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let (_did_id, did_input, owner_pk) = create_did(1, &owner_pair);

        let details = Did::get_did(did_input).expect("did should be present");
        assert!(!details.deactivated);
        assert_eq!(details.version, 0);
        assert_eq!(details.keys.len(), 1);
        assert_eq!(details.keys[0].public_key, owner_pk);
        assert_eq!(details.keys[0].roles, vec![KeyRole::Authentication]);
        assert!(!details.keys[0].revoked);
    });
}

#[test]
fn add_key_rejects_second_active_authentication_key() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let (_did_id, did_input, _owner_pk) = create_did(1, &owner_pair);
        let second_pair = keypair(2);
        let second_pk = public_key(&second_pair);
        let roles = vec![KeyRole::Authentication];
        let did_signature = add_key_signature(&owner_pair, &did_input, &second_pk, &roles);

        assert_noop!(
            Did::add_key(
                RuntimeOrigin::signed(1),
                did_input,
                second_pk,
                roles,
                did_signature
            ),
            Error::<Test>::AuthenticationKeyAlreadyExists
        );
    });
}

#[test]
fn revoke_key_rejects_last_authentication_key() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let (_did_id, did_input, owner_pk) = create_did(1, &owner_pair);
        let did_signature = revoke_key_signature(&owner_pair, &did_input, &owner_pk);

        assert_noop!(
            Did::revoke_key(RuntimeOrigin::signed(1), did_input, owner_pk, did_signature),
            Error::<Test>::CannotRevokeLastAuthenticationKey
        );
    });
}

#[test]
fn update_roles_rejects_removing_last_authentication_role() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let (_did_id, did_input, owner_pk) = create_did(1, &owner_pair);
        let new_roles = vec![KeyRole::AssertionMethod];
        let did_signature = update_roles_signature(&owner_pair, &did_input, &owner_pk, &new_roles);

        assert_noop!(
            Did::update_roles(
                RuntimeOrigin::signed(1),
                did_input,
                owner_pk,
                new_roles,
                did_signature
            ),
            Error::<Test>::CannotRemoveLastAuthenticationRole
        );
    });
}

#[test]
fn rotate_key_requires_authentication_when_rotating_auth_key() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let (_did_id, did_input, owner_pk) = create_did(1, &owner_pair);
        let new_pair = keypair(2);
        let new_pk = public_key(&new_pair);
        let new_roles = vec![KeyRole::AssertionMethod];
        let did_signature =
            rotate_key_signature(&owner_pair, &did_input, &owner_pk, &new_pk, &new_roles);

        assert_noop!(
            Did::rotate_key(
                RuntimeOrigin::signed(1),
                did_input,
                owner_pk,
                new_pk,
                new_roles,
                did_signature
            ),
            Error::<Test>::CannotRevokeLastAuthenticationKey
        );
    });
}

#[test]
fn non_authentication_key_cannot_authorize_calls() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let (_did_id, did_input, _owner_pk) = create_did(1, &owner_pair);

        let aux_pair = keypair(2);
        let aux_pk = public_key(&aux_pair);
        let aux_roles = vec![KeyRole::AssertionMethod];
        let add_sig = add_key_signature(&owner_pair, &did_input, &aux_pk, &aux_roles);
        assert_ok!(Did::add_key(
            RuntimeOrigin::signed(1),
            did_input.clone(),
            aux_pk,
            aux_roles,
            add_sig
        ));

        let entry = MetadataEntry {
            key: b"name".to_vec(),
            value: b"alice".to_vec(),
        };
        let wrong_sig = set_metadata_signature(&aux_pair, &did_input, &entry);
        assert_noop!(
            Did::set_metadata(
                RuntimeOrigin::signed(1),
                did_input.clone(),
                entry.clone(),
                wrong_sig
            ),
            Error::<Test>::InvalidSignature
        );

        let good_sig = set_metadata_signature(&owner_pair, &did_input, &entry);
        assert_ok!(Did::set_metadata(
            RuntimeOrigin::signed(1),
            did_input.clone(),
            entry,
            good_sig
        ));
    });
}

#[test]
fn rotate_authentication_key_moves_authority_to_new_key() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        let owner_pair = keypair(1);
        let (did_id, did_input, owner_pk) = create_did(1, &owner_pair);

        let new_pair = keypair(2);
        let new_pk = public_key(&new_pair);
        let new_roles = vec![KeyRole::Authentication];
        let rotate_sig =
            rotate_key_signature(&owner_pair, &did_input, &owner_pk, &new_pk, &new_roles);
        assert_ok!(Did::rotate_key(
            RuntimeOrigin::signed(1),
            did_input.clone(),
            owner_pk.clone(),
            new_pk.clone(),
            new_roles,
            rotate_sig
        ));
        System::assert_last_event(RuntimeEvent::Did(crate::Event::KeyRotated {
            did: did_input.clone(),
            old_public_key: owner_pk.clone(),
            new_public_key: new_pk.clone(),
        }));

        let entry = MetadataEntry {
            key: b"status".to_vec(),
            value: b"ok".to_vec(),
        };
        let old_sig = set_metadata_signature(&owner_pair, &did_input, &entry);
        assert_noop!(
            Did::set_metadata(
                RuntimeOrigin::signed(1),
                did_input.clone(),
                entry.clone(),
                old_sig
            ),
            Error::<Test>::InvalidSignature
        );

        let new_sig = set_metadata_signature(&new_pair, &did_input, &entry);
        assert_ok!(Did::set_metadata(
            RuntimeOrigin::signed(1),
            did_input.clone(),
            entry,
            new_sig
        ));

        let details = Did::get_did(did_input).expect("did should remain present");
        assert_eq!(
            details
                .keys
                .iter()
                .filter(|k| !k.revoked && k.roles.contains(&KeyRole::Authentication))
                .count(),
            1
        );
        assert_eq!(details.version, 2);
        assert!(DidRecords::<Test>::contains_key(did_id));
    });
}
