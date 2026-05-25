use super::mock_runtime::{new_test_ext, Did, RuntimeOrigin};
use super::test_helpers::{add_key_signature, create_did, keypair, public_key, revoke_key_signature};
use crate::{KeyRole, VerificationMethodType};
use frame_support::assert_ok;

#[test]
fn resolve_did_returns_invalid_did_error() {
    new_test_ext().execute_with(|| {
        let result = Did::resolve_did(b"did:qsb:not_base58".to_vec());
        assert!(result.did_document.is_none());
        assert_eq!(
            result.did_resolution_metadata.error,
            Some(b"invalidDid".to_vec())
        );
    });
}

#[test]
fn resolve_did_returns_not_found_error() {
    new_test_ext().execute_with(|| {
        let fake_id = [9u8; 32];
        let fake_did = {
            let mut out = b"did:qsb:".to_vec();
            out.extend_from_slice(bs58::encode(fake_id).into_string().as_bytes());
            out
        };

        let result = Did::resolve_did(fake_did);
        assert!(result.did_document.is_none());
        assert_eq!(
            result.did_resolution_metadata.error,
            Some(b"notFound".to_vec())
        );
    });
}

#[test]
fn resolve_did_maps_active_keys_and_roles() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let (_did_id, did_input, _owner_pk) = create_did(1, &owner_pair);

        let second_pair = keypair(2);
        let second_pk = public_key(&second_pair);
        let second_roles = vec![KeyRole::AssertionMethod, KeyRole::CapabilityInvocation];
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

        let revoke_sig = revoke_key_signature(&owner_pair, &did_input, &second_pk);
        assert_ok!(Did::revoke_key(
            RuntimeOrigin::signed(1),
            did_input.clone(),
            second_pk.clone(),
            revoke_sig
        ));

        let result = Did::resolve_did(did_input.clone());
        let did_doc = result.did_document.expect("did document should exist");

        assert_eq!(did_doc.id, did_input);
        assert_eq!(result.did_resolution_metadata.error, None);
        assert_eq!(
            result.did_resolution_metadata.content_type,
            Some(b"application/did+ld+json".to_vec())
        );
        assert!(!result.did_document_metadata.deactivated);
        assert_eq!(result.did_document_metadata.version_id, 2);

        assert_eq!(did_doc.verification_method.len(), 1);
        assert_eq!(did_doc.authentication.len(), 1);
        assert!(did_doc
            .verification_method
            .iter()
            .any(|vm| vm.public_key_multibase.is_some() && vm.public_key_jwk.is_none()));
        assert!(did_doc
            .verification_method
            .iter()
            .any(|vm| vm.id.ends_with(b"#update")));
        assert!(did_doc
            .verification_method
            .iter()
            .all(|vm| vm.controller == did_doc.id));
        assert!(!did_doc
            .verification_method
            .iter()
            .any(|vm| vm.id.ends_with(b"#key-1")));
    });
}
