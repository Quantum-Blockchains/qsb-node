use super::mock_runtime::{new_test_ext, Did, RuntimeOrigin};
use super::test_helpers::{create_did, keypair, sign};
use crate::ServiceEndpoint;
use codec::Encode;
use frame_support::assert_ok;

#[test]
fn service_management_still_works_with_authentication_signature() {
    new_test_ext().execute_with(|| {
        let owner_pair = keypair(1);
        let (_did_id, did_input, _owner_pk) = create_did(1, &owner_pair);
        let service = ServiceEndpoint {
            id: b"svc-1".to_vec(),
            service_type: b"type".to_vec(),
            endpoint: b"https://example.org".to_vec(),
        };

        let mut add_payload = b"QSB_DID_ADD_SERVICE".to_vec();
        add_payload.extend_from_slice(&did_input.encode());
        add_payload.extend_from_slice(&service.encode());
        let add_sig = sign(&owner_pair, &add_payload);
        assert_ok!(Did::add_service(
            RuntimeOrigin::signed(1),
            did_input.clone(),
            service.clone(),
            add_sig
        ));

        let mut remove_payload = b"QSB_DID_REMOVE_SERVICE".to_vec();
        remove_payload.extend_from_slice(&did_input.encode());
        remove_payload.extend_from_slice(&service.id.encode());
        let remove_sig = sign(&owner_pair, &remove_payload);
        assert_ok!(Did::remove_service(
            RuntimeOrigin::signed(1),
            did_input.clone(),
            service.id.clone(),
            remove_sig
        ));
    });
}
