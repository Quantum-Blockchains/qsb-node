use super::mock_runtime::{new_test_ext, Did, RuntimeEvent, RuntimeOrigin, System, Test};
use super::test_helpers::{create_did, deactivate_signature, keypair, sign};
use crate::{Error, ServiceEndpoint};
use codec::Encode;
use frame_support::{assert_noop, assert_ok};

#[test]
fn deactivate_did_blocks_follow_up_mutations() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        let owner_pair = keypair(1);
        let (_did_id, did_input, _owner_pk) = create_did(1, &owner_pair);
        let deactivate_sig = deactivate_signature(&owner_pair, &did_input);
        assert_ok!(Did::deactivate_did(
            RuntimeOrigin::signed(1),
            did_input.clone(),
            deactivate_sig
        ));
        System::assert_last_event(RuntimeEvent::Did(crate::Event::DidDeactivated {
            did: did_input.clone(),
        }));

        let service = ServiceEndpoint {
            id: b"#svc-2".to_vec(),
            service_type: b"type".to_vec(),
            endpoint: b"https://example.org/2".to_vec(),
        };
        let mut add_payload = b"QSB_DID_ADD_SERVICE".to_vec();
        add_payload.extend_from_slice(&did_input.encode());
        add_payload.extend_from_slice(&service.encode());
        let add_sig = sign(&owner_pair, &add_payload);

        assert_noop!(
            Did::add_service(RuntimeOrigin::signed(1), did_input, service, add_sig),
            Error::<Test>::DidDeactivated
        );
    });
}
