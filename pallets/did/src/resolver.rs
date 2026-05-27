use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use crate::did_utils;
use crate::pallet::{Config, DidRecords};
use crate::{
    DidDetails, DidDocument, DidDocumentMetadata, DidResolutionMetadata, DidResolutionResult,
    DidVerificationMethod, KeyRole,
};
use sp_std::vec;
use sp_std::vec::Vec;

fn multibase_from_public_key(public_key: &[u8], codec: u64) -> Vec<u8> {
    let mut prefixed = encode_uvarint(codec);
    prefixed.extend_from_slice(public_key);
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

fn map_to_did_document(did: &[u8], details: &DidDetails) -> DidDocument {
    let mut verification_method = Vec::new();
    let mut authentication = Vec::new();
    let mut assertion_method = Vec::new();
    let mut key_agreement = Vec::new();
    let mut capability_invocation = Vec::new();
    let mut capability_delegation = Vec::new();

    for key in details.keys.iter().filter(|k| !k.revoked) {
        let controller = key.controller.clone().unwrap_or_else(|| did.to_vec());
        let vm_id = key.key_id.clone();

        verification_method.push(DidVerificationMethod {
            id: vm_id.clone(),
            vm_type: b"Multikey".to_vec(),
            controller,
            public_key_multibase: key
                .multicodec
                .map(|codec| multibase_from_public_key(&key.public_key, codec)),
        });

        for role in &key.roles {
            match role {
                KeyRole::Authentication => authentication.push(vm_id.clone()),
                KeyRole::AssertionMethod => assertion_method.push(vm_id.clone()),
                KeyRole::KeyAgreement => key_agreement.push(vm_id.clone()),
                KeyRole::CapabilityInvocation => capability_invocation.push(vm_id.clone()),
                KeyRole::CapabilityDelegation => capability_delegation.push(vm_id.clone()),
            }
        }
    }

    DidDocument {
        context: vec![
            b"https://www.w3.org/ns/did/v1".to_vec(),
            b"https://w3id.org/security/multikey/v1".to_vec(),
            b"https://w3id.org/security/suites/jws-2020/v1".to_vec(),
        ],
        id: did.to_vec(),
        verification_method,
        authentication,
        assertion_method,
        key_agreement,
        capability_invocation,
        capability_delegation,
        service: details.services.clone(),
    }
}

pub(crate) fn resolve_did<T: Config>(did_input: Vec<u8>) -> DidResolutionResult {
    let did_id = match did_utils::decode_did_id::<T>(&did_input) {
        Ok(did_id) => did_id,
        Err(_) => {
            return DidResolutionResult {
                did_document: None,
                did_document_metadata: DidDocumentMetadata {
                    deactivated: false,
                    version_id: 0,
                },
                did_resolution_metadata: DidResolutionMetadata {
                    content_type: None,
                    error: Some(b"invalidDid".to_vec()),
                },
            };
        }
    };

    let Some(details) = DidRecords::<T>::get(did_id) else {
        return DidResolutionResult {
            did_document: None,
            did_document_metadata: DidDocumentMetadata {
                deactivated: false,
                version_id: 0,
            },
            did_resolution_metadata: DidResolutionMetadata {
                content_type: None,
                error: Some(b"notFound".to_vec()),
            },
        };
    };

    let did = did_utils::did_string_from_did_id(&did_id);
    let did_document = map_to_did_document(&did, &details);

    DidResolutionResult {
        did_document: Some(did_document),
        did_document_metadata: DidDocumentMetadata {
            deactivated: details.deactivated,
            version_id: details.version,
        },
        did_resolution_metadata: DidResolutionMetadata {
            content_type: Some(b"application/did+ld+json".to_vec()),
            error: None,
        },
    }
}
