use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::RuntimeDebug;
use sp_std::vec::Vec;

#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub enum KeyRole {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub enum KeyMaterialInput {
    Multikey(Vec<u8>),
    Jwk(Vec<u8>),
}

#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub enum DidKeyMaterial {
    Multikey {
        multicodec: u64,
        public_key: Vec<u8>,
    },
    Jwk {
        public_key_jwk: Vec<u8>,
    },
}

#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub struct DidKey {
    pub key_id: Vec<u8>,
    pub key_material: DidKeyMaterial,
    pub roles: Vec<KeyRole>,
    pub controller: Option<Vec<u8>>,
    pub revoked: bool,
}

#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub struct ServiceEndpoint {
    pub id: Vec<u8>,
    #[cfg_attr(feature = "std", serde(rename = "type"))]
    pub service_type: Vec<u8>,
    #[cfg_attr(feature = "std", serde(rename = "serviceEndpoint"))]
    pub endpoint: Vec<u8>,
}

#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub struct MetadataEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub struct DidDetails {
    pub version: u64,
    pub deactivated: bool,
    pub keys: Vec<DidKey>,
    pub services: Vec<ServiceEndpoint>,
    pub metadata: Vec<MetadataEntry>,
    pub next_key_index: u32,
}

#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub struct DidVerificationMethod {
    pub id: Vec<u8>,
    #[cfg_attr(feature = "std", serde(rename = "type"))]
    pub vm_type: Vec<u8>,
    pub controller: Vec<u8>,
    #[cfg_attr(feature = "std", serde(rename = "publicKeyMultibase"))]
    pub public_key_multibase: Option<Vec<u8>>,
    #[cfg_attr(feature = "std", serde(rename = "publicKeyJwk"))]
    pub public_key_jwk: Option<Vec<u8>>,
}

#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub struct DidDocument {
    #[cfg_attr(feature = "std", serde(rename = "@context"))]
    pub context: Vec<Vec<u8>>,
    pub id: Vec<u8>,
    #[cfg_attr(feature = "std", serde(rename = "verificationMethod"))]
    pub verification_method: Vec<DidVerificationMethod>,
    pub authentication: Vec<Vec<u8>>,
    #[cfg_attr(feature = "std", serde(rename = "assertionMethod"))]
    pub assertion_method: Vec<Vec<u8>>,
    #[cfg_attr(feature = "std", serde(rename = "keyAgreement"))]
    pub key_agreement: Vec<Vec<u8>>,
    #[cfg_attr(feature = "std", serde(rename = "capabilityInvocation"))]
    pub capability_invocation: Vec<Vec<u8>>,
    #[cfg_attr(feature = "std", serde(rename = "capabilityDelegation"))]
    pub capability_delegation: Vec<Vec<u8>>,
    pub service: Vec<ServiceEndpoint>,
}

#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub struct DidDocumentMetadata {
    pub deactivated: bool,
    #[cfg_attr(feature = "std", serde(rename = "versionId"))]
    pub version_id: u64,
}

#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub struct DidResolutionMetadata {
    #[cfg_attr(feature = "std", serde(rename = "contentType"))]
    pub content_type: Option<Vec<u8>>,
    pub error: Option<Vec<u8>>,
}

#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub struct DidResolutionResult {
    #[cfg_attr(feature = "std", serde(rename = "didDocument"))]
    pub did_document: Option<DidDocument>,
    #[cfg_attr(feature = "std", serde(rename = "didDocumentMetadata"))]
    pub did_document_metadata: DidDocumentMetadata,
    #[cfg_attr(feature = "std", serde(rename = "didResolutionMetadata"))]
    pub did_resolution_metadata: DidResolutionMetadata,
}
