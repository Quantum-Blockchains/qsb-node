pub(crate) const DID_PREFIX: &[u8] = b"did:qsb:";
pub(crate) const DID_MATERIAL_PREFIX: &[u8] = b"QSB_DID";
pub(crate) const DID_CREATE_PREFIX: &[u8] = b"QSB_DID_CREATE";
pub(crate) const DID_ADD_KEY_PREFIX: &[u8] = b"QSB_DID_ADD_KEY";
pub(crate) const DID_REVOKE_KEY_PREFIX: &[u8] = b"QSB_DID_REVOKE_KEY";
pub(crate) const DID_DEACTIVATE_PREFIX: &[u8] = b"QSB_DID_DEACTIVATE";
pub(crate) const DID_ADD_SERVICE_PREFIX: &[u8] = b"QSB_DID_ADD_SERVICE";
pub(crate) const DID_REMOVE_SERVICE_PREFIX: &[u8] = b"QSB_DID_REMOVE_SERVICE";
pub(crate) const DID_SET_METADATA_PREFIX: &[u8] = b"QSB_DID_SET_METADATA";
pub(crate) const DID_REMOVE_METADATA_PREFIX: &[u8] = b"QSB_DID_REMOVE_METADATA";
pub(crate) const DID_ROTATE_KEY_PREFIX: &[u8] = b"QSB_DID_ROTATE_KEY";
pub(crate) const DID_UPDATE_ROLES_PREFIX: &[u8] = b"QSB_DID_UPDATE_ROLES";
// Generous upper bound for compact JWK public-key JSON payloads, including
// post-quantum ML-DSA-44/65/87 representations.
pub(crate) const MAX_JWK_PUBLIC_KEY_BYTES: usize = 8 * 1024;

// Quantum-Safe Cryptosuites v0.3 (CG-FINAL-di-quantum-safe-20260422) Table 1.
pub(crate) const MULTICODEC_ML_DSA_44: u64 = 0x1210;
pub(crate) const MULTICODEC_SLH_DSA_SHA2_128S: u64 = 0x1220;
pub(crate) const MULTICODEC_FALCON_512: u64 = 0x122c;
pub(crate) const MULTICODEC_SQISIGN_I: u64 = 0x122e;

pub(crate) const ML_DSA_44_PUBLIC_KEY_LEN: usize = 1312;
pub(crate) const SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN: usize = 32;
pub(crate) const FALCON_512_PUBLIC_KEY_LEN: usize = 897;
pub(crate) const SQISIGN_I_PUBLIC_KEY_LEN: usize = 65;
