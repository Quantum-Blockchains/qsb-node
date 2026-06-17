# DID Pallet (`pallets/did`)

## Table of contents

1. [Pallet purpose](#1-pallet-purpose)
2. [Scope and source file](#2-scope-and-source-file)
3. [Data model](#3-data-model)
4. [Storage](#4-storage)
5. [Conventions and constants](#5-conventions-and-constants)
6. [DID ID input format and decoding](#6-did-id-input-format-and-decoding)
7. [Signatures and verification](#7-signatures-and-verification)
8. [Extrinsics (calls)](#8-extrinsics-calls)
9. [Public helper API](#9-public-helper-api)
10. [Events](#10-events)
11. [Errors (`Error<T>`)](#11-errors-errort)
12. [Security behavior and current limitations](#12-security-behavior-and-current-limitations)
13. [Example flow](#13-example-flow)
14. [Suggested future improvements (optional)](#14-suggested-future-improvements-optional)

## 1. Pallet purpose

This pallet stores and manages DID (Decentralized Identifier) documents on-chain.
It provides:

- DID creation from a public key,
- DID key management (add, revoke, rotate, role updates),
- service management (`ServiceEndpoint`),
- metadata management (`MetadataEntry`),
- DID deactivation.

Operation authorization is based on `mldsa44` cryptographic signatures.

## 2. Scope and source file

- Implementation: `pallets/did/src/lib.rs`
- This document describes the current implementation and its actual runtime behavior.

## 3. Data model

### 3.1. `KeyRole`

DID key role enum:

- `Authentication`
- `AssertionMethod`
- `KeyAgreement`
- `CapabilityInvocation`
- `CapabilityDelegation`

Note: DID call authorization uses the active `#update` key with the `CapabilityInvocation` role.
That key must be a Multikey ML-DSA-44 key.

### 3.2. `DidKey`

Represents a key inside a DID:

- `key_material: DidKeyMaterial` - either normalized Multikey material or opaque JWK bytes,
- `roles: Vec<KeyRole>` - roles assigned to the key,
- `revoked: bool` - revocation flag.

Key material variants:

- `Multikey { multicodec, public_key }` - validated Multikey input normalized into raw public key bytes plus multicodec.
- `Jwk { public_key_jwk }` - opaque stored byte sequence. The pallet does not parse or validate JSON/JWK fields.

### 3.3. `ServiceEndpoint`

Service entry in the DID:

- `id: Vec<u8>`
- `service_type: Vec<u8>`
- `endpoint: Vec<u8>`

### 3.4. `MetadataEntry`

Metadata entry:

- `key: Vec<u8>`
- `value: Vec<u8>`

### 3.5. `DidDetails`

Main DID record structure:

- `version: u64` - incremented on each modification,
- `deactivated: bool` - DID deactivation flag,
- `keys: Vec<DidKey>` - key list,
- `services: Vec<ServiceEndpoint>` - service list,
- `metadata: Vec<MetadataEntry>` - metadata list.

## 4. Storage

### 4.1. `DidRecords`

```rust
StorageMap<_, Twox64Concat, [u8; 32], DidDetails, OptionQuery>
```

- Map key: `did_id` (`[u8; 32]`)
- Map value: `DidDetails`
- Missing entry means the DID does not exist.

## 5. Conventions and constants

### 5.1. DID prefix

- DID string prefix: `did:qsb:`

### 5.2. DID generation material

`did_id` is computed as:

```text
blake2_256("QSB_DID" ++ genesis_hash ++ public_key)
```

Where:

- `genesis_hash = frame_system::Pallet::<T>::block_hash(0)`
- `++` means byte concatenation.

As a result, the same `public_key` on different chains/genesis states produces a different DID.

### 5.3. Signature payload domain prefixes

Each DID-signed call uses a dedicated domain prefix:

- `QSB_DID_CREATE`
- `QSB_DID_ADD_KEY`
- `QSB_DID_REVOKE_KEY`
- `QSB_DID_DEACTIVATE`
- `QSB_DID_ADD_SERVICE`
- `QSB_DID_REMOVE_SERVICE`
- `QSB_DID_SET_METADATA`
- `QSB_DID_REMOVE_METADATA`
- `QSB_DID_ROTATE_KEY`
- `QSB_DID_UPDATE_ROLES`

This separates signature contexts across operations.

## 6. DID ID input format and decoding

The `decode_did_id(input: &[u8])` function accepts two formats:

- full DID string: `did:qsb:<base58_32_bytes>`
- base58 bytes without prefix

Process:

1. If input starts with `did:qsb:`, the prefix is stripped.
2. The remaining bytes are Base58-decoded.
3. The decoded value must be exactly 32 bytes long.

Errors:

- invalid Base58 or invalid length -> `InvalidDidId`.

## 7. Signatures and verification

## 7.1. `create_did`: self-signature with provided key

`create_did` accepts only Multikey ML-DSA-44 input and verifies the signature against the decoded raw key:

1. `public_key` -> Multikey validation and multicodec check.
2. decoded raw key -> `mldsa44::Public::try_from(...)`
3. `did_signature` -> `mldsa44::Signature::try_from(...)`
4. `mldsa44_verify(signature, payload, raw_public_key)`

Errors:

- invalid public key format -> `InvalidPublicKey`
- invalid Multikey format -> `InvalidMultikey`
- unsupported create/update multicodec -> `UnsupportedMultikeyCodec`
- invalid signature format -> `InvalidDidSignature`
- signature mismatch -> `InvalidSignature`

## 7.2. Other calls: signature by active `#update` key

`verify_did_signature(did_id, signature, payload)`:

1. Loads `DidDetails` from `DidRecords`.
2. Finds the active `#update` key.
3. Parses `mldsa44::Signature`.
4. Ensures the key has `CapabilityInvocation`.
5. Ensures the key material is Multikey and parses the raw ML-DSA-44 public key.
6. Verifies `mldsa44_verify(signature, payload, public_key)`.

Important:

- Only the active `#update` key can authorize DID calls.
- If the DID has no active `#update` key or the key lacks `CapabilityInvocation`, the operation fails with `InvalidAuthenticationKeyCount`.
- The function does not return which exact key signed the call.

## 8. Extrinsics (calls)

All calls require `ensure_signed(origin)` and use weights from `T::WeightInfo`.
Weight implementation is benchmark-generated and stored in `pallets/did/src/default_weights.rs`.

## 8.1. `create_did` (`call_index(0)`)

Parameters:

- `public_key: Vec<u8>` - Multikey ML-DSA-44
- `did_signature: Vec<u8>`

Signature payload:

```text
"QSB_DID_CREATE" ++ SCALE(public_key)
```

Behavior:

1. Validates and decodes Multikey input.
2. Computes `did_id` from the raw public key bytes.
3. Ensures the record does not exist (`DidAlreadyExists`).
4. Verifies the signature against the decoded raw key.
5. Creates DID with one `#update` key:
   - `key_material = Multikey { multicodec, public_key }`
   - `roles = [CapabilityInvocation]`
   - `revoked = false`
6. Initializes `version = 0`, `deactivated = false`, empty `services` and `metadata`.

Event:

- `DidCreated { did }` where `did` is `did:qsb:<base58(did_id)>`.

## 8.2. `add_key` (`call_index(1)`)

Parameters:

- `did_id: Vec<u8>`
- `key_id_suffix: Option<Vec<u8>>`
- `key_material: KeyMaterialInput`
- `roles: Vec<KeyRole>`
- `controller: Option<Vec<u8>>`
- `did_signature: Vec<u8>`

Payload:

```text
"QSB_DID_ADD_KEY"
  ++ SCALE(did_id)
  ++ SCALE(key_id_suffix)
  ++ SCALE(key_material)
  ++ SCALE(roles)
  ++ SCALE(controller)
```

Conditions:

- DID exists,
- DID is not deactivated,
- key with the same normalized `key_material` does not already exist,
- Multikey input is structurally validated and known codec lengths are checked,
- JWK input is stored as an opaque byte sequence; it is only checked for non-empty content and `MaxJwkLength`,
- JWK input cannot be assigned `CapabilityInvocation`.

Effect:

- adds `DidKey { key_material, roles, controller, revoked: false }`,
- `version += 1`.

Event:

- `KeyAdded { did, key_material }`

## 8.3. `revoke_key` (`call_index(2)`)

Parameters:

- `did_id: Vec<u8>`
- `key_id: Vec<u8>`
- `did_signature: Vec<u8>`

Payload:

```text
"QSB_DID_REVOKE_KEY" ++ SCALE(did_id) ++ SCALE(key_id)
```

Conditions:

- DID exists,
- DID is not deactivated,
- target key id exists,
- target key is not already revoked,
- the `#update` key cannot be revoked through `revoke_key`.

Effect:

- `key.revoked = true`,
- `version += 1`.

Event:

- `KeyRevoked { did, key_material }`

## 8.4. `deactivate_did` (`call_index(3)`)

Parameters:

- `did_id: Vec<u8>`
- `did_signature: Vec<u8>`

Payload:

```text
"QSB_DID_DEACTIVATE" ++ SCALE(did_id)
```

Conditions:

- DID exists,
- DID is not already deactivated.

Effect:

- `deactivated = true`,
- `version += 1`.

Event:

- `DidDeactivated { did }`

## 8.5. `add_service` (`call_index(4)`)

Parameters:

- `did_id: Vec<u8>`
- `service: ServiceEndpoint`
- `did_signature: Vec<u8>`

Payload:

```text
"QSB_DID_ADD_SERVICE" ++ SCALE(did_id) ++ SCALE(service)
```

Conditions:

- DID exists,
- DID is not deactivated,
- no existing service with the same `service.id`.

Effect:

- adds the service,
- `version += 1`.

Event:

- `ServiceAdded { did, service_id }`

## 8.6. `remove_service` (`call_index(5)`)

Parameters:

- `did_id: Vec<u8>`
- `service_id: Vec<u8>`
- `did_signature: Vec<u8>`

Payload:

```text
"QSB_DID_REMOVE_SERVICE" ++ SCALE(did_id) ++ SCALE(service_id)
```

Conditions:

- DID exists,
- DID is not deactivated,
- service with `service_id` exists.

Effect:

- removes service using `swap_remove`,
- `version += 1`.

Event:

- `ServiceRemoved { did, service_id }`

## 8.7. `set_metadata` (`call_index(6)`)

Parameters:

- `did_id: Vec<u8>`
- `entry: MetadataEntry`
- `did_signature: Vec<u8>`

Payload:

```text
"QSB_DID_SET_METADATA" ++ SCALE(did_id) ++ SCALE(entry)
```

Conditions:

- DID exists,
- DID is not deactivated.

Effect:

- if `entry.key` exists, updates `value`,
- otherwise inserts a new entry,
- `version += 1`.

Event:

- `MetadataSet { did, key }`

## 8.8. `remove_metadata` (`call_index(7)`)

Parameters:

- `did_id: Vec<u8>`
- `key: Vec<u8>`
- `did_signature: Vec<u8>`

Payload:

```text
"QSB_DID_REMOVE_METADATA" ++ SCALE(did_id) ++ SCALE(key)
```

Conditions:

- DID exists,
- DID is not deactivated,
- metadata entry with `key` exists.

Effect:

- removes metadata using `swap_remove`,
- `version += 1`.

Event:

- `MetadataRemoved { did, key }`

## 8.9. `rotate_key` (`call_index(8)`)

Parameters:

- `did_id: Vec<u8>`
- `old_key_id: Vec<u8>`
- `new_key_material: KeyMaterialInput`
- `new_key_id_suffix: Option<Vec<u8>>`
- `new_controller: Option<Vec<u8>>`
- `roles: Vec<KeyRole>`
- `did_signature: Vec<u8>`

Payload:

```text
"QSB_DID_ROTATE_KEY"
  ++ SCALE(did_id)
  ++ SCALE(old_key_id)
  ++ SCALE(new_key_material)
  ++ SCALE(new_key_id_suffix)
  ++ SCALE(new_controller)
  ++ SCALE(roles)
```

Conditions:

- DID exists,
- DID is not deactivated,
- `new_key_material` does not already exist in `keys`,
- `old_key_id` exists and is not revoked,
- rotating the `#update` key requires the new key to be Multikey ML-DSA-44 with `CapabilityInvocation`,
- JWK input is opaque and cannot be assigned `CapabilityInvocation`.

Effect:

- old key is marked revoked,
- adds a new active key with provided roles,
- `version += 1`.

Event:

- `KeyRotated { did, old_key_material, new_key_material }`

## 8.10. `update_roles` (`call_index(9)`)

Parameters:

- `did_id: Vec<u8>`
- `key_id: Vec<u8>`
- `roles: Vec<KeyRole>`
- `did_signature: Vec<u8>`

Payload:

```text
"QSB_DID_UPDATE_ROLES" ++ SCALE(did_id) ++ SCALE(key_id) ++ SCALE(roles)
```

Conditions:

- DID exists,
- DID is not deactivated,
- key exists and is not revoked,
- the `#update` key must keep `CapabilityInvocation`,
- JWK keys cannot be assigned `CapabilityInvocation`.

Effect:

- updates `key.roles = roles`,
- `version += 1`.

Event:

- `RolesUpdated { did, key_material }`

## 9. Public helper API

### 9.1. `get_did(did_id: Vec<u8>) -> Result<DidDetails, Error<T>>`

- Accepts DID with or without prefix (base58).
- Returns full `DidDetails` record.
- Error: `DidNotFound` or `InvalidDidId`.

## 10. Events

Events are emitted only after a successful state mutation.

- `DidCreated(did)` - confirms DID creation and returns canonical DID string.
- `KeyAdded(did, key_material)` - indicates a new key was added to the DID document.
- `KeyRevoked(did, key_material)` - indicates a DID key was revoked.
- `DidDeactivated(did)` - confirms DID deactivation.
- `KeyRotated(did, old_key_material, new_key_material)` - records key rotation (old key revoked, new key added).
- `RolesUpdated(did, key_material)` - indicates role set update for a key.
- `ServiceAdded(did, service_id)` - indicates a service endpoint was added.
- `ServiceRemoved(did, service_id)` - indicates a service endpoint was removed.
- `MetadataSet(did, key)` - confirms metadata insert/update for a key.
- `MetadataRemoved(did, key)` - confirms metadata removal for a key.

## 11. Errors (`Error<T>`)

- `DidAlreadyExists` - attempt to create an already existing DID.
- `DidNotFound` - DID not found in storage.
- `DidDeactivated` - operation is not allowed on a deactivated DID.
- `KeyAlreadyExists` - key already exists in DID.
- `AuthenticationKeyAlreadyExists` - legacy error retained in the pallet error enum.
- `KeyNotFound` - key does not exist.
- `KeyAlreadyRevoked` - key is already revoked.
- `CannotRevokeLastAuthenticationKey` - attempt to revoke the `#update` key.
- `CannotRemoveLastAuthenticationRole` - attempt to remove `CapabilityInvocation` from the `#update` key.
- `InvalidAuthenticationKeyCount` - missing or invalid active `#update` authorization key.
- `InvalidDidId` - invalid DID/base58 format or decoded length != 32.
- `ServiceAlreadyExists` - duplicate `service.id`.
- `ServiceNotFound` - service with given `id` not found.
- `MetadataNotFound` - metadata with given `key` not found.
- `InvalidSignature` - signature verification failed.
- `InvalidPublicKey` - invalid public key format (mainly in `create_did`).
- `InvalidDidSignature` - invalid signature format.
- `InvalidMultikey` - invalid Multikey lexical structure or known codec length.
- `UnsupportedMultikeyCodec` - unsupported Multikey codec for `create_did` or `#update` rotation.
- `InvalidJwk` - JWK byte sequence is empty.
- `JwkTooLarge` - JWK byte sequence exceeds `MaxJwkLength`.
- `UnsupportedKeyFormatForCapabilityInvocation` - non-Multikey material was assigned `CapabilityInvocation` or used for DID authorization.

## 12. Security behavior and current limitations

- DID call authorization uses only the active `#update` key with `CapabilityInvocation`.
- The `#update` key must be Multikey ML-DSA-44.
- JWK material is stored opaquely, is not parsed as JSON, and cannot receive `CapabilityInvocation`.
- `verify_did_signature` does not return which key signed the call, so events do not identify the DID-level signing key.
- Extrinsic weights are benchmarked and mapped through `T::WeightInfo`.

## 13. Example flow

1. User calls `create_did(public_key, did_signature)` with a Multikey ML-DSA-44 key.
2. DID is created with one active `#update` key using `CapabilityInvocation`.
3. `add_key` can add additional Multikey or opaque JWK material.
4. DID document changes are authorized by signature from the active `#update` key.
5. Keys can be revoked or rotated, but `#update` remains Multikey ML-DSA-44.
6. `deactivate_did` blocks further modifications.

## 14. Suggested future improvements (optional)

- Emit the exact key that authorized the call.
- Keep benchmarks up to date and regenerate weights after any logic change that affects call cost.
- Consider key indexing/mapping for faster verification with very large key sets.
