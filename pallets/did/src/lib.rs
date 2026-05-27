#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::ensure;
pub use pallet::*;
pub use types::*;

mod constants;
mod did_utils;
mod key_validation;
mod types;

pub mod default_weights;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use crate::constants::*;
    use crate::default_weights::WeightInfo;
    use crate::key_validation::KeyValidationError;
    use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
    use frame_system::pallet_prelude::OriginFor;
    use sp_core::mldsa44;
    use sp_io::crypto::mldsa44_verify;
    use sp_std::vec;
    use sp_std::vec::Vec;

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type WeightInfo: crate::default_weights::WeightInfo;
    }

    #[pallet::storage]
    pub(super) type DidRecords<T: Config> =
        StorageMap<_, Twox64Concat, [u8; 32], DidDetails, OptionQuery>;

    #[pallet::error]
    pub enum Error<T> {
        DidAlreadyExists,
        DidNotFound,
        DidDeactivated,
        KeyAlreadyExists,
        AuthenticationKeyAlreadyExists,
        KeyNotFound,
        KeyAlreadyRevoked,
        CannotRevokeLastAuthenticationKey,
        CannotRemoveLastAuthenticationRole,
        InvalidAuthenticationKeyCount,
        InvalidDidId,
        ServiceAlreadyExists,
        ServiceNotFound,
        MetadataNotFound,
        InvalidSignature,
        InvalidPublicKey,
        InvalidDidSignature,
        InvalidController,
        KeyIdAlreadyExists,
        InvalidKeyIdSuffix,
        InvalidServiceId,
        InvalidServiceEndpoint,
        InvalidMultikey,
        UnsupportedMultikeyCodec,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        DidCreated {
            did: Vec<u8>,
        },
        KeyAdded {
            did: Vec<u8>,
            public_key: Vec<u8>,
        },
        KeyRevoked {
            did: Vec<u8>,
            public_key: Vec<u8>,
        },
        DidDeactivated {
            did: Vec<u8>,
        },
        KeyRotated {
            did: Vec<u8>,
            old_public_key: Vec<u8>,
            new_public_key: Vec<u8>,
        },
        RolesUpdated {
            did: Vec<u8>,
            public_key: Vec<u8>,
        },
        ServiceAdded {
            did: Vec<u8>,
            service_id: Vec<u8>,
        },
        ServiceRemoved {
            did: Vec<u8>,
            service_id: Vec<u8>,
        },
        MetadataSet {
            did: Vec<u8>,
            key: Vec<u8>,
        },
        MetadataRemoved {
            did: Vec<u8>,
            key: Vec<u8>,
        },
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::create_did())]
        pub fn create_did(
            origin: OriginFor<T>,
            public_key: Vec<u8>,
            did_signature: Vec<u8>,
        ) -> DispatchResult {
            let _ = frame_system::ensure_signed(origin)?;
            let (codec, raw_public_key) = crate::key_validation::validate_multikey(&public_key)
                .map_err(|err| match err {
                    KeyValidationError::InvalidMultikey => Error::<T>::InvalidMultikey,
                })?;
            ensure!(
                codec == MULTICODEC_ML_DSA_44,
                Error::<T>::UnsupportedMultikeyCodec
            );
            Self::validate_public_key(&raw_public_key)?;

            let did_id = Self::did_id_from_public_key(&raw_public_key);
            ensure!(
                !DidRecords::<T>::contains_key(did_id),
                Error::<T>::DidAlreadyExists
            );

            let mut payload = DID_CREATE_PREFIX.to_vec();
            payload.extend_from_slice(&public_key.encode());
            Self::verify_signature_with_public_key(&did_signature, &payload, &raw_public_key)?;

            let did = Self::did_string_from_did_id(&did_id);

            let mut key_id = did.to_vec();
            key_id.extend_from_slice(b"#update");

            let details = DidDetails {
                version: 0,
                deactivated: false,
                keys: vec![DidKey {
                    key_id,
                    multicodec: Some(codec),
                    public_key: raw_public_key,
                    roles: vec![KeyRole::CapabilityInvocation],
                    revoked: false,
                    controller: None,
                }],
                services: Vec::new(),
                metadata: Vec::new(),
                next_key_index: 2,
            };

            DidRecords::<T>::insert(did_id, details);
            Self::deposit_event(Event::DidCreated { did });
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::add_key())]
        pub fn add_key(
            origin: OriginFor<T>,
            did_id: Vec<u8>,
            key_id_suffix: Option<Vec<u8>>,
            public_key: Vec<u8>,
            roles: Vec<KeyRole>,
            controller: Option<Vec<u8>>,
            did_signature: Vec<u8>,
        ) -> DispatchResult {
            let _ = frame_system::ensure_signed(origin)?;
            let mut payload = DID_ADD_KEY_PREFIX.to_vec();
            payload.extend_from_slice(&did_id.encode());
            payload.extend_from_slice(&key_id_suffix.encode());
            payload.extend_from_slice(&public_key.encode());
            payload.extend_from_slice(&roles.encode());
            payload.extend_from_slice(&controller.encode());
            let did_id = Self::decode_did_id(&did_id)?;
            Self::verify_did_signature(did_id, &did_signature, &payload)?;
            let (codec, normalized_public_key) =
                crate::key_validation::validate_multikey(&public_key).map_err(|err| match err {
                    KeyValidationError::InvalidMultikey => Error::<T>::InvalidMultikey,
                })?;
            ensure!(
                crate::key_validation::validate_known_codec_length(codec, &normalized_public_key),
                Error::<T>::InvalidMultikey
            );
            Self::validate_controller_for_did(&controller)?;
            let did = Self::did_string_from_did_id(&did_id);

            DidRecords::<T>::try_mutate(did_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::DidNotFound)?;
                ensure!(!details.deactivated, Error::<T>::DidDeactivated);
                ensure!(
                    !details
                        .keys
                        .iter()
                        .any(|key| key.public_key == normalized_public_key),
                    Error::<T>::KeyAlreadyExists
                );
                let key_id = Self::resolve_unique_key_id(details, &did, key_id_suffix)?;

                details.keys.push(DidKey {
                    key_id,
                    multicodec: Some(codec),
                    public_key: normalized_public_key.clone(),
                    roles,
                    controller,
                    revoked: false,
                });
                details.version = details.version.saturating_add(1);
                Ok(())
            })?;

            Self::deposit_event(Event::KeyAdded { did, public_key });
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::revoke_key())]
        pub fn revoke_key(
            origin: OriginFor<T>,
            did_id: Vec<u8>,
            key_id: Vec<u8>,
            did_signature: Vec<u8>,
        ) -> DispatchResult {
            let _ = frame_system::ensure_signed(origin)?;
            let mut payload = DID_REVOKE_KEY_PREFIX.to_vec();
            payload.extend_from_slice(&did_id.encode());
            payload.extend_from_slice(&key_id.encode());
            let did_id = Self::decode_did_id(&did_id)?;
            Self::verify_did_signature(did_id, &did_signature, &payload)?;
            let did = Self::did_string_from_did_id(&did_id);
            let update_key_id = Self::update_key_id(&did);
            let mut revoked_public_key: Option<Vec<u8>> = None;

            DidRecords::<T>::try_mutate(did_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::DidNotFound)?;
                ensure!(!details.deactivated, Error::<T>::DidDeactivated);

                let key_idx = details
                    .keys
                    .iter()
                    .position(|key| key.key_id == key_id)
                    .ok_or(Error::<T>::KeyNotFound)?;

                ensure!(
                    !details.keys[key_idx].revoked,
                    Error::<T>::KeyAlreadyRevoked
                );
                ensure!(
                    details.keys[key_idx].key_id != update_key_id,
                    Error::<T>::CannotRevokeLastAuthenticationKey
                );

                details.keys[key_idx].revoked = true;
                revoked_public_key = Some(details.keys[key_idx].public_key.clone());
                details.version = details.version.saturating_add(1);
                Ok(())
            })?;

            let public_key = revoked_public_key.ok_or(Error::<T>::KeyNotFound)?;
            Self::deposit_event(Event::KeyRevoked { did, public_key });
            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::deactivate_did())]
        pub fn deactivate_did(
            origin: OriginFor<T>,
            did_id: Vec<u8>,
            did_signature: Vec<u8>,
        ) -> DispatchResult {
            let _ = frame_system::ensure_signed(origin)?;
            let mut payload = DID_DEACTIVATE_PREFIX.to_vec();
            payload.extend_from_slice(&did_id.encode());
            let did_id = Self::decode_did_id(&did_id)?;
            Self::verify_did_signature(did_id, &did_signature, &payload)?;
            let did = Self::did_string_from_did_id(&did_id);

            DidRecords::<T>::try_mutate(did_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::DidNotFound)?;
                ensure!(!details.deactivated, Error::<T>::DidDeactivated);
                details.deactivated = true;
                details.version = details.version.saturating_add(1);
                Ok(())
            })?;

            Self::deposit_event(Event::DidDeactivated { did });
            Ok(())
        }

        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::add_service())]
        pub fn add_service(
            origin: OriginFor<T>,
            did_id: Vec<u8>,
            service: ServiceEndpoint,
            did_signature: Vec<u8>,
        ) -> DispatchResult {
            let _ = frame_system::ensure_signed(origin)?;
            let mut payload = DID_ADD_SERVICE_PREFIX.to_vec();
            payload.extend_from_slice(&did_id.encode());
            payload.extend_from_slice(&service.encode());
            let did_id = Self::decode_did_id(&did_id)?;
            Self::verify_did_signature(did_id, &did_signature, &payload)?;
            let did = Self::did_string_from_did_id(&did_id);
            Self::validate_service(&service, &did)?;
            let service_id = service.id.clone();

            DidRecords::<T>::try_mutate(did_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::DidNotFound)?;
                ensure!(!details.deactivated, Error::<T>::DidDeactivated);
                ensure!(
                    !details.services.iter().any(|entry| entry.id == service.id),
                    Error::<T>::ServiceAlreadyExists
                );
                details.services.push(service);
                details.version = details.version.saturating_add(1);
                Ok(())
            })?;

            Self::deposit_event(Event::ServiceAdded { did, service_id });
            Ok(())
        }

        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::remove_service())]
        pub fn remove_service(
            origin: OriginFor<T>,
            did_id: Vec<u8>,
            service_id: Vec<u8>,
            did_signature: Vec<u8>,
        ) -> DispatchResult {
            let _ = frame_system::ensure_signed(origin)?;
            let mut payload = DID_REMOVE_SERVICE_PREFIX.to_vec();
            payload.extend_from_slice(&did_id.encode());
            payload.extend_from_slice(&service_id.encode());
            let did_id = Self::decode_did_id(&did_id)?;
            Self::verify_did_signature(did_id, &did_signature, &payload)?;
            let did = Self::did_string_from_did_id(&did_id);

            DidRecords::<T>::try_mutate(did_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::DidNotFound)?;
                ensure!(!details.deactivated, Error::<T>::DidDeactivated);
                let index = details
                    .services
                    .iter()
                    .position(|entry| entry.id == service_id)
                    .ok_or(Error::<T>::ServiceNotFound)?;
                details.services.swap_remove(index);
                details.version = details.version.saturating_add(1);
                Ok(())
            })?;

            Self::deposit_event(Event::ServiceRemoved { did, service_id });
            Ok(())
        }

        #[pallet::call_index(6)]
        #[pallet::weight(T::WeightInfo::set_metadata())]
        pub fn set_metadata(
            origin: OriginFor<T>,
            did_id: Vec<u8>,
            entry: MetadataEntry,
            did_signature: Vec<u8>,
        ) -> DispatchResult {
            let _ = frame_system::ensure_signed(origin)?;
            let mut payload = DID_SET_METADATA_PREFIX.to_vec();
            payload.extend_from_slice(&did_id.encode());
            payload.extend_from_slice(&entry.encode());
            let did_id = Self::decode_did_id(&did_id)?;
            Self::verify_did_signature(did_id, &did_signature, &payload)?;
            let did = Self::did_string_from_did_id(&did_id);
            let key = entry.key.clone();

            DidRecords::<T>::try_mutate(did_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::DidNotFound)?;
                ensure!(!details.deactivated, Error::<T>::DidDeactivated);
                if let Some(existing) = details
                    .metadata
                    .iter_mut()
                    .find(|item| item.key == entry.key)
                {
                    existing.value = entry.value;
                } else {
                    details.metadata.push(entry);
                }
                details.version = details.version.saturating_add(1);
                Ok(())
            })?;

            Self::deposit_event(Event::MetadataSet { did, key });
            Ok(())
        }

        #[pallet::call_index(7)]
        #[pallet::weight(T::WeightInfo::remove_metadata())]
        pub fn remove_metadata(
            origin: OriginFor<T>,
            did_id: Vec<u8>,
            key: Vec<u8>,
            did_signature: Vec<u8>,
        ) -> DispatchResult {
            let _ = frame_system::ensure_signed(origin)?;
            let mut payload = DID_REMOVE_METADATA_PREFIX.to_vec();
            payload.extend_from_slice(&did_id.encode());
            payload.extend_from_slice(&key.encode());
            let did_id = Self::decode_did_id(&did_id)?;
            Self::verify_did_signature(did_id, &did_signature, &payload)?;
            let did = Self::did_string_from_did_id(&did_id);

            DidRecords::<T>::try_mutate(did_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::DidNotFound)?;
                ensure!(!details.deactivated, Error::<T>::DidDeactivated);
                let index = details
                    .metadata
                    .iter()
                    .position(|item| item.key == key)
                    .ok_or(Error::<T>::MetadataNotFound)?;
                details.metadata.swap_remove(index);
                details.version = details.version.saturating_add(1);
                Ok(())
            })?;

            Self::deposit_event(Event::MetadataRemoved { did, key });
            Ok(())
        }

        #[pallet::call_index(8)]
        #[pallet::weight(T::WeightInfo::rotate_key())]
        pub fn rotate_key(
            origin: OriginFor<T>,
            did_id: Vec<u8>,
            old_key_id: Vec<u8>,
            new_public_key: Vec<u8>,
            new_key_id_suffix: Option<Vec<u8>>,
            new_controller: Option<Vec<u8>>,
            roles: Vec<KeyRole>,
            did_signature: Vec<u8>,
        ) -> DispatchResult {
            let _ = frame_system::ensure_signed(origin)?;
            let mut payload = DID_ROTATE_KEY_PREFIX.to_vec();
            payload.extend_from_slice(&did_id.encode());
            payload.extend_from_slice(&old_key_id.encode());
            payload.extend_from_slice(&new_public_key.encode());
            payload.extend_from_slice(&new_key_id_suffix.encode());
            payload.extend_from_slice(&new_controller.encode());
            payload.extend_from_slice(&roles.encode());
            let did_id = Self::decode_did_id(&did_id)?;
            Self::verify_did_signature(did_id, &did_signature, &payload)?;
            let (new_codec, normalized_new_public_key) =
                crate::key_validation::validate_multikey(&new_public_key).map_err(|err| {
                    match err {
                        KeyValidationError::InvalidMultikey => Error::<T>::InvalidMultikey,
                    }
                })?;
            ensure!(
                crate::key_validation::validate_known_codec_length(
                    new_codec,
                    &normalized_new_public_key
                ),
                Error::<T>::InvalidMultikey
            );
            Self::validate_controller_for_did(&new_controller)?;
            let did = Self::did_string_from_did_id(&did_id);
            let update_key_id = Self::update_key_id(&did);
            let mut old_public_key_for_event: Option<Vec<u8>> = None;

            DidRecords::<T>::try_mutate(did_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::DidNotFound)?;
                ensure!(!details.deactivated, Error::<T>::DidDeactivated);
                ensure!(
                    !details
                        .keys
                        .iter()
                        .any(|key| key.public_key == normalized_new_public_key),
                    Error::<T>::KeyAlreadyExists
                );
                let key_idx = details
                    .keys
                    .iter()
                    .position(|key| key.key_id == old_key_id)
                    .ok_or(Error::<T>::KeyNotFound)?;
                ensure!(
                    !details.keys[key_idx].revoked,
                    Error::<T>::KeyAlreadyRevoked
                );

                let key_id = if details.keys[key_idx].key_id == update_key_id {
                    ensure!(
                        new_codec == MULTICODEC_ML_DSA_44,
                        Error::<T>::UnsupportedMultikeyCodec
                    );
                    Self::validate_public_key(&normalized_new_public_key)?;
                    ensure!(
                        roles.contains(&KeyRole::CapabilityInvocation),
                        Error::<T>::CannotRemoveLastAuthenticationRole
                    );
                    update_key_id.clone()
                } else {
                    Self::resolve_unique_key_id(details, &did, new_key_id_suffix)?
                };
                
                old_public_key_for_event = Some(details.keys[key_idx].public_key.clone());
                details.keys[key_idx].revoked = true;

                details.keys.push(DidKey {
                    key_id,
                    multicodec: Some(new_codec),
                    public_key: normalized_new_public_key,
                    roles,
                    controller: new_controller,
                    revoked: false,
                });
                details.version = details.version.saturating_add(1);
                Ok(())
            })?;

            Self::deposit_event(Event::KeyRotated {
                did,
                old_public_key: old_public_key_for_event.ok_or(Error::<T>::KeyNotFound)?,
                new_public_key,
            });
            Ok(())
        }

        #[pallet::call_index(9)]
        #[pallet::weight(T::WeightInfo::update_roles())]
        pub fn update_roles(
            origin: OriginFor<T>,
            did_id: Vec<u8>,
            key_id: Vec<u8>,
            roles: Vec<KeyRole>,
            did_signature: Vec<u8>,
        ) -> DispatchResult {
            let _ = frame_system::ensure_signed(origin)?;
            let mut payload = DID_UPDATE_ROLES_PREFIX.to_vec();
            payload.extend_from_slice(&did_id.encode());
            payload.extend_from_slice(&key_id.encode());
            payload.extend_from_slice(&roles.encode());
            let did_id = Self::decode_did_id(&did_id)?;
            Self::verify_did_signature(did_id, &did_signature, &payload)?;
            let did = Self::did_string_from_did_id(&did_id);
            let update_key_id = Self::update_key_id(&did);
            let mut updated_public_key: Option<Vec<u8>> = None;

            DidRecords::<T>::try_mutate(did_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::DidNotFound)?;
                ensure!(!details.deactivated, Error::<T>::DidDeactivated);
                let key_idx = details
                    .keys
                    .iter()
                    .position(|key| key.key_id == key_id)
                    .ok_or(Error::<T>::KeyNotFound)?;
                ensure!(
                    !details.keys[key_idx].revoked,
                    Error::<T>::KeyAlreadyRevoked
                );
                if details.keys[key_idx].key_id == update_key_id {
                    ensure!(
                        roles.contains(&KeyRole::CapabilityInvocation),
                        Error::<T>::CannotRemoveLastAuthenticationRole
                    );
                }

                details.keys[key_idx].roles = roles;
                updated_public_key = Some(details.keys[key_idx].public_key.clone());
                details.version = details.version.saturating_add(1);
                Ok(())
            })?;

            let public_key = updated_public_key.ok_or(Error::<T>::KeyNotFound)?;
            Self::deposit_event(Event::RolesUpdated { did, public_key });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn key_id_exists(details: &DidDetails, key_id: &[u8]) -> bool {
            details.keys.iter().any(|key| key.key_id == key_id)
        }

        fn resolve_unique_key_id(
            details: &mut DidDetails,
            did: &[u8],
            requested_key_id_suffix: Option<Vec<u8>>,
        ) -> Result<Vec<u8>, Error<T>> {
            if let Some(id_suffix) = requested_key_id_suffix {
                ensure!(
                    !id_suffix.starts_with(b"did:"),
                    Error::<T>::InvalidKeyIdSuffix
                );

                let normalized_suffix = if id_suffix.starts_with(b"#") {
                    id_suffix
                } else {
                    let mut prefixed = b"#".to_vec();
                    prefixed.extend_from_slice(&id_suffix);
                    prefixed
                };
                ensure!(
                    normalized_suffix.len() > 1,
                    Error::<T>::InvalidKeyIdSuffix
                );
                ensure!(
                    crate::did_utils::is_valid_key_id_suffix(&normalized_suffix),
                    Error::<T>::InvalidKeyIdSuffix
                );

                let full_key_id = crate::did_utils::build_full_key_id(did, &normalized_suffix);
                ensure!(
                    !Self::key_id_exists(details, &full_key_id),
                    Error::<T>::KeyIdAlreadyExists
                );
                return Ok(full_key_id);
            }

            loop {
                let suffix = crate::did_utils::key_suffix_from_index(details.next_key_index);
                let full_key_id = crate::did_utils::build_full_key_id(did, &suffix);

                if !Self::key_id_exists(details, &full_key_id) {
                    details.next_key_index = details.next_key_index.saturating_add(1);
                    return Ok(full_key_id);
                }

                details.next_key_index = details.next_key_index.saturating_add(1);
            }
        }

        fn update_key_id(did: &[u8]) -> Vec<u8> {
            let mut key_id = did.to_vec();
            key_id.extend_from_slice(b"#update");
            key_id
        }

        fn validate_public_key(public_key: &[u8]) -> Result<(), Error<T>> {
            let _ = mldsa44::Public::try_from(public_key).map_err(|_| Error::<T>::InvalidPublicKey)?;
            Ok(())
        }

        fn validate_controller_for_did(
            controller: &Option<Vec<u8>>,
        ) -> Result<(), Error<T>> {
            if let Some(controller_did) = controller {
                ensure!(
                    crate::did_utils::is_strict_did_uri::<T>(controller_did),
                    Error::<T>::InvalidController
                );
            }
            Ok(())
        }

        fn validate_service(service: &ServiceEndpoint, did: &[u8]) -> Result<(), Error<T>> {
            ensure!(
                !service.id.is_empty(),
                Error::<T>::InvalidServiceId
            );
            ensure!(
                !service.endpoint.is_empty(),
                Error::<T>::InvalidServiceEndpoint
            );

            // service.id: URI or DID URL fragment.
            let service_id_valid = if service.id.starts_with(b"#") {
                crate::did_utils::is_valid_key_id_suffix(&service.id)
            } else {
                crate::did_utils::is_valid_uri(&service.id)
            };
            ensure!(service_id_valid, Error::<T>::InvalidServiceId);

            if service.id.starts_with(b"#") {
                let mut full = did.to_vec();
                full.extend_from_slice(&service.id);
                ensure!(
                    crate::did_utils::is_valid_did_url::<T>(&full),
                    Error::<T>::InvalidServiceId
                );
            }

            // serviceEndpoint: this pallet currently supports URI string endpoint.
            ensure!(
                crate::did_utils::is_valid_uri(&service.endpoint),
                Error::<T>::InvalidServiceEndpoint
            );

            Ok(())
        }

        fn verify_signature_with_public_key(
            did_signature: &[u8],
            payload: &[u8],
            public_key: &[u8],
        ) -> Result<(), Error<T>> {
            let pk =
                mldsa44::Public::try_from(public_key).map_err(|_| Error::<T>::InvalidPublicKey)?;
            let sig = mldsa44::Signature::try_from(did_signature)
                .map_err(|_| Error::<T>::InvalidDidSignature)?;

            ensure!(
                mldsa44_verify(&sig, payload, &pk),
                Error::<T>::InvalidSignature
            );
            Ok(())
        }

        fn verify_did_signature(
            did_id: [u8; 32],
            did_signature: &[u8],
            payload: &[u8],
        ) -> Result<(), Error<T>> {
            let details = DidRecords::<T>::get(did_id).ok_or(Error::<T>::DidNotFound)?;
            let did = Self::did_string_from_did_id(&did_id);
            let update_key_id = Self::update_key_id(&did);
            let sig = mldsa44::Signature::try_from(did_signature)
                .map_err(|_| Error::<T>::InvalidDidSignature)?;

            let key = details
                .keys
                .iter()
                .find(|key| !key.revoked && key.key_id == update_key_id)
                .ok_or(Error::<T>::InvalidAuthenticationKeyCount)?;
            ensure!(
                key.roles.contains(&KeyRole::CapabilityInvocation),
                Error::<T>::InvalidAuthenticationKeyCount
            );

            let pk =
                mldsa44::Public::try_from(key.public_key.as_slice()).map_err(|_| Error::<T>::InvalidPublicKey)?;
            ensure!(mldsa44_verify(&sig, payload, &pk), Error::<T>::InvalidSignature);
            Ok(())
        }

        fn did_id_from_public_key(public_key: &[u8]) -> [u8; 32] {
            crate::did_utils::did_id_from_public_key::<T>(public_key)
        }

        fn did_string_from_did_id(did_id: &[u8; 32]) -> Vec<u8> {
            crate::did_utils::did_string_from_did_id(did_id)
        }

        fn decode_did_id(input: &[u8]) -> Result<[u8; 32], Error<T>> {
            crate::did_utils::decode_did_id::<T>(input)
        }

        pub fn get_did(did_id: Vec<u8>) -> Result<DidDetails, Error<T>> {
            let did_id = Self::decode_did_id(&did_id)?;
            DidRecords::<T>::get(did_id).ok_or(Error::<T>::DidNotFound)
        }
    }
}
