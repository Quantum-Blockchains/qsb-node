#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::ensure;
pub use pallet::*;
pub use types::*;

mod auth;
mod constants;
mod did_utils;
mod resolver;
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
            let did_id = Self::did_id_from_public_key(&public_key);
            ensure!(
                !DidRecords::<T>::contains_key(did_id),
                Error::<T>::DidAlreadyExists
            );

            let mut payload = DID_CREATE_PREFIX.to_vec();
            payload.extend_from_slice(&public_key.encode());
            Self::verify_signature_with_public_key(&did_signature, &payload, &public_key)?;

            let did = Self::did_string_from_did_id(&did_id);

            let mut key_id = did.to_vec();
            key_id.extend_from_slice(b"#update");

            let details = DidDetails {
                version: 0,
                deactivated: false,
                keys: vec![DidKey {
                    key_id,
                    vm_type: VerificationMethodType::Multikey,
                    public_key,
                    roles: vec![KeyRole::Authentication],
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
            vm_type: VerificationMethodType,
            public_key: Vec<u8>,
            roles: Vec<KeyRole>,
            controller: Option<Vec<u8>>,
            did_signature: Vec<u8>,
        ) -> DispatchResult {
            let _ = frame_system::ensure_signed(origin)?;
            let mut payload = DID_ADD_KEY_PREFIX.to_vec();
            payload.extend_from_slice(&did_id.encode());
            payload.extend_from_slice(&key_id_suffix.encode());
            payload.extend_from_slice(&vm_type.encode());
            payload.extend_from_slice(&public_key.encode());
            payload.extend_from_slice(&roles.encode());
            payload.extend_from_slice(&controller.encode());
            let did_id = Self::decode_did_id(&did_id)?;
            Self::verify_did_signature(did_id, &did_signature, &payload)?;
            Self::validate_public_key(&public_key)?;
            Self::validate_controller_for_did(did_id, &controller)?;
            let did = Self::did_string_from_did_id(&did_id);
            let new_key_has_authentication = Self::roles_contain_authentication(&roles);

            DidRecords::<T>::try_mutate(did_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::DidNotFound)?;
                ensure!(!details.deactivated, Error::<T>::DidDeactivated);
                ensure!(
                    !details.keys.iter().any(|key| key.public_key == public_key),
                    Error::<T>::KeyAlreadyExists
                );
                ensure!(
                    !new_key_has_authentication
                        || Self::active_authentication_key_count(details) == 0,
                    Error::<T>::AuthenticationKeyAlreadyExists
                );

                let key_id = Self::resolve_unique_key_id(details, &did, key_id_suffix)?;

                details.keys.push(DidKey {
                    key_id,
                    vm_type,
                    public_key: public_key.clone(),
                    roles,
                    controller,
                    revoked: false,
                });
                Self::ensure_single_active_authentication_key(details)?;
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
            public_key: Vec<u8>,
            did_signature: Vec<u8>,
        ) -> DispatchResult {
            let _ = frame_system::ensure_signed(origin)?;
            let mut payload = DID_REVOKE_KEY_PREFIX.to_vec();
            payload.extend_from_slice(&did_id.encode());
            payload.extend_from_slice(&public_key.encode());
            let did_id = Self::decode_did_id(&did_id)?;
            Self::verify_did_signature(did_id, &did_signature, &payload)?;
            let did = Self::did_string_from_did_id(&did_id);

            DidRecords::<T>::try_mutate(did_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::DidNotFound)?;
                ensure!(!details.deactivated, Error::<T>::DidDeactivated);

                let key_idx = details
                    .keys
                    .iter()
                    .position(|key| key.public_key == public_key)
                    .ok_or(Error::<T>::KeyNotFound)?;

                ensure!(
                    !details.keys[key_idx].revoked,
                    Error::<T>::KeyAlreadyRevoked
                );
                let is_authentication_key = Self::key_has_authentication(&details.keys[key_idx]);
                if is_authentication_key {
                    ensure!(
                        Self::active_authentication_key_count(details) > 1,
                        Error::<T>::CannotRevokeLastAuthenticationKey
                    );
                }

                details.keys[key_idx].revoked = true;
                Self::ensure_single_active_authentication_key(details)?;
                details.version = details.version.saturating_add(1);
                Ok(())
            })?;

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
            old_public_key: Vec<u8>,
            new_public_key: Vec<u8>,
            new_key_id_suffix: Option<Vec<u8>>,
            new_vm_type: VerificationMethodType,
            new_controller: Option<Vec<u8>>,
            roles: Vec<KeyRole>,
            did_signature: Vec<u8>,
        ) -> DispatchResult {
            let _ = frame_system::ensure_signed(origin)?;
            let mut payload = DID_ROTATE_KEY_PREFIX.to_vec();
            payload.extend_from_slice(&did_id.encode());
            payload.extend_from_slice(&old_public_key.encode());
            payload.extend_from_slice(&new_public_key.encode());
            payload.extend_from_slice(&new_key_id_suffix.encode());
            payload.extend_from_slice(&new_vm_type.encode());
            payload.extend_from_slice(&new_controller.encode());
            payload.extend_from_slice(&roles.encode());
            let did_id = Self::decode_did_id(&did_id)?;
            Self::verify_did_signature(did_id, &did_signature, &payload)?;
            Self::validate_public_key(&new_public_key)?;
            Self::validate_controller_for_did(did_id, &new_controller)?;
            let did = Self::did_string_from_did_id(&did_id);
            let new_key_has_authentication = Self::roles_contain_authentication(&roles);

            DidRecords::<T>::try_mutate(did_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::DidNotFound)?;
                ensure!(!details.deactivated, Error::<T>::DidDeactivated);
                ensure!(
                    !details
                        .keys
                        .iter()
                        .any(|key| key.public_key == new_public_key),
                    Error::<T>::KeyAlreadyExists
                );
                let key_idx = details
                    .keys
                    .iter()
                    .position(|key| key.public_key == old_public_key)
                    .ok_or(Error::<T>::KeyNotFound)?;
                ensure!(
                    !details.keys[key_idx].revoked,
                    Error::<T>::KeyAlreadyRevoked
                );

                let old_key_has_authentication =
                    Self::key_has_authentication(&details.keys[key_idx]);
                let active_authentication_count = Self::active_authentication_key_count(details);

                if old_key_has_authentication {
                    ensure!(
                        new_key_has_authentication,
                        Error::<T>::CannotRevokeLastAuthenticationKey
                    );
                } else if new_key_has_authentication {
                    ensure!(
                        active_authentication_count == 0,
                        Error::<T>::AuthenticationKeyAlreadyExists
                    );
                }

                let key_id = Self::resolve_unique_key_id(details, &did, new_key_id_suffix)?;
                
                details.keys[key_idx].revoked = true;

                details.keys.push(DidKey {
                    key_id,
                    vm_type: new_vm_type,
                    public_key: new_public_key.clone(),
                    roles,
                    controller: new_controller,
                    revoked: false,
                });
                Self::ensure_single_active_authentication_key(details)?;
                details.version = details.version.saturating_add(1);
                Ok(())
            })?;

            Self::deposit_event(Event::KeyRotated {
                did,
                old_public_key,
                new_public_key,
            });
            Ok(())
        }

        #[pallet::call_index(9)]
        #[pallet::weight(T::WeightInfo::update_roles())]
        pub fn update_roles(
            origin: OriginFor<T>,
            did_id: Vec<u8>,
            public_key: Vec<u8>,
            roles: Vec<KeyRole>,
            did_signature: Vec<u8>,
        ) -> DispatchResult {
            let _ = frame_system::ensure_signed(origin)?;
            let mut payload = DID_UPDATE_ROLES_PREFIX.to_vec();
            payload.extend_from_slice(&did_id.encode());
            payload.extend_from_slice(&public_key.encode());
            payload.extend_from_slice(&roles.encode());
            let did_id = Self::decode_did_id(&did_id)?;
            Self::verify_did_signature(did_id, &did_signature, &payload)?;
            let did = Self::did_string_from_did_id(&did_id);

            DidRecords::<T>::try_mutate(did_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::DidNotFound)?;
                ensure!(!details.deactivated, Error::<T>::DidDeactivated);
                let key_idx = details
                    .keys
                    .iter()
                    .position(|key| key.public_key == public_key)
                    .ok_or(Error::<T>::KeyNotFound)?;
                ensure!(
                    !details.keys[key_idx].revoked,
                    Error::<T>::KeyAlreadyRevoked
                );

                let old_has_authentication = Self::key_has_authentication(&details.keys[key_idx]);
                let new_has_authentication = Self::roles_contain_authentication(&roles);
                let active_authentication_count = Self::active_authentication_key_count(details);

                if old_has_authentication && !new_has_authentication {
                    ensure!(
                        active_authentication_count > 1,
                        Error::<T>::CannotRemoveLastAuthenticationRole
                    );
                }
                if !old_has_authentication && new_has_authentication {
                    ensure!(
                        active_authentication_count == 0,
                        Error::<T>::AuthenticationKeyAlreadyExists
                    );
                }

                details.keys[key_idx].roles = roles;
                Self::ensure_single_active_authentication_key(details)?;
                details.version = details.version.saturating_add(1);
                Ok(())
            })?;

            Self::deposit_event(Event::RolesUpdated { did, public_key });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn key_id_exists(details: &DidDetails, key_id: &[u8]) -> bool {
            details.keys.iter().any(|key| key.key_id == key_id)
        }

        fn build_full_key_id(did: &[u8], key_suffix: &[u8]) -> Vec<u8> {
            let mut key_id = did.to_vec();
            key_id.extend_from_slice(key_suffix);
            key_id
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

                let full_key_id = Self::build_full_key_id(did, &normalized_suffix);
                ensure!(
                    !Self::key_id_exists(details, &full_key_id),
                    Error::<T>::KeyIdAlreadyExists
                );
                return Ok(full_key_id);
            }

            loop {
                let suffix = Self::key_suffix_from_index(details.next_key_index);
                let full_key_id = Self::build_full_key_id(did, &suffix);

                if !Self::key_id_exists(details, &full_key_id) {
                    details.next_key_index = details.next_key_index.saturating_add(1);
                    return Ok(full_key_id);
                }

                details.next_key_index = details.next_key_index.saturating_add(1);
            }
        }

        fn key_suffix_from_index(index: u32) -> Vec<u8> {
            let mut out = b"#key-".to_vec();

            if index == 0 {
                out.push(b'0');
                return out;
            }

            let mut digits = [0u8; 10];
            let mut n = index;
            let mut i = 0usize;
            while n > 0 {
                digits[i] = (n % 10) as u8;
                n /= 10;
                i += 1;
            }

            while i > 0 {
                i -= 1;
                out.push(b'0' + digits[i]);
            }

            out
        }

        fn validate_public_key(public_key: &[u8]) -> Result<(), Error<T>> {
            let _ = mldsa44::Public::try_from(public_key).map_err(|_| Error::<T>::InvalidPublicKey)?;
            Ok(())
        }

        fn validate_controller_for_did(
            did_id: [u8; 32],
            controller: &Option<Vec<u8>>,
        ) -> Result<(), Error<T>> {
            if let Some(controller_did) = controller {
                let controller_id =
                    Self::decode_did_id(controller_did).map_err(|_| Error::<T>::InvalidController)?;
                ensure!(controller_id == did_id, Error::<T>::InvalidController);
            }
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
            Self::ensure_single_active_authentication_key(&details)?;
            let sig = mldsa44::Signature::try_from(did_signature)
                .map_err(|_| Error::<T>::InvalidDidSignature)?;

            for key in details
                .keys
                .iter()
                .filter(|key| !key.revoked && Self::key_has_authentication(key))
            {
                if let Ok(pk) = mldsa44::Public::try_from(key.public_key.as_slice()) {
                    if mldsa44_verify(&sig, payload, &pk) {
                        return Ok(());
                    }
                }
            }

            Err(Error::<T>::InvalidSignature)
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

        fn roles_contain_authentication(roles: &[KeyRole]) -> bool {
            crate::auth::roles_contain_authentication(roles)
        }

        fn key_has_authentication(key: &DidKey) -> bool {
            crate::auth::key_has_authentication(key)
        }

        fn active_authentication_key_count(details: &DidDetails) -> usize {
            crate::auth::active_authentication_key_count(details)
        }

        fn ensure_single_active_authentication_key(details: &DidDetails) -> Result<(), Error<T>> {
            crate::auth::ensure_single_active_authentication_key::<T>(details)
        }

        pub fn resolve_did(did_input: Vec<u8>) -> DidResolutionResult {
            crate::resolver::resolve_did::<T>(did_input)
        }

        pub fn get_did(did_id: Vec<u8>) -> Result<DidDetails, Error<T>> {
            let did_id = Self::decode_did_id(&did_id)?;
            DidRecords::<T>::get(did_id).ok_or(Error::<T>::DidNotFound)
        }
    }
}
