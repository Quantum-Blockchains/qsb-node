use crate::pallet::{Config, Error};
use crate::{DidDetails, DidKey, KeyRole};
use frame_support::ensure;

pub(crate) fn roles_contain_authentication(roles: &[KeyRole]) -> bool {
    roles.iter().any(|role| *role == KeyRole::Authentication)
}

pub(crate) fn key_has_authentication(key: &DidKey) -> bool {
    roles_contain_authentication(&key.roles)
}

pub(crate) fn active_authentication_key_count(details: &DidDetails) -> usize {
    details
        .keys
        .iter()
        .filter(|key| !key.revoked && key_has_authentication(key))
        .count()
}

pub(crate) fn ensure_single_active_authentication_key<T: Config>(
    details: &DidDetails,
) -> Result<(), Error<T>> {
    ensure!(
        active_authentication_key_count(details) == 1,
        Error::<T>::InvalidAuthenticationKeyCount
    );
    Ok(())
}
