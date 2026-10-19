//! The operator's CRs read from their shared watch's store once it has
//! listed, from the API otherwise (tests, or a watch that can't list): a
//! store that hasn't listed is never read as empty.

use std::fmt::Debug;

use kube::api::{Api, ListParams};
use kube::runtime::reflector::Store;
use kube::{Resource, ResourceExt};
use serde::de::DeserializeOwned;
use weebo_kit_adapters::instance::STORE_READY_TIMEOUT;

/// The `K`s `api.list(params)` returns: from `store` (the same watch
/// scope, kept to `namespace` when set) once it has listed, sorted as the
/// API server would.
pub async fn list<K>(
    store: Option<&Store<K>>,
    api: &Api<K>,
    params: &ListParams,
    namespace: Option<&str>,
) -> Result<Vec<K>, kube::Error>
where
    K: Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned + 'static,
{
    if let Some(store) = store
        && weebo_kit_adapters::wait_synced(store, STORE_READY_TIMEOUT).await
    {
        let mut objects: Vec<K> = store
            .state()
            .iter()
            .filter(|o| namespace.is_none_or(|ns| o.namespace().as_deref() == Some(ns)))
            .map(|o| K::clone(o))
            .collect();
        objects.sort_by_key(|o| (o.namespace(), o.name_any()));
        return Ok(objects);
    }
    Ok(api.list(params).await?.items)
}
