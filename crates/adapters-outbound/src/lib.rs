//! Outbound adapters: the admin API gateway on the generated
//! `batlehub-client` (implementing `application::ports::AdminGateway`),
//! its factory (one per `BatleHubLocalInstance`), the operator's instance
//! directory, the CRs bound to an instance, the configuration's sources,
//! and BatleHub's configuration parser behind
//! `application::ports::ConfigParser`.

pub mod admin_gateway;
pub mod config_parser;
pub mod dependents;
pub mod gateway_factory;
pub mod instances;
pub mod metered;
mod redact;
pub mod scoped;
pub mod sources;
pub mod workloads;

pub use admin_gateway::HttpAdminGateway;
pub use config_parser::BatleHubConfigParser;
pub use dependents::ClusterDependents;
pub use gateway_factory::HttpGatewayFactory;
pub use instances::LocalInstanceDirectory;
pub use metered::MeteredFactory;
pub use sources::KubeConfigSources;
pub use workloads::KubeWorkloads;
