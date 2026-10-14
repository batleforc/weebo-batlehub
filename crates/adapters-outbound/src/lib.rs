//! Outbound adapters: the admin API gateway on the generated
//! `batlehub-client` (implementing `application::ports::AdminGateway`),
//! its factory (one per `BatleHubLocalInstance`), the operator's instance
//! directory, the CRs bound to an instance, and BatleHub's configuration
//! parser behind `application::ports::ConfigParser`.

pub mod admin_gateway;
pub mod config_parser;
pub mod dependents;
pub mod gateway_factory;
pub mod instances;

pub use admin_gateway::HttpAdminGateway;
pub use config_parser::UnavailableConfigParser;
pub use dependents::ClusterDependents;
pub use gateway_factory::HttpGatewayFactory;
pub use instances::LocalInstanceDirectory;
