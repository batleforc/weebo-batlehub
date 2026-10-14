//! Test harness of the operator: the kit's envtest control plane with this
//! operator's CRDs, status polling, and a gateway factory serving an
//! in-memory BatleHub.

pub mod envtest;
pub mod polling;
pub mod static_gateway_factory;

pub use application::test_support::{FakeConfigParser, FakeDependents, FakeGateway};
pub use static_gateway_factory::StaticGatewayFactory;
