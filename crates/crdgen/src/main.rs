//! Writes `deploy/crd/<kind, lowercase>.yaml`, one file per CRD, from the
//! `api` types (`CustomResourceExt::crd()`). Run by `task recu`; the
//! result is committed and installed by the chart and the envtest tests.

use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::CustomResourceExt;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "deploy/crd")]
    out: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.out)?;
    // The other kinds of the spec (maintenances, grants, policies) join
    // here as they are built.
    write_crd(&args.out, &api::LocalInstance::crd())?;
    write_crd(&args.out, &api::Registry::crd())?;
    write_crd(&args.out, &api::NamespaceClaim::crd())?;
    println!("wrote CRDs to {}", args.out.display());
    Ok(())
}

fn write_crd(out: &Path, crd: &CustomResourceDefinition) -> anyhow::Result<()> {
    let name = crd.spec.names.kind.to_lowercase();
    fs::write(
        out.join(format!("{name}.yaml")),
        serde_norway::to_string(crd)?,
    )?;
    Ok(())
}
