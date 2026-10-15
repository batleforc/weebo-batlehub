//! `weebo-batlehub-importer`: prints the CRs describing what exists, or
//! with `--apply` creates them in the current kube context.
//!
//! - `instance`: a Helm release of BatleHub's chart (its values, `helm get
//!   values --all -o yaml <release>`) as a `BatleHubLocalInstance`;
//! - `governance`: a live instance's grants and policies, adopted as
//!   `BatleHubPackageGrant`s and `BatleHubPackagePolicy`s.

use std::path::PathBuf;

use adapters_outbound::HttpAdminGateway;
use anyhow::Context;
use api::LocalInstance;
use application::use_cases::import::{Scope, import_governance};
use clap::{Parser, Subcommand, ValueEnum};
use importer::{
    ChartOptions, FIELD_MANAGER, Mode, adopt_all, chart_instance, governance, manifests,
    read_values, sorted, to_yaml,
};
use kube::Client;
use kube::api::{Api, Patch, PatchParams};

#[derive(Parser, Debug)]
#[command(
    name = "weebo-batlehub-importer",
    version,
    about = "Import an existing BatleHub as weebo-batlehub CRs"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum ModeArg {
    /// Keep the release; the operator pilots it (external + podSelector).
    External,
    /// The operator deploys it instead (managed).
    Managed,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// A Helm release of BatleHub's chart as a BatleHubLocalInstance.
    Instance {
        /// The release's values: `helm get values --all -o yaml <release>`
        /// (`-` for stdin).
        #[arg(long)]
        values: PathBuf,
        /// The release's name.
        #[arg(long)]
        release: String,
        /// The release's namespace, the instance's.
        #[arg(long, short, default_value = "default")]
        namespace: String,
        #[arg(long, value_enum, default_value = "external")]
        mode: ModeArg,
        /// The instance's name (default: the release's).
        #[arg(long)]
        name: Option<String>,
        /// external: the admin token's Secret, `name/key` (labelled
        /// batlehub.weebo.io/instance-token=true).
        #[arg(long)]
        token_secret: Option<String>,
        /// external: push the configuration (manageConfig).
        #[arg(long)]
        manage_config: bool,
        /// Create the instance in the current kube context instead of
        /// printing it.
        #[arg(long)]
        apply: bool,
    },
    /// A live instance's grants and policies, adopted as CRs.
    Governance {
        /// The instance's base URL.
        #[arg(long, env = "BATLEHUB_URL")]
        url: String,
        /// An admin token of the instance.
        #[arg(long, env = "BATLEHUB_TOKEN", hide_env_values = true)]
        token: String,
        /// The namespace of the CRs: the instance's.
        #[arg(long, short, default_value = "default")]
        namespace: String,
        /// The BatleHubLocalInstance they name (default: none, the
        /// namespace's only one).
        #[arg(long)]
        instance_ref: Option<String>,
        /// Only these registries (repeatable). Default: all.
        #[arg(long = "registry")]
        registries: Vec<String>,
        /// Packages to read besides those the instance lists (one with a
        /// policy but never cached; repeatable).
        #[arg(long = "package")]
        packages: Vec<String>,
        /// Create and adopt the CRs in the current kube context instead of
        /// printing them.
        #[arg(long)]
        apply: bool,
        /// With --apply: also take over CRs that exist but hold nothing yet.
        #[arg(long, requires = "apply")]
        force: bool,
        /// PEM bundle trusted on top of the system roots.
        #[arg(long)]
        ca_file: Option<PathBuf>,
        /// Skip TLS verification (testing only).
        #[arg(long)]
        insecure_skip_verify: bool,
    },
}

fn read(path: &PathBuf) -> anyhow::Result<String> {
    if path.as_os_str() == "-" {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)?;
        return Ok(text);
    }
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    match Args::parse().command {
        Command::Instance {
            values,
            release,
            namespace,
            mode,
            name,
            token_secret,
            manage_config,
            apply,
        } => {
            let values = read_values(&read(&values)?).map_err(anyhow::Error::msg)?;
            let token_secret = match token_secret {
                Some(text) => Some(
                    text.split_once('/')
                        .map(|(n, k)| (n.to_string(), k.to_string()))
                        .context("--token-secret is name/key")?,
                ),
                None => None,
            };
            let options = ChartOptions {
                release,
                namespace: namespace.clone(),
                mode: match mode {
                    ModeArg::External => Mode::External,
                    ModeArg::Managed => Mode::Managed,
                },
                name,
                token_secret,
                manage_config,
            };
            let (instance, warnings) =
                chart_instance(&values, &options).map_err(anyhow::Error::msg)?;
            for warning in &warnings {
                eprintln!("warning: {warning}");
            }
            if apply {
                let client = Client::try_default()
                    .await
                    .context("connecting to Kubernetes")?;
                let api: Api<LocalInstance> = Api::namespaced(client, &namespace);
                let name = kube::ResourceExt::name_any(&instance);
                anyhow::ensure!(
                    api.get_opt(&name).await?.is_none(),
                    "BatleHubLocalInstance {namespace}/{name} exists already"
                );
                let mut body = serde_json::to_value(&instance)?;
                body["apiVersion"] = "batlehub.weebo.io/v1alpha1".into();
                body["kind"] = "BatleHubLocalInstance".into();
                api.patch(
                    &name,
                    &PatchParams::apply(FIELD_MANAGER),
                    &Patch::Apply(&body),
                )
                .await
                .context("creating the instance")?;
                eprintln!("created BatleHubLocalInstance {namespace}/{name}");
            } else {
                let mut body = serde_json::to_value(&instance)?;
                body["apiVersion"] = "batlehub.weebo.io/v1alpha1".into();
                body["kind"] = "BatleHubLocalInstance".into();
                print!("{}", to_yaml(&[sorted(body)]).map_err(anyhow::Error::msg)?);
            }
        }
        Command::Governance {
            url,
            token,
            namespace,
            instance_ref,
            registries,
            packages,
            apply,
            force,
            ca_file,
            insecure_skip_verify,
        } => {
            let ca = match &ca_file {
                Some(path) => Some(
                    std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
                ),
                None => None,
            };
            if insecure_skip_verify {
                eprintln!("warning: TLS verification disabled");
            }
            let http = HttpAdminGateway::client(ca.as_deref(), insecure_skip_verify)
                .map_err(anyhow::Error::msg)?;
            let gateway =
                HttpAdminGateway::new(&url, token.trim(), http).map_err(anyhow::Error::msg)?;
            let scope = Scope {
                registries,
                packages,
            };
            let imported = import_governance(&gateway, &scope)
                .await
                .map_err(|f| anyhow::anyhow!("reading BatleHub: {}", f.message))?;
            for warning in &imported.warnings {
                eprintln!("warning: {warning}");
            }
            let items = governance(&imported, &namespace, instance_ref.as_deref());
            if apply {
                let client = Client::try_default()
                    .await
                    .context("connecting to Kubernetes")?;
                let summary = adopt_all(&client, &namespace, &items, force).await;
                eprintln!(
                    "{} adopted, {} already adopted, {} failed",
                    summary.adopted, summary.skipped, summary.failed
                );
                anyhow::ensure!(summary.failed == 0, "{} CR(s) not adopted", summary.failed);
            } else {
                let docs: Vec<_> = manifests(&items).into_iter().map(sorted).collect();
                print!("{}", to_yaml(&docs).map_err(anyhow::Error::msg)?);
                eprintln!("{} CR(s)", items.len());
            }
        }
    }
    Ok(())
}
