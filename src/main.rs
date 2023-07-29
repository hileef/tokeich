use std::io::Write;
use std::path::PathBuf;
use anyhow::{anyhow, Context, Result};
use chrono::DateTime;
use clap::{Parser};
use directories::{BaseDirs, ProjectDirs};
use k8s_openapi::chrono;
use k8s_openapi::chrono::Utc;
use k8s_openapi::serde::{Deserialize, Serialize};
use kube::config::{ExecConfig, NamedAuthInfo};

/// Basic kubernetes client exec authentication token caching
#[derive(clap::Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Inject tokeich cache cmd usage into kubernetes config
    On,

    /// Remove tokeich cache cmd usage from kubernetes config
    Off,

    /// Used transparently when tokeich is 'on'
    Cache(CacheCmd),
}

#[derive(clap::Parser, Debug)]
#[command(author, version, about, long_about = None, arg_required_else_help = true)]
struct CacheCmd {
    /// Kubernetes client exec command to call and cache results from
    #[arg(raw = true)]
    cmd: Vec<String>,
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::On => modify_kube_config(true),
        Command::Off => modify_kube_config(false),
        Command::Cache(c) => cached_auth_call(c)
    }
}

fn ensure_cache_dir() -> Result<PathBuf> {
    let proj_dirs = ProjectDirs::from("", "", "tokeich")
        .context("failed to determine project directories on this platform")?;

    let cache_dir = proj_dirs.cache_dir();
    if !cache_dir.exists() {
        std::fs::create_dir_all(cache_dir)
            .context(format!("could not create cache directory at path {}", cache_dir.to_string_lossy()))?;
    }

    Ok(cache_dir.to_path_buf())
}

fn cache_path_for(cache_dir: PathBuf, cache_key: &[String]) -> PathBuf {
    let file_name = blake3::hash(
        &cache_key.iter().map(|s| s.as_bytes())
            .collect::<Vec<&[u8]>>().concat()).to_string();

    cache_dir.join(PathBuf::from(file_name).with_extension("json"))
}

fn cached_auth_call(args: CacheCmd) -> Result<()> {
    let cache_file_path = cache_path_for(ensure_cache_dir()?, &args.cmd);

    let exec_creds =
        if !cache_file_path.exists() {
            populate_with_call(&cache_file_path, &args.cmd)
        } else {
            read_from_or_populate_with_call(&cache_file_path, &args.cmd)
        }.context("could not extract credentials from underlying command")?;

    let creds = serde_json::to_vec(&exec_creds)
        .context("could not encode to json")?;

    std::io::stdout().write_all(&creds)
        .context("could not write out to stdout")?;

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecCredential {
    pub kind: Option<String>,
    #[serde(rename = "apiVersion")]
    pub api_version: Option<String>,
    pub spec: Option<ExecCredentialSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ExecCredentialStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecCredentialSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    interactive: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecCredentialStatus {
    #[serde(rename = "expirationTimestamp")]
    pub expiration_timestamp: Option<String>,
    pub token: Option<String>,
    #[serde(rename = "clientCertificateData")]
    pub client_certificate_data: Option<String>,
    #[serde(rename = "clientKeyData")]
    pub client_key_data: Option<String>,
}

fn populate_with_call(store_path: &PathBuf, args: &[String]) -> Result<ExecCredential> {
    let (cmd, args) = args.split_first()
        .context("command structure incorrect")?;

    let res = std::process::Command::new(cmd).args(args).output()
        .context("failed to get auth info from underlying program")?;

    if !res.status.success() {
        return Err(anyhow!(
            "failed to get auth info from underlying program ({}): {}",
            res.status, std::str::from_utf8(&res.stderr)?
        ));
    }

    let parsed_red: ExecCredential = serde_json::from_slice(res.stdout.as_slice())
        .context("could not transform into exec credential")?;

    std::fs::write(store_path, res.stdout.as_slice())
        .context("could not read from cached file")?;

    Ok(parsed_red)
}

fn read_from_or_populate_with_call(store_path: &PathBuf, args: &[String]) -> Result<ExecCredential> {
    let read_from_file = std::fs::read(store_path)
        .context("could not read from cached file")?;

    let parsed_red: ExecCredential = serde_json::from_slice(read_from_file.as_slice())
        .context("could not transform into exec credential")?;

    if let Some(status) = &parsed_red.status {
        if let Some(ts) = &status.expiration_timestamp {
            let ts : DateTime<Utc> = ts.parse()
                .context("could not decode timestamp")?;

            if ts.le(&Utc::now()) {
                return populate_with_call(store_path, args);
            }
        }
    }

    Ok(parsed_red)
}

fn modify_kube_config(present: bool) -> Result<()> {
    let cfg_path = locate_kube_config_file()?;

    let contents = std::fs::read(&cfg_path)
        .context("could not read from cached file")?;

    let mut cfg: kube::config::Kubeconfig = serde_yaml::from_slice(&contents)
        .context("could not deserialize kubernetes config")?;

    let mut modified = false;
    let mut recomputed : Vec<NamedAuthInfo> = Vec::with_capacity(cfg.auth_infos.len());

    for named_auth_info in cfg.auth_infos {
        if let Some(ref auth_info) = named_auth_info.auth_info {
            if let Some(exec_cfg) = &auth_info.exec {
                if let Some(new_exec_cfg) = modify_exec_call(exec_cfg, present)? {

                    let mut new_auth_info = auth_info.clone();
                    new_auth_info.exec = Some(new_exec_cfg);

                    let mut new_named_auth = named_auth_info.clone();
                    new_named_auth.auth_info = Some(new_auth_info);

                    recomputed.push(new_named_auth);
                    modified = true;
                    continue
                }
            }
        }

        recomputed.push(named_auth_info)
    }

    if !modified {
        return Ok(())
    }

    cfg.auth_infos = recomputed;

    let new_contents = serde_yaml::to_string(&cfg)
        .context("could not serialize kubernetes config")?;

    std::fs::write(cfg_path, new_contents)
        .context("could not write to kube config file")?;

    Ok(())
}

fn locate_kube_config_file() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("KUBECONFIG") {
        return Ok(PathBuf::from(path));
    }

    let default = BaseDirs::new()
        .ok_or(anyhow!("failed to determine base directories on this platform"))?
        .home_dir().join(".kube").join("config");

    Ok(default)
}

const TOKEICH_CACHE_CMD_0: &str = "tokeich";
const TOKEICH_CACHE_CMD_1: &str = "cache";
const TOKEICH_CACHE_CMD_2: &str = "--";

fn inject_kube_exec_entry_cache_call(cfg: &ExecConfig) -> Result<Option<ExecConfig>> {
    let command = cfg.command.as_ref()
        .context("could not find required command from kubernetes user exec authentication")?;

    if command == TOKEICH_CACHE_CMD_0 {
        return Ok(None); // cache already present
    }

    let mut new_cfg = cfg.clone();
    new_cfg.command = Some(String::from(TOKEICH_CACHE_CMD_0));

    let mut args: Vec<String> = cfg.args.clone().unwrap_or(vec![]);
    let mut new_args: Vec<String> = Vec::with_capacity(3 + args.len());
    new_args.push(String::from(TOKEICH_CACHE_CMD_1));
    new_args.push(String::from(TOKEICH_CACHE_CMD_2));
    new_args.push(command.clone());
    new_args.append(&mut args);
    new_cfg.args = Some(new_args);

    Ok(Some(new_cfg))
}

fn remove_kube_exec_entry_cache_call(cfg: &ExecConfig) -> Result<Option<ExecConfig>> {
    let command = cfg.command.as_ref()
        .context("could not find required command from kubernetes user exec authentication")?;

    if command != TOKEICH_CACHE_CMD_0 {
        return Ok(None); // cache already absent
    }

    let args = cfg.args.as_ref()
        .ok_or_else(|| anyhow!("could not find required command from kubernetes user exec authentication"))?;

    if args.len() < 3 || args[0] != TOKEICH_CACHE_CMD_1 || args[1] != TOKEICH_CACHE_CMD_2 {
        return Err(anyhow!("command did not match expected structure"))
    }

    let mut new_cfg = cfg.clone();
    new_cfg.command = Some(args[2].clone());
    new_cfg.args = Some(args[3..].to_vec());

    Ok(Some(new_cfg))
}

fn modify_exec_call(cfg: &ExecConfig, present: bool) -> Result<Option<ExecConfig>> {
    if present {
        inject_kube_exec_entry_cache_call(cfg)
    } else {
        remove_kube_exec_entry_cache_call(cfg)
    }
}
