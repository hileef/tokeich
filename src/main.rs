use std::io::Write;
use std::path::PathBuf;
use anyhow::{anyhow, Context, Result};
use clap::{Parser};
use directories::{BaseDirs, ProjectDirs};
use k8s_openapi::chrono::DateTime;
use k8s_openapi::chrono::Utc;
use k8s_openapi::serde::{Deserialize, Serialize};
use kube::config::{ExecConfig, NamedAuthInfo, ExecInteractiveMode};

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

    /// Display information such as default cache directory
    Info
}

#[derive(clap::Parser, Debug)]
#[command(author, version, about, long_about = None, arg_required_else_help = true)]
struct CacheCmd {
    /// Kubernetes auth user name
    name: String,

    /// Kubernetes auth user exec config, as json in base64
    config: String,
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::On => update_kube_config(true),
        Command::Off => update_kube_config(false),
        Command::Cache(c) => cached_exec(c),
        Command::Info => info()
    }
}

fn info() -> Result<()> {
    let cache_dir = cache_dir()?;
    println!("default cache directory location is : {}", cache_dir.to_string_lossy());

    return Ok(())
}

fn cache_dir() -> Result<PathBuf> {
    return Ok(
        ProjectDirs::from("", "", "tokeich")
            .context("failed to determine project directories on this platform")?
            .cache_dir().to_path_buf()
    );
}

fn ensure_cache_dir() -> Result<PathBuf> {
    let cache_dir = cache_dir()?;
    if !cache_dir.exists() {
        std::fs::create_dir_all(&cache_dir)
            .context(format!("could not create cache directory at path {}", cache_dir.to_string_lossy()))?;
    }

    Ok(cache_dir.to_path_buf())
}

fn cache_for(dir: PathBuf, key: &String) -> PathBuf {
    let file_name = blake3::hash(key.as_bytes()).to_string();

    dir.join(PathBuf::from(file_name).with_extension("json"))
}

fn cached_exec(args: CacheCmd) -> Result<()> {
    let cache_file_path = cache_for(ensure_cache_dir()?, &args.name);

    let exec_config = decode_from_b64(args.config)
        .context("could not extract exec config from provided arguments")?;

    let exec_creds =
        if !cache_file_path.exists() {
            exec_n_store(&exec_config, &cache_file_path)
        } else {
            read_or_exec_n_store(&exec_config, &cache_file_path)
        }.context("could not obtain credentials to provide to kubectl")?;

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

fn update_kube_config(present: bool) -> Result<()> {
    let cfg_path = find_kube_config()?;

    let contents = std::fs::read(&cfg_path)
        .context("could not read from kube config file")?;

    let mut cfg: kube::config::Kubeconfig = serde_yaml::from_slice(&contents)
        .context("could not deserialize kubernetes config")?;

    let mut modified = false;
    let mut recomputed : Vec<NamedAuthInfo> = Vec::with_capacity(cfg.auth_infos.len());

    for user in cfg.auth_infos {
        if let Some(ref auth) = user.auth_info {
            if let Some(exec_cfg) = &auth.exec {
                if let Some(new_exec_cfg) = maybe_update_cfg(exec_cfg, &user.name, present)? {

                    let mut new_auth = auth.clone();
                    new_auth.exec = Some(new_exec_cfg);

                    let mut new_user = user.clone();
                    new_user.auth_info = Some(new_auth);

                    recomputed.push(new_user);
                    modified = true;
                    continue
                }
            }
        }

        recomputed.push(user)
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

fn find_kube_config() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("KUBECONFIG") {
        return Ok(PathBuf::from(path));
    }

    let default = BaseDirs::new()
        .ok_or(anyhow!("failed to determine base directories on this platform"))?
        .home_dir().join(".kube").join("config");

    Ok(default)
}

const TOKEICH_CACHE_CMD: &str = "tokeich";
const TOKEICH_CACHE_ARG: &str = "cache";

fn inject_kube_exec_entry_cache_call(cfg: &ExecConfig, name: &String) -> Result<Option<ExecConfig>> {
    let command = cfg.command.as_ref()
        .context("could not find required command from kubernetes user exec authentication")?;

    if command == TOKEICH_CACHE_CMD {
        return Ok(None); // cache already present
    }

    let as_b64_cfg = encode_to_b64(cfg)
        .context("failed to transform exec configuration")?;

    let mut new_cfg = cfg.clone();
    new_cfg.command = Some(String::from(TOKEICH_CACHE_CMD));
    new_cfg.args = Some(vec![
        String::from(TOKEICH_CACHE_ARG),
        name.to_string(),
        as_b64_cfg
    ]);

    Ok(Some(new_cfg))
}

fn remove_kube_exec_entry_cache_call(cfg: &ExecConfig) -> Result<Option<ExecConfig>> {
    let command = cfg.command.as_ref()
        .context("could not find required command from kubernetes user exec authentication")?;

    if command != TOKEICH_CACHE_CMD {
        return Ok(None); // cache already absent
    }

    let args = cfg.args.as_ref()
        .ok_or_else(|| anyhow!("could not find required command from kubernetes user exec authentication"))?;

    if args.len() != 3 || args[0] != TOKEICH_CACHE_ARG {
        return Err(anyhow!("command did not match expected structure"))
    }

    let original_cfg = decode_from_b64(args[2].clone())
        .context("failed to transform exec configuration")?;

    Ok(Some(original_cfg))
}

fn maybe_update_cfg(cfg: &ExecConfig, name: &String, present: bool) -> Result<Option<ExecConfig>> {
    let res = if present {
        inject_kube_exec_entry_cache_call(cfg, name)
    } else {
        remove_kube_exec_entry_cache_call(cfg)
    };

    if let Ok(Some(_)) = res {
        if present {
            println!("   -> injected tokeich cache usage for {name}")
        } else {
            println!("   -> removed tokeich cache usage for {name}")
        }
    }

    res
}

fn decode_from_b64(exec_cfg: String) -> Result<ExecConfig> {
    use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};

    let exec_cfg = BASE64_STANDARD_NO_PAD.decode(exec_cfg)
        .context("failed to deserialize exec config from base64")?;

    let exec_cfg: ExecConfig = serde_json::from_slice(&exec_cfg)
        .context("failed to deserialize exec config from json")?;

    Ok(exec_cfg)
}

fn encode_to_b64(exec_cfg: &ExecConfig) -> Result<String> {
    use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};

    let exec_cfg = serde_json::to_vec(&exec_cfg)
        .context("failed to serialize exec config to json")?;

    let exec_cfg = BASE64_STANDARD_NO_PAD.encode(exec_cfg);

    Ok(exec_cfg)
}

fn read_or_exec_n_store(args: &ExecConfig, location: &PathBuf) -> Result<ExecCredential> {
    let read_from_file = std::fs::read(location)
        .context(format!("could not read from cached file at {}", location.to_string_lossy()))?;

    let parsed_red: ExecCredential = serde_json::from_slice(read_from_file.as_slice())
        .context("could not transform into exec credential")?;

    if let Some(status) = &parsed_red.status {
        if let Some(ts) = &status.expiration_timestamp {
            let ts : DateTime<Utc> = ts.parse()
                .context("could not decode timestamp")?;

            if ts.le(&Utc::now()) {
                return exec_n_store(args, location);
            }
        }
    }

    Ok(parsed_red)
}

fn exec_n_store(cfg: &ExecConfig, location: &PathBuf) -> Result<ExecCredential> {
    // Heavily "inspired" from kube-client/src/client/auth/mod.rs ,
    // since function is not exported

    let mut cmd = match &cfg.command {
        Some(cmd) => std::process::Command::new(cmd),
        None => return Err(anyhow!("exec spec must specify a command")),
    };

    if let Some(args) = &cfg.args {
        cmd.args(args);
    }

    if let Some(env) = &cfg.env {
        let envs = env
            .iter()
            .flat_map(|env| match (env.get("name"), env.get("value")) {
                (Some(name), Some(value)) => Some((name, value)),
                _ => None,
            });
        cmd.envs(envs);
    }

    let interactive = cfg.interactive_mode != Some(ExecInteractiveMode::Never);
    if interactive {
        cmd.stdin(std::process::Stdio::inherit());
    } else {
        cmd.stdin(std::process::Stdio::piped());
    }

    let exec_info = serde_json::to_string(&ExecCredential {
        api_version: cfg.api_version.clone(),
        kind: None,
        spec: Some(ExecCredentialSpec {
            interactive: Some(interactive),
        }),
        status: None,
    })
        .context("could not serialize exec info")?;

    cmd.env("KUBERNETES_EXEC_INFO", exec_info);

    if let Some(envs) = &cfg.drop_env {
        for env in envs {
            cmd.env_remove(env);
        }
    }

    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let res = cmd.output()
        .context("failed to get auth info from underlying program")?;

    if !res.status.success() {
        return Err(anyhow!(
            "failed to get auth info from underlying program ({}): {}",
            res.status, std::str::from_utf8(&res.stderr)?
        ));
    }
    let creds = serde_json::from_slice(&res.stdout)
        .context("could not transform into exec credential")?;

    std::fs::write(location, res.stdout.as_slice())
        .context("could not read from cached file")?;

    Ok(creds)
}

