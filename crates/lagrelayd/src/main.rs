//! LagRelay relay daemon: runs as a bridge, an exit, or both.
mod config;
mod server;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use config::{Client, Config};
use lagcore::session::decode_key;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "lagrelayd", version, about = "Self-hosted game traffic relay")]
struct Cli {
    /// Config file path
    #[arg(short, long, default_value_os_t = default_config())]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a config with a new key pair
    Init {
        /// Display name for this relay, e.g. tokyo
        #[arg(long)]
        name: String,
        /// Public IP address or hostname clients connect to
        #[arg(long)]
        public_addr: String,
        #[arg(long, default_value_t = lagcore::DEFAULT_PORT)]
        port: u16,
        /// Also act as an internet exit (Linux only; needs root for TUN and NAT)
        #[arg(long)]
        exit: bool,
        /// Overwrite an existing config, replacing its key
        #[arg(long)]
        force: bool,
    },
    /// Authorize a client by its public key (from `lagrelay key`)
    AddClient { name: String, public_key: String },
    /// Revoke a client
    RemoveClient { name: String },
    /// List authorized clients
    Clients,
    /// Print the link clients paste into `lagrelay relay add`. It contains the access token
    Link,
    /// Replace the access token, locking out every link issued so far
    RotateToken,
    /// Run the relay
    Run,
}

/// `%APPDATA%` on Windows, since its default permissions keep the access token private.
fn default_config() -> PathBuf {
    match std::env::var_os("APPDATA") {
        Some(a) if cfg!(windows) => PathBuf::from(a).join("LagRelay").join("relayd.toml"),
        _ => PathBuf::from("/etc/lagrelay/relayd.toml"),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init { name, public_addr, port, exit, force } => {
            if cli.config.exists() && !force {
                bail!("{} already exists; pass --force to replace it and its key", cli.config.display());
            }
            let c = Config::new(name, public_addr, port, exit)?;
            c.save(&cli.config)?;
            println!("wrote {}", cli.config.display());
            println!("client link (keep it private, it contains the access token):\n{}", c.share_link()?);
        }
        Cmd::AddClient { name, public_key } => {
            decode_key(&public_key).context("public key")?;
            let mut c = Config::load(&cli.config)?;
            if c.clients.iter().any(|x| x.name == name || x.public_key == public_key) {
                bail!("client name or key already present");
            }
            let vip = c.next_vip()?;
            c.clients.push(Client { name: name.clone(), public_key, vip });
            c.save(&cli.config)?;
            println!("added {name} with tunnel address {vip}; restart lagrelayd to apply");
        }
        Cmd::RemoveClient { name } => {
            let mut c = Config::load(&cli.config)?;
            let before = c.clients.len();
            c.clients.retain(|x| x.name != name);
            if c.clients.len() == before {
                bail!("no client named {name}");
            }
            c.save(&cli.config)?;
            println!("removed {name}; restart lagrelayd to apply");
        }
        Cmd::Clients => {
            for x in Config::load(&cli.config)?.clients {
                println!("{}\t{}\t{}", x.name, x.vip, x.public_key);
            }
        }
        Cmd::Link => println!("{}", Config::load(&cli.config)?.share_link()?),
        Cmd::RotateToken => {
            let mut c = Config::load(&cli.config)?;
            c.access_token = lagcore::session::generate_token();
            c.save(&cli.config)?;
            println!("new client link (restart lagrelayd to apply; old links stop working):\n{}", c.share_link()?);
        }
        Cmd::Run => {
            let c = Config::load(&cli.config)?;
            tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(server::Server::run(c))?;
        }
    }
    Ok(())
}
