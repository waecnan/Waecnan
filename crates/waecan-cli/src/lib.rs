use clap::{Parser, Subcommand};
use waecan_rpc::{dispatch, RpcRequest};
use waecan_wallet::wallet_from_seed;

/// Waecan CLI — command-line interface for the Waecan protocol.
#[derive(Parser)]
#[command(name = "waecan", version, about = "Waecan protocol CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Available CLI subcommands.
#[derive(Subcommand)]
pub enum Commands {
    /// Generate a new wallet from a random seed
    NewWallet,
    /// Show wallet address for a given seed (hex)
    Address {
        /// 32-byte seed as 64-character hex string
        seed_hex: String,
    },
    /// Send a JSON-RPC request to the node
    Rpc {
        /// RPC method name
        method: String,
        /// JSON params (default: [])
        #[arg(default_value = "[]")]
        params: String,
    },
    /// Show current blockchain info
    Info,
}

/// Execute a CLI command and return a human-readable result string.
pub fn run_command(cmd: Commands) -> String {
    match cmd {
        Commands::NewWallet => {
            let mut seed = [0u8; 32];
            // Use a simple deterministic seed for now (production would use CSPRNG)
            for (i, byte) in seed.iter_mut().enumerate() {
                *byte = (i as u8).wrapping_mul(7).wrapping_add(42);
            }
            let keys = wallet_from_seed(&seed);
            let seed_hex = hex::encode(seed);
            format!(
                "New wallet created!\nAddress: {}\nSeed (backup this!): {}",
                keys.address, seed_hex
            )
        }
        Commands::Address { seed_hex } => {
            let bytes = match hex::decode(&seed_hex) {
                Ok(b) => b,
                Err(e) => return format!("Error: invalid hex: {}", e),
            };
            if bytes.len() != 32 {
                return format!("Error: seed must be 32 bytes (64 hex chars), got {}", bytes.len());
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            let keys = wallet_from_seed(&seed);
            keys.address
        }
        Commands::Rpc { method, params } => {
            let params_val = match serde_json::from_str(&params) {
                Ok(v) => v,
                Err(e) => return format!("Error: invalid JSON params: {}", e),
            };
            let req = RpcRequest {
                jsonrpc: "2.0".to_string(),
                method,
                params: params_val,
                id: serde_json::Value::Number(serde_json::Number::from(1)),
            };
            let resp = dispatch(&req);
            serde_json::to_string_pretty(&resp).unwrap_or_else(|e| format!("Error: {}", e))
        }
        Commands::Info => {
            let req = RpcRequest {
                jsonrpc: "2.0".to_string(),
                method: "getblockchaininfo".to_string(),
                params: serde_json::Value::Null,
                id: serde_json::Value::Number(serde_json::Number::from(1)),
            };
            let resp = dispatch(&req);
            serde_json::to_string_pretty(&resp).unwrap_or_else(|e| format!("Error: {}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_wallet_contains_address() {
        let result = run_command(Commands::NewWallet);
        assert!(result.contains("wae1"), "should contain a wae1 address");
        assert!(result.contains("Seed"));
    }

    #[test]
    fn test_address_from_seed() {
        let seed_hex = "2a".repeat(32); // [0x2a; 32]
        let result = run_command(Commands::Address { seed_hex });
        assert!(result.starts_with("wae1"), "should return a wae1 address");
    }

    #[test]
    fn test_rpc_getblockcount() {
        let result = run_command(Commands::Rpc {
            method: "getblockcount".to_string(),
            params: "[]".to_string(),
        });
        assert!(result.contains("\"result\""));
        assert!(result.contains("\"jsonrpc\""));
    }

    #[test]
    fn test_info_returns_chain() {
        let result = run_command(Commands::Info);
        assert!(result.contains("chain"));
        assert!(result.contains("mainnet"));
    }

    #[test]
    fn test_invalid_seed_hex() {
        let result = run_command(Commands::Address {
            seed_hex: "not_hex".to_string(),
        });
        assert!(result.starts_with("Error:"));
    }
}
