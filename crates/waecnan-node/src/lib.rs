/// Node configuration.
pub struct NodeConfig {
    /// Directory for chain data (RocksDB).
    pub data_dir: String,
    /// P2P listen port.
    pub p2p_port: u16,
    /// JSON-RPC listen port.
    pub rpc_port: u16,
    /// Number of mining threads.
    pub miner_threads: usize,
    /// Bech32m address for mining rewards.
    pub miner_address: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            data_dir: "./waecnan-data".to_string(),
            p2p_port: 19334,
            rpc_port: 19335,
            miner_threads: 1,
            miner_address: String::new(),
        }
    }
}

/// Runtime state of a Waecan node.
pub struct NodeState {
    pub config: NodeConfig,
    pub height: u64,
    pub running: bool,
}

impl NodeState {
    /// Create a new node state from config.
    pub fn new(config: NodeConfig) -> Self {
        NodeState {
            config,
            height: 0,
            running: false,
        }
    }

    /// Start the node.
    pub fn start(&mut self) {
        self.running = true;
    }

    /// Stop the node.
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Return a JSON status string.
    pub fn get_status(&self) -> String {
        serde_json::json!({
            "height": self.height,
            "running": self.running,
            "p2p_port": self.config.p2p_port,
            "rpc_port": self.config.rpc_port
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_ports() {
        let cfg = NodeConfig::default();
        assert_eq!(cfg.p2p_port, 19334);
        assert_eq!(cfg.rpc_port, 19335);
    }

    #[test]
    fn test_new_state_initial() {
        let state = NodeState::new(NodeConfig::default());
        assert_eq!(state.height, 0);
        assert!(!state.running);
    }

    #[test]
    fn test_start_sets_running() {
        let mut state = NodeState::new(NodeConfig::default());
        state.start();
        assert!(state.running);
    }

    #[test]
    fn test_stop_sets_not_running() {
        let mut state = NodeState::new(NodeConfig::default());
        state.start();
        state.stop();
        assert!(!state.running);
    }

    #[test]
    fn test_get_status_valid_json() {
        let state = NodeState::new(NodeConfig::default());
        let status = state.get_status();
        let parsed: serde_json::Value = serde_json::from_str(&status).unwrap();
        assert_eq!(parsed["running"], false);
        assert_eq!(parsed["height"], 0);
        assert_eq!(parsed["p2p_port"], 19334);
        assert_eq!(parsed["rpc_port"], 19335);
    }
}
