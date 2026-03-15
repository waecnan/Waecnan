use std::time::Duration;

use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity};
use libp2p::identity::Keypair;
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{self};
use libp2p::swarm::{NetworkBehaviour, Swarm};
use libp2p::{identify, noise, tcp, yamux, SwarmBuilder};

/// GossipSub topic for new block announcements.
pub const TOPIC_BLOCKS: &str = "waecan/blocks/1";

/// GossipSub topic for new transaction announcements.
pub const TOPIC_TXS: &str = "waecan/transactions/1";

/// Seed nodes for initial peer discovery.
pub const SEED_NODES: &[&str] = &["/ip4/127.0.0.1/tcp/19334"];

/// Combined libp2p behaviour for the Waecan node.
#[derive(NetworkBehaviour)]
pub struct WaecanBehaviour {
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
}

/// Build a configured libp2p Swarm with Waecan's network behaviour.
pub fn build_swarm(keypair: Keypair) -> Result<Swarm<WaecanBehaviour>, Box<dyn std::error::Error>> {
    let peer_id = keypair.public().to_peer_id();

    // Kademlia
    let store = MemoryStore::new(peer_id);
    let kademlia = kad::Behaviour::new(peer_id, store);

    // GossipSub
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .build()
        .map_err(|e| format!("gossipsub config error: {e}"))?;

    let gossipsub =
        gossipsub::Behaviour::new(MessageAuthenticity::Signed(keypair.clone()), gossipsub_config)
            .map_err(|e| format!("gossipsub behaviour error: {e}"))?;

    // Identify
    let identify = identify::Behaviour::new(identify::Config::new(
        "/waecan/1.0.0".to_string(),
        keypair.public(),
    ));

    let behaviour = WaecanBehaviour {
        kademlia,
        gossipsub,
        identify,
    };

    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    Ok(swarm)
}

/// Broadcast a serialized block to all peers via GossipSub.
pub fn broadcast_block(
    swarm: &mut Swarm<WaecanBehaviour>,
    block_bytes: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let topic = IdentTopic::new(TOPIC_BLOCKS);
    swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic, block_bytes)?;
    Ok(())
}

/// Broadcast a serialized transaction to all peers via GossipSub.
pub fn broadcast_tx(
    swarm: &mut Swarm<WaecanBehaviour>,
    tx_bytes: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let topic = IdentTopic::new(TOPIC_TXS);
    swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic, tx_bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topic_strings() {
        assert_eq!(TOPIC_BLOCKS, "waecan/blocks/1");
        assert_eq!(TOPIC_TXS, "waecan/transactions/1");
    }

    #[test]
    fn test_seed_nodes_non_empty() {
        assert!(!SEED_NODES.is_empty());
        for node in SEED_NODES {
            assert!(node.starts_with("/ip4/"));
        }
    }

    #[tokio::test]
    async fn test_build_swarm_ok() {
        let keypair = Keypair::generate_ed25519();
        let result = build_swarm(keypair);
        assert!(result.is_ok(), "build_swarm should succeed");
    }
}
