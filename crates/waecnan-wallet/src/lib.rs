use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use waecnan_core::block::Block;
use waecnan_core::transaction::{Transaction, TransactionInput, TransactionOutput, MIN_FEE_ATOMIC};
use waecnan_crypto::address::WaecanAddress;
use waecnan_crypto::hash::hash_to_point;
use waecnan_crypto::keys::{derive_keypairs, MasterSeed};
use waecnan_crypto::pedersen::PedersenCommitment;
use waecnan_crypto::ring_sig::{mlsag_sign, Ring, RingMember};
use waecnan_crypto::stealth::{compute_output_key, derive_output_private_key, scan_output};

/// Wallet error type.
#[derive(Debug)]
pub enum WalletError {
    InsufficientFunds,
    InvalidAddress,
    CryptoError(String),
}

/// Wallet key material derived from a seed.
pub struct WalletKeys {
    pub spend_private: Scalar,
    pub spend_public: EdwardsPoint,
    pub view_private: Scalar,
    pub view_public: EdwardsPoint,
    pub address: String,
}

/// A transaction output owned by this wallet.
pub struct OwnedOutput {
    pub txid: [u8; 32],
    pub output_idx: usize,
    pub amount: u64,
    pub key_image: CompressedEdwardsY,
}

/// Create wallet keys from a 32-byte seed.
pub fn wallet_from_seed(seed: &[u8; 32]) -> WalletKeys {
    let master = MasterSeed::from_bytes(*seed);
    let (spend, view) = derive_keypairs(&master).expect("key derivation failed");

    let addr = WaecanAddress {
        spend_public: spend.public,
        view_public: view.public,
    };
    let address = addr.to_bech32m().expect("address encoding failed");

    WalletKeys {
        spend_private: spend.private,
        spend_public: spend.public,
        view_private: view.private,
        view_public: view.public,
        address,
    }
}

/// Scan a block for outputs belonging to this wallet.
///
/// For each transaction output, uses the stealth address protocol
/// to check ownership. Returns a list of owned outputs with
/// pre-computed key images for spending.
pub fn scan_block(keys: &WalletKeys, block: &Block) -> Vec<OwnedOutput> {
    let mut found = Vec::new();

    for tx in &block.transactions {
        let tx_pub_compressed = tx.tx_public_key;
        let tx_pub = match tx_pub_compressed.decompress() {
            Some(p) => p,
            None => continue,
        };

        for (idx, output) in tx.outputs.iter().enumerate() {
            let output_key = match output.output_key.decompress() {
                Some(p) => p,
                None => continue,
            };

            if scan_output(&tx_pub, &keys.view_private, &keys.spend_public, &output_key) {
                // Derive the one-time private key to compute the key image
                let output_priv =
                    derive_output_private_key(&tx_pub, &keys.view_private, &keys.spend_private);
                let hp = hash_to_point(&output_key.compress());
                let key_image = (output_priv * hp).compress();

                // Decrypt amount from encrypted_amount field
                let amount = u64::from_le_bytes(output.encrypted_amount);

                found.push(OwnedOutput {
                    txid: [0u8; 32], // placeholder txid
                    output_idx: idx,
                    amount,
                    key_image,
                });
            }
        }
    }

    found
}

/// Build a transaction spending owned outputs to a recipient.
#[allow(clippy::too_many_arguments)]
pub fn build_transaction(
    keys: &WalletKeys,
    inputs: Vec<OwnedOutput>,
    ring_members: Vec<Vec<RingMember>>,
    recipient: &str,
    amount: u64,
    fee: u64,
) -> Result<Transaction, WalletError> {
    if fee < MIN_FEE_ATOMIC {
        return Err(WalletError::CryptoError("Fee below minimum".into()));
    }

    let total_in: u64 = inputs.iter().map(|i| i.amount).sum();
    if total_in < amount + fee {
        return Err(WalletError::InsufficientFunds);
    }

    // Validate recipient address
    let recipient_addr =
        WaecanAddress::from_bech32m(recipient).map_err(|_| WalletError::InvalidAddress)?;

    // Generate a random tx secret for the stealth address
    let tx_secret = Scalar::from_bytes_mod_order([42u8; 32]); // stub: deterministic for now

    // Create the output to recipient
    let (output_key, tx_public_key) = compute_output_key(
        &tx_secret,
        &recipient_addr.view_public,
        &recipient_addr.spend_public,
    );

    let b_out = Scalar::from(1u64);
    let out_commit = PedersenCommitment::commit(amount, &b_out);

    let recipient_output = TransactionOutput {
        output_key: output_key.compress(),
        commitment: out_commit,
        range_proof: vec![1, 2, 3],
        encrypted_amount: amount.to_le_bytes(),
    };

    let mut outputs = vec![recipient_output];

    // Change output if needed
    let change = total_in - amount - fee;
    if change > 0 {
        let change_secret = Scalar::from_bytes_mod_order([43u8; 32]); // stub
        let (change_key, _) =
            compute_output_key(&change_secret, &keys.view_public, &keys.spend_public);
        let b_change = Scalar::from(1u64);
        let change_commit = PedersenCommitment::commit(change, &b_change);

        outputs.push(TransactionOutput {
            output_key: change_key.compress(),
            commitment: change_commit,
            range_proof: vec![1, 2, 3],
            encrypted_amount: change.to_le_bytes(),
        });
    }

    // Build inputs with ring signatures
    let msg = [0u8; 32]; // stub message
    let mut tx_inputs = Vec::new();

    for (i, owned) in inputs.iter().enumerate() {
        let decoys = if i < ring_members.len() {
            &ring_members[i]
        } else {
            return Err(WalletError::CryptoError("Not enough ring members".into()));
        };

        let mut members = decoys.clone();
        let real_member = RingMember {
            output_key: keys.spend_public,
        };
        let real_index = 0;
        members.insert(real_index, real_member);

        let ring = Ring { members };
        let ring_sig = mlsag_sign(
            &ring,
            real_index,
            &keys.spend_private,
            &msg,
            &mut ChaCha20Rng::from_entropy(),
        )
        .map_err(|e| WalletError::CryptoError(format!("{}", e)))?;

        let b_in = Scalar::from(1u64);
        let pseudo_commit = PedersenCommitment::commit(owned.amount, &b_in);

        tx_inputs.push(TransactionInput {
            ring,
            key_image: owned.key_image,
            ring_sig,
            pseudo_commit,
        });
    }

    Ok(Transaction {
        version: 1,
        inputs: tx_inputs,
        outputs,
        fee,
        tx_public_key: tx_public_key.compress(),
        extra: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_from_seed_deterministic() {
        let seed = [42u8; 32];
        let w1 = wallet_from_seed(&seed);
        let w2 = wallet_from_seed(&seed);
        assert_eq!(w1.address, w2.address);
        assert!(w1.address.starts_with("wae1"));
    }

    #[test]
    fn test_different_seeds_different_addresses() {
        let w1 = wallet_from_seed(&[1u8; 32]);
        let w2 = wallet_from_seed(&[2u8; 32]);
        assert_ne!(w1.address, w2.address);
    }

    #[test]
    fn test_scan_block_finds_owned_output() {
        let keys = wallet_from_seed(&[42u8; 32]);

        // Create a tx with an output sent to this wallet
        let tx_secret = Scalar::from_bytes_mod_order([99u8; 32]);
        let (output_key, tx_pub) =
            compute_output_key(&tx_secret, &keys.view_public, &keys.spend_public);

        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TransactionOutput {
                output_key: output_key.compress(),
                commitment: PedersenCommitment::commit(1000, &Scalar::from(1u64)),
                range_proof: vec![],
                encrypted_amount: 1000u64.to_le_bytes(),
            }],
            fee: MIN_FEE_ATOMIC,
            tx_public_key: tx_pub.compress(),
            extra: vec![],
        };

        let block = Block {
            header: waecnan_core::block::BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp: 0,
                difficulty: 1,
                nonce: 0,
                height: 0,
            },
            coinbase: waecnan_core::block::CoinbaseTx {
                height: 0,
                reward: 0,
                miner_output_key: CompressedEdwardsY::default(),
                genesis_message: vec![],
            },
            transactions: vec![tx],
        };

        let found = scan_block(&keys, &block);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].amount, 1000);
    }

    #[test]
    fn test_scan_block_ignores_others() {
        let keys = wallet_from_seed(&[42u8; 32]);
        let other = wallet_from_seed(&[99u8; 32]);

        // Output sent to other wallet
        let tx_secret = Scalar::from_bytes_mod_order([10u8; 32]);
        let (output_key, tx_pub) =
            compute_output_key(&tx_secret, &other.view_public, &other.spend_public);

        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TransactionOutput {
                output_key: output_key.compress(),
                commitment: PedersenCommitment::commit(1000, &Scalar::from(1u64)),
                range_proof: vec![],
                encrypted_amount: 1000u64.to_le_bytes(),
            }],
            fee: MIN_FEE_ATOMIC,
            tx_public_key: tx_pub.compress(),
            extra: vec![],
        };

        let block = Block {
            header: waecnan_core::block::BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp: 0,
                difficulty: 1,
                nonce: 0,
                height: 0,
            },
            coinbase: waecnan_core::block::CoinbaseTx {
                height: 0,
                reward: 0,
                miner_output_key: CompressedEdwardsY::default(),
                genesis_message: vec![],
            },
            transactions: vec![tx],
        };

        let found = scan_block(&keys, &block);
        assert!(found.is_empty());
    }

    #[test]
    fn test_build_transaction_insufficient_funds() {
        let keys = wallet_from_seed(&[42u8; 32]);
        let owned = OwnedOutput {
            txid: [0u8; 32],
            output_idx: 0,
            amount: 100,
            key_image: CompressedEdwardsY::default(),
        };
        let result = build_transaction(
            &keys,
            vec![owned],
            vec![vec![]],
            &keys.address,
            1000, // more than owned
            MIN_FEE_ATOMIC,
        );
        assert!(matches!(result, Err(WalletError::InsufficientFunds)));
    }
}
