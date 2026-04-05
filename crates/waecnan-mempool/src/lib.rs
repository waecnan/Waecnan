use std::collections::{HashMap, HashSet};

use curve25519_dalek::edwards::CompressedEdwardsY;
use thiserror::Error;
use tiny_keccak::{Hasher, Keccak};

use waecnan_core::error::CoreError;
use waecnan_core::transaction::Transaction;
use waecnan_core::validation::validate_transaction;

/// Maximum mempool size: 50 MB.
const MAX_MEMPOOL_BYTES: usize = 52_428_800;

/// Errors returned by mempool operations.
#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("Transaction validation failed: {0}")]
    ValidationFailed(#[from] CoreError),
    #[error("Key image already in mempool")]
    DuplicateKeyImage,
    #[error("Key image already spent on chain")]
    KeyImageSpent,
    #[error("Mempool is full and transaction fee is too low")]
    MempoolFull,
}

/// Compute a deterministic transaction ID by hashing key fields.
fn compute_txid(tx: &Transaction) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(&[tx.version]);
    hasher.update(&(tx.inputs.len() as u32).to_le_bytes());
    for input in &tx.inputs {
        hasher.update(input.key_image.as_bytes());
    }
    hasher.update(&(tx.outputs.len() as u32).to_le_bytes());
    for output in &tx.outputs {
        hasher.update(output.output_key.as_bytes());
    }
    hasher.update(&tx.fee.to_le_bytes());
    hasher.update(tx.tx_public_key.as_bytes());
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// Transaction pool holding valid unconfirmed transactions.
pub struct Mempool {
    transactions: HashMap<[u8; 32], Transaction>,
    key_images: HashSet<CompressedEdwardsY>,
    current_size: usize,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Mempool {
    /// Create an empty mempool.
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
            key_images: HashSet::new(),
            current_size: 0,
        }
    }

    /// Add a transaction to the mempool.
    ///
    /// Rules enforced:
    /// 1. Transaction passes `validate_transaction()`.
    /// 2. No key image already in mempool.
    /// 3. No key image already spent on chain.
    /// 4. Total mempool size <= 50 MB after adding.
    /// 5. If full: reject if fee is lower than lowest-fee tx in pool.
    pub fn add(
        &mut self,
        tx: Transaction,
        chain_key_images: &HashSet<CompressedEdwardsY>,
    ) -> Result<[u8; 32], MempoolError> {
        // Rule 1: validate transaction
        validate_transaction(&tx, chain_key_images)?;

        // Rule 2: no key image already in mempool
        for input in &tx.inputs {
            if self.key_images.contains(&input.key_image) {
                return Err(MempoolError::DuplicateKeyImage);
            }
        }

        // Rule 3: no key image already spent on chain
        for input in &tx.inputs {
            if chain_key_images.contains(&input.key_image) {
                return Err(MempoolError::KeyImageSpent);
            }
        }

        let tx_size = tx.serialized_size();

        // Rule 4 + 5: if adding would exceed limit, try eviction
        if self.current_size + tx_size > MAX_MEMPOOL_BYTES {
            // Find the lowest-fee transaction in the pool
            let lowest = self
                .transactions
                .iter()
                .min_by_key(|(_, t)| t.fee)
                .map(|(id, t)| (*id, t.fee, t.serialized_size()));

            if let Some((lowest_id, lowest_fee, lowest_size)) = lowest {
                if tx.fee <= lowest_fee {
                    return Err(MempoolError::MempoolFull);
                }
                // Evict the lowest-fee tx
                if let Some(evicted) = self.transactions.remove(&lowest_id) {
                    for input in &evicted.inputs {
                        self.key_images.remove(&input.key_image);
                    }
                    self.current_size -= lowest_size;
                }
            } else {
                return Err(MempoolError::MempoolFull);
            }
        }

        let txid = compute_txid(&tx);

        // Track key images
        for input in &tx.inputs {
            self.key_images.insert(input.key_image);
        }

        self.current_size += tx_size;
        self.transactions.insert(txid, tx);

        Ok(txid)
    }

    /// Remove a transaction by its ID.
    pub fn remove(&mut self, txid: &[u8; 32]) {
        if let Some(tx) = self.transactions.remove(txid) {
            for input in &tx.inputs {
                self.key_images.remove(&input.key_image);
            }
            self.current_size -= tx.serialized_size();
        }
    }

    /// Return transactions ordered by highest fee first, up to `max_bytes`.
    pub fn get_transactions(&self, max_bytes: usize) -> Vec<Transaction> {
        let mut txs: Vec<&Transaction> = self.transactions.values().collect();
        txs.sort_by(|a, b| b.fee.cmp(&a.fee));

        let mut result = Vec::new();
        let mut total = 0usize;
        for tx in txs {
            let size = tx.serialized_size();
            if total + size > max_bytes {
                continue;
            }
            total += size;
            result.push(tx.clone());
        }
        result
    }

    /// Check if a key image is already in the mempool.
    pub fn contains_key_image(&self, img: &CompressedEdwardsY) -> bool {
        self.key_images.contains(img)
    }

    /// Current total serialized size of all transactions in the mempool.
    pub fn size_bytes(&self) -> usize {
        self.current_size
    }

    /// Number of transactions in the mempool.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Whether the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use waecnan_core::transaction::{TransactionInput, TransactionOutput, MIN_FEE_ATOMIC};
    use waecnan_crypto::pedersen::PedersenCommitment;
    use waecnan_crypto::ring_sig::{mlsag_sign, Ring, RingMember};

    fn make_valid_tx(seed: u8, fee_multiplier: u64) -> Transaction {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let mut spend_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut spend_bytes);
        let spend_priv = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(spend_bytes);
        let spend_pub = &spend_priv * &ED25519_BASEPOINT_POINT;

        let fee = fee_multiplier * MIN_FEE_ATOMIC;
        let b_in = curve25519_dalek::scalar::Scalar::from(1u64);
        let pseudo_commit = PedersenCommitment::commit(100 * MIN_FEE_ATOMIC, &b_in);

        let b_out = curve25519_dalek::scalar::Scalar::from(1u64);
        let out_commit = PedersenCommitment::commit(100 * MIN_FEE_ATOMIC - fee, &b_out);

        let mut members = Vec::new();
        for _ in 0..11 {
            members.push(RingMember {
                output_key: spend_pub,
            });
        }
        let ring = Ring { members };

        let key_image =
            (&spend_priv * waecnan_crypto::hash::hash_to_point(&spend_pub.compress())).compress();

        let output = TransactionOutput {
            output_key: spend_pub.compress(),
            commitment: out_commit,
            range_proof: vec![1, 2, 3],
            encrypted_amount: [0u8; 8],
        };

        // Build tx with dummy signature to compute hash
        let dummy_sig =
            mlsag_sign(&ring, 0, &spend_priv, &[0u8; 32], &mut rng).expect("sign failed");
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                ring: ring.clone(),
                key_image,
                ring_sig: dummy_sig,
                pseudo_commit,
            }],
            outputs: vec![output],
            fee,
            tx_public_key: spend_pub.compress(),
            extra: vec![],
        };

        // Re-sign with the real transaction hash
        let msg = waecnan_core::block_validation::hash_transaction(&tx);
        let real_sig =
            mlsag_sign(&ring, 0, &spend_priv, &msg, &mut rng).expect("sign failed");
        tx.inputs[0].ring_sig = real_sig;
        tx
    }

    #[test]
    fn test_add_valid_tx() {
        let mut pool = Mempool::new();
        let tx = make_valid_tx(42, 1);
        let chain_ki = HashSet::new();
        let result = pool.add(tx, &chain_ki);
        assert!(result.is_ok());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_duplicate_key_image_rejected() {
        let mut pool = Mempool::new();
        let tx1 = make_valid_tx(42, 1);
        let tx2 = make_valid_tx(42, 2); // same seed → same key image
        let chain_ki = HashSet::new();
        assert!(pool.add(tx1, &chain_ki).is_ok());
        let result = pool.add(tx2, &chain_ki);
        assert!(matches!(result, Err(MempoolError::DuplicateKeyImage)));
    }

    #[test]
    fn test_spent_key_image_rejected() {
        let mut pool = Mempool::new();
        let tx = make_valid_tx(42, 1);
        let mut chain_ki = HashSet::new();
        // Pre-mark the key image as spent on chain
        chain_ki.insert(tx.inputs[0].key_image);
        let result = pool.add(tx, &chain_ki);
        // Will fail at validate_transaction (rule 5: key image spent) or our rule 3
        assert!(result.is_err());
    }

    #[test]
    fn test_get_transactions_fee_order() {
        let mut pool = Mempool::new();
        let chain_ki = HashSet::new();

        let tx_low = make_valid_tx(10, 1);
        let tx_high = make_valid_tx(20, 5);

        pool.add(tx_low, &chain_ki).unwrap();
        pool.add(tx_high, &chain_ki).unwrap();

        let txs = pool.get_transactions(usize::MAX);
        assert_eq!(txs.len(), 2);
        assert!(txs[0].fee > txs[1].fee, "highest fee should come first");
    }

    #[test]
    fn test_remove_tx() {
        let mut pool = Mempool::new();
        let tx = make_valid_tx(42, 1);
        let chain_ki = HashSet::new();
        let txid = pool.add(tx, &chain_ki).unwrap();
        assert_eq!(pool.len(), 1);
        pool.remove(&txid);
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.size_bytes(), 0);
    }
}
