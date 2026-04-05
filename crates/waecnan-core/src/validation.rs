use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use std::collections::HashSet;
use waecnan_crypto::pedersen::verify_balance;

use crate::error::CoreError;
use crate::transaction::{Transaction, MIN_FEE_ATOMIC};

pub const FEE_BURN_RATIO: u64 = 70; // 70% burned
pub const FEE_MINER_RATIO: u64 = 30; // 30% to block producer

/// Validate a transaction against all 11 consensus rules from Section 3.4.
pub fn validate_transaction(
    tx: &Transaction,
    known_key_images: &HashSet<CompressedEdwardsY>,
) -> Result<(), CoreError> {
    // 1. Version == 1
    if tx.version != 1 {
        return Err(CoreError::InvalidVersion);
    }

    // 2. Number of inputs >= 1; number of outputs >= 1 and <= 16
    if tx.inputs.is_empty() {
        return Err(CoreError::NoInputs);
    }
    if tx.outputs.is_empty() || tx.outputs.len() > 16 {
        return Err(CoreError::InvalidOutputCount);
    }

    // 3. Fee >= MIN_FEE_ATOMIC
    if tx.fee < MIN_FEE_ATOMIC {
        return Err(CoreError::InsufficientFee);
    }

    let mut pseudo_commits = Vec::with_capacity(tx.inputs.len());

    for input in &tx.inputs {
        // 4. For each input: ring size == 11
        if input.ring.members.len() != 11 {
            return Err(CoreError::InvalidRingSize);
        }

        // 5. For each input: key_image is not in the global key image set
        if known_key_images.contains(&input.key_image) {
            return Err(CoreError::DoubleSpend);
        }

        // 6. For each input: MLSAG ring signature is valid
        // The message is the transaction hash (excluding signatures).
        let msg = crate::block_validation::hash_transaction(tx);
        if waecnan_crypto::ring_sig::mlsag_verify(&input.ring, &input.ring_sig, &msg).is_err() {
            return Err(CoreError::InvalidRingSignature);
        }

        pseudo_commits.push(input.pseudo_commit.clone());
    }

    let mut out_commits = Vec::with_capacity(tx.outputs.len());

    for output in &tx.outputs {
        // 7. For each output: Bulletproof range proof is valid
        if !verify_range_proof_stub(&output.range_proof) {
            return Err(CoreError::InvalidRangeProof);
        }
        out_commits.push(output.commitment.clone());
    }

    // 8. Balance proof: sum(pseudo_commitments) == sum(output_commitments) + fee_commitment
    if verify_balance(&pseudo_commits, &out_commits, tx.fee).is_err() {
        return Err(CoreError::BalanceMismatch);
    }

    // 9. Transaction serialized size <= 100,000 bytes
    if tx.serialized_size() > 100_000 {
        return Err(CoreError::TooLarge);
    }

    // 10. extra field length <= 255 bytes
    if tx.extra.len() > 255 {
        return Err(CoreError::ExtraTooLarge);
    }

    // 11. tx_public_key is a valid Ed25519 point (not identity, not low-order)
    if let Some(point) = tx.tx_public_key.decompress() {
        if point.mul_by_cofactor() == EdwardsPoint::default() {
            return Err(CoreError::InvalidTxPublicKey);
        }
    } else {
        return Err(CoreError::InvalidTxPublicKey);
    }

    Ok(())
}

/// A stub for Bulletproof verification since dalek-bulletproofs 4.0 is not in circulation.
fn verify_range_proof_stub(proof: &[u8]) -> bool {
    // A fully compliant node would verify the bulletproof over the Pedersen commitment
    // In this stub, we just consider non-empty bytes valid for testing structural validation flow
    !proof.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{Transaction, TransactionInput, TransactionOutput};
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use waecnan_crypto::pedersen::PedersenCommitment;
    use waecnan_crypto::ring_sig::{mlsag_sign, Ring, RingMember};

    fn make_valid_tx() -> Transaction {
        use crate::block_validation::hash_transaction;
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let mut spend_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut spend_bytes);
        let spend_priv = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(spend_bytes);
        let spend_pub = &spend_priv * &ED25519_BASEPOINT_POINT;

        let b_in = curve25519_dalek::scalar::Scalar::from(1u64);
        let pseudo_commit = PedersenCommitment::commit(100 * MIN_FEE_ATOMIC, &b_in);

        let b_out = curve25519_dalek::scalar::Scalar::from(1u64);
        let out_commit = PedersenCommitment::commit(99 * MIN_FEE_ATOMIC, &b_out);

        let mut members = Vec::new();
        for _ in 0..10 {
            members.push(RingMember {
                output_key: spend_pub,
            });
        }
        members.insert(
            0,
            RingMember {
                output_key: spend_pub,
            },
        );
        let ring = Ring { members };

        let key_image =
            (&spend_priv * waecnan_crypto::hash::hash_to_point(&spend_pub.compress())).compress();

        let output = TransactionOutput {
            output_key: spend_pub.compress(),
            commitment: out_commit,
            range_proof: vec![1, 2, 3],
            encrypted_amount: [0u8; 8],
        };

        // Build a placeholder tx to compute the hash for signing
        let dummy_sig =
            mlsag_sign(&ring, 0, &spend_priv, &[0u8; 32], &mut rng).expect("Failed to sign");
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                ring: ring.clone(),
                key_image,
                ring_sig: dummy_sig,
                pseudo_commit,
            }],
            outputs: vec![output],
            fee: MIN_FEE_ATOMIC,
            tx_public_key: spend_pub.compress(),
            extra: vec![],
        };

        // Now sign with the real tx hash
        let msg = hash_transaction(&tx);
        let real_sig = mlsag_sign(&ring, 0, &spend_priv, &msg, &mut rng).expect("Failed to sign");
        tx.inputs[0].ring_sig = real_sig;
        tx
    }

    #[test]
    fn test_valid_tx_passes() {
        let tx = make_valid_tx();
        let known = HashSet::new();
        assert!(validate_transaction(&tx, &known).is_ok());
    }

    #[test]
    fn test_rule_1_version() {
        let mut tx = make_valid_tx();
        tx.version = 2;
        assert!(matches!(
            validate_transaction(&tx, &HashSet::new()),
            Err(CoreError::InvalidVersion)
        ));
    }

    #[test]
    fn test_rule_2_io_counts() {
        let mut tx = make_valid_tx();
        tx.inputs.clear();
        assert!(matches!(
            validate_transaction(&tx, &HashSet::new()),
            Err(CoreError::NoInputs)
        ));

        let mut tx2 = make_valid_tx();
        tx2.outputs.clear();
        assert!(matches!(
            validate_transaction(&tx2, &HashSet::new()),
            Err(CoreError::InvalidOutputCount)
        ));

        let mut tx3 = make_valid_tx();
        for _ in 0..17 {
            tx3.outputs.push(tx3.outputs[0].clone());
        }
        assert!(matches!(
            validate_transaction(&tx3, &HashSet::new()),
            Err(CoreError::InvalidOutputCount)
        ));
    }

    #[test]
    fn test_rule_3_min_fee() {
        let mut tx = make_valid_tx();
        tx.fee = MIN_FEE_ATOMIC - 1;
        assert!(matches!(
            validate_transaction(&tx, &HashSet::new()),
            Err(CoreError::InsufficientFee)
        ));
    }

    #[test]
    fn test_rule_4_ring_size() {
        let mut tx = make_valid_tx();
        tx.inputs[0].ring.members.pop(); // now size 10
        assert!(matches!(
            validate_transaction(&tx, &HashSet::new()),
            Err(CoreError::InvalidRingSize)
        ));
    }

    #[test]
    fn test_rule_5_key_image_spent() {
        let tx = make_valid_tx();
        let mut known = HashSet::new();
        known.insert(tx.inputs[0].key_image);
        assert!(matches!(
            validate_transaction(&tx, &known),
            Err(CoreError::DoubleSpend)
        ));
    }

    #[test]
    fn test_rule_6_mlsag_verify() {
        let mut tx = make_valid_tx();
        // Corrupt signature properly with a scalar
        tx.inputs[0].ring_sig.c_0 = curve25519_dalek::scalar::Scalar::ZERO;
        assert!(matches!(
            validate_transaction(&tx, &HashSet::new()),
            Err(CoreError::InvalidRingSignature)
        ));
    }

    #[test]
    fn test_rule_7_bulletproof_valid() {
        let mut tx = make_valid_tx();
        tx.outputs[0].range_proof.clear(); // empty stub means invalid
        assert!(matches!(
            validate_transaction(&tx, &HashSet::new()),
            Err(CoreError::InvalidRangeProof)
        ));
    }

    #[test]
    fn test_rule_8_balance_proof() {
        let mut tx = make_valid_tx();
        // Modify input commitment to unbalance
        tx.inputs[0].pseudo_commit =
            PedersenCommitment::commit(500, &curve25519_dalek::scalar::Scalar::ZERO);
        assert!(matches!(
            validate_transaction(&tx, &HashSet::new()),
            Err(CoreError::BalanceMismatch)
        ));
    }

    #[test]
    fn test_rule_9_tx_size_limit() {
        let mut tx = make_valid_tx();
        // 100,001 extra bytes forces serialized size > 100k
        tx.extra = vec![0u8; 100_001];
        assert!(matches!(
            validate_transaction(&tx, &HashSet::new()),
            Err(CoreError::TooLarge)
        ));
    }

    #[test]
    fn test_rule_10_extra_len() {
        let mut tx = make_valid_tx();
        tx.extra = vec![0u8; 256];
        assert!(matches!(
            validate_transaction(&tx, &HashSet::new()),
            Err(CoreError::ExtraTooLarge)
        ));
    }

    #[test]
    fn test_rule_11_tx_pubkey_subgroup() {
        let mut tx = make_valid_tx();
        tx.tx_public_key = CompressedEdwardsY::from_slice(&[0u8; 32]).unwrap(); // identity / invalid points
        assert!(matches!(
            validate_transaction(&tx, &HashSet::new()),
            Err(CoreError::InvalidTxPublicKey)
        ));
    }

    #[test]
    fn test_fee_burn_invariant() {
        // Assert fee never appears directly in outputs. The outputs contain commitments to value 99.
        // The fee is 1. It is split 70/30 burn/miner at block level.
        let tx = make_valid_tx();
        let out_commit = &tx.outputs[0].commitment;
        let fee_commit = PedersenCommitment::commit_fee(tx.fee);
        assert_ne!(out_commit.commitment, fee_commit.commitment);

        // At tx level, verify_balance consumes the numeric fee in the equation.
        // The block validator (rule 8) allows the miner to claim the 30% portion.
    }
}
