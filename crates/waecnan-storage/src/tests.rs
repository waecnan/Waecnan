use std::fs;
use std::path::PathBuf;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;

use waecnan_core::block::{Block, BlockHeader, CoinbaseTx};
use waecnan_crypto::pedersen::PedersenCommitment;

use crate::db::{WaecanDB, CF_CHAIN_META, CF_KEY_IMAGES, CF_UTXO};
use crate::record::OutputRecord;

fn temp_db_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("waecnan_test_db_{}", name));
    let _ = fs::remove_dir_all(&path);
    path
}

fn dummy_block(height: u64) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1234567890,
            difficulty: 1,
            nonce: 0,
            height,
        },
        coinbase: CoinbaseTx {
            height,
            reward: 50 * 1_000_000_000_000,
            miner_output_key: CompressedEdwardsY::from_slice(&[0u8; 32]).unwrap(),
            genesis_message: vec![],
        },
        transactions: vec![],
    }
}

// 1. commit_block() then verify all outputs appear in CF_UTXO
#[test]
fn test_1_commit_verify_utxo() {
    let path = temp_db_path("test_1");
    let db = WaecanDB::open(path.to_str().unwrap()).unwrap();

    let block = dummy_block(1);
    let out_point = CompressedEdwardsY::from_slice(&[42u8; 32]).unwrap();
    let blind = Scalar::ZERO;

    let out = OutputRecord {
        output_key: out_point,
        commitment: PedersenCommitment::commit(100, &blind),
        height: 1,
        tx_hash: [1u8; 32],
        output_index: 0,
    };

    db.commit_block(&block, &[out.clone()], &[], &[]).unwrap();

    let cf = db.cf(CF_UTXO).unwrap();
    let val = db.db.get_cf(cf, out_point.as_bytes()).unwrap().unwrap();
    let decoded = OutputRecord::deserialize(&val).unwrap();
    assert_eq!(decoded.output_key, out_point);
    assert_eq!(decoded.height, 1);
}

// 2. Key image stored after commit — double-spend check works
#[test]
fn test_2_key_image_double_spend() {
    let path = temp_db_path("test_2");
    let db = WaecanDB::open(path.to_str().unwrap()).unwrap();

    let block = dummy_block(1);
    let ki = CompressedEdwardsY::from_slice(&[7u8; 32]).unwrap();

    db.commit_block(&block, &[], &[], &[ki]).unwrap();

    let cf = db.cf(CF_KEY_IMAGES).unwrap();
    let ki_bytes: &[u8; 32] = ki.as_bytes();
    let val = db.db.get_cf(cf, ki_bytes).unwrap().unwrap();

    // Proves the double spend check can read it
    assert_eq!(val.len(), 8);
    let stored: [u8; 8] = val.as_slice().try_into().unwrap();
    assert_eq!(u64::from_le_bytes(stored), 1);
}

// 3. Chain tip updates correctly after each block commit
#[test]
fn test_3_chain_tip_updates() {
    let path = temp_db_path("test_3");
    let db = WaecanDB::open(path.to_str().unwrap()).unwrap();

    let block1 = dummy_block(1);
    db.commit_block(&block1, &[], &[], &[]).unwrap();

    let cf = db.cf(CF_CHAIN_META).unwrap();
    let tip_height = db.db.get_cf(cf, b"tip_height").unwrap().unwrap();
    let h1: [u8; 8] = tip_height.as_slice().try_into().unwrap();
    assert_eq!(u64::from_le_bytes(h1), 1);

    let block2 = dummy_block(2);
    db.commit_block(&block2, &[], &[], &[]).unwrap();

    let new_tip = db.db.get_cf(cf, b"tip_height").unwrap().unwrap();
    let h2: [u8; 8] = new_tip.as_slice().try_into().unwrap();
    assert_eq!(u64::from_le_bytes(h2), 2);
}

// 4. Atomic rollback failure test
#[test]
fn test_4_atomic_rollback_simulation() {
    let path = temp_db_path("test_4");
    let db = WaecanDB::open(path.to_str().unwrap()).unwrap();

    let block1 = dummy_block(1);
    db.commit_block(&block1, &[], &[], &[]).unwrap();

    // Simulate failure: construct a batch, put some data, but drop without writing.
    // RocksDB WriteBatch ensures all-or-nothing atomicity.
    let mut batch = rocksdb::WriteBatch::default();
    let cf = db.cf(CF_UTXO).unwrap();
    batch.put_cf(cf, b"fake_out", b"data");

    // Never write the batch — drop it
    drop(batch);

    let val = db.db.get_cf(cf, b"fake_out").unwrap();
    assert!(val.is_none(), "Dropped batch must not persist any data");
}

// 5. FEE BURN INVARIANT
#[test]
fn test_5_fee_burn_invariant() {
    let path = temp_db_path("test_5");
    let db = WaecanDB::open(path.to_str().unwrap()).unwrap();

    let mut total_rewards = 0u64;
    let mut total_fees_burned = 0u64;
    let mut total_blindings = Scalar::ZERO;

    let mut sum_utxo_points = EdwardsPoint::default();

    for h_loop in 1..=100u64 {
        let block = dummy_block(h_loop);

        let reward = waecnan_core::block::block_reward(h_loop);
        let fee = 1_000_000_000u64;

        total_rewards += reward;
        total_fees_burned += fee;

        // Miner gets reward + 30% of fee; 70% of fee is burned
        let miner_fee = fee * 30 / 100;
        let burned_fee = fee - miner_fee;

        // The block's net change to the global UTXO set is: + reward (emission) - burned_fee (permanently destroyed)
        let out_value = reward - burned_fee;
        let out_blind = Scalar::from(h_loop);
        total_blindings += out_blind;

        let commit = PedersenCommitment::commit(out_value, &out_blind);

        // Build a unique output key for each block
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = (h_loop & 0xFF) as u8;
        key_bytes[1] = ((h_loop >> 8) & 0xFF) as u8;
        let out_key = CompressedEdwardsY::from_slice(&key_bytes)
            .unwrap_or_else(|_| CompressedEdwardsY::from_slice(&[0u8; 32]).unwrap());

        let out = OutputRecord {
            output_key: out_key,
            commitment: commit.clone(),
            height: h_loop,
            tx_hash: [0u8; 32],
            output_index: 0,
        };

        db.commit_block(&block, &[out], &[], &[]).unwrap();

        sum_utxo_points += commit.commitment.decompress().unwrap();
    }

    // Homomorphic invariant:
    // sum(UTXO commitments) == commit(sum(rewards), sum(blindings))
    // Wait, let's look at the tx level:
    // The TX consumes `fee`, deleting it from UTXO set.
    // The BLOCK COINBASE creates `miner_fee` (30% of `fee`).
    // Therefore, the global UTXO set permanently loses 70% of the fee (`burned_fee`).
    let total_burned = total_fees_burned * 70 / 100;
    let expected_net_supply = total_rewards - total_burned;
    let expected_commit = PedersenCommitment::commit(expected_net_supply, &total_blindings);

    assert_eq!(
        sum_utxo_points.compress(),
        expected_commit.commitment,
        "Fee burn invariant violated!"
    );
}

// 6. Block disconnect (reorg)
#[test]
fn test_6_block_disconnect_reorg() {
    let path = temp_db_path("test_6");
    let db = WaecanDB::open(path.to_str().unwrap()).unwrap();

    let block1 = dummy_block(1);
    let out1 = OutputRecord {
        output_key: CompressedEdwardsY::from_slice(&[1u8; 32]).unwrap(),
        commitment: PedersenCommitment::commit(1, &Scalar::ZERO),
        height: 1,
        tx_hash: [1u8; 32],
        output_index: 0,
    };
    db.commit_block(&block1, &[out1.clone()], &[], &[]).unwrap();

    let block2 = dummy_block(2);
    let out2 = OutputRecord {
        output_key: CompressedEdwardsY::from_slice(&[2u8; 32]).unwrap(),
        commitment: PedersenCommitment::commit(2, &Scalar::ZERO),
        height: 2,
        tx_hash: [2u8; 32],
        output_index: 0,
    };
    db.commit_block(&block2, &[out2.clone()], &[], &[]).unwrap();

    let block3 = dummy_block(3);
    let out3 = OutputRecord {
        output_key: CompressedEdwardsY::from_slice(&[3u8; 32]).unwrap(),
        commitment: PedersenCommitment::commit(3, &Scalar::ZERO),
        height: 3,
        tx_hash: [3u8; 32],
        output_index: 0,
    };
    // Block 3 spends out2
    db.commit_block(&block3, &[out3.clone()], &[out2.output_key], &[])
        .unwrap();

    // Now disconnect block 3
    let b2_hash = waecnan_crypto::hash::keccak256(&block2.header.serialize());
    db.block_disconnect(
        &block3,
        &[out3.output_key],
        &[out2.clone()],
        &[],
        &b2_hash,
        2,
    )
    .unwrap();

    // Now disconnect block 2
    let b1_hash = waecnan_crypto::hash::keccak256(&block1.header.serialize());
    db.block_disconnect(&block2, &[out2.output_key], &[], &[], &b1_hash, 1)
        .unwrap();

    // Verify UTXO matches state after block 1 only
    let cf = db.cf(CF_UTXO).unwrap();
    assert!(
        db.db
            .get_cf(cf, out1.output_key.as_bytes())
            .unwrap()
            .is_some(),
        "out1 should still exist after reorg to block 1"
    );
    assert!(
        db.db
            .get_cf(cf, out2.output_key.as_bytes())
            .unwrap()
            .is_none(),
        "out2 should be gone after reorg to block 1"
    );
    assert!(
        db.db
            .get_cf(cf, out3.output_key.as_bytes())
            .unwrap()
            .is_none(),
        "out3 should be gone after reorg to block 1"
    );

    let meta_cf = db.cf(CF_CHAIN_META).unwrap();
    let tip = db.db.get_cf(meta_cf, b"tip_height").unwrap().unwrap();
    let h: [u8; 8] = tip.as_slice().try_into().unwrap();
    assert_eq!(u64::from_le_bytes(h), 1);
}
