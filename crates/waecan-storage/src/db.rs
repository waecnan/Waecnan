use curve25519_dalek::edwards::CompressedEdwardsY;
use rocksdb::{ColumnFamily, Options, WriteBatch, DB};
use waecan_core::block::Block;

use crate::error::StorageError;
use crate::record::OutputRecord;

pub const CF_BLOCKS: &str = "blocks";
pub const CF_HEADERS: &str = "headers";
pub const CF_UTXO: &str = "utxo";
pub const CF_KEY_IMAGES: &str = "key_images";
pub const CF_TX_INDEX: &str = "tx_index";
pub const CF_CHAIN_META: &str = "chain_meta";
pub const CF_BURN_LOG: &str = "burn_log";

pub const ALL_CFS: &[&str] = &[
    CF_BLOCKS,
    CF_HEADERS,
    CF_UTXO,
    CF_KEY_IMAGES,
    CF_TX_INDEX,
    CF_CHAIN_META,
    CF_BURN_LOG,
];

pub struct WaecanDB {
    pub db: DB,
}

impl WaecanDB {
    pub fn open(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = DB::open_cf(&opts, path, ALL_CFS)?;
        Ok(Self { db })
    }

    /// Store a block and update the utxo set atomically.
    pub fn commit_block(
        &self,
        block: &Block,
        new_outputs: &[OutputRecord],
        spent_keys: &[CompressedEdwardsY],
        key_images: &[CompressedEdwardsY],
    ) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();

        let block_cf = self.cf(CF_BLOCKS)?;
        let utxo_cf = self.cf(CF_UTXO)?;
        let key_images_cf = self.cf(CF_KEY_IMAGES)?;
        let meta_cf = self.cf(CF_CHAIN_META)?;

        // 1. Store block header bytes (keyed by keccak256 hash)
        let header_bytes = block.header.serialize();
        let hash_id = waecan_crypto::hash::keccak256(&header_bytes);
        batch.put_cf(block_cf, hash_id, header_bytes);

        // 2. Update UTXO set: add new outputs
        for out in new_outputs {
            let serialized = out.serialize();
            batch.put_cf(utxo_cf, out.output_key.as_bytes(), serialized);
        }

        // 3. Update UTXO set: remove spent outputs
        for key in spent_keys {
            let key_bytes: &[u8; 32] = key.as_bytes();
            batch.delete_cf(utxo_cf, key_bytes);
        }

        // 4. Record key images (double-spend prevention)
        for img in key_images {
            let img_bytes: &[u8; 32] = img.as_bytes();
            batch.put_cf(key_images_cf, img_bytes, block.header.height.to_le_bytes());
        }

        // 5. Update chain tip
        batch.put_cf(meta_cf, b"tip_hash", hash_id);
        batch.put_cf(meta_cf, b"tip_height", block.header.height.to_le_bytes());

        self.db.write(batch)?;
        Ok(())
    }

    /// Process a chain reorganization by disconnecting a block.
    pub fn block_disconnect(
        &self,
        _block: &Block,
        removed_outputs: &[CompressedEdwardsY],
        restored_outputs: &[OutputRecord],
        removed_key_images: &[CompressedEdwardsY],
        new_tip_hash: &[u8; 32],
        new_tip_height: u64,
    ) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();

        let utxo_cf = self.cf(CF_UTXO)?;
        let key_images_cf = self.cf(CF_KEY_IMAGES)?;
        let meta_cf = self.cf(CF_CHAIN_META)?;

        // Reverse of commit:
        // 1. Remove new outputs created by this block
        for key in removed_outputs {
            let key_bytes: &[u8; 32] = key.as_bytes();
            batch.delete_cf(utxo_cf, key_bytes);
        }

        // 2. Restore outputs that were spent in this block
        for out in restored_outputs {
            let serialized = out.serialize();
            batch.put_cf(utxo_cf, out.output_key.as_bytes(), serialized);
        }

        // 3. Remove key images this block added
        for img in removed_key_images {
            let img_bytes: &[u8; 32] = img.as_bytes();
            batch.delete_cf(key_images_cf, img_bytes);
        }

        // 4. Update the chain tip to the previous block's height/hash
        batch.put_cf(meta_cf, b"tip_hash", new_tip_hash);
        batch.put_cf(meta_cf, b"tip_height", new_tip_height.to_le_bytes());

        self.db.write(batch)?;
        Ok(())
    }

    pub fn cf(&self, name: &'static str) -> Result<&ColumnFamily, StorageError> {
        self.db
            .cf_handle(name)
            .ok_or(StorageError::MissingColumnFamily(name))
    }
}
