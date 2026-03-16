pub mod db;
pub mod error;
pub mod record;

pub use db::WaecanDB;
pub use error::StorageError;
pub use record::OutputRecord;

#[cfg(test)]
mod tests;
