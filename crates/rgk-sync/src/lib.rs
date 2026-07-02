#![allow(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]
//! # rgk-sync
//!
//! Reusable chain-scanning service glue.
//!
//! `rgk-kaspa` owns live node access, and `rgk-indexer` owns durable RGK state.
//! This crate joins the two without moving either responsibility: it loads a
//! persisted scan cursor, asks a scanner backend for added virtual-chain
//! blocks, and commits the advanced cursor only after a successful scan.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use rgk_core::{Bytes32, KaspaChainId, KaspaOutpoint};
use rgk_indexer::{
    IndexerError, ObservedSpendRecord, ObservedSpendStore, RebuildSource, RebuildSpendEvidence,
    ScanCursor, ScanCursorStore, DEFAULT_SCAN_CURSOR,
};
use rgk_kaspa::KaspaChainBackend;
#[cfg(test)]
use rgk_kaspa::KaspaScriptPublicKey;
use thiserror::Error;

/// A scanner batch returned by a chain backend.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScanBatch {
    pub removed_chain_block_hashes: Vec<Bytes32>,
    pub added_chain_block_hashes: Vec<Bytes32>,
    pub last_added_daa_score: Option<u64>,
    pub observed_spends: usize,
    pub observed_spend_records: Vec<ObservedSpendRecord>,
}

impl ScanBatch {
    pub fn empty() -> Self {
        Self {
            removed_chain_block_hashes: Vec::new(),
            added_chain_block_hashes: Vec::new(),
            last_added_daa_score: None,
            observed_spends: 0,
            observed_spend_records: Vec::new(),
        }
    }
}

/// Minimal chain-scanner contract used by [`ScanService`].
pub trait ScanBackend {
    fn current_scan_cursor(&self, chain_id: KaspaChainId) -> Result<ScanCursor, SyncError>;

    fn scan_from_cursor(
        &self,
        cursor: &ScanCursor,
        min_confirmation_count: Option<u64>,
    ) -> Result<ScanBatch, SyncError>;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScanServiceConfig {
    pub cursor_name: String,
    pub chain_id: KaspaChainId,
    pub min_confirmation_count: Option<u64>,
}

impl ScanServiceConfig {
    pub fn new(chain_id: KaspaChainId) -> Self {
        Self {
            cursor_name: DEFAULT_SCAN_CURSOR.to_string(),
            chain_id,
            min_confirmation_count: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScanTick {
    pub initialised_cursor: bool,
    pub start_cursor: ScanCursor,
    pub end_cursor: ScanCursor,
    pub added_chain_blocks: usize,
    pub observed_spends: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScanRunSummary {
    pub ticks: u64,
    pub initialised_cursor: bool,
    pub added_chain_blocks: usize,
    pub observed_spends: usize,
    pub end_cursor: Option<ScanCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum SyncError {
    #[error("scan cursor is for {actual:?}, expected {expected:?}")]
    CursorChainMismatch {
        expected: KaspaChainId,
        actual: KaspaChainId,
    },
    #[error("scan reorg detected: {} removed chain block(s)", removed_chain_block_hashes.len())]
    Reorg {
        removed_chain_block_hashes: Vec<Bytes32>,
    },
    #[error("scan batch added blocks but did not report a DAA score")]
    MissingAddedDaaScore,
    #[error("scan batch reported {observed_spends} observed spend(s) but supplied {records} durable record(s)")]
    ObservedSpendRecordMismatch {
        observed_spends: usize,
        records: usize,
    },
    #[error("indexer cursor storage error: {0}")]
    Indexer(#[from] IndexerError),
    #[error("chain scan error: {0}")]
    Chain(String),
}

/// Restart-safe scanner driver.
pub struct ScanService<'a, B: ScanBackend, C: ScanCursorStore + ObservedSpendStore> {
    backend: &'a B,
    cursor_store: &'a mut C,
    config: ScanServiceConfig,
}

impl<'a, B: ScanBackend, C: ScanCursorStore + ObservedSpendStore> ScanService<'a, B, C> {
    pub fn new(backend: &'a B, cursor_store: &'a mut C, config: ScanServiceConfig) -> Self {
        Self {
            backend,
            cursor_store,
            config,
        }
    }

    pub fn tick(&mut self) -> Result<ScanTick, SyncError> {
        let Some(start_cursor) = self
            .cursor_store
            .load_scan_cursor(&self.config.cursor_name)?
        else {
            let cursor = self.backend.current_scan_cursor(self.config.chain_id)?;
            self.cursor_store
                .store_scan_cursor(&self.config.cursor_name, cursor.clone())?;
            return Ok(ScanTick {
                initialised_cursor: true,
                start_cursor: cursor.clone(),
                end_cursor: cursor,
                added_chain_blocks: 0,
                observed_spends: 0,
            });
        };

        if start_cursor.chain_id != self.config.chain_id {
            return Err(SyncError::CursorChainMismatch {
                expected: self.config.chain_id,
                actual: start_cursor.chain_id,
            });
        }

        let batch = self
            .backend
            .scan_from_cursor(&start_cursor, self.config.min_confirmation_count)?;
        if !batch.removed_chain_block_hashes.is_empty() {
            return Err(SyncError::Reorg {
                removed_chain_block_hashes: batch.removed_chain_block_hashes,
            });
        }
        if batch.observed_spends != batch.observed_spend_records.len() {
            return Err(SyncError::ObservedSpendRecordMismatch {
                observed_spends: batch.observed_spends,
                records: batch.observed_spend_records.len(),
            });
        }

        let end_cursor = if let Some(last_hash) = batch.added_chain_block_hashes.last().copied() {
            ScanCursor {
                chain_id: start_cursor.chain_id,
                block_hash: last_hash,
                daa_score: batch
                    .last_added_daa_score
                    .ok_or(SyncError::MissingAddedDaaScore)?,
            }
        } else {
            start_cursor.clone()
        };

        for record in batch.observed_spend_records {
            self.cursor_store.record_observed_spend(record)?;
        }

        if end_cursor != start_cursor {
            self.cursor_store
                .store_scan_cursor(&self.config.cursor_name, end_cursor.clone())?;
        }

        Ok(ScanTick {
            initialised_cursor: false,
            start_cursor,
            end_cursor,
            added_chain_blocks: batch.added_chain_block_hashes.len(),
            observed_spends: batch.observed_spends,
        })
    }

    /// Run ticks until `max_idle_ticks` consecutive ticks observe no new blocks.
    ///
    /// This is deterministic and testable; production daemons can call it in a
    /// supervising loop or call [`Self::tick`] directly around their own sleep,
    /// logging, and shutdown policy.
    pub fn run_until_idle(&mut self, max_idle_ticks: u32) -> Result<ScanRunSummary, SyncError> {
        let mut summary = ScanRunSummary {
            ticks: 0,
            initialised_cursor: false,
            added_chain_blocks: 0,
            observed_spends: 0,
            end_cursor: None,
        };
        let mut idle_ticks = 0u32;

        loop {
            let tick = self.tick()?;
            summary.ticks += 1;
            summary.initialised_cursor |= tick.initialised_cursor;
            summary.added_chain_blocks += tick.added_chain_blocks;
            summary.observed_spends += tick.observed_spends;
            summary.end_cursor = Some(tick.end_cursor.clone());

            if tick.added_chain_blocks == 0 && !tick.initialised_cursor {
                idle_ticks = idle_ticks.saturating_add(1);
            } else {
                idle_ticks = 0;
            }
            if idle_ticks >= max_idle_ticks {
                break;
            }
        }

        Ok(summary)
    }
}

/// Source that exposes any [`KaspaChainBackend`] as indexer rebuild evidence.
///
/// The source reads only already-observed spend facts. It does not claim to
/// discover arbitrary historical transitions; callers still provide the
/// expected RGK rebuild plan.
pub struct KaspaRebuildSource<'a, B: KaspaChainBackend + ?Sized> {
    backend: &'a B,
}

impl<'a, B: KaspaChainBackend + ?Sized> KaspaRebuildSource<'a, B> {
    pub fn new(backend: &'a B) -> Self {
        Self { backend }
    }
}

impl<B: KaspaChainBackend + ?Sized> RebuildSource for KaspaRebuildSource<'_, B> {
    fn chain_id(&self) -> Result<KaspaChainId, IndexerError> {
        self.backend
            .network_id()
            .map_err(|e| IndexerError::RebuildSource(e.to_string()))
    }

    fn spend_evidence(
        &self,
        spent: KaspaOutpoint,
    ) -> Result<Option<RebuildSpendEvidence>, IndexerError> {
        if let Some(spending) = self
            .backend
            .get_utxo(spent)
            .map_err(|e| IndexerError::RebuildSource(e.to_string()))?
            .and_then(|utxo| utxo.spending)
        {
            let confirmation_depth = self
                .backend
                .confirmation_depth(spending.txid)
                .map_err(|e| IndexerError::RebuildSource(e.to_string()))?;
            return Ok(Some(RebuildSpendEvidence {
                spending_txid: spending.txid,
                block_daa_score: spending.block_daa_score,
                confirmation_depth,
            }));
        }

        let Some(tx) = self
            .backend
            .get_spending_transaction(spent)
            .map_err(|e| IndexerError::RebuildSource(e.to_string()))?
        else {
            return Ok(None);
        };
        let confirmation_depth = self
            .backend
            .confirmation_depth(tx.txid)
            .map_err(|e| IndexerError::RebuildSource(e.to_string()))?;
        Ok(Some(RebuildSpendEvidence {
            spending_txid: tx.txid,
            block_daa_score: None,
            confirmation_depth,
        }))
    }
}

#[cfg(feature = "wrpc")]
impl ScanBackend for rgk_kaspa::WrpcBackend {
    fn current_scan_cursor(&self, chain_id: KaspaChainId) -> Result<ScanCursor, SyncError> {
        let tip = self
            .current_tip()
            .map_err(|e| SyncError::Chain(e.to_string()))?;
        Ok(ScanCursor {
            chain_id,
            block_hash: tip.hash,
            daa_score: tip.daa_score,
        })
    }

    fn scan_from_cursor(
        &self,
        cursor: &ScanCursor,
        min_confirmation_count: Option<u64>,
    ) -> Result<ScanBatch, SyncError> {
        let scan = self
            .scan_virtual_chain_from_block(cursor.block_hash, min_confirmation_count)
            .map_err(|e| SyncError::Chain(e.to_string()))?;
        Ok(ScanBatch {
            removed_chain_block_hashes: scan.removed_chain_block_hashes,
            added_chain_block_hashes: scan.added_chain_block_hashes,
            last_added_daa_score: scan.last_added_daa_score,
            observed_spends: scan.observed_spends,
            observed_spend_records: scan
                .observed_spend_records
                .into_iter()
                .map(|spend| ObservedSpendRecord {
                    spent: spend.spent,
                    spending_txid: spend.info.txid,
                    input_index: spend.info.input_index,
                    block_daa_score: spend.info.block_daa_score,
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use rgk_core::{KaspaChainId, KASPA_LOCAL_TOCCATA};
    use rgk_indexer::InMemoryIndexer;
    use rgk_kaspa::{FixtureBackend, KaspaTxSummary, KaspaUtxo};

    #[derive(Default)]
    struct FixtureScanBackend {
        current: Option<ScanCursor>,
        batches: VecDeque<ScanBatch>,
    }

    impl ScanBackend for FixtureScanBackend {
        fn current_scan_cursor(&self, chain_id: KaspaChainId) -> Result<ScanCursor, SyncError> {
            let mut cursor = self.current.clone().expect("fixture current cursor");
            cursor.chain_id = chain_id;
            Ok(cursor)
        }

        fn scan_from_cursor(
            &self,
            _cursor: &ScanCursor,
            _min_confirmation_count: Option<u64>,
        ) -> Result<ScanBatch, SyncError> {
            self.batches
                .front()
                .cloned()
                .ok_or_else(|| SyncError::Chain("no fixture batch".into()))
        }
    }

    struct MutatingFixtureScanBackend {
        current: ScanCursor,
        batches: core::cell::RefCell<VecDeque<ScanBatch>>,
    }

    impl ScanBackend for MutatingFixtureScanBackend {
        fn current_scan_cursor(&self, chain_id: KaspaChainId) -> Result<ScanCursor, SyncError> {
            let mut cursor = self.current.clone();
            cursor.chain_id = chain_id;
            Ok(cursor)
        }

        fn scan_from_cursor(
            &self,
            _cursor: &ScanCursor,
            _min_confirmation_count: Option<u64>,
        ) -> Result<ScanBatch, SyncError> {
            Ok(self
                .batches
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(ScanBatch::empty))
        }
    }

    fn cursor(byte: u8, daa_score: u64) -> ScanCursor {
        ScanCursor {
            chain_id: KASPA_LOCAL_TOCCATA,
            block_hash: [byte; 32],
            daa_score,
        }
    }

    fn observed_spend(byte: u8, input_index: u32, daa_score: u64) -> ObservedSpendRecord {
        ObservedSpendRecord {
            spent: KaspaOutpoint {
                transaction_id: [byte; 32],
                index: input_index,
            },
            spending_txid: [byte.saturating_add(10); 32],
            input_index,
            block_daa_score: Some(daa_score),
        }
    }

    #[test]
    fn first_tick_initialises_missing_cursor() {
        let backend = FixtureScanBackend {
            current: Some(cursor(1, 10)),
            batches: VecDeque::new(),
        };
        let mut indexer = InMemoryIndexer::new();
        let mut service = ScanService::new(
            &backend,
            &mut indexer,
            ScanServiceConfig::new(KASPA_LOCAL_TOCCATA),
        );

        let tick = service.tick().expect("tick");
        assert!(tick.initialised_cursor);
        assert_eq!(tick.end_cursor, cursor(1, 10));
        assert_eq!(
            indexer
                .load_scan_cursor(DEFAULT_SCAN_CURSOR)
                .expect("load cursor"),
            Some(cursor(1, 10))
        );
    }

    #[test]
    fn tick_advances_cursor_after_added_blocks() {
        let mut indexer = InMemoryIndexer::new();
        indexer
            .store_scan_cursor(DEFAULT_SCAN_CURSOR, cursor(1, 10))
            .expect("store cursor");
        let mut backend = FixtureScanBackend {
            current: None,
            batches: VecDeque::new(),
        };
        backend.batches.push_back(ScanBatch {
            removed_chain_block_hashes: Vec::new(),
            added_chain_block_hashes: vec![[2u8; 32], [3u8; 32]],
            last_added_daa_score: Some(12),
            observed_spends: 2,
            observed_spend_records: vec![observed_spend(4, 0, 11), observed_spend(5, 1, 12)],
        });
        let mut service = ScanService::new(
            &backend,
            &mut indexer,
            ScanServiceConfig::new(KASPA_LOCAL_TOCCATA),
        );

        let tick = service.tick().expect("tick");
        assert!(!tick.initialised_cursor);
        assert_eq!(tick.added_chain_blocks, 2);
        assert_eq!(tick.observed_spends, 2);
        assert_eq!(tick.end_cursor, cursor(3, 12));
        assert_eq!(
            indexer
                .load_scan_cursor(DEFAULT_SCAN_CURSOR)
                .expect("load cursor"),
            Some(cursor(3, 12))
        );
        assert_eq!(indexer.observed_spend_count().expect("spend count"), 2);
        assert_eq!(
            indexer
                .observed_spend(observed_spend(4, 0, 11).spent)
                .expect("observed spend"),
            Some(observed_spend(4, 0, 11))
        );
    }

    #[test]
    fn tick_rejects_removed_chain_blocks() {
        let mut indexer = InMemoryIndexer::new();
        indexer
            .store_scan_cursor(DEFAULT_SCAN_CURSOR, cursor(1, 10))
            .expect("store cursor");
        let mut backend = FixtureScanBackend {
            current: None,
            batches: VecDeque::new(),
        };
        backend.batches.push_back(ScanBatch {
            removed_chain_block_hashes: vec![[9u8; 32]],
            added_chain_block_hashes: Vec::new(),
            last_added_daa_score: None,
            observed_spends: 0,
            observed_spend_records: Vec::new(),
        });
        let mut service = ScanService::new(
            &backend,
            &mut indexer,
            ScanServiceConfig::new(KASPA_LOCAL_TOCCATA),
        );

        let err = service.tick().expect_err("reorg expected");
        assert!(matches!(
            err,
            SyncError::Reorg {
                removed_chain_block_hashes
            } if removed_chain_block_hashes == vec![[9u8; 32]]
        ));
        assert_eq!(
            indexer
                .load_scan_cursor(DEFAULT_SCAN_CURSOR)
                .expect("load cursor"),
            Some(cursor(1, 10))
        );
    }

    #[test]
    fn tick_rejects_count_only_observed_spends_before_cursor_advance() {
        let mut indexer = InMemoryIndexer::new();
        indexer
            .store_scan_cursor(DEFAULT_SCAN_CURSOR, cursor(1, 10))
            .expect("store cursor");
        let mut backend = FixtureScanBackend {
            current: None,
            batches: VecDeque::new(),
        };
        backend.batches.push_back(ScanBatch {
            removed_chain_block_hashes: Vec::new(),
            added_chain_block_hashes: vec![[2u8; 32]],
            last_added_daa_score: Some(11),
            observed_spends: 1,
            observed_spend_records: Vec::new(),
        });
        let mut service = ScanService::new(
            &backend,
            &mut indexer,
            ScanServiceConfig::new(KASPA_LOCAL_TOCCATA),
        );

        let err = service.tick().expect_err("record mismatch expected");

        assert!(matches!(
            err,
            SyncError::ObservedSpendRecordMismatch {
                observed_spends: 1,
                records: 0,
            }
        ));
        assert_eq!(
            indexer
                .load_scan_cursor(DEFAULT_SCAN_CURSOR)
                .expect("load cursor"),
            Some(cursor(1, 10))
        );
        assert_eq!(indexer.observed_spend_count().expect("spend count"), 0);
    }

    #[test]
    fn tick_rejects_cursor_chain_mismatch() {
        let mut indexer = InMemoryIndexer::new();
        indexer
            .store_scan_cursor(
                DEFAULT_SCAN_CURSOR,
                ScanCursor {
                    chain_id: KaspaChainId::KaspaMainnet,
                    block_hash: [1u8; 32],
                    daa_score: 10,
                },
            )
            .expect("store cursor");
        let backend = FixtureScanBackend::default();
        let mut service = ScanService::new(
            &backend,
            &mut indexer,
            ScanServiceConfig::new(KASPA_LOCAL_TOCCATA),
        );

        let err = service.tick().expect_err("mismatch expected");
        assert!(matches!(err, SyncError::CursorChainMismatch { .. }));
    }

    #[test]
    fn run_until_idle_accumulates_batches() {
        let mut indexer = InMemoryIndexer::new();
        let batches = VecDeque::from([
            ScanBatch {
                removed_chain_block_hashes: Vec::new(),
                added_chain_block_hashes: vec![[2u8; 32]],
                last_added_daa_score: Some(11),
                observed_spends: 1,
                observed_spend_records: vec![observed_spend(6, 0, 11)],
            },
            ScanBatch::empty(),
        ]);
        let backend = MutatingFixtureScanBackend {
            current: cursor(1, 10),
            batches: core::cell::RefCell::new(batches),
        };
        let mut service = ScanService::new(
            &backend,
            &mut indexer,
            ScanServiceConfig::new(KASPA_LOCAL_TOCCATA),
        );

        let summary = service.run_until_idle(1).expect("run");
        assert_eq!(summary.ticks, 3);
        assert!(summary.initialised_cursor);
        assert_eq!(summary.added_chain_blocks, 1);
        assert_eq!(summary.observed_spends, 1);
        assert_eq!(summary.end_cursor, Some(cursor(2, 11)));
    }

    #[test]
    fn kaspa_rebuild_source_reads_fixture_spend_evidence() {
        let spent = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        let txid = [9u8; 32];
        let mut backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        backend.add_utxo_at(
            10,
            KaspaUtxo::from_script_public_key(
                spent,
                1_000,
                KaspaScriptPublicKey::new(Vec::new()).unwrap(),
                Some(10),
                None,
            ),
        );
        backend.submit(KaspaTxSummary::new(txid, 42, Vec::new()));
        backend.spend_at(spent, 11, txid, 0);

        let source = KaspaRebuildSource::new(&backend);
        let evidence = source
            .spend_evidence(spent)
            .expect("source query")
            .expect("spend evidence");

        assert_eq!(source.chain_id().expect("chain id"), KASPA_LOCAL_TOCCATA);
        assert_eq!(evidence.spending_txid, txid);
        assert_eq!(evidence.block_daa_score, Some(11));
        assert_eq!(evidence.confirmation_depth, Some(1));
    }
}
