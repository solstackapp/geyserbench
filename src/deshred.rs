use std::{collections::HashSet, hash::Hash, sync::atomic::{AtomicU64, Ordering}};

use itertools::Itertools;
use tracing::{debug, warn};
use solana_ledger::{
    blockstore::MAX_DATA_SHREDS_PER_SLOT,
    shred::{
        merkle::{Shred, ShredCode},
        ReedSolomonCache, ShredType, Shredder,
    },
};
use solana_perf::packet::PacketBatch;
use solana_sdk::clock::{Slot, MAX_PROCESSING_AGE};

// metrics for deshred ops
pub struct DeshredMetrics {
    pub recovered_count: AtomicU64,
    pub entry_count: AtomicU64,
    pub txn_count: AtomicU64,
    pub unknown_start_position_count: AtomicU64,
    pub fec_recovery_error_count: AtomicU64,
    pub bincode_deserialize_error_count: AtomicU64,
    pub unknown_start_position_error_count: AtomicU64,
}

impl Default for DeshredMetrics {
    fn default() -> Self {
        Self {
            recovered_count: AtomicU64::new(0),
            entry_count: AtomicU64::new(0),
            txn_count: AtomicU64::new(0),
            unknown_start_position_count: AtomicU64::new(0),
            fec_recovery_error_count: AtomicU64::new(0),
            bincode_deserialize_error_count: AtomicU64::new(0),
            unknown_start_position_error_count: AtomicU64::new(0),
        }
    }
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
enum ShredStatus {
    #[default]
    Unknown,
    /// Shred that is **not** marked as DATA_COMPLETE_SHRED
    NotDataComplete,
    /// Shred that is marked as DATA_COMPLETE_SHRED
    DataComplete,
}

/// Tracks per-slot shred information for data shreds
/// Guaranteed to have MAX_DATA_SHREDS_PER_SLOT entries in each Vec
#[derive(Debug)]
pub struct ShredsStateTracker {
    data_status: Vec<ShredStatus>,
    data_shreds: Vec<Option<Shred>>,
    already_recovered_fec_sets: Vec<bool>,
    already_deshredded: Vec<bool>,
}

impl Default for ShredsStateTracker {
    fn default() -> Self {
        Self {
            data_status: vec![ShredStatus::Unknown; MAX_DATA_SHREDS_PER_SLOT],
            data_shreds: vec![None; MAX_DATA_SHREDS_PER_SLOT],
            already_recovered_fec_sets: vec![false; MAX_DATA_SHREDS_PER_SLOT],
            already_deshredded: vec![false; MAX_DATA_SHREDS_PER_SLOT],
        }
    }
}

const SLOT_LOOKBACK: Slot = 50;

pub fn reconstruct_shreds(
    packet_batch: PacketBatch,
    all_shreds: &mut ahash::HashMap<
        Slot,
        (
            ahash::HashMap<u32 /* fec_set_index */, HashSet<ComparableShred>>,
            ShredsStateTracker,
        ),
    >,
    slot_fec_indexes_to_iterate: &mut Vec<(Slot, u32)>,
    deshredded_entries: &mut Vec<(Slot, Vec<solana_entry::entry::Entry>)>,
    highest_slot_seen: &mut Slot,
    rs_cache: &ReedSolomonCache,
    metrics: &DeshredMetrics,
) -> usize {
    deshredded_entries.clear();
    slot_fec_indexes_to_iterate.clear();

    // ingest all packets
    for packet in packet_batch.iter().filter_map(|p| p.data(..)) {
        // Skip heartbeat/keepalive packets (real shreds are ~1228 bytes)
        if packet.len() < 64 {
            continue;
        }
        match solana_ledger::shred::Shred::new_from_serialized_shred(packet.to_vec())
            .and_then(Shred::try_from)
        {
            Ok(shred) => {
                let slot = shred.common_header().slot;
                let index = shred.index() as usize;
                let fec_set_index = shred.fec_set_index();
                let (all_shreds, state_tracker) = all_shreds.entry(slot).or_default();
                if highest_slot_seen.saturating_sub(SLOT_LOOKBACK) > slot {
                    debug!(
                        "Old shred slot: {slot}, fec_set_index: {fec_set_index}, index: {index}"
                    );
                    continue;
                }
                if state_tracker.already_recovered_fec_sets[fec_set_index as usize]
                    || state_tracker.already_deshredded[index]
                {
                    debug!("Already completed slot: {slot}, fec_set_index: {fec_set_index}, index: {index}");
                    continue;
                }
                let Some(_shred_index) = update_state_tracker(&shred, state_tracker) else {
                    continue;
                };

                all_shreds
                    .entry(fec_set_index)
                    .or_default()
                    .insert(ComparableShred(shred));
                slot_fec_indexes_to_iterate.push((slot, fec_set_index));
                *highest_slot_seen = std::cmp::max(*highest_slot_seen, slot);
            }
            Err(_) => {}
        }
    }
    slot_fec_indexes_to_iterate.sort_unstable();
    slot_fec_indexes_to_iterate.dedup();

    // try recovering by FEC set
    let mut total_recovered_count = 0;
    for (slot, fec_set_index) in slot_fec_indexes_to_iterate.iter() {
        let (all_shreds, state_tracker) = all_shreds.entry(*slot).or_default();
        let shreds = all_shreds.entry(*fec_set_index).or_default();
        let (
            num_expected_data_shreds,
            num_expected_coding_shreds,
            num_data_shreds,
            num_coding_shreds,
        ) = get_data_shred_info(shreds);

        // haven't received last data shred, haven't seen any coding shreds, so wait until more arrive
        let min_shreds_needed_to_recover = num_expected_data_shreds as usize;
        if num_expected_data_shreds == 0
            || shreds.len() < min_shreds_needed_to_recover
            || num_data_shreds == num_expected_data_shreds
        {
            continue;
        }

        // try to recover if we have enough shreds in the FEC set
        let merkle_shreds = shreds
            .iter()
            .sorted_by_key(|s| (u8::MAX - s.shred_type() as u8, s.index()))
            .map(|s| s.0.clone())
            .collect_vec();
        let recovered = match solana_ledger::shred::merkle::recover(merkle_shreds, rs_cache) {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    "Failed to recover shreds for slot {slot} fec_set_index {fec_set_index}. \
                     num_expected_data_shreds: {num_expected_data_shreds}, num_data_shreds: {num_data_shreds} \
                     num_expected_coding_shreds: {num_expected_coding_shreds} num_coding_shreds: {num_coding_shreds} Err: {e}",
                );
                continue;
            }
        };

        let mut fec_set_recovered_count = 0;
        for shred in recovered {
            match shred {
                Ok(shred) => {
                    if update_state_tracker(&shred, state_tracker).is_none() {
                        continue;
                    }
                    total_recovered_count += 1;
                    fec_set_recovered_count += 1;
                }
                Err(e) => warn!(
                    "Failed to recover shred for slot {slot}, fec set: {fec_set_index}. Err: {e}"
                ),
            }
        }

        if fec_set_recovered_count > 0 {
            debug!("recovered slot: {slot}, fec_index: {fec_set_index}, recovered count: {fec_set_recovered_count}");
            state_tracker.already_recovered_fec_sets[*fec_set_index as usize] = true;
            shreds.clear();
        }
    }

    // deshred and bincode deserialize
    for (slot, fec_set_index) in slot_fec_indexes_to_iterate.iter() {
        let (_all_shreds, state_tracker) = all_shreds.entry(*slot).or_default();
        let Some((start_data_complete_idx, end_data_complete_idx, unknown_start)) =
            get_indexes(state_tracker, *fec_set_index as usize)
        else {
            continue;
        };
        if unknown_start {
            metrics
                .unknown_start_position_count
                .fetch_add(1, Ordering::Relaxed);
        }

        let to_deshred =
            &state_tracker.data_shreds[start_data_complete_idx..=end_data_complete_idx];
        let deshredded_payload = match Shredder::deshred(
            to_deshred.iter().map(|s| s.as_ref().unwrap().payload()),
        ) {
            Ok(v) => v,
            Err(e) => {
                warn!("slot {slot} failed to deshred start_data_complete_idx: {start_data_complete_idx}, end_data_complete_idx: {end_data_complete_idx}. Err: {e}");
                metrics
                    .fec_recovery_error_count
                    .fetch_add(1, Ordering::Relaxed);
                if unknown_start {
                    metrics
                        .unknown_start_position_error_count
                        .fetch_add(1, Ordering::Relaxed);
                }
                continue;
            }
        };

        let entries = match bincode::deserialize::<Vec<solana_entry::entry::Entry>>(
            &deshredded_payload,
        ) {
            Ok(entries) => entries,
            Err(e) => {
                debug!(
                    "Failed to deserialize bincode payload of size {} for slot {slot}, \
                     start: {start_data_complete_idx}, end: {end_data_complete_idx}, \
                     unknown_start: {unknown_start}. Err: {e}",
                    deshredded_payload.len()
                );
                metrics
                    .bincode_deserialize_error_count
                    .fetch_add(1, Ordering::Relaxed);
                if unknown_start {
                    metrics
                        .unknown_start_position_error_count
                        .fetch_add(1, Ordering::Relaxed);
                }
                continue;
            }
        };
        metrics
            .entry_count
            .fetch_add(entries.len() as u64, Ordering::Relaxed);
        let txn_count: u64 = entries.iter().map(|e| e.transactions.len() as u64).sum();
        metrics.txn_count.fetch_add(txn_count, Ordering::Relaxed);
        debug!(
            "Decoded slot: {slot} start: {start_data_complete_idx} end: {end_data_complete_idx} entries: {}, txns: {txn_count}",
            entries.len(),
        );

        deshredded_entries.push((*slot, entries));
        to_deshred.iter().for_each(|shred| {
            let Some(shred) = shred.as_ref() else {
                return;
            };
            state_tracker.already_recovered_fec_sets[shred.fec_set_index() as usize] = true;
            state_tracker.already_deshredded[shred.index() as usize] = true;
        })
    }

    // cleanup old slots
    if all_shreds.len() > MAX_PROCESSING_AGE {
        let slot_threshold = highest_slot_seen.saturating_sub(SLOT_LOOKBACK);
        let mut incomplete_count = 0u64;
        all_shreds.retain(|slot, (fec_set_indexes, state_tracker)| {
            if *slot >= slot_threshold {
                return true;
            }
            for (fec_set_index, _shreds) in fec_set_indexes.iter() {
                if !state_tracker.already_recovered_fec_sets[*fec_set_index as usize] {
                    incomplete_count += 1;
                }
            }
            false
        });
        if incomplete_count > 0 {
            warn!("Cleaned up old slots with {incomplete_count} incomplete FEC sets");
        }
    }

    if total_recovered_count > 0 {
        metrics
            .recovered_count
            .fetch_add(total_recovered_count as u64, Ordering::Relaxed);
    }

    total_recovered_count
}

/// Return the inclusive range of shreds that constitute one complete segment
fn get_indexes(
    tracker: &ShredsStateTracker,
    index: usize,
) -> Option<(usize, usize, bool)> {
    if index >= tracker.data_status.len() {
        return None;
    }

    // find the right boundary (first DataComplete >= index)
    let mut end = index;
    while end < tracker.data_status.len() {
        if tracker.already_deshredded[end] {
            return None;
        }
        match &tracker.data_status[end] {
            ShredStatus::Unknown => return None,
            ShredStatus::DataComplete => break,
            ShredStatus::NotDataComplete => end += 1,
        }
    }
    if end == tracker.data_status.len() {
        return None;
    }

    if end == 0 {
        return Some((0, 0, false));
    }
    if index == 0 {
        return Some((0, end, false));
    }

    // find the left boundary (prev DataComplete + 1)
    let mut start = index;
    let mut next = start - 1;
    loop {
        match tracker.data_status[next] {
            ShredStatus::NotDataComplete => {
                if tracker.already_deshredded[next] {
                    return None;
                }
                if next == 0 {
                    return Some((0, end, false));
                }
                start = next;
                next -= 1;
            }
            ShredStatus::DataComplete => return Some((start, end, false)),
            ShredStatus::Unknown => return Some((start, end, true)),
        }
    }
}

/// Upon receiving a new shred, update the state tracker.
/// Returns shred index on new insert, None if already exists.
fn update_state_tracker(shred: &Shred, state_tracker: &mut ShredsStateTracker) -> Option<usize> {
    let index = shred.index() as usize;
    if state_tracker.already_recovered_fec_sets[shred.fec_set_index() as usize] {
        return None;
    }
    if shred.shred_type() == ShredType::Data
        && (state_tracker.data_shreds[index].is_some()
            || !matches!(state_tracker.data_status[index], ShredStatus::Unknown))
    {
        return None;
    }
    if let Shred::ShredData(s) = &shred {
        state_tracker.data_shreds[index] = Some(shred.clone());
        if s.data_complete() || s.last_in_slot() {
            state_tracker.data_status[index] = ShredStatus::DataComplete;
        } else {
            state_tracker.data_status[index] = ShredStatus::NotDataComplete;
        }
    };
    Some(index)
}

/// Check if we can reconstruct (having minimum number of data + coding shreds)
fn get_data_shred_info(
    shreds: &HashSet<ComparableShred>,
) -> (u16, u16, u16, u16) {
    let mut num_expected_data_shreds = 0;
    let mut num_expected_coding_shreds = 0;
    let mut num_data_shreds = 0;
    let mut num_coding_shreds = 0;
    for shred in shreds {
        match &shred.0 {
            Shred::ShredCode(s) => {
                num_coding_shreds += 1;
                num_expected_data_shreds = s.coding_header.num_data_shreds;
                num_expected_coding_shreds = s.coding_header.num_coding_shreds;
            }
            Shred::ShredData(s) => {
                num_data_shreds += 1;
                if num_expected_data_shreds == 0 && (s.data_complete() || s.last_in_slot()) {
                    num_expected_data_shreds =
                        (shred.0.index() - shred.0.fec_set_index()) as u16 + 1;
                }
            }
        }
    }
    (
        num_expected_data_shreds,
        num_expected_coding_shreds,
        num_data_shreds,
        num_coding_shreds,
    )
}

/// Issue: datashred equality comparison is wrong due to data size being smaller than the 1203 bytes allocated
#[derive(Clone, Debug, Eq)]
pub struct ComparableShred(Shred);

impl std::ops::Deref for ComparableShred {
    type Target = Shred;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Hash for ComparableShred {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match &self.0 {
            Shred::ShredCode(s) => {
                s.common_header.hash(state);
                s.coding_header.hash(state);
            }
            Shred::ShredData(s) => {
                s.common_header.hash(state);
                s.data_header.hash(state);
            }
        }
    }
}

impl PartialEq for ComparableShred {
    fn eq(&self, other: &Self) -> bool {
        match &self.0 {
            Shred::ShredCode(s1) => match &other.0 {
                Shred::ShredCode(s2) => {
                    let solana_ledger::shred::ShredVariant::MerkleCode {
                        proof_size,
                        chained: _,
                        resigned,
                    } = s1.common_header.shred_variant
                    else {
                        return false;
                    };

                    let comparison_len =
                        <ShredCode as solana_ledger::shred::traits::Shred>::SIZE_OF_PAYLOAD
                            .saturating_sub(
                                usize::from(proof_size)
                                    * solana_ledger::shred::merkle::SIZE_OF_MERKLE_PROOF_ENTRY
                                    + if resigned {
                                        solana_ledger::shred::SIZE_OF_SIGNATURE
                                    } else {
                                        0
                                    },
                            );

                    s1.coding_header == s2.coding_header
                        && s1.common_header == s2.common_header
                        && s1.payload[..comparison_len] == s2.payload[..comparison_len]
                }
                Shred::ShredData(_) => false,
            },
            Shred::ShredData(s1) => match &other.0 {
                Shred::ShredCode(_) => false,
                Shred::ShredData(s2) => {
                    let Ok(s1_data) = solana_ledger::shred::layout::get_data(self.payload()) else {
                        return false;
                    };
                    let Ok(s2_data) = solana_ledger::shred::layout::get_data(other.payload())
                    else {
                        return false;
                    };
                    s1.data_header == s2.data_header
                        && s1.common_header == s2.common_header
                        && s1_data == s2_data
                }
            },
        }
    }
}
