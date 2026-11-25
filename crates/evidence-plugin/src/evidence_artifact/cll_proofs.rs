//! The interop profile's Checkpointed Local Log proof items, as a peer sends
//! them (profile §6.2.1 steps 12 and 13): a `cll-inclusion-proof` is
//! `[MMR node index, inclusion path]` and a `cll-consistency-proof` is
//! `[from size, to size, one path per earlier peak, the peaks to the
//! right]`, both in CBOR. Reading one never trusts its sizes or indices
//! beyond the profile's integers.

use cll::mmr::{pos_to_leaf_index, root_from_peaks, verify_inclusion, Hash, InclusionProof};

/// The longest inclusion path an MMR of profile size can have.
const MAX_PATH: usize = 64;

/// The largest MMR node index read from a peer: the profile's integers.
const MAX_NODE_INDEX: u64 = (1 << 53) - 1;

/// A `cll-inclusion-proof` item: `[MMR node index, inclusion path]`.
pub(super) fn inclusion_parts(octets: &[u8]) -> Option<(u64, Vec<Hash>)> {
    let value: ciborium::Value = ciborium::from_reader(octets).ok()?;
    let ciborium::Value::Array(items) = value else {
        return None;
    };
    let [index, path] = items.as_slice() else {
        return None;
    };
    let index = u64::try_from(index.as_integer()?).ok()?;
    if index > MAX_NODE_INDEX {
        return None;
    }
    Some((index, hash_list(path)?))
}

/// The leaf an inclusion proof is for.
pub(crate) fn inclusion_leaf(octets: &[u8]) -> Option<u64> {
    let (index, _) = inclusion_parts(octets)?;
    pos_to_leaf_index(index).ok()
}

/// Whether `proof` proves the leaf `leaf` with entry `entry` in the MMR of
/// `size` nodes whose peaks are `peaks` (profile §6.2.1 step 12). The item's
/// node index must be the leaf's own, and `cll::mmr::verify_inclusion`
/// derives the path's shape from the leaf and `size`, so the path must climb
/// from that node to the one peak that holds it. A leaf cannot be passed off
/// at another position or under another size: a peak that is itself a leaf
/// would otherwise match any position given an empty path.
pub(crate) fn proves(proof: &[u8], leaf: u64, entry: &Hash, size: u64, peaks: &[Hash]) -> bool {
    let Some((index, path)) = inclusion_parts(proof) else {
        return false;
    };
    if cll::mmr::leaf_index_to_pos(leaf).ok() != Some(index) {
        return false;
    }
    let Ok(positions) = cll::mmr::peaks(size) else {
        return false;
    };
    // The peak that holds the leaf: peaks ascend and each holds the nodes
    // after the one before it.
    let Some(k) = positions.iter().position(|&p| p >= index) else {
        return false;
    };
    if positions.len() != peaks.len() {
        return false;
    }
    let hex = |hashes: &[Hash]| hashes.iter().map(hex::encode).collect();
    let item = InclusionProof {
        v: 1,
        kind: "inclusion".into(),
        size,
        leaf_index: leaf,
        witness: hex(&path),
        peaks_left: hex(&peaks[..k]),
        peaks_right: hex(&peaks[k + 1..]),
    };
    verify_inclusion(&root_from_peaks(peaks), size, leaf, entry, &item)
}

/// Whether `proof` (a `cll-consistency-proof` item) proves that the MMR of
/// `to_size` nodes with peaks `to_peaks` extends the one of `from_size` nodes
/// with peaks `from_peaks` (profile §6.2.1 step 13): evidence-request's
/// `check_consistency_proof`, which reads the item as deterministic CBOR and
/// requires the proof's own sizes to be these two.
pub(super) fn consistent(
    from_size: u64,
    from_peaks: &[Hash],
    to_size: u64,
    to_peaks: &[Hash],
    proof: &[u8],
) -> bool {
    evidence_request::cll_material::check_consistency_proof(
        from_size, from_peaks, to_size, to_peaks, proof,
    )
    .is_ok()
}

fn hash_list(value: &ciborium::Value) -> Option<Vec<Hash>> {
    let ciborium::Value::Array(items) = value else {
        return None;
    };
    if items.len() > MAX_PATH {
        return None;
    }
    items
        .iter()
        .map(|item| match item {
            ciborium::Value::Bytes(b) => b.as_slice().try_into().ok(),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence_request_parity::{corpus_ledger, NODE_KEY_SEED};
    use cll::checkpoint::verify_checkpoint_cose_offline;
    use cll::mmr::leaf_hash;
    use evidence_request::cll_material::encode_inclusion_proof;

    /// A leaf that is itself a peak cannot be passed off at another
    /// position: in a three-leaf MMR, leaf 2 is the right peak, and an empty
    /// path from leaf 0's position must not reach it.
    #[test]
    fn an_inclusion_proof_proves_its_leafs_position() {
        use cll::mmr::{add_leaf, peaks, MemoryNodeStore, NodeReader};
        let entries = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let mut nodes = MemoryNodeStore::new();
        for e in &entries {
            add_leaf(&mut nodes, leaf_hash(e)).unwrap();
        }
        let size = nodes.size();
        let peak_hashes: Vec<Hash> = peaks(size)
            .unwrap()
            .iter()
            .map(|&p| nodes.node(p))
            .collect();
        let proof = |leaf: u64| {
            let path = cll::mmr::inclusion_proof(&nodes, leaf, size)
                .unwrap()
                .witness;
            let path: Vec<Hash> = path
                .iter()
                .map(|h| hex::decode(h).unwrap().try_into().unwrap())
                .collect();
            encode_inclusion_proof(leaf, &path).unwrap()
        };
        for (leaf, entry) in entries.iter().enumerate() {
            assert!(
                proves(&proof(leaf as u64), leaf as u64, entry, size, &peak_hashes),
                "{leaf}"
            );
        }
        let forged = encode_inclusion_proof(0, &[]).unwrap();
        assert!(!proves(&forged, 0, &entries[2], size, &peak_hashes));
        assert!(!proves(&proof(2), 2, &entries[2], size, &peak_hashes[..1]));
    }

    /// A consistency proof is read as deterministic CBOR (evidence-request's
    /// check): the proof between 3 and 7 leaves passes, and the same proof
    /// with an integer in a longer form or a trailing octet is refused. The
    /// plugin's own reader accepted both before #368 step 8.
    #[test]
    fn a_consistency_proof_is_read_as_deterministic_cbor() {
        use cll::mmr::{
            add_leaf, consistency_proof, node_count, peaks, MemoryNodeStore, NodeReader,
        };
        use evidence_request::cll_material::encode_consistency_proof;
        let mut nodes = MemoryNodeStore::new();
        for i in 0..7u8 {
            add_leaf(&mut nodes, leaf_hash(&[i; 32])).unwrap();
        }
        let peaks_at = |size: u64| -> Vec<Hash> {
            peaks(size)
                .unwrap()
                .iter()
                .map(|&p| nodes.node(p))
                .collect()
        };
        let (a, b) = (node_count(3), node_count(7));
        let paths: Vec<Vec<Hash>> = consistency_proof(&nodes, a, b)
            .unwrap()
            .witness
            .iter()
            .map(|p| {
                p.iter()
                    .map(|h| hex::decode(h).unwrap().try_into().unwrap())
                    .collect()
            })
            .collect();
        let proof = encode_consistency_proof(a, b, &peaks_at(a), &paths, &peaks_at(b)).unwrap();
        assert!(consistent(a, &peaks_at(a), b, &peaks_at(b), &proof));
        assert!(!consistent(
            a,
            &peaks_at(a),
            node_count(6),
            &peaks_at(b),
            &proof
        ));
        let mut trailing = proof.clone();
        trailing.push(0);
        assert!(!consistent(a, &peaks_at(a), b, &peaks_at(b), &trailing));
        let mut long_form = proof.clone();
        assert!(long_form[1] < 24, "a small size is one byte");
        long_form.splice(1..2, [0x18, proof[1]]);
        assert!(!consistent(a, &peaks_at(a), b, &peaks_at(b), &long_form));
    }

    /// An index that is not a leaf proves nothing, and no hostile item
    /// panics.
    #[test]
    fn a_hostile_proof_is_refused_without_panicking() {
        let entry = [3u8; 32];
        let mut proof = Vec::new();
        ciborium::into_writer(
            &ciborium::Value::Array(vec![
                ciborium::Value::Integer(2.into()),
                ciborium::Value::Array(vec![]),
            ]),
            &mut proof,
        )
        .unwrap();
        assert!(!proves(&proof, 1, &entry, 3, &[leaf_hash(&entry)]));
        assert!(inclusion_parts(b"not cbor").is_none());
        let ledger = corpus_ledger();
        let cps = crate::evidence_request_parity::corpus_checkpoints(
            &ledger,
            &ed25519_dalek::SigningKey::from_bytes(&NODE_KEY_SEED),
        );
        let decoded = |i: usize| {
            verify_checkpoint_cose_offline(&cps[i].statement)
                .decoded
                .unwrap()
        };
        let (a, b) = (decoded(0), decoded(1));
        assert!(!consistent(
            a.mmr_size,
            &a.new_peak_hashes,
            b.mmr_size,
            &b.new_peak_hashes,
            b"\x84\x00"
        ));
    }
}
