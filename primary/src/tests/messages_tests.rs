use super::*;
use crate::primary;
use crate::error::{ConsensusError};
use crypto::generate_keypair;
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use tokio::sync;


//CONSENSUS MESSAGE TESTS
//TODO: Add TC tests.

/*#[tokio::test]
async fn verify_valid_accept_vote() {
    assert!(accept_vote().verify(&committee()).is_ok());
}

#[tokio::test]
async fn verify_accept_vote_unknown_authority() {
    // Create Accept Vote with unknown authority.
    let mut rng = StdRng::from_seed([1; 32]);
    let (unknown_pub, unknown_priv) = generate_keypair(&mut rng);
   
    let accept_vote = AcceptVote::new_from_key(special_header().digest(), 1, 1, unknown_pub, &unknown_priv);

    // Verify the QC.
    match accept_vote.verify(&committee()) {
        Err(ConsensusError::UnknownAuthority(name)) => assert_eq!(name, unknown_pub),
        _ => assert!(false),
    }
}


#[tokio::test]
async fn verify_valid_qc() {
    assert!(qc().verify(&committee()).is_ok());
}

#[tokio::test]
async fn verify_valid_fast_qc() {
    assert!(fast_qc().verify(&committee()).is_ok());
}


#[tokio::test]
async fn verify_qc_authority_reuse() {
    // Modify QC to reuse one authority.
    let mut qc = qc();
    let _ = qc.votes.pop();
    let vote = qc.votes[0].clone();
    qc.votes.push(vote.clone());

    // Verify the QC.
    match qc.verify(&committee()) {
        Err(ConsensusError::AuthorityReuse(name)) => assert_eq!(name, vote.0),
        _ => assert!(false),
    }
}

#[tokio::test]
async fn verify_qc_unknown_authority() {
    let mut qc = qc();

    // Modify QC to add one unknown authority.
    let mut rng = StdRng::from_seed([1; 32]);
    let (unknown, _) = generate_keypair(&mut rng);
    let (_, sig) = qc.votes.pop().unwrap();
    qc.votes.push((unknown, sig));

    // Verify the QC.
    match qc.verify(&committee()) {
        Err(ConsensusError::UnknownAuthority(name)) => assert_eq!(name, unknown),
        _ => assert!(false),
    }
}

#[tokio::test]
async fn verify_qc_insufficient_stake() {
    // Modify QC to remove one authority.
    let mut qc = qc();
    let _ = qc.votes.pop();

    // Verify the QC.
    match qc.verify(&committee()) {
        Err(ConsensusError::QCRequiresQuorum) => assert!(true),
        _ => assert!(false),
    }
}*/

// Bug DA-1 Reproduction: QC Does Not Bind to Proposal Value
//
// The vote hash only includes [slot, view, marker_byte], NOT the proposals.
// proposal_digest() is commented out at messages.rs:128, 194, 246.
// A Byzantine node can reuse a valid ConfirmQC to forge a Commit for
// a different value, violating AgreementSafety.
#[test]
fn test_da1_qc_does_not_bind_to_proposals() {
    use crate::common::keys;
    use crate::common::committee;
    use ed25519_dalek::Digest as _;

    let keys = keys();
    let committee = committee();

    // Two distinct proposal sets representing different values (v1 vs v2).
    let proposals_v1: HashMap<PublicKey, Proposal> = {
        let mut map = HashMap::new();
        map.insert(keys[0].0, Proposal { header_digest: Digest([1u8; 32]), height: 1 });
        map
    };
    let proposals_v2: HashMap<PublicKey, Proposal> = {
        let mut map = HashMap::new();
        map.insert(keys[0].0, Proposal { header_digest: Digest([2u8; 32]), height: 1 });
        map
    };

    // Sanity: the proposals are genuinely different.
    let dig_v1 = proposal_digest(&ConsensusMessage::Commit {
        slot: 1, view: 1, qc: QC { id: Digest::default(), votes: vec![] },
        proposals: proposals_v1.clone(),
    });
    let dig_v2 = proposal_digest(&ConsensusMessage::Commit {
        slot: 1, view: 1, qc: QC { id: Digest::default(), votes: vec![] },
        proposals: proposals_v2.clone(),
    });
    if dig_v1 == dig_v2 {
        std::panic!("Proposals must be different for this test");
    }

    // --- Build a valid ConfirmQC for (slot=1, view=1) via the slow path ---

    // Step 1: Compute prepare_id = hash(slot, view, 0)
    //   This is what verify_commit reconstructs. Note: proposal_digest is NOT included.
    let slot: Slot = 1;
    let view: View = 1;
    let prepare_id = {
        let mut h = Sha512::new();
        h.update(slot.to_le_bytes());
        h.update(view.to_le_bytes());
        h.update((0u8).to_le_bytes());
        Digest(h.finalize().as_slice()[..32].try_into().unwrap())
    };

    // Step 2: Compute confirm_id = hash(slot, view, prepare_id, 1)
    let confirm_id = {
        let mut h = Sha512::new();
        h.update(slot.to_le_bytes());
        h.update(view.to_le_bytes());
        h.update(&prepare_id.0);
        h.update((1u8).to_le_bytes());
        Digest(h.finalize().as_slice()[..32].try_into().unwrap())
    };

    // Step 3: 3-of-4 nodes sign the confirm_id (slow path quorum)
    let votes: Vec<(PublicKey, Signature)> = keys.iter().take(3)
        .map(|(pk, sk)| (*pk, Signature::new(&confirm_id, sk)))
        .collect();

    let confirm_qc = QC { id: confirm_id, votes };

    // --- The attack ---

    // Honest Commit(v1): should pass — this is the legitimate commit.
    let commit_v1 = ConsensusMessage::Commit {
        slot, view,
        qc: confirm_qc.clone(),
        proposals: proposals_v1.clone(),
    };
    if !verify_commit(&commit_v1, &committee) {
        std::panic!("Honest Commit(v1) must pass verification");
    }

    // Forged Commit(v2): SAME QC, DIFFERENT proposals.
    // BUG DA-1: This passes because the QC id does not bind to proposals.
    let commit_v2 = ConsensusMessage::Commit {
        slot, view,
        qc: confirm_qc.clone(),
        proposals: proposals_v2.clone(),
    };
    if !verify_commit(&commit_v2, &committee) {
        std::panic!("BUG DA-1: Forged Commit(v2) should pass (demonstrating the bug)");
    }

    // Both commits pass verification with the same QC but different values.
    // If s3 receives commit_v1 and s2 receives commit_v2, they commit
    // different values for the same slot — AgreementSafety violation.
    println!("DA-1 CONFIRMED: verify_commit accepts two Commits with different \
              proposals but the same QC for (slot={}, view={})", slot, view);
}

// Bug DA-2 Reproduction: Timeout Digest Hashes Nothing
//
// Timeout::digest() (messages.rs:1349-1358) creates a hash with NO fields.
// All content (slot, view, high_qc) is commented out.
// Every Timeout message produces the identical digest regardless of content.
#[test]
fn test_da2_timeout_digest_hashes_nothing() {
    use crate::common::keys;
    use crypto::Hash as _;

    let keys = keys();

    // Create two Timeout messages for completely different (slot, view) pairs.
    let timeout_a = Timeout::new_from_key(
        None,           // high_prop
        None,           // high_qc
        1,              // slot
        1,              // view
        keys[0].0,      // author
        &keys[0].1,     // secret
    );
    let timeout_b = Timeout::new_from_key(
        None,
        None,
        99,             // different slot
        42,             // different view
        keys[1].0,      // different author
        &keys[1].1,
    );

    // BUG DA-2: Both timeouts produce the exact same digest.
    let dig_a = timeout_a.digest();
    let dig_b = timeout_b.digest();
    if dig_a != dig_b {
        std::panic!("Expected identical digests (bug DA-2), but they differ");
    }

    println!("DA-2 CONFIRMED: Timeout(slot=1,view=1) and Timeout(slot=99,view=42) \
              have identical digest: {}", dig_a);
}

// Bug DA-3 Reproduction: TC Verification Always Returns Ok
//
// TC::PartialEq (messages.rs:1405-1411) always returns true.
// TC::verify() (messages.rs:1518-1522) checks `Self::genesis(committee) == *self`
// which always succeeds, short-circuiting all quorum/signature checks.
#[test]
fn test_da3_tc_verify_always_passes() {
    use crate::common::{keys, committee};

    let committee = committee();
    let keys = keys();

    // Create a completely EMPTY TC — no timeouts at all.
    // This should FAIL verification (no quorum), but passes due to DA-3.
    let empty_tc = TC { slot: 1, view: 1, timeouts: vec![] };
    if empty_tc.verify(&committee).is_err() {
        std::panic!("BUG DA-3: Empty TC should pass verification (demonstrating the bug)");
    }

    // Create a TC with a single timeout from one node (below quorum).
    let single_timeout = Timeout::new_from_key(
        None, None, 1, 1, keys[0].0, &keys[0].1,
    );
    let under_quorum_tc = TC { slot: 5, view: 10, timeouts: vec![single_timeout] };
    if under_quorum_tc.verify(&committee).is_err() {
        std::panic!("BUG DA-3: Under-quorum TC should pass verification (demonstrating the bug)");
    }

    // Verify that PartialEq always returns true (the root cause).
    let tc_a = TC { slot: 1, view: 1, timeouts: vec![] };
    let tc_b = TC { slot: 99, view: 99, timeouts: vec![] };
    if tc_a != tc_b {
        std::panic!("BUG DA-3: TC PartialEq should always return true");
    }

    println!("DA-3 CONFIRMED: Empty TC and under-quorum TC both pass TC::verify()");
}

// Bug DA-5 Reproduction: View Change Selects Wrong Winning View
//
// In TC::get_winning_proposals() (messages.rs:1454), the comparison uses
// other_view (the QC's actual view) correctly, but the assignment stores
// timeout.view (the failed round's view) instead of *other_view.
// This decouples winning_view from actual QC evidence.
#[test]
fn test_da5_viewchange_wrong_winning_view() {
    use crate::common::{keys, committee};

    let keys = keys();
    let committee = committee();

    // Scenario: Two timeouts with high_qc Confirm messages at different views.
    //
    // timeout_1: timed out from view=5, carries high_qc from Confirm at view=3
    //            proposals = proposals_v1 (the correct winner — higher QC view)
    // timeout_2: timed out from view=7, carries high_qc from Confirm at view=2
    //            proposals = proposals_v2 (should lose — lower QC view)
    //
    // Correct behavior: timeout_1's proposals win (view 3 > view 2)
    // Bug DA-5: After processing timeout_1, winning_view is set to timeout.view=5
    //           (not other_view=3). Then timeout_2 has other_view=2, which is NOT > 5,
    //           so timeout_2 doesn't override. In this case the result is accidentally correct.
    //
    // The bug manifests when ordering is reversed: process timeout_2 first.
    // timeout_2: other_view=2 > winning_view=0, so winning_view = timeout.view = 7, proposals = v2
    // timeout_1: other_view=3 > winning_view=7? NO (3 < 7). So v1 doesn't override.
    // Result: v2 wins despite v1 having the higher QC view. WRONG.

    let proposals_v1: HashMap<PublicKey, Proposal> = {
        let mut map = HashMap::new();
        map.insert(keys[0].0, Proposal { header_digest: Digest([1u8; 32]), height: 1 });
        map
    };
    let proposals_v2: HashMap<PublicKey, Proposal> = {
        let mut map = HashMap::new();
        map.insert(keys[0].0, Proposal { header_digest: Digest([2u8; 32]), height: 1 });
        map
    };

    // Build Confirm messages as high_qc evidence
    let dummy_qc = QC { id: Digest::default(), votes: vec![] };

    let high_qc_view3 = ConsensusMessage::Confirm {
        slot: 1, view: 3, qc: dummy_qc.clone(), proposals: proposals_v1.clone(),
    };
    let high_qc_view2 = ConsensusMessage::Confirm {
        slot: 1, view: 2, qc: dummy_qc.clone(), proposals: proposals_v2.clone(),
    };

    // Build timeouts: timeout_2 (view=7, qc_view=2) FIRST, then timeout_1 (view=5, qc_view=3)
    // This ordering triggers the bug.
    let timeout_2 = Timeout::new_from_key(
        None, Some(high_qc_view2), 1, 7, keys[1].0, &keys[1].1,
    );
    let timeout_1 = Timeout::new_from_key(
        None, Some(high_qc_view3), 1, 5, keys[0].0, &keys[0].1,
    );

    // TC with timeout_2 first (the ordering that triggers the bug)
    let tc = TC::new(&committee, 1, 8, vec![timeout_2, timeout_1]);
    let winning = tc.get_winning_proposals(&committee);

    // The correct answer is proposals_v1 (QC view 3 > QC view 2).
    // Bug DA-5: proposals_v2 wins because winning_view was inflated to 7 (timeout.view).
    let expected_correct = &proposals_v1.get(&keys[0].0).unwrap().header_digest;
    let actual = winning.get(&keys[0].0).map(|p| &p.header_digest);

    if actual == Some(expected_correct) {
        std::panic!("Bug DA-5 not triggered — expected wrong proposal to win");
    }

    // Verify it selected the WRONG proposals (v2 instead of v1)
    let wrong_v2 = &proposals_v2.get(&keys[0].0).unwrap().header_digest;
    if actual != Some(wrong_v2) {
        std::panic!("Unexpected result: neither v1 nor v2 won");
    }

    println!("DA-5 CONFIRMED: get_winning_proposals selected proposals from QC view 2 \
              instead of QC view 3, because winning_view was inflated to timeout.view=7");
}

// Bug DA-13 Reproduction: QC PartialEq Always Returns false
//
// QC::PartialEq (messages.rs:1287-1292) always returns false.
// This is the mirror image of DA-3 (TC always true).
// QC genesis check in QC::verify() is dead code — never matches.
#[test]
fn test_da13_qc_partialeq_always_false() {
    let qc_a = QC { id: Digest::default(), votes: vec![] };
    let qc_b = QC { id: Digest::default(), votes: vec![] };

    // Two identical QCs should be equal, but PartialEq always returns false.
    if qc_a == qc_b {
        std::panic!("Bug DA-13 not triggered — QCs compared equal");
    }

    // Even a QC compared with itself (via clone) returns false.
    let qc_c = qc_a.clone();
    if qc_a == qc_c {
        std::panic!("Bug DA-13 not triggered — QC equal to its clone");
    }

    println!("DA-13 CONFIRMED: QC PartialEq always returns false, \
              even for identical QCs");
}

// BUG-03 Reproduction (message-level): Confirm Double-Vote via verify_confirm
//
// verify_confirm() accepts two Confirm messages with different proposals but
// same (slot, view, QC) because proposal_digest is commented out (BUG-01).
// Combined with the missing last_voted_consensus check in is_valid()
// (core.rs:1235-1246), a node will vote for both, violating ConfirmUniqueness.
#[test]
fn test_bug03_confirm_double_vote_verify() {
    use crate::common::{keys, committee};
    use ed25519_dalek::Digest as _;
    use std::convert::TryInto;

    let keys = keys();
    let committee = committee();

    let slot: u64 = 1;
    let view: u64 = 1;

    // Build prepare_id = hash(slot, view, 0) — same as verify_confirm reconstructs
    let prepare_id = {
        let mut h = Sha512::new();
        h.update(slot.to_le_bytes());
        h.update(view.to_le_bytes());
        h.update((0u8).to_le_bytes());
        Digest(h.finalize().as_slice()[..32].try_into().unwrap())
    };

    // Build a valid PrepareQC: 3-of-4 signatures on prepare_id
    let qc_votes: Vec<(PublicKey, Signature)> = keys.iter().take(3)
        .map(|(pk, sk)| (*pk, Signature::new(&prepare_id, sk)))
        .collect();
    let prepare_qc = QC { id: prepare_id, votes: qc_votes };

    // Two different proposal sets
    let proposals_v1: HashMap<PublicKey, Proposal> = {
        let mut m = HashMap::new();
        m.insert(keys[0].0, Proposal { header_digest: Digest([1u8; 32]), height: 1 });
        m
    };
    let proposals_v2: HashMap<PublicKey, Proposal> = {
        let mut m = HashMap::new();
        m.insert(keys[0].0, Proposal { header_digest: Digest([2u8; 32]), height: 1 });
        m
    };

    // Two Confirm messages: same (slot, view, QC), different proposals
    let confirm_v1 = ConsensusMessage::Confirm {
        slot, view, qc: prepare_qc.clone(), proposals: proposals_v1,
    };
    let confirm_v2 = ConsensusMessage::Confirm {
        slot, view, qc: prepare_qc.clone(), proposals: proposals_v2,
    };

    // Sanity: digests are identical (BUG-01 prerequisite)
    assert_eq!(confirm_v1.digest(), confirm_v2.digest(),
        "Precondition: Confirm digests must match due to BUG-01");

    // BUG-03: verify_confirm passes for BOTH — no proposal binding
    let pass_v1 = verify_confirm(&confirm_v1, &committee);
    let pass_v2 = verify_confirm(&confirm_v2, &committee);

    if !pass_v1 {
        std::panic!("verify_confirm(v1) should pass");
    }
    if !pass_v2 {
        std::panic!("BUG-03: verify_confirm(v2) should also pass (demonstrating the bug)");
    }

    // Both pass verification. The is_valid() Confirm branch (core.rs:1235-1246)
    // only checks curr_view <= view and verify_confirm — NO last_voted_consensus
    // check. So a node will vote for both, creating two ConfirmVotes for the
    // same (slot, view) with different proposal values.
    println!("BUG-03 CONFIRMED: verify_confirm accepts two Confirm messages with \
              different proposals for (slot={}, view={}). Combined with missing \
              last_voted_consensus check in is_valid() Confirm branch, a node \
              will double-vote.", slot, view);
}
