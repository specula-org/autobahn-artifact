// Copyright(C) Facebook, Inc. and its affiliates.
use super::*;
use super::panic;
use crate::{common::{
    certificate, committee, committee_with_base_port, header, headers, keys, listener, votes, special_header, special_votes, header_from_cert,
}, proposer::Proposer, header_waiter::HeaderWaiter};
use config::Parameters;
use crypto::{Hash, Signature};
use std::{fs, time::Duration};
use tokio::{sync::mpsc::channel, time::sleep};
use serial_test::serial;

#[tokio::test]
#[serial]
async fn process_header() {
    let mut keys = keys();
    let _ = keys.pop().unwrap(); // Skip the header' author.
    let (name, secret) = keys.pop().unwrap();
    let mut signature_service = SignatureService::new(secret);

    let committee = committee_with_base_port(13_000);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_parents, _rx_parents) = channel(1);

    let(tx_committer, _rx_committer) = channel(1);
    let(_tx_request_header_sync, rx_request_header_sync) = channel(1);
    let (tx_info, _rx_info) = channel(1);
    let (tx_header_waiter_instances, rx_header_waiter_instances) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_header";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Make the vote we expect to receive.
    let expected = Vote::new(&header(), &name, &mut signature_service, Vec::new()).await;

    // Spawn a listener to receive the vote.
    let address = committee
        .primary(&header().author)
        .unwrap()
        .primary_to_primary;
    let handle = listener(address);

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee,
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    let leader_elector = LeaderElector::new(committee.clone());

    let parameters = Parameters::default();
    let timeout_delay = 1000;

    // Spawn the core.
    Core::spawn(
        name,
        committee,
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        rx_header_waiter_instances,
        /* rx_proposer */ rx_headers,
        tx_committer,
        /* tx_proposer */ tx_parents,
        rx_request_header_sync,
        tx_info,
        leader_elector,
        parameters.timeout_delay,
        parameters.use_optimistic_tips,
        parameters.use_parallel_proposals,
        parameters.k,
        parameters.use_fast_path,
        parameters.fast_path_timeout,
        parameters.use_ride_share,
        parameters.car_timeout,
        false, // simulate_asynchrony
        0,     // asynchrony_start
        0,     // asynchrony_duration
    );

    // Send a header to the core.
    tx_primary_messages
        .send(PrimaryMessage::Header(header(), false))
        .await
        .unwrap();


    let received = handle.await.unwrap();
    match bincode::deserialize(&received).unwrap() {
        PrimaryMessage::Vote(x) => assert_eq!(x, expected),
        x => panic!("Unexpected message: {:?}", x),
    }

    // Ensure the header is correctly stored.
    let stored = store
        .read(header().id.to_vec())
        .await
        .unwrap()
        .map(|x| bincode::deserialize(&x).unwrap());
    assert_eq!(stored, Some(header()));
}

#[tokio::test]
#[serial]
async fn process_header_missing_parent() {
    let mut keys = keys();
    let _ = keys.pop().unwrap(); // Skip the header' author.
    let (name, secret) = keys.pop().unwrap();
    let mut signature_service = SignatureService::new(secret);

    let committee = committee_with_base_port(13_000);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_parents, _rx_parents) = channel(1);

    let(tx_committer, _rx_committer) = channel(1);
    let(_tx_request_header_sync, rx_request_header_sync) = channel(1);
    let (tx_info, _rx_info) = channel(1);
    let (tx_header_waiter_instances, rx_header_waiter_instances) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_header";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee,
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    let leader_elector = LeaderElector::new(committee.clone());
    let timeout_delay = 1000;

    let parameters = Parameters::default();

    // Spawn the core.
    Core::spawn(
        name,
        committee,
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        rx_header_waiter_instances,
        /* rx_proposer */ rx_headers,
        tx_committer,
        /* tx_proposer */ tx_parents,
        rx_request_header_sync,
        tx_info,
        leader_elector,
        parameters.timeout_delay,
        parameters.use_optimistic_tips,
        parameters.use_parallel_proposals,
        parameters.k,
        parameters.use_fast_path,
        parameters.fast_path_timeout,
        parameters.use_ride_share,
        parameters.car_timeout,
        false, // simulate_asynchrony
        0,     // asynchrony_start
        0,     // asynchrony_duration
    );

    let header_one = header();
    let cert_one = certificate(&header_one);
    let header_two: Header = Header { author: header_one.author, height: header_one.height + 1, payload: header_one.payload, 
        parent_cert: cert_one, id: header_one.id, signature: header_one.signature, consensus_messages: HashMap::new(), num_active_instances: 0, special: false};
    let id = header_two.digest().clone();

    // Send a header to the core.
    tx_primary_messages
        .send(PrimaryMessage::Header(header_two, false))
        .await
        .unwrap();

    // Ensure the header is not stored.
    assert!(store.read(id.to_vec()).await.unwrap().is_none());
}


#[tokio::test]
#[serial]
async fn process_header_invalid_height() {
    let (name, secret) = keys().pop().unwrap();
    let signature_service = SignatureService::new(secret);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_parents, _rx_parents) = channel(1);

    let(tx_committer, _rx_committer) = channel(1);
    let(_tx_request_header_sync, rx_request_header_sync) = channel(1);
    let (tx_info, _rx_info) = channel(1);
    let (tx_header_waiter_instances, rx_header_waiter_instances) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_header_missing_parent";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee(),
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    let leader_elector = LeaderElector::new(committee().clone());
    let timeout_delay = 1000;

    let parameters = Parameters::default();

    // Spawn the core.
    Core::spawn(
        name,
        committee(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        rx_header_waiter_instances,
        /* rx_proposer */ rx_headers,
        tx_committer,
        /* tx_proposer */ tx_parents,
        rx_request_header_sync,
        tx_info,
        leader_elector,
        parameters.timeout_delay,
        parameters.use_optimistic_tips,
        parameters.use_parallel_proposals,
        parameters.k,
        parameters.use_fast_path,
        parameters.fast_path_timeout,
        parameters.use_ride_share,
        parameters.car_timeout,
        false, // simulate_asynchrony
        0,     // asynchrony_start
        0,     // asynchrony_duration
    );

    // Send a header to the core.
    let header = Header {
        parent_cert: Certificate::genesis_cert(&committee()),//[Digest::default()].iter().cloned().collect(),
        height: 2,
        ..header()
    };
    let id = header.id.clone();
    tx_primary_messages
        .send(PrimaryMessage::Header(header, false))
        .await
        .unwrap();

    // Sleep to ensure header is processed
    sleep(Duration::from_millis(1000)).await;

    // Ensure the header is not stored.
    assert!(store.read(id.to_vec()).await.unwrap().is_none());
}

#[tokio::test]
#[serial]
async fn process_header_missing_payload() {
    let (name, secret) = keys().pop().unwrap();
    let signature_service = SignatureService::new(secret);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_parents, _rx_parents) = channel(1);

    let(tx_committer, _rx_committer) = channel(1);
    let(_tx_request_header_sync, rx_request_header_sync) = channel(1);
    let (tx_info, _rx_info) = channel(1);
    let (tx_header_waiter_instances, rx_header_waiter_instances) = channel(1);


    // Create a new test store.
    let path = ".db_test_process_header_missing_payload";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee(),
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    let leader_elector = LeaderElector::new(committee().clone());
    let timeout_delay = 1000;

    let parameters = Parameters::default();

    // Spawn the core.
    Core::spawn(
        name,
        committee(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        rx_header_waiter_instances,
        /* rx_proposer */ rx_headers,
        tx_committer,
        /* tx_proposer */ tx_parents,
        rx_request_header_sync,
        tx_info,
        leader_elector,
        parameters.timeout_delay,
        parameters.use_optimistic_tips,
        parameters.use_parallel_proposals,
        parameters.k,
        parameters.use_fast_path,
        parameters.fast_path_timeout,
        parameters.use_ride_share,
        parameters.car_timeout,
        false, // simulate_asynchrony
        0,     // asynchrony_start
        0,     // asynchrony_duration
    );

    // Send a header to the core.
    let header = Header {
        payload: [(Digest::default(), 0)].iter().cloned().collect(),
        ..header()
    };
    let id = header.id.clone();
    tx_primary_messages
        .send(PrimaryMessage::Header(header, false))
        .await
        .unwrap();

    // Ensure the header is not stored.
    assert!(store.read(id.to_vec()).await.unwrap().is_none());
}

#[tokio::test]
#[serial]
async fn process_votes() {
    let (name, secret) = keys().pop().unwrap();
    let signature_service = SignatureService::new(secret);

    let committee = committee_with_base_port(13_100);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (tx_headers, rx_headers) = channel(1);
    let (tx_parents, mut rx_parents) = channel(1);

    let(tx_committer, _rx_committer) = channel(1);
    let(_tx_request_header_sync, rx_request_header_sync) = channel(1);
    let (tx_info, mut rx_info) = channel(1);
    let (tx_header_waiter_instances, rx_header_waiter_instances) = channel(1);


    // Create a new test store.
    let path = ".db_test_process_vote";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee,
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    let leader_elector = LeaderElector::new(committee.clone());
    let timeout_delay = 1000;

    let parameters = Parameters::default();

    // Spawn the core.
    Core::spawn(
        name,
        committee.clone(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        rx_header_waiter_instances,
        /* rx_proposer */ rx_headers,
        tx_committer,
        /* tx_proposer */ tx_parents,
        rx_request_header_sync,
        tx_info,
        leader_elector,
        parameters.timeout_delay,
        parameters.use_optimistic_tips,
        parameters.use_parallel_proposals,
        parameters.k,
        parameters.use_fast_path,
        parameters.fast_path_timeout,
        parameters.use_ride_share,
        parameters.car_timeout,
        false, // simulate_asynchrony
        0,     // asynchrony_start
        0,     // asynchrony_duration
    );



    // Receive geneis parent cert from the proposer
    rx_parents.recv().await.unwrap();

    let header = header();
    // Make the certificate we expect to receive.
    let expected = certificate(&header);

    //Note: core uses Header::genesis instead of Header::default now
    tx_headers
        .send(header.clone())
        .await
        .unwrap();
    sleep(Duration::from_millis(500)).await;
    /*tx_primary_messages
        .send(PrimaryMessage::Header(header.clone()))
        .await
        .unwrap();*/

    // Send a votes to the core.
    for vote in votes(&header) {
        //println!("Vote origin is {:?}", vote.origin);
        tx_primary_messages
            .send(PrimaryMessage::Vote(vote))
            .await
            .unwrap();
    }

    let received_cert = rx_parents.recv().await.unwrap();
    assert_eq!(received_cert.height, expected.height);
    assert_eq!(received_cert.author, expected.author);
    assert_eq!(received_cert.header_digest, expected.header_digest);
    //println!("Expected cert is {:?}, {:?}", expected.header_digest, expected.height);

    // Ensure the listener received the certificate and stored it.
    /*let stored = store
        .read(expected.digest().to_vec())
        .await
        .unwrap()
        .map(|x| bincode::deserialize(&x).unwrap());
    assert_eq!(stored, Some(expected));*/
}

#[tokio::test]
#[serial]
async fn process_certificates() {
    let (name, secret) = keys().pop().unwrap();
    let signature_service = SignatureService::new(secret);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(3);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (tx_headers, rx_headers) = channel(1);
    let (tx_parents, mut rx_parents) = channel(1);

    let(tx_committer, mut rx_committer) = channel(3);
    let(_tx_request_header_sync, rx_request_header_sync) = channel(1);
    let (tx_info, _rx_info) = channel(1);
    let (tx_header_waiter_instances, rx_header_waiter_instances) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_certificates";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee(),
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    let leader_elector = LeaderElector::new(committee().clone());
    let timeout_delay = 1000;

    let parameters = Parameters::default();

    // Spawn the core.
    Core::spawn(
        name,
        committee(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        rx_header_waiter_instances,
        /* rx_proposer */ rx_headers,
        tx_committer,
        /* tx_proposer */ tx_parents,
        rx_request_header_sync,
        tx_info,
        leader_elector,
        parameters.timeout_delay,
        parameters.use_optimistic_tips,
        parameters.use_parallel_proposals,
        parameters.k,
        parameters.use_fast_path,
        parameters.fast_path_timeout,
        parameters.use_ride_share,
        parameters.car_timeout,
        false, // simulate_asynchrony
        0,     // asynchrony_start
        0,     // asynchrony_duration
    );


    // Send enough certificates to the core.
    let certificates: Vec<Certificate> = headers()
        .iter()
        .map(|header| certificate(header))
        .collect();

    // Send enough headers to the core.
    let headers_from_certs: Vec<Header> = certificates
        .iter()
        .map(|cert| header_from_cert(cert))
        .collect();


   
    for x in headers().iter() {
        //println!("author is {:?}", x.author);
        tx_primary_messages
            .send(PrimaryMessage::Header(x.clone(), false))
            .await
            .unwrap();
    }

   
    for x in headers_from_certs {
        //println!("Sending headers with author {:?}", x.author);
        tx_primary_messages
            .send(PrimaryMessage::Header(x, false))
            .await
            .unwrap();
    }

    // Ensure the certificates are stored.
    for x in &certificates {
        //println!("Cert digest is {:?}", x.digest());
        let stored = store.read(x.digest().to_vec()).await.unwrap();
        let serialized = bincode::serialize(x).unwrap();
        assert_eq!(stored, Some(serialized));
    }
}

#[tokio::test]
#[serial]
async fn process_prepare() {
    let mut keys = keys();
    let _ = keys.pop().unwrap(); // Skip the header' author.
    let (name, secret) = keys.pop().unwrap();
    let mut signature_service = SignatureService::new(secret);

    let committee = committee_with_base_port(13_000);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_parents, _rx_parents) = channel(1);

    let(tx_committer, _rx_committer) = channel(1);
    let(_tx_request_header_sync, rx_request_header_sync) = channel(1);
    let (tx_info, _rx_info) = channel(1);
    let (tx_header_waiter_instances, rx_header_waiter_instances) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_header";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Spawn a listener to receive the vote.
    let address = committee
        .primary(&header().author)
        .unwrap()
        .primary_to_primary;
    //let handle = listener(address);

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee,
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    let leader_elector = LeaderElector::new(committee.clone());
    let timeout_delay = 1000;

    let parameters = Parameters::default();

    // Spawn the core.
    Core::spawn(
        name,
        committee.clone(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        rx_header_waiter_instances,
        /* rx_proposer */ rx_headers,
        tx_committer,
        /* tx_proposer */ tx_parents,
        rx_request_header_sync,
        tx_info,
        leader_elector,
        parameters.timeout_delay,
        parameters.use_optimistic_tips,
        parameters.use_parallel_proposals,
        parameters.k,
        parameters.use_fast_path,
        parameters.fast_path_timeout,
        parameters.use_ride_share,
        parameters.car_timeout,
        false, // simulate_asynchrony
        0,     // asynchrony_start
        0,     // asynchrony_duration
    );


    // Send headers to the core, so they won't request sync
    let header_list = headers();
    for x in header_list.clone() {
        tx_primary_messages
            .send(PrimaryMessage::Header(x, false))
            .await
            .unwrap();
    }

    let mut proposals: HashMap<PublicKey, Proposal> = HashMap::new();
    for x in &header_list {
        proposals.insert(x.author, Proposal { header_digest: x.digest(), height: x.height() });
    }
    let prepare_message: ConsensusMessage = ConsensusMessage::Prepare { slot: 1, view: 1, tc: None, qc_ticket: None, proposals };

    let mut consensus_messages: HashMap<Digest, ConsensusMessage> = HashMap::new();
    consensus_messages.insert(prepare_message.digest(), prepare_message.clone());

    let parent_cert = certificate(&header_list[0]);
    let header = special_header(parent_cert, consensus_messages);

    // Send a header to the core.
    tx_primary_messages
        .send(PrimaryMessage::Header(header.clone(), false))
        .await
        .unwrap();


    listener(address).await.unwrap();

    // Make the vote we expect to receive.
    let handle = listener(address);
    let received = handle.await.unwrap();
    match bincode::deserialize(&received).unwrap() {
        PrimaryMessage::Vote(x) => {
            //assert_eq!(x, expected);
            assert!(!x.consensus_votes.is_empty());
            assert_eq!(x.height, 2);
            assert_eq!(prepare_message.digest(), x.consensus_votes[0].1);
        }
        x => panic!("Unexpected message: {:?}", x),
    }


    // Ensure the header is correctly stored.
    let stored = store
        .read(header.id.to_vec())
        .await
        .unwrap()
        .map(|x| bincode::deserialize(&x).unwrap());
    assert_eq!(stored, Some(header));
}

#[tokio::test]
#[serial]
async fn generate_confirm() {
    let mut keys = keys();
    let _ = keys.pop().unwrap(); // Skip the header' author.
    let (name, secret) = keys.pop().unwrap();
    let mut signature_service = SignatureService::new(secret);

    let committee = committee_with_base_port(13_000);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (tx_headers, rx_headers) = channel(1);
    let (tx_parents, mut rx_parents) = channel(1);

    let(tx_committer, _rx_committer) = channel(1);
    let(_tx_request_header_sync, rx_request_header_sync) = channel(1);
    let (tx_info, mut rx_info) = channel(1);
    let (tx_header_waiter_instances, rx_header_waiter_instances) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_header";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Spawn a listener to receive the vote.
    let address = committee
        .primary(&header().author)
        .unwrap()
        .primary_to_primary;
    //let handle = listener(address);

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee,
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    let leader_elector = LeaderElector::new(committee.clone());
    let timeout_delay = 1000;

    let parameters = Parameters::default();

    // Spawn the core.
    Core::spawn(
        name,
        committee.clone(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        rx_header_waiter_instances,
        /* rx_proposer */ rx_headers,
        tx_committer,
        /* tx_proposer */ tx_parents,
        rx_request_header_sync,
        tx_info,
        leader_elector,
        parameters.timeout_delay,
        parameters.use_optimistic_tips,
        parameters.use_parallel_proposals,
        parameters.k,
        parameters.use_fast_path,
        parameters.fast_path_timeout,
        parameters.use_ride_share,
        parameters.car_timeout,
        false, // simulate_asynchrony
        0,     // asynchrony_start
        0,     // asynchrony_duration
    );


    // Receive the first prepare message from proposer
    rx_info.recv().await.unwrap();
    rx_parents.recv().await.unwrap();

    /*Proposer::spawn(
        name, 
        committee.clone(), 
        signature_service, 
        100, 
        timeout_delay, 
        rx_parents, 
        rx_workers, 
        rx_info, 
        tx_headers,
    );*/


    // Send headers to the core, so they won't request sync
    let header_list = headers();
    for x in header_list.clone() {
        tx_primary_messages
            .send(PrimaryMessage::Header(x, false))
            .await
            .unwrap();
    }

    let mut proposals: HashMap<PublicKey, Proposal> = HashMap::new();
    for x in &header_list {
        proposals.insert(x.author, Proposal { header_digest: x.digest(), height: x.height() });
    }
    let prepare_message: ConsensusMessage = ConsensusMessage::Prepare { slot: 1, view: 1, tc: None, qc_ticket:None, proposals: proposals.clone() };

    let mut consensus_messages: HashMap<Digest, ConsensusMessage> = HashMap::new();
    consensus_messages.insert(prepare_message.digest().clone(), prepare_message.clone());

    let parent_cert = certificate(&header_list[0]);
    let header = special_header(parent_cert, consensus_messages.clone());
    let consensus_digests = vec![prepare_message.digest()];


    // Send a header to the core.
    tx_headers
        .send(header.clone())
        .await
        .unwrap();


    for vote in special_votes(&header, consensus_digests) {
        //println!("sending special votes");
        let message = PrimaryMessage::Vote(vote);
        tx_primary_messages
            .send(message)
            .await
            .unwrap();
    }


    let confirm_message = rx_info.recv().await.unwrap();
    match confirm_message {
        ConsensusMessage::Confirm { slot, view, qc, proposals: _ } => {
            assert_eq!(slot, 1);
            assert_eq!(view, 1);
            assert_eq!(qc.id, prepare_message.digest().clone());
            assert_eq!(qc.votes.len(), 3);
        },
        _ => panic!("Wrong message type"),
    };
}

#[tokio::test]
#[serial]
async fn generate_commit() {
    let mut keys = keys();
    let _ = keys.pop().unwrap(); // Skip the header' author.
    let (name, secret) = keys.pop().unwrap();
    let mut signature_service = SignatureService::new(secret);

    let committee = committee_with_base_port(13_000);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (tx_headers, mut rx_headers) = channel(1);
    let (tx_parents, mut rx_parents) = channel(1);

    let(tx_committer, mut rx_committer) = channel(1);
    let(_tx_request_header_sync, rx_request_header_sync) = channel(1);
    let (tx_info, mut rx_info) = channel(1);
    let (tx_header_waiter_instances, rx_header_waiter_instances) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_header";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Spawn a listener to receive the vote.
    let address = committee
        .primary(&header().author)
        .unwrap()
        .primary_to_primary;
    //let handle = listener(address);

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee,
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    let leader_elector = LeaderElector::new(committee.clone());
    let timeout_delay = 1000;


    let parameters = Parameters::default();

    // Spawn the core.
    Core::spawn(
        name,
        committee.clone(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        rx_header_waiter_instances,
        /* rx_proposer */ rx_headers,
        tx_committer,
        /* tx_proposer */ tx_parents,
        rx_request_header_sync,
        tx_info,
        leader_elector,
        parameters.timeout_delay,
        parameters.use_optimistic_tips,
        parameters.use_parallel_proposals,
        parameters.k,
        parameters.use_fast_path,
        parameters.fast_path_timeout,
        parameters.use_ride_share,
        parameters.car_timeout,
        false, // simulate_asynchrony
        0,     // asynchrony_start
        0,     // asynchrony_duration
    );


    // Receive the first prepare message from proposer
    rx_info.recv().await.unwrap();
    rx_parents.recv().await.unwrap();

    /*Proposer::spawn(
        name, 
        committee.clone(), 
        signature_service, 
        100, 
        timeout_delay, 
        rx_parents, 
        rx_workers, 
        rx_info, 
        tx_headers,
    );*/


    // Send headers to the core, so they won't request sync
    let header_list = headers();
    for x in header_list.clone() {
        tx_primary_messages
            .send(PrimaryMessage::Header(x, false))
            .await
            .unwrap();
    }

    let mut proposals: HashMap<PublicKey, Proposal> = HashMap::new();
    for x in &header_list {
        proposals.insert(x.author, Proposal { header_digest: x.digest(), height: x.height() });
    }
    let prepare_message: ConsensusMessage = ConsensusMessage::Prepare { slot: 1, view: 1, tc: None, qc_ticket: None, proposals: proposals.clone() };

    let mut consensus_messages: HashMap<Digest, ConsensusMessage> = HashMap::new();
    consensus_messages.insert(prepare_message.digest().clone(), prepare_message.clone());

    let parent_cert = certificate(&header_list[0]);
    let header = special_header(parent_cert, consensus_messages.clone());
    let consensus_digests = vec![prepare_message.digest()];


    // Send a header to the core.
    tx_headers
        .send(header.clone())
        .await
        .unwrap();


    for vote in special_votes(&header, consensus_digests) {
        //println!("sending special votes");
        let message = PrimaryMessage::Vote(vote);
        tx_primary_messages
            .send(message)
            .await
            .unwrap();
    }


    let confirm_message = rx_info.recv().await.unwrap();
    match confirm_message.clone() {
        ConsensusMessage::Confirm { slot, view, qc, proposals: _ } => {
            consensus_messages.clear();
            consensus_messages.insert(confirm_message.digest().clone(), confirm_message.clone());
            
            let confirm_parent_cert = certificate(&header);
            let confirm_header = special_header(confirm_parent_cert, consensus_messages.clone());

            //println!("confirm header height {:?} author {:?}", confirm_header.height, confirm_header.author);

            tx_headers
                .send(confirm_header.clone())
                .await
                .unwrap();

            sleep(Duration::from_millis(500)).await;
            let confirm_digests = vec![confirm_message.digest().clone()];

            for vote in special_votes(&confirm_header, confirm_digests) {
                //println!("sending special votes confirm");
                let message = PrimaryMessage::Vote(vote);
                tx_primary_messages
                    .send(message)
                    .await
                    .unwrap();
            }

            //println!("after sending votes");

            let commit_message = rx_info.recv().await.unwrap();
            rx_parents.recv().await.unwrap();

            match commit_message.clone() {
                ConsensusMessage::Commit { slot: slot1, view: view1, qc: qc1, proposals: proposals1 } => {
                    consensus_messages.clear();
                    consensus_messages.insert(commit_message.digest().clone(), commit_message.clone());
                    
                    let commit_parent_cert = certificate(&confirm_header);
                    let commit_header = special_header(commit_parent_cert, consensus_messages.clone());

                    //println!("sending commit header: {:?}, {:?}", commit_header.height, commit_header.author);
                    
                    // Ensure that the confirm header is processed and received
                    //sleep(Duration::from_millis(500)).await;
                    tx_headers
                        .send(commit_header)
                        .await
                        .unwrap();


                    //println!("awaiting committer");
                    let receive_commit_message = rx_committer.recv().await.unwrap();
                    match receive_commit_message {
                        ConsensusMessage::Commit { slot: slot2, view: view2, qc: qc2, proposals: proposals2 } => {
                            assert_eq!(slot1, slot2);
                            assert_eq!(view1, view2);
                        },
                        _ => {},
                    };
                },
                _ => {},
            };
        },
        _ => panic!("Wrong message type"),
    };
}

#[tokio::test]
#[serial]
async fn generate_pipelined_prepare() {
    let mut keys = keys();
    let _ = keys.pop().unwrap(); // Skip the header' author.
    let (name, secret) = keys.pop().unwrap();
    let mut signature_service = SignatureService::new(secret);

    let committee = committee_with_base_port(13_000);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_parents, mut rx_parents) = channel(1);

    let(tx_committer, _rx_committer) = channel(1);
    let(_tx_request_header_sync, rx_request_header_sync) = channel(1);
    let (tx_info, mut rx_info) = channel(1);
    let (tx_header_waiter_instances, rx_header_waiter_instances) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_header";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Spawn a listener to receive the vote.
    let address = committee
        .primary(&header().author)
        .unwrap()
        .primary_to_primary;
    //let handle = listener(address);

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee,
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    let leader_elector = LeaderElector::new(committee.clone());
    let timeout_delay = 1000;

    let parameters = Parameters::default();

    // Spawn the core.
    Core::spawn(
        name,
        committee.clone(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        rx_header_waiter_instances,
        /* rx_proposer */ rx_headers,
        tx_committer,
        /* tx_proposer */ tx_parents,
        rx_request_header_sync,
        tx_info,
        leader_elector,
        parameters.timeout_delay,
        parameters.use_optimistic_tips,
        parameters.use_parallel_proposals,
        parameters.k,
        parameters.use_fast_path,
        parameters.fast_path_timeout,
        parameters.use_ride_share,
        parameters.car_timeout,
        false, // simulate_asynchrony
        0,     // asynchrony_start
        0,     // asynchrony_duration
    );



    // Receive the first prepare message from proposer
    rx_info.recv().await.unwrap();
    rx_parents.recv().await.unwrap();

    // Send headers to the core, so they won't request sync
    let header_list = headers();
    for x in header_list.clone() {
        tx_primary_messages
            .send(PrimaryMessage::Header(x, false))
            .await
            .unwrap();
    }


    let mut proposals: HashMap<PublicKey, Proposal> = HashMap::new();
    for x in &header_list {
        proposals.insert(x.author, Proposal { header_digest: x.digest(), height: x.height() });
    }
    let prepare_message: ConsensusMessage = ConsensusMessage::Prepare { slot: 1, view: 1, tc: None, qc_ticket: None, proposals };

    let mut consensus_messages: HashMap<Digest, ConsensusMessage> = HashMap::new();
    consensus_messages.insert(prepare_message.digest(), prepare_message.clone());

    let parent_cert = certificate(&header_list[0]);
    let header = special_header(parent_cert, consensus_messages);

    // Send a header to the core.
    tx_primary_messages
        .send(PrimaryMessage::Header(header.clone(), false))
        .await
        .unwrap();


    // Send enough certificates to the core.
    let certificates: Vec<Certificate> = headers()
        .iter()
        .rev()
        .skip(1)
        .map(|header| certificate(header))
        .collect();

    // Send enough headers to the core.
    let headers_from_certs: Vec<Header> = certificates
        .iter()
        .rev()
        .skip(1)
        .map(|cert| header_from_cert(cert))
        .collect();


    for x in headers_from_certs.clone() {
        //println!("header author is {:?}", x.author);
        tx_primary_messages
            .send(PrimaryMessage::Header(x, false))
            .await
            .unwrap();
    }


    // Send a header to the core.
    //println!("special header author is {:?}", header.author);
    tx_primary_messages
        .send(PrimaryMessage::Header(header.clone(), false))
        .await
        .unwrap();


    listener(address).await.unwrap();
    let output_message = rx_info.recv().await.unwrap();

    match output_message {
        ConsensusMessage::Prepare { slot, view, tc: _, qc_ticket: _, proposals: _ } => {
            assert_eq!(slot, 2);
            assert_eq!(view, 1);
        },
        _ => {}
    };


    // Ensure the header is correctly stored.
    let stored = store
        .read(header.id.to_vec())
        .await
        .unwrap()
        .map(|x| bincode::deserialize(&x).unwrap());
    assert_eq!(stored, Some(header));
}

#[tokio::test]
#[serial]
async fn local_timeout_view() {
    let mut keys = keys();
    let _ = keys.pop().unwrap(); // Skip the header' author.
    let (name, secret) = keys.pop().unwrap();
    let mut signature_service = SignatureService::new(secret);

    let committee = committee_with_base_port(13_000);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_parents, _rx_parents) = channel(1);

    let(tx_committer, _rx_committer) = channel(1);
    let(_tx_request_header_sync, rx_request_header_sync) = channel(1);
    let (tx_info, mut rx_info) = channel(1);
    let (tx_header_waiter_instances, rx_header_waiter_instances) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_header";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Spawn a listener to receive the vote.
    let address = committee
        .primary(&header().author)
        .unwrap()
        .primary_to_primary;
    let handle = listener(address);

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee,
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    let leader_elector = LeaderElector::new(committee.clone());
    let timeout_delay = 1000;

    let parameters = Parameters::default();

    // Spawn the core.
    Core::spawn(
        name,
        committee.clone(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        rx_header_waiter_instances,
        /* rx_proposer */ rx_headers,
        tx_committer,
        /* tx_proposer */ tx_parents,
        rx_request_header_sync,
        tx_info,
        leader_elector,
        parameters.timeout_delay,
        parameters.use_optimistic_tips,
        parameters.use_parallel_proposals,
        parameters.k,
        parameters.use_fast_path,
        parameters.fast_path_timeout,
        parameters.use_ride_share,
        parameters.car_timeout,
        false, // simulate_asynchrony
        0,     // asynchrony_start
        0,     // asynchrony_duration
    );


    /*let message = handle.await.unwrap();

    match bincode::deserialize(&message).unwrap() {
         PrimaryMessage::Timeout(timeout) => {
             assert_eq!(timeout.slot, 1);
             assert_eq!(timeout.view, 1);
         }
         x => panic!("Unexpected message: {:?}", x),
     };*/
}

#[tokio::test]
#[serial]
async fn sync_missing_proposals() {
    let mut keys = keys();
    let _ = keys.pop().unwrap(); // Skip the header' author.
    let (name, secret) = keys.pop().unwrap();
    let mut signature_service = SignatureService::new(secret);

    let committee = committee_with_base_port(13_000);

    let (tx_sync_headers, rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_parents, mut rx_parents) = channel(1);

    let(tx_committer, _rx_committer) = channel(1);
    let(_tx_request_header_sync, rx_request_header_sync) = channel(1);
    let (tx_info, mut rx_info) = channel(1);
    let (tx_header_waiter_instances, rx_header_waiter_instances) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_header";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Spawn a listener to receive the vote.
    let address = committee
        .primary(&header().author)
        .unwrap()
        .primary_to_primary;
    //let handle = listener(address);

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee,
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    let leader_elector = LeaderElector::new(committee.clone());
    let timeout_delay = 100000;

    let parameters = Parameters::default();

    // Spawn the core.
    Core::spawn(
        name,
        committee.clone(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        rx_header_waiter_instances,
        /* rx_proposer */ rx_headers,
        tx_committer,
        /* tx_proposer */ tx_parents,
        rx_request_header_sync,
        tx_info,
        leader_elector,
        parameters.timeout_delay,
        parameters.use_optimistic_tips,
        parameters.use_parallel_proposals,
        parameters.k,
        parameters.use_fast_path,
        parameters.fast_path_timeout,
        parameters.use_ride_share,
        parameters.car_timeout,
        false, // simulate_asynchrony
        0,     // asynchrony_start
        0,     // asynchrony_duration
    );



    // Receive the first prepare message from proposer
    rx_info.recv().await.unwrap();
    rx_parents.recv().await.unwrap();



    HeaderWaiter::spawn(
        name, 
        committee, 
        store.clone(), 
        Arc::new(AtomicU64::new(0)), 
        50, 
        timeout_delay, 
        1, 
        rx_sync_headers, 
        tx_headers_loopback, 
        tx_header_waiter_instances,
    );

    // Send headers to the core, so they won't request sync
    let header_list = headers();
    /*for x in header_list.clone() {
        tx_primary_messages
            .send(PrimaryMessage::Header(x))
            .await
            .unwrap();
    }*/

    tx_primary_messages
        .send(PrimaryMessage::Header(header_list[0].clone(), false))
        .await
        .unwrap();


    let mut proposals: HashMap<PublicKey, Proposal> = HashMap::new();
    for x in &header_list {
        proposals.insert(x.author, Proposal { header_digest: x.digest(), height: x.height() });
    }
    let prepare_message: ConsensusMessage = ConsensusMessage::Prepare { slot: 1, view: 1, tc: None, qc_ticket: None, proposals };

    let mut consensus_messages: HashMap<Digest, ConsensusMessage> = HashMap::new();
    consensus_messages.insert(prepare_message.digest(), prepare_message.clone());

    let parent_cert = certificate(&header_list[0]);
    let header = special_header(parent_cert, consensus_messages);

    // Send the special header to the core, should trigger sync
    tx_primary_messages
        .send(PrimaryMessage::Header(header.clone(), false))
        .await
        .unwrap();


    sleep(Duration::from_millis(500)).await;
    // Send the misssing proposals
    for x in header_list.into_iter().skip(1) {
        //println!("header author is {:?}", x.author);
        tx_primary_messages
            .send(PrimaryMessage::Header(x, false))
            .await
            .unwrap();
    }


    // Wait for the proposals to appear in the store
    sleep(Duration::from_millis(500)).await;

    // Ensure the header is correctly stored.
    let stored = store
        .read(header.id.to_vec())
        .await
        .unwrap()
        .map(|x| bincode::deserialize(&x).unwrap());
    assert_eq!(stored, Some(header));
}





/*#[tokio::test]
#[serial]
async fn process_special_header() {
    let mut keys = keys();
    let _ = keys.pop().unwrap(); // Skip the header' author.
    let (name, secret) = keys.pop().unwrap();
    let mut signature_service = SignatureService::new(secret);

    let committee = committee_with_base_port(13_000);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_consensus, _rx_consensus) = channel(1);
    let (tx_parents, _rx_parents) = channel(1);

    let(tx_committer, _rx_committer) = channel(1);
    let(tx_validation, rx_validation) = channel(1);
    let(tx_sailfish, mut rx_special) = channel(1);
    let(_tx_pushdown_cert, rx_pushdown_cert) = channel(1);
    let(_tx_request_header_sync, rx_request_header_sync) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_header";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Make the vote we expect to receive.
    //let expected = Vote::new(&header(), &name, &mut signature_service, 0u8, None, None).await;
    let special_expected = Vote::new(&special_header(), &name, &mut signature_service, true).await;

    // Spawn a listener to receive the vote.
    let address = committee
        .primary(&header().author)
        .unwrap()
        .primary_to_primary;
    let handle = listener(address.clone());
    

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee,
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    // Spawn the core.
    Core::spawn(
        name,
        committee,
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        tx_committer,
        /* tx_proposer */ tx_parents,
        rx_validation,
        tx_sailfish,
        rx_pushdown_cert,
        rx_request_header_sync
    );

//  // Send a normal header to the core. 
//     tx_primary_messages
//         .send(PrimaryMessage::Header(header()))
//         .await
//         .unwrap();

    
//     //Generates vote:
//     // Ensure the listener correctly received the vote.
//     let received = handle.await.unwrap();
//     match bincode::deserialize(&received).unwrap() {
//         PrimaryMessage::Vote(x) => assert_eq!(x, expected),
//         x => panic!("Unexpected message: {:?}", x),
//     }

//     // Ensure the header is correctly stored.
//     let stored = store
//         .read(header().id.to_vec())
//         .await
//         .unwrap()
//         .map(|x| bincode::deserialize(&x).unwrap());
//     assert_eq!(stored, Some(header()));

    
//     //// Start special header
//     ////////// once we confirm parent is stored.
//     let handle = listener(address.clone());

    //Send special header with special edge = previous header
    tx_primary_messages
        .send(PrimaryMessage::Header(special_header()))
        .await
        .unwrap();

   
    //TODO: create receiver for validation
    //send back val result = correct
    let val = rx_special.recv().await.unwrap();
    tx_validation.send((val, 1u8, None, None)).await.unwrap();
    

    // Ensure the listener correctly received the vote.
    
    let received = handle.await.unwrap();
    match bincode::deserialize(&received).unwrap() {
        PrimaryMessage::Vote(x) => assert_eq!(x, special_expected),
        x => panic!("Unexpected message: {:?}", x),
    }

    // Ensure the header is correctly stored.
    let stored = store
        .read(special_header().id.to_vec())
        .await
        .unwrap()
        .map(|x| bincode::deserialize(&x).unwrap());
    assert_eq!(stored, Some(special_header()));
}*/

//todo: process special vote




/*#[tokio::test]
#[serial]
async fn process_special_votes() { 
    let (name, secret) = keys().pop().unwrap();
    let signature_service = SignatureService::new(secret);

    let committee = committee_with_base_port(13_100);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = channel(1);
    let (tx_headers, rx_headers) = channel(1);
    let (tx_consensus, _rx_consensus) = channel(1);
    let (tx_parents, _rx_parents) = channel(1);

    let(tx_committer, _rx_committer) = channel(1);
    let(tx_validation, rx_validation) = channel(1);
    let(tx_sailfish, mut rx_special) = channel(1);
    let(_tx_pushdown_cert, rx_pushdown_cert) = channel(1);
    let(_tx_request_header_sync, rx_request_header_sync) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_vote";
    let _ = fs::remove_dir_all(path);
    let store = Store::new(path).unwrap();

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee,
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    // Spawn the core.
    Core::spawn(
        name,
        committee.clone(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        tx_committer,
        /* tx_proposer */ tx_parents,
        rx_validation,
        tx_sailfish,
        rx_pushdown_cert,
        rx_request_header_sync
    );

    // Spawn all listeners to receive our newly formed certificate.
    let vote_handles: Vec<_> = committee
        .others_primaries(&name)
        .iter()
        .map(|(_, address)| listener(address.clone().primary_to_primary))
        .collect();

    //Send new special header to core (to propose itself)

    let header = special_header();
    tx_headers
        .send(header)
        .await
        .unwrap();
    //will broadcast header and process own vote

    //Ensure special header is processed first and becomes "current_header"
    sleep(Duration::from_millis(100)).await;


      // Ensure all listeners got the header.
      for received in try_join_all(vote_handles).await.unwrap() {
        match bincode::deserialize(&received).unwrap() {
            PrimaryMessage::Header(x) => assert_eq!(x, special_header()),
            x => panic!("Unexpected message: {:?}", x),
        }
    }
    //println!("received all votes");
    // // Send a votes to the core. ==> Sending only 2 votes. Supplementing quorum with own vote (called as result of process_header).
    let mut count = 0;
    for vote in special_votes(&special_header()) {
        if vote.author == name {continue;}
        tx_primary_messages
            .send(PrimaryMessage::Vote(vote))
            .await
            .unwrap();
        count = count+1;
        if count == 2 { break;}
    }

    //println!("count {}", count); 

     //send back val result = correct ==> allows us to form our own vote.
     let val = rx_special.recv().await.unwrap();
     tx_validation.send((val, name.0[0] % 2, None, None)).await.unwrap();

    //Upon receiving all votes, will broadcast cert.

    // Make the certificate we expect to receive.
    let expected = special_certificate(&special_header());
    
    // let received = rx_committer.recv().await.unwrap();
    // assert_eq!(received, expected);

    //println!("expected num votes: {}", expected.votes.len());

     // Spawn all listeners to receive our newly formed certificate.
    let cert_handles: Vec<_> = committee
    .others_primaries(&name)
    .iter()
    .map(|(_, address)| listener(address.clone().primary_to_primary))
    .collect();

    // Ensure all listeners got the certificate.
    for received in try_join_all(cert_handles).await.unwrap() {
        match bincode::deserialize(&received).unwrap() {
            PrimaryMessage::Certificate(x) => {//println!{"received cert with {} votes", x.votes.len()}; assert_eq!(x, expected)},
            x => panic!("Unexpected message: {:?}", x),
        }
    }
}*/


/*#[tokio::test]
#[serial]
async fn process_special_certificate() {
    let (name, secret) = keys().pop().unwrap();
    let signature_service = SignatureService::new(secret);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(3);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_consensus, mut _rx_consensus) = channel(3);
    let (tx_parents, mut _rx_parents) = channel(1);

    let(tx_committer, mut rx_committer) = channel(2);
    let(_tx_validation, rx_validation) = channel(1);
    let(tx_sailfish, _rx_special) = channel(3);
    let(_tx_pushdown_cert, rx_pushdown_cert) = channel(1);
    let(_tx_request_header_sync, rx_request_header_sync) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_certificates";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee(),
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    // Spawn the core.
    Core::spawn(
        name,
        committee(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        tx_committer,
        /* tx_proposer */ tx_parents,
        rx_validation,
        tx_sailfish,
        rx_pushdown_cert,
        rx_request_header_sync
    );

    //Send one special cert to core
    let cert = special_certificate(&special_header());
    tx_primary_messages
            .send(PrimaryMessage::Certificate(cert.clone()))
            .await
            .unwrap();

    //Make sure cert is stored
    //Make sure committer receives two certs, one for parent, one for self.

    // Ensure the core sends the certificates to the consensus committer.
    let expected_parent_cert = Certificate {
        header_digest: Header::genesis(&committee()).,
        ..Certificate::default()
    };
    let parent = rx_committer.recv().await.unwrap(); //TODO: Receive special parent
    assert_eq!(parent, expected_parent_cert);

    let received = rx_committer.recv().await.unwrap();
    assert_eq!(received, cert);
    
    // Ensure the certificates are stored.
    let stored = store.read(cert.digest().to_vec()).await.unwrap();
    let serialized = bincode::serialize(&cert).unwrap();
    assert_eq!(stored, Some(serialized));

}*/

/// Bug AUTOBAHN-MC-001 Reproduction: Multi-View Voting (Agreement Violation)
///
/// Demonstrates that a node can vote for Prepare messages in BOTH view 1 and
/// view 2 for the same slot.  This is the root cause of the agreement violation
/// found by TLC model checking: if all N nodes vote in both views, two
/// conflicting fast PrepareQCs form, producing two Commit messages with
/// different values for the same slot.
///
/// Reproduction level: Level 2 (state injection via ConsensusRequest messages
/// through the Core's normal channel interface).
#[tokio::test]
#[serial]
async fn bug1_multi_view_voting() {
    let mut all_keys = keys();
    // We need to know the public keys but also pass ownership of one secret.
    // keys() returns [(pk0,sk0), (pk1,sk1), (pk2,sk2), (pk3,sk3)].
    // We'll use keys[2] as Core identity.
    let pk0 = all_keys[0].0;
    let pk1 = all_keys[1].0;
    let pk3 = all_keys[3].0;
    let pk2 = all_keys[2].0;
    let name = pk2;

    // Build fresh key sets for signing (keys() is deterministic).
    let sign_keys = keys(); // fresh copy for signatures

    // Core needs ownership of its secret key.
    let secret = keys().into_iter().nth(2).unwrap().1;

    // Use a dedicated port range to avoid collisions with other tests.
    let committee = committee_with_base_port(17_000);

    // --- channels (large buffers to avoid blocking) ---
    let (tx_sync_headers, _rx_sync_headers) = channel(100);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(100);
    let (tx_primary_messages, rx_primary_messages) = channel(100);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(100);
    let (_tx_headers, rx_headers) = channel(100);
    let (tx_parents, _rx_parents) = channel(100);
    let (tx_committer, _rx_committer) = channel(100);
    let (_tx_request_header_sync, rx_request_header_sync) = channel(100);
    let (tx_info, _rx_info) = channel(100);
    let (_tx_hwi, rx_header_waiter_instances) = channel(100);

    let path = ".db_test_bug1_multi_view";
    let _ = fs::remove_dir_all(path);
    let store = Store::new(path).unwrap();

    let synchronizer = Synchronizer::new(
        name, &committee, store.clone(), tx_sync_headers, tx_sync_certificates,
    );
    let leader_elector = LeaderElector::new(committee.clone());

    // Spawn Core: k=1 (avoids slot arithmetic underflow), timeout 60 s,
    // fast path ON.
    Core::spawn(
        name,
        committee.clone(),
        store.clone(),
        synchronizer,
        SignatureService::new(secret),
        Arc::new(AtomicU64::new(0)),
        50,  // gc_depth
        rx_primary_messages,
        rx_headers_loopback,
        rx_header_waiter_instances,
        rx_headers,
        tx_committer,
        tx_parents,
        rx_request_header_sync,
        tx_info,
        leader_elector,
        60_000, // timeout_delay – long enough to never fire during the test
        true,   // use_optimistic_tips
        true,   // use_parallel_proposals
        1,      // k
        true,   // use_fast_path
        500,    // fast_path_timeout
        false,  // use_ride_share
        500,    // car_timeout
        false, 0, 0, // simulate_asynchrony off
    );

    // Let the Core's event-loop start.
    sleep(Duration::from_millis(200)).await;

    // ── Step 1: Prepare(slot=1, view=1) via ConsensusRequest ──────────
    let genesis_proposals = Header::genesis_proposals(&committee);
    let prepare_v1 = ConsensusMessage::Prepare {
        slot: 1, view: 1, tc: None, qc_ticket: None,
        proposals: genesis_proposals.clone(),
    };

    let req_v1 = ConsensusRequest {
        author: pk3,
        message: prepare_v1.clone(),
        sig: Signature::new(&prepare_v1.digest(), &sign_keys[3].1),
    };

    // Listener at keys[3]'s address – will capture the ConsensusVote.
    let addr_3 = committee.primary(&pk3).unwrap().primary_to_primary;
    let handle_v1 = listener(addr_3);

    tx_primary_messages
        .send(PrimaryMessage::ConsensusRequest(req_v1))
        .await
        .unwrap();

    let received_v1 = handle_v1.await.unwrap();
    let vote_v1: PrimaryMessage = bincode::deserialize(&received_v1).unwrap();

    let digest_v1 = match &vote_v1 {
        PrimaryMessage::ConsensusVote(cv) => {
            println!(
                "VOTE 1: Node {} voted for Prepare(slot=1, view=1), digest={}",
                cv.author, cv.digest
            );
            assert_eq!(cv.slot, 1);
            assert_eq!(cv.digest, prepare_v1.digest());
            cv.digest.clone()
        }
        other => panic!("Expected ConsensusVote for view 1, got: {:?}", other),
    };

    // ── Step 2: Send 3 Timeouts → TC forms → view advances to 2 ──────
    let t0 = Timeout::new_from_key(None, None, 1, 1, pk0, &sign_keys[0].1);
    let t1 = Timeout::new_from_key(None, None, 1, 1, pk1, &sign_keys[1].1);
    let t3 = Timeout::new_from_key(None, None, 1, 1, pk3, &sign_keys[3].1);

    tx_primary_messages.send(PrimaryMessage::Timeout(t0.clone())).await.unwrap();
    tx_primary_messages.send(PrimaryMessage::Timeout(t1.clone())).await.unwrap();
    tx_primary_messages.send(PrimaryMessage::Timeout(t3.clone())).await.unwrap();

    // Give Core time to form TC and advance view.
    sleep(Duration::from_millis(500)).await;

    // ── Step 3: Prepare(slot=1, view=2) via ConsensusRequest ──────────
    let tc = TC::new(&committee, 1, 1, vec![t0, t1, t3]);
    let prepare_v2 = ConsensusMessage::Prepare {
        slot: 1, view: 2, tc: Some(tc), qc_ticket: None,
        proposals: genesis_proposals.clone(),
    };

    let req_v2 = ConsensusRequest {
        author: pk0,
        message: prepare_v2.clone(),
        sig: Signature::new(&prepare_v2.digest(), &sign_keys[0].1),
    };

    let addr_0 = committee.primary(&pk0).unwrap().primary_to_primary;
    let handle_v2 = listener(addr_0);

    tx_primary_messages
        .send(PrimaryMessage::ConsensusRequest(req_v2))
        .await
        .unwrap();

    let received_v2 = handle_v2.await.unwrap();
    let vote_v2: PrimaryMessage = bincode::deserialize(&received_v2).unwrap();

    let digest_v2 = match &vote_v2 {
        PrimaryMessage::ConsensusVote(cv) => {
            println!(
                "VOTE 2: Node {} voted for Prepare(slot=1, view=2), digest={}",
                cv.author, cv.digest
            );
            assert_eq!(cv.slot, 1);
            assert_eq!(cv.digest, prepare_v2.digest());
            cv.digest.clone()
        }
        other => panic!("Expected ConsensusVote for view 2, got: {:?}", other),
    };

    // ── Verification ──────────────────────────────────────────────────
    assert_ne!(
        digest_v1, digest_v2,
        "Digests must differ (same slot, different views/proposals)"
    );

    println!();
    println!("=== BUG AUTOBAHN-MC-001 CONFIRMED ===");
    println!("Node voted for BOTH Prepare(slot=1, view=1) AND Prepare(slot=1, view=2).");
    println!("With all N nodes behaving identically, two fast PrepareQCs form,");
    println!("producing conflicting Commit messages → Agreement violation.");

    let _ = fs::remove_dir_all(path);
}

/// BUG-03 Reproduction (Core level): Missing Confirm Double-Vote Protection
///
/// The is_valid() Confirm branch (core.rs:1235-1246) does NOT check
/// last_voted_consensus, unlike the Prepare branch. A node processes and
/// votes for two Confirm ConsensusRequests for the same (slot, view),
/// demonstrating the missing deduplication.
///
/// Uses genesis proposals so the synchronizer can resolve them.
///
/// Reproduction level: Level 2 (state injection via ConsensusRequest).
#[tokio::test]
#[serial]
async fn bug3_confirm_double_vote() {
    use ed25519_dalek::Digest as _;
    use std::convert::TryInto;

    let all_keys = keys();
    let pk0 = all_keys[0].0;
    let pk2 = all_keys[2].0;
    let pk3 = all_keys[3].0;
    let name = pk2;

    let sign_keys = keys();
    let secret = keys().into_iter().nth(2).unwrap().1;
    let committee = committee_with_base_port(25_000);

    let (tx_sync_headers, _rx_sync_h) = channel(100);
    let (tx_sync_certs, _rx_sync_c) = channel(100);
    let (tx_primary, rx_primary) = channel(100);
    let (_, rx_headers_loopback) = channel(100);
    let (_, rx_headers) = channel(100);
    let (tx_parents, _rx_parents) = channel(100);
    let (tx_committer, _rx_committer) = channel(100);
    let (_, rx_request) = channel(100);
    let (tx_info, _rx_info) = channel(100);
    let (_, rx_hwi) = channel(100);

    let path = ".db_test_bug3_confirm_double_vote";
    let _ = fs::remove_dir_all(path);
    let store = Store::new(path).unwrap();
    let synchronizer = Synchronizer::new(
        name, &committee, store.clone(), tx_sync_headers, tx_sync_certs,
    );
    let leader = LeaderElector::new(committee.clone());

    Core::spawn(
        name, committee.clone(), store.clone(), synchronizer,
        SignatureService::new(secret),
        Arc::new(AtomicU64::new(0)),
        50, rx_primary, rx_headers_loopback, rx_hwi, rx_headers,
        tx_committer, tx_parents, rx_request, tx_info, leader,
        60_000, true, true, 1, true, 500, false, 500, false, 0, 0,
    );

    sleep(Duration::from_millis(200)).await;

    let slot: u64 = 1;
    let view: u64 = 1;
    let genesis_proposals = Header::genesis_proposals(&committee);

    // Build prepare_id = hash(slot, view, 0) — proposal_digest omitted (BUG-01)
    let prepare_id = {
        let mut h = ed25519_dalek::Sha512::new();
        h.update(slot.to_le_bytes());
        h.update(view.to_le_bytes());
        h.update((0u8).to_le_bytes());
        Digest(h.finalize().as_slice()[..32].try_into().unwrap())
    };

    // Build PrepareQC with 3-of-4 signatures
    let qc_votes: Vec<(PublicKey, Signature)> = sign_keys.iter().take(3)
        .map(|(pk, sk)| (*pk, Signature::new(&prepare_id, sk)))
        .collect();
    let prepare_qc = QC { id: prepare_id, votes: qc_votes };

    // Build Confirm using genesis proposals (resolvable by synchronizer)
    let confirm = ConsensusMessage::Confirm {
        slot, view, qc: prepare_qc, proposals: genesis_proposals,
    };

    // --- Send first Confirm from pk3 ---
    let req1 = ConsensusRequest {
        author: pk3,
        message: confirm.clone(),
        sig: Signature::new(&confirm.digest(), &sign_keys[3].1),
    };
    let addr_3 = committee.primary(&pk3).unwrap().primary_to_primary;
    let handle1 = listener(addr_3);

    tx_primary.send(PrimaryMessage::ConsensusRequest(req1)).await.unwrap();

    let data1 = handle1.await.unwrap();
    match bincode::deserialize::<PrimaryMessage>(&data1).unwrap() {
        PrimaryMessage::ConsensusVote(cv) => {
            println!("VOTE 1: ConfirmVote(slot={}, digest={})", cv.slot, cv.digest);
            assert_eq!(cv.slot, 1);
        }
        other => panic!("Expected ConsensusVote, got: {:?}", other),
    };

    // --- Send SAME Confirm from pk0 (second vote) ---
    // BUG-03: is_valid() Confirm branch has no last_voted_consensus check,
    // so the node votes again for the same (slot, view).
    let req2 = ConsensusRequest {
        author: pk0,
        message: confirm.clone(),
        sig: Signature::new(&confirm.digest(), &sign_keys[0].1),
    };
    let addr_0 = committee.primary(&pk0).unwrap().primary_to_primary;
    let handle2 = listener(addr_0);

    tx_primary.send(PrimaryMessage::ConsensusRequest(req2)).await.unwrap();

    let data2 = handle2.await.unwrap();
    match bincode::deserialize::<PrimaryMessage>(&data2).unwrap() {
        PrimaryMessage::ConsensusVote(cv) => {
            println!("VOTE 2: ConfirmVote(slot={}, digest={})", cv.slot, cv.digest);
            assert_eq!(cv.slot, 1);
        }
        other => panic!("Expected ConsensusVote (second), got: {:?}", other),
    };

    println!();
    println!("=== BUG-03 CONFIRMED ===");
    println!("Node voted TWICE for Confirm(slot=1, view=1) — no deduplication.");
    println!("With different proposals (via BUG-01), this produces conflicting ConfirmQCs.");

    let _ = fs::remove_dir_all(path);
}

/// BUG-04 Reproduction: View Advancement Side-Effect on Rejected Messages
///
/// The is_valid() Prepare branch (core.rs:1226-1229) advances the node's
/// local view BEFORE checking ticket_valid and last_voted_consensus.
/// A rejected Prepare for a higher view corrupts the node's view, preventing
/// it from participating in legitimate lower views.
///
/// Reproduction level: Level 2 (state injection via ConsensusRequest).
#[tokio::test]
#[serial]
async fn bug4_view_advance_side_effect() {
    let all_keys = keys();
    let pk0 = all_keys[0].0;
    let pk2 = all_keys[2].0;
    let pk3 = all_keys[3].0;
    let name = pk2;

    let sign_keys = keys();
    let secret = keys().into_iter().nth(2).unwrap().1;
    let committee = committee_with_base_port(26_000);

    let (tx_sync_headers, _rx_sync_h) = channel(100);
    let (tx_sync_certs, _rx_sync_c) = channel(100);
    let (tx_primary, rx_primary) = channel(100);
    let (_, rx_headers_loopback) = channel(100);
    let (_, rx_headers) = channel(100);
    let (tx_parents, _rx_parents) = channel(100);
    let (tx_committer, _rx_committer) = channel(100);
    let (_, rx_request) = channel(100);
    let (tx_info, _rx_info) = channel(100);
    let (_, rx_hwi) = channel(100);

    let path = ".db_test_bug4_view_advance";
    let _ = fs::remove_dir_all(path);
    let store = Store::new(path).unwrap();
    let synchronizer = Synchronizer::new(
        name, &committee, store.clone(), tx_sync_headers, tx_sync_certs,
    );
    let leader = LeaderElector::new(committee.clone());

    Core::spawn(
        name, committee.clone(), store.clone(), synchronizer,
        SignatureService::new(secret),
        Arc::new(AtomicU64::new(0)),
        50, rx_primary, rx_headers_loopback, rx_hwi, rx_headers,
        tx_committer, tx_parents, rx_request, tx_info, leader,
        60_000, true, true, 1, true, 500, false, 500, false, 0, 0,
    );

    sleep(Duration::from_millis(200)).await;

    let genesis_proposals = Header::genesis_proposals(&committee);

    // Step 1: Send INVALID Prepare(slot=1, view=3, tc=None).
    // tc=None means ticket_valid = (view == 1) = false for view=3.
    // But the view is advanced to 3 as a SIDE-EFFECT before rejection.
    let invalid_prepare = ConsensusMessage::Prepare {
        slot: 1, view: 3, tc: None, qc_ticket: None,
        proposals: genesis_proposals.clone(),
    };
    let req_invalid = ConsensusRequest {
        author: pk3,
        message: invalid_prepare.clone(),
        sig: Signature::new(&invalid_prepare.digest(), &sign_keys[3].1),
    };

    tx_primary.send(PrimaryMessage::ConsensusRequest(req_invalid)).await.unwrap();
    sleep(Duration::from_millis(300)).await;
    println!("Step 1: Sent INVALID Prepare(slot=1, view=3, tc=None) — rejected.");

    // Step 2: Send VALID Prepare(slot=1, view=1, tc=None).
    // This SHOULD succeed (view 1 with tc=None is valid).
    // BUG-04: It is REJECTED because views[1] was corrupted to 3.
    let valid_prepare = ConsensusMessage::Prepare {
        slot: 1, view: 1, tc: None, qc_ticket: None,
        proposals: genesis_proposals.clone(),
    };
    let req_valid = ConsensusRequest {
        author: pk0,
        message: valid_prepare.clone(),
        sig: Signature::new(&valid_prepare.digest(), &sign_keys[0].1),
    };

    let addr_0 = committee.primary(&pk0).unwrap().primary_to_primary;
    let handle = listener(addr_0);

    tx_primary.send(PrimaryMessage::ConsensusRequest(req_valid)).await.unwrap();

    // If bug exists, no vote is sent — the listener times out.
    let result = tokio::time::timeout(Duration::from_millis(2000), handle).await;

    match result {
        Ok(Ok(data)) => {
            let msg: PrimaryMessage = bincode::deserialize(&data).unwrap();
            panic!("BUG-04 not triggered: node voted despite view corruption. Got: {:?}", msg);
        }
        Ok(Err(e)) => panic!("Listener error: {:?}", e),
        Err(_timeout) => {
            println!("Step 2: VALID Prepare(slot=1, view=1) — NO vote received (2s timeout).");
            println!();
            println!("=== BUG-04 CONFIRMED ===");
            println!("Invalid Prepare(view=3) advanced views[1] from 0 to 3 as side-effect.");
            println!("Valid Prepare(view=1) rejected because views[1]=3 != 1.");
        }
    }

    let _ = fs::remove_dir_all(path);
}
