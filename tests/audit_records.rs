#![cfg(feature = "as4")]
//! One audit record per exchange leg, with the evidence checked against the
//! wire. Fields are asserted
//! through the record's JSON form, which is the stored-data contract — the
//! record itself is opaque.

#[path = "common/peers.rs"]
mod peers;
#[allow(unreachable_pub)]
#[path = "common/ported_as4.rs"]
mod ported;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use asx::testkit::audit::MemoryAuditSink;
use asx::testkit::loopback::Loopback;
use asx::{AuditDurability, AuditRecord, ErrorKind};
use base64::Engine as _;
use peers::{HANDLER_ERR, Preset, pair};
use ported::{FailingSink, Log, LoggingDedup, LoggingSink};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn only(sink: &MemoryAuditSink) -> Value {
    let records = sink.records_json();
    assert_eq!(records.len(), 1, "exactly one record: {records:#?}");
    records.into_iter().next().expect("one record")
}

fn assert_uuid_v7(id: &str) {
    assert_eq!(id.len(), 36, "{id}");
    assert_eq!(&id[14..15], "7", "UUIDv7: {id}");
}

/// Keep every response body the sender sees.
fn capture_responses(loopback: &Loopback) -> Arc<Mutex<Vec<Vec<u8>>>> {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = captured.clone();
    loopback.intercept(move |resp| sink.lock().unwrap().push(resp.body().to_vec()));
    captured
}

const EB: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/";

/// `(eb:MessageId, eb:Timestamp)` of a signal's `eb:SignalMessage`, read by
/// an independent XML parse of the bytes on the wire (not the library's
/// receipt builder).
fn signal_identity(wire: &[u8]) -> (String, String) {
    let text = std::str::from_utf8(wire).expect("a SOAP signal is UTF-8");
    let doc = roxmltree::Document::parse(text).expect("the signal parses");
    let info = doc
        .descendants()
        .find(|n| n.has_tag_name((EB, "SignalMessage")))
        .and_then(|n| n.children().find(|c| c.has_tag_name((EB, "MessageInfo"))))
        .expect("eb:SignalMessage/eb:MessageInfo");
    let child = |name: &str| {
        info.children()
            .find(|c| c.has_tag_name((EB, name)))
            .and_then(|c| c.text())
            .unwrap_or_else(|| panic!("eb:{name}"))
            .to_string()
    };
    (child("MessageId"), child("Timestamp"))
}

fn rfc3339_millis(t: std::time::SystemTime) -> String {
    let ms = t.duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    chrono_free_format(ms)
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` of Unix milliseconds (civil-from-days, Howard
/// Hinnant), so the test does not reuse the library's formatter.
fn chrono_free_format(ms: i64) -> String {
    let (secs, millis) = (ms.div_euclid(1000), ms.rem_euclid(1000));
    let (days, tod) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        tod / 3600,
        tod % 3600 / 60,
        tod % 60
    )
}

fn triples(v: &Value) -> Vec<(String, String, String)> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["uri"].as_str().unwrap().to_owned(),
                e["digest_algorithm"].as_str().unwrap().to_owned(),
                e["digest"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

// ── Send side ───────────────────────────────────────────────────────────────

/// (a) An AS4 send answered by a signed NRR receipt: one `delivered` record
/// whose evidence is the receipt as received, also returned as the
/// `Verified` receipt's evidence.
#[tokio::test]
async fn as4_send_with_signed_nrr_receipt_leaves_one_delivered_record() {
    let p = pair(Preset::Bdew);
    let responses = capture_responses(&p.loopback);
    let message = Preset::Bdew
        .message(&p.to_b, b"audit-payload")
        .message_id("audit-delivered@asx.test");
    let receipt = p.sender.send(message).await.expect("verified receipt");
    let wire = responses.lock().unwrap().pop().expect("a response");

    assert_eq!(p.sender_audit.records(), vec![receipt.evidence().clone()]);
    let r = only(&p.sender_audit);
    assert_uuid_v7(r["record_id"].as_str().unwrap());
    assert_eq!(r["protocol"], "as4");
    assert_eq!(r["direction"], "outbound");
    assert_eq!(r["outcome"], "delivered");
    assert_eq!(r["message_id"], "audit-delivered@asx.test");
    assert_eq!(r["local_party"], p.a.id.as_str());
    assert_eq!(r["partner"], p.b.id.as_str());
    assert_eq!(r["profile"], "bdew-1.2");
    assert_eq!(r["quirks"], serde_json::json!([]));
    assert_eq!(r["disposition"], "receipt");
    assert_eq!(r["error_kind"], Value::Null);
    assert!(r["message_timestamp"].is_string(), "the sent eb:Timestamp");
    // The receipt exactly as received.
    assert_eq!(r["signal"]["bytes"], b64(&wire));
    assert_eq!(r["signal"]["sha256"], sha256_hex(&wire));
    assert_eq!(r["signal"]["ref_to_message_id"], "audit-delivered@asx.test");
    assert_eq!(r["signal"]["signed"], true);
    assert!(
        r["signal"]["timestamp"].is_string(),
        "eb:Timestamp verbatim"
    );
    let text = String::from_utf8_lossy(&wire);
    let timestamp = r["signal"]["timestamp"].as_str().unwrap();
    assert!(
        text.contains(&format!("Timestamp>{timestamp}<")),
        "{timestamp}"
    );
    // The NRR digest list is the list of references we signed.
    let nrr = triples(&r["signal"]["nrr"]);
    assert!(!nrr.is_empty());
    assert_eq!(triples(&r["references"]), nrr);
    for (_, _, digest) in &nrr {
        assert!(text.contains(digest.as_str()), "{digest} is in the receipt");
    }
    // The typed receipt: the partner's id and time, from the record.
    let (receipt_id, receipt_ts) = signal_identity(&wire);
    assert_eq!(receipt.message_id(), Some(receipt_id.as_str()));
    assert_eq!(rfc3339_millis(receipt.timestamp().unwrap()), receipt_ts);
    assert_eq!(receipt.evidence().receipt().as_ref(), Some(&*receipt));
    assert_eq!(receipt.evidence().outcome(), asx::AuditOutcome::Delivered);
    assert_eq!(receipt.evidence().handed_off_at(), None);
    // The receiver recorded the same receipt it sent.
    assert_eq!(
        p.receiver_audit.records()[0].receipt().as_ref(),
        Some(&*receipt)
    );
    // The receipt signer.
    let receiver = p.b.signing.certificate();
    assert_eq!(receipt.signer(), &receiver);
    assert_eq!(r["signer"]["certificate_der"], b64(receiver.der()));
    assert_eq!(
        r["signer"]["fingerprint_sha256"],
        sha256_hex(receiver.der())
    );
}

/// (b) The partner answers with an `eb:Error`: one `partner_error` record
/// carrying the ebMS code, which is also the error's evidence.
#[tokio::test]
async fn as4_send_answered_by_an_error_signal_leaves_a_partner_error_record() {
    let p = pair(Preset::Bdew);
    p.mode.store(HANDLER_ERR, Ordering::SeqCst);
    let responses = capture_responses(&p.loopback);
    let err = p
        .sender
        .send(Preset::Bdew.message(&p.to_b, b"x"))
        .await
        .expect_err("refused");
    assert_eq!(err.kind(), ErrorKind::PartnerError, "{err}");
    let wire = responses.lock().unwrap().pop().expect("a response");

    let r = only(&p.sender_audit);
    assert_eq!(err.evidence(), Some(&p.sender_audit.records()[0]));
    assert_eq!(r["outcome"], "partner_error");
    assert_eq!(r["error_kind"], "partner_error");
    assert_eq!(r["ebms_code"], "EBMS:0202");
    assert_eq!(r["disposition"], "error");
    assert_eq!(r["signal"]["bytes"], b64(&wire));
    assert!(r["signal"]["message_id"].is_string());
    // An eb:Error is not a receipt (GPKE: only a positive receipt counts).
    let record = err.evidence().unwrap();
    assert_eq!(record.outcome(), asx::AuditOutcome::PartnerError);
    assert_eq!(record.receipt(), None);
}

/// A response that verifies as neither: `indeterminate`, with the bytes.
#[tokio::test]
async fn as4_send_with_an_unverifiable_response_leaves_an_indeterminate_record() {
    let p = pair(Preset::Bdew);
    p.loopback
        .intercept(|resp| *resp.body_mut() = bytes::Bytes::from_static(b"<not-a-signal/>"));
    let err = p
        .sender
        .send(Preset::Bdew.message(&p.to_b, b"x"))
        .await
        .expect_err("not a signal");
    assert_eq!(err.kind(), ErrorKind::Indeterminate, "{err}");

    let r = only(&p.sender_audit);
    assert_eq!(err.evidence(), Some(&p.sender_audit.records()[0]));
    assert_eq!(r["outcome"], "indeterminate");
    assert_eq!(r["error_kind"], "indeterminate");
    assert_eq!(r["signal"]["bytes"], b64(b"<not-a-signal/>"));
    assert_eq!(r["signal"]["signed"], false);
}

// ── Receive side ────────────────────────────────────────────────────────────

/// (e) An authenticated inbound message: one `accepted` record with the
/// sender's certificate, the references it signed and the receipt issued,
/// written before the dedup claim is accepted.
#[tokio::test]
async fn as4_receive_leaves_an_accepted_record_before_the_claim_is_settled() {
    let p = pair(Preset::Bdew);
    let responses = capture_responses(&p.loopback);
    p.sender
        .send(
            Preset::Bdew
                .message(&p.to_b, b"x")
                .message_id("audit-inbound@asx.test"),
        )
        .await
        .expect("delivered");
    let request = p.loopback.last_request().unwrap();
    let wire = responses.lock().unwrap().pop().expect("the receipt");

    // The same message to a second receiver whose sink and store log.
    let log: Log = Arc::default();
    let sink = LoggingSink(MemoryAuditSink::new(), log.clone());
    let logged = ported::client(
        Preset::Bdew.profile(),
        &p.ca,
        &p.b,
        p.a.partner(peers::A_URL),
        &Loopback::new(),
        |b| b.audit(sink.clone()),
    );
    let inbound = ported::accepting_inbound(
        &logged,
        LoggingDedup(Arc::new(asx::MemoryDedup::default()), log.clone()),
    );
    let (status, _) = ported::post(&inbound, ported::clone_request(&request)).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(*log.lock().unwrap(), ["claim", "record", "accept"]);
    assert_eq!(sink.0.records().len(), 1);

    let r = only(&p.receiver_audit);
    assert_uuid_v7(r["record_id"].as_str().unwrap());
    assert_eq!(r["protocol"], "as4");
    assert_eq!(r["direction"], "inbound");
    assert_eq!(r["outcome"], "accepted");
    assert_eq!(r["message_id"], "audit-inbound@asx.test");
    assert_eq!(r["partner"], p.a.id.as_str());
    assert_eq!(r["local_party"], p.b.id.as_str());
    assert_eq!(r["profile"], "bdew-1.2");
    assert!(r["message_timestamp"].is_string());
    // BDEW carries no eb:ConversationId: the field is
    // present and null.
    assert_eq!(r.get("conversation_id"), Some(&Value::Null));
    let sender = p.a.signing.certificate();
    assert_eq!(r["signer"]["certificate_der"], b64(sender.der()));
    assert_eq!(r["signer"]["fingerprint_sha256"], sha256_hex(sender.der()));
    let uris: Vec<&str> = r["references"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["uri"].as_str().unwrap())
        .collect();
    assert!(uris.iter().any(|u| u.starts_with("cid:")), "{uris:?}");
    assert!(uris.iter().any(|u| u.starts_with('#')), "{uris:?}");
    // The receipt the receiver issued, exactly as sent, with its own id and
    // time as written in it.
    assert_eq!(r["signal"]["bytes"], b64(&wire));
    assert_eq!(r["signal"]["ref_to_message_id"], "audit-inbound@asx.test");
    assert_eq!(r["signal"]["signed"], true);
    let (receipt_id, receipt_ts) = signal_identity(&wire);
    assert_eq!(r["signal"]["message_id"], receipt_id.as_str());
    assert_eq!(r["signal"]["timestamp"], receipt_ts.as_str());
    assert_eq!(
        receipt_ts.len(),
        "2026-11-27T22:59:59.400Z".len(),
        "{receipt_ts}"
    );
    let record = &p.receiver_audit.records()[0];
    assert_eq!(record.outcome(), asx::AuditOutcome::Accepted);
    let receipt = record.receipt().expect("a positive receipt");
    assert_eq!(receipt.message_id(), Some(receipt_id.as_str()));
    assert_eq!(rfc3339_millis(receipt.timestamp().unwrap()), receipt_ts);
    let handed_off = record.handed_off_at().expect("the handler ran");
    assert!(
        handed_off <= receipt.timestamp().unwrap(),
        "handoff, then receipt"
    );
}

/// The handler's `evidence()` and the stored record are one leg: one
/// `record_id`, and the handler's `recorded_at` is the stored `handed_off_at`.
#[tokio::test]
async fn the_handler_and_the_sink_see_one_record_id() {
    let p = pair(Preset::Bdew);
    p.sender
        .send(Preset::Bdew.message(&p.to_b, b"x"))
        .await
        .expect("delivered");
    let request = p.loopback.last_request().unwrap();
    let sink = MemoryAuditSink::new();
    let receiver = ported::client(
        Preset::Bdew.profile(),
        &p.ca,
        &p.b,
        p.a.partner(peers::A_URL),
        &Loopback::new(),
        |b| b.audit(sink.clone()),
    );
    let seen: Arc<Mutex<Vec<AuditRecord>>> = Arc::default();
    let inbound = {
        let seen = seen.clone();
        receiver.inbound(
            asx::MemoryDedup::default(),
            move |m: asx::Verified<asx::as4::UserMessage>| {
                seen.lock().unwrap().push(m.evidence().clone());
                async { Ok::<(), asx::Reject>(()) }
            },
        )
    };
    let (status, _) = ported::post(&inbound, request).await;
    assert_eq!(status, http::StatusCode::OK);
    let handler = seen.lock().unwrap().pop().expect("the handler ran");
    let stored = sink.records().pop().expect("one record");
    assert_eq!(handler.record_id(), stored.record_id());
    assert_eq!(handler.receipt(), None, "not issued at handoff");
    assert_eq!(handler.signal(), None);
    assert_eq!(handler.handed_off_at(), stored.handed_off_at());
    let at_handoff = serde_json::to_value(&handler).unwrap();
    assert_eq!(at_handoff["recorded_at"], at_handoff["handed_off_at"]);
    assert!(stored.receipt().is_some());
}

/// (g) A retransmission of an accepted message is answered with a fresh
/// receipt, recorded as `duplicate`: the sender may hold only this receipt,
/// whose time is the GPKE ÜZ. The handler does not run again.
#[tokio::test]
async fn a_retransmission_is_recorded_as_a_duplicate_with_its_fresh_receipt() {
    let p = pair(Preset::Bdew);
    p.sender
        .send(Preset::Bdew.message(&p.to_b, b"x"))
        .await
        .expect("delivered");
    let request = p.loopback.last_request().unwrap();
    let inbound = ported::accepting_inbound(&p.receiver, peers::SharedDedup(p.dedup.clone()));
    let (status, body) = ported::post(&inbound, request).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(p.calls.load(Ordering::SeqCst), 1, "the handler ran once");
    let records = p.receiver_audit.records();
    assert_eq!(records.len(), 2);
    let (first, again) = (&records[0], &records[1]);
    assert_eq!(first.outcome(), asx::AuditOutcome::Accepted);
    assert_eq!(again.outcome(), asx::AuditOutcome::Duplicate);
    assert_eq!(again.message_id(), first.message_id());
    assert_ne!(again.record_id(), first.record_id());
    assert_eq!(again.handed_off_at(), None, "the handler did not run");
    assert_eq!(again.signal(), Some(body.as_ref()), "the receipt as sent");
    let (id, ts) = signal_identity(&body);
    let receipt = again.receipt().expect("a duplicate's receipt is positive");
    assert_eq!(receipt.message_id(), Some(id.as_str()));
    assert_eq!(rfc3339_millis(receipt.timestamp().unwrap()), ts);
    let earlier = first.receipt().unwrap();
    assert_ne!(
        earlier.message_id(),
        receipt.message_id(),
        "a fresh receipt"
    );
    assert!(receipt.timestamp() >= earlier.timestamp());
}

/// A durable sink that fails on a duplicate withholds its receipt: the
/// retryable storage failure, never an unrecorded receipt.
#[tokio::test]
async fn a_failing_durable_sink_withholds_a_duplicates_receipt() {
    let p = pair(Preset::Bdew);
    p.sender
        .send(Preset::Bdew.message(&p.to_b, b"x"))
        .await
        .expect("delivered");
    let request = p.loopback.last_request().unwrap();
    let failing = ported::client(
        Preset::Bdew.profile(),
        &p.ca,
        &p.b,
        p.a.partner(peers::A_URL),
        &Loopback::new(),
        |b| b.audit(FailingSink(AuditDurability::Durable)),
    );
    let (status, body) = ported::post(
        &ported::accepting_inbound(&failing, peers::SharedDedup(p.dedup.clone())),
        request,
    )
    .await;
    assert_eq!(status, http::StatusCode::INTERNAL_SERVER_ERROR);
    let text = String::from_utf8_lossy(&body);
    assert!(!text.contains("Receipt>"), "no receipt: {text}");
    assert!(text.contains("EBMS:0004"), "{text}");
}

/// The test service is receipted, not delivered, and its receipt is recorded
/// (outcome accepted, no handoff).
#[tokio::test]
async fn a_test_service_receipt_is_recorded() {
    let p = pair(Preset::Bdew);
    let receipt = p
        .sender
        .send(
            asx::as4::Message::ping(&p.to_b).payload(asx::Payload::new(&b"ping"[..], "text/plain")),
        )
        .await
        .expect("a ping is receipted");
    assert_eq!(p.calls.load(Ordering::SeqCst), 0, "never delivered");
    let r = p.receiver_audit.records();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].outcome(), asx::AuditOutcome::Accepted);
    assert_eq!(r[0].handed_off_at(), None);
    assert_eq!(
        r[0].receipt().as_ref(),
        Some(&*receipt),
        "the receipt the sender verified"
    );
}

/// Every receipt the receiver signs has a record: accepted, duplicate and test
/// service, counted at the signer.
#[tokio::test]
async fn every_signed_receipt_has_a_record() {
    #[derive(Debug)]
    struct Counting(asx::KeyPair, Arc<std::sync::atomic::AtomicUsize>);
    impl asx::Signer for Counting {
        fn certificate_chain(&self) -> &[asx::Certificate] {
            self.0.certificate_chain()
        }
        fn sign<'a>(
            &'a self,
            algorithm: asx::SignatureAlgorithm,
            data: &'a [u8],
        ) -> asx::BoxFuture<'a, Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>> {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0.sign(algorithm, data)
        }
    }
    let p = pair(Preset::Bdew);
    p.sender
        .send(Preset::Bdew.message(&p.to_b, b"x"))
        .await
        .expect("delivered");
    let request = p.loopback.last_request().unwrap();
    p.sender
        .send(
            asx::as4::Message::ping(&p.to_b).payload(asx::Payload::new(&b"ping"[..], "text/plain")),
        )
        .await
        .expect("pinged");
    let ping = p.loopback.last_request().unwrap();

    let signs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sink = MemoryAuditSink::new();
    let mut local = asx::LocalParty::new(&p.b.id)
        .signer(Counting(p.b.signing.key_pair(), signs.clone()))
        .decrypter(p.b.encryption.key_pair())
        .tls_identity(p.b.tls.key_pair());
    if let Some(t) = &p.b.party_type {
        local = local.party_type(t);
    }
    let receiver = asx::as4::As4::builder(Preset::Bdew.profile())
        .local(local)
        .trust_anchor(p.ca.anchor())
        .partner(p.a.partner(peers::A_URL))
        .http_client(Loopback::new())
        .audit(sink.clone())
        .build()
        .expect("builds");
    let inbound = ported::accepting_inbound(&receiver, asx::MemoryDedup::default());
    for req in [ported::clone_request(&request), request, ping] {
        let (status, _) = ported::post(&inbound, req).await;
        assert_eq!(status, http::StatusCode::OK);
    }
    let outcomes: Vec<_> = sink.records().iter().map(AuditRecord::outcome).collect();
    use asx::AuditOutcome::{Accepted, Duplicate};
    assert_eq!(outcomes, [Accepted, Duplicate, Accepted]);
    assert_eq!(
        signs.load(Ordering::SeqCst),
        outcomes.len(),
        "one record per signature"
    );
}

/// An unauthenticated retransmission of an accepted message id (a signed
/// property altered) is refused before the dedup claim: no duplicate record,
/// no receipt.
#[tokio::test]
async fn an_unauthenticated_retransmission_writes_no_duplicate_record() {
    let p = pair(Preset::Bdew);
    p.sender
        .send(Preset::Bdew.message(&p.to_b, b"x"))
        .await
        .expect("delivered");
    assert_eq!(p.receiver_audit.records().len(), 1);
    let mut request = p.loopback.last_request().unwrap();
    let body = String::from_utf8_lossy(request.body()).into_owned();
    let forged = body.replacen("ABC123", "ABC124", 1);
    assert_ne!(forged, body, "a signed BDEW part property");
    *request.body_mut() = bytes::Bytes::from(forged);
    let inbound = ported::accepting_inbound(&p.receiver, peers::SharedDedup(p.dedup.clone()));
    let (status, _) = ported::post(&inbound, request).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST);
    assert_eq!(p.receiver_audit.records().len(), 1, "no duplicate record");
}

/// (h) An unauthenticated sender cannot write to the durable store.
#[tokio::test]
async fn an_invalid_signature_leaves_no_record() {
    let p = pair(Preset::Bdew);
    p.sender
        .send(
            Preset::Bdew
                .message(&p.to_b, b"x")
                .message_id("audit-tampered@asx.test"),
        )
        .await
        .expect("delivered");
    let mut request = p.loopback.last_request().unwrap();
    let body = String::from_utf8_lossy(request.body()).into_owned();
    let tampered = body.replacen("audit-tampered", "audit-tampereX", 1);
    assert_ne!(tampered, body);
    *request.body_mut() = bytes::Bytes::from(tampered);

    let sink = MemoryAuditSink::new();
    let receiver = ported::client(
        Preset::Bdew.profile(),
        &p.ca,
        &p.b,
        p.a.partner(peers::A_URL),
        &Loopback::new(),
        |b| b.audit(sink.clone()),
    );
    let (status, _) = ported::post(
        &ported::accepting_inbound(&receiver, asx::MemoryDedup::default()),
        request,
    )
    .await;
    assert_eq!(
        status,
        http::StatusCode::BAD_REQUEST,
        "a tampered message is refused"
    );
    assert!(sink.records().is_empty());
}

// ── Failure semantics ───────────────────────────────────────────────────────

/// (l) A durable sink that fails on receive fails the receive: no receipt
/// goes out, the claim is released, and the retransmission is processed
/// again (never answered as a duplicate).
#[tokio::test]
async fn a_failing_durable_sink_fails_the_receive_and_leaves_the_claim_unsettled() {
    let p = pair(Preset::Bdew);
    p.sender
        .send(Preset::Bdew.message(&p.to_b, b"x"))
        .await
        .expect("delivered");
    let request = p.loopback.last_request().unwrap();

    let log: Log = Arc::default();
    let dedup = LoggingDedup(Arc::new(asx::MemoryDedup::default()), log.clone());
    let failing = ported::client(
        Preset::Bdew.profile(),
        &p.ca,
        &p.b,
        p.a.partner(peers::A_URL),
        &Loopback::new(),
        |b| b.audit(FailingSink(AuditDurability::Durable)),
    );
    let (status, body) = ported::post(
        &ported::accepting_inbound(&failing, dedup.clone()),
        ported::clone_request(&request),
    )
    .await;
    assert_eq!(status, http::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        !String::from_utf8_lossy(&body).contains("Receipt>"),
        "no receipt"
    );
    assert!(!log.lock().unwrap().contains(&"accept"), "{log:?}");

    let sink = MemoryAuditSink::new();
    let working = ported::client(
        Preset::Bdew.profile(),
        &p.ca,
        &p.b,
        p.a.partner(peers::A_URL),
        &Loopback::new(),
        |b| b.audit(sink.clone()),
    );
    let (status, _) = ported::post(&ported::accepting_inbound(&working, dedup), request).await;
    assert_eq!(status, http::StatusCode::OK, "the retransmission");
    let r = only(&sink);
    assert_eq!(r["outcome"], "accepted", "processed again, not a duplicate");
}

/// A leg whose record was never written never reuses its id: the retry's
/// handler sees a new `record_id`, and the store holds exactly that one.
#[tokio::test]
async fn a_failed_leg_never_reuses_its_record_id() {
    let p = pair(Preset::Bdew);
    p.sender
        .send(Preset::Bdew.message(&p.to_b, b"x"))
        .await
        .expect("delivered");
    let request = p.loopback.last_request().unwrap();
    let dedup = Arc::new(asx::MemoryDedup::default());
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let handler = |seen: Arc<Mutex<Vec<String>>>| {
        move |m: asx::Verified<asx::as4::UserMessage>| {
            seen.lock()
                .unwrap()
                .push(m.evidence().record_id().to_string());
            async { Ok::<(), asx::Reject>(()) }
        }
    };
    let failing = ported::client(
        Preset::Bdew.profile(),
        &p.ca,
        &p.b,
        p.a.partner(peers::A_URL),
        &Loopback::new(),
        |b| b.audit(FailingSink(AuditDurability::Durable)),
    );
    let (status, _) = ported::post(
        &failing.inbound(peers::SharedDedup(dedup.clone()), handler(seen.clone())),
        ported::clone_request(&request),
    )
    .await;
    assert_eq!(status, http::StatusCode::INTERNAL_SERVER_ERROR);
    let sink = MemoryAuditSink::new();
    let working = ported::client(
        Preset::Bdew.profile(),
        &p.ca,
        &p.b,
        p.a.partner(peers::A_URL),
        &Loopback::new(),
        |b| b.audit(sink.clone()),
    );
    let (status, _) = ported::post(
        &working.inbound(peers::SharedDedup(dedup), handler(seen.clone())),
        request,
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    let ids = seen.lock().unwrap().clone();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
    let stored = sink.records();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].record_id(), ids[1]);
}

/// (m) A durable sink that fails after the receipt verified fails the send
/// with `Backend`, not retryable (the message was delivered), and keeps the
/// verified receipt as the evidence to reconcile from.
#[tokio::test]
async fn a_failing_durable_sink_fails_the_send_with_the_evidence() {
    let p = pair(Preset::Bdew);
    let sender = ported::client(
        Preset::Bdew.profile(),
        &p.ca,
        &p.a,
        p.to_b.clone(),
        &p.loopback,
        |b| b.audit(FailingSink(AuditDurability::Durable)),
    );
    let responses = capture_responses(&p.loopback);
    let err = sender
        .send(
            Preset::Bdew
                .message(&p.to_b, b"x")
                .message_id("audit-send-fail@asx.test"),
        )
        .await
        .expect_err("delivered, but the evidence is not stored");
    assert_eq!(err.kind(), ErrorKind::Backend, "{err}");
    assert!(!err.is_retryable(), "delivered: resending is not the fix");
    let wire = responses.lock().unwrap().pop().expect("the receipt");
    let evidence = serde_json::to_value(err.evidence().expect("the verified receipt")).unwrap();
    assert_eq!(evidence["outcome"], "delivered");
    assert_eq!(evidence["message_id"], "audit-send-fail@asx.test");
    assert_eq!(evidence["signal"]["sha256"], sha256_hex(&wire));
    let text = err.to_string();
    assert!(text.contains("audit-send-fail@asx.test"), "{text}");
    assert!(text.contains(&sha256_hex(&wire)), "{text}");
    assert_eq!(p.calls.load(Ordering::SeqCst), 1, "it was delivered");
}

/// (n) A best-effort sink's failure fails neither the receive nor the send.
#[tokio::test]
async fn a_failing_best_effort_sink_does_not_fail_the_exchange() {
    let p = pair(Preset::Bdew);
    let sender = ported::client(
        Preset::Bdew.profile(),
        &p.ca,
        &p.a,
        p.to_b.clone(),
        &p.loopback,
        |b| b.audit(FailingSink(AuditDurability::BestEffort)),
    );
    sender
        .send(Preset::Bdew.message(&p.to_b, b"x"))
        .await
        .expect("best-effort audit never fails the send");
    let request = p.loopback.last_request().unwrap();
    let receiver = ported::client(
        Preset::Bdew.profile(),
        &p.ca,
        &p.b,
        p.a.partner(peers::A_URL),
        &Loopback::new(),
        |b| b.audit(FailingSink(AuditDurability::BestEffort)),
    );
    let (status, body) = ported::post(
        &ported::accepting_inbound(&receiver, asx::MemoryDedup::default()),
        request,
    )
    .await;
    assert_eq!(
        status,
        http::StatusCode::OK,
        "best-effort audit never fails the receive"
    );
    assert!(String::from_utf8_lossy(&body).contains("Receipt"));
}

// ── Stored form ─────────────────────────────────────────────────────────────

/// The shape of a JSON value: object keys recursively, array element shapes,
/// and the JSON type of every leaf (null stays null).
fn shape(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            Value::Object(map.iter().map(|(k, v)| (k.clone(), shape(v))).collect())
        }
        Value::Array(items) => Value::Array(items.iter().take(1).map(shape).collect()),
        Value::String(_) => Value::String("string".into()),
        Value::Number(_) => Value::String("number".into()),
        Value::Bool(_) => Value::String("bool".into()),
        Value::Null => Value::Null,
    }
}

/// (o) The JSON form of an AS4 delivered record has the shape of the golden
/// record of the stored-data contract, byte fields in standard base64 with
/// padding, digests lowercase hex and `recorded_at` RFC 3339 UTC with
/// milliseconds; and it reads back unchanged.
#[tokio::test]
async fn json_form_matches_the_golden_shape_and_round_trips() {
    let p = pair(Preset::Edelivery);
    let receipt = p
        .sender
        .send(
            Preset::Edelivery
                .message(&p.to_b, b"x")
                .message_id("audit-golden@asx.test"),
        )
        .await
        .expect("verified exchange");
    let record = receipt.evidence();
    let json = serde_json::to_value(record).unwrap();

    let golden: Value = serde_json::from_str(
        &std::fs::read_to_string("tests/fixtures/audit/record-as4-delivered.json")
            .expect("the golden record"),
    )
    .unwrap();
    assert_eq!(shape(&json), shape(&golden), "{json:#}");
    for field in [
        "protocol",
        "direction",
        "outcome",
        "disposition",
        "mic",
        "error_kind",
        "ebms_code",
    ] {
        assert_eq!(json[field], golden[field], "{field}");
    }
    assert_eq!(json["signal"]["signed"], golden["signal"]["signed"]);

    let recorded_at = json["recorded_at"].as_str().unwrap();
    assert_eq!(
        recorded_at.len(),
        "2026-10-16T09:30:12.345Z".len(),
        "{recorded_at}"
    );
    assert!(
        recorded_at.ends_with('Z') && recorded_at.as_bytes()[19] == b'.',
        "{recorded_at}"
    );
    let bytes = json["signal"]["bytes"].as_str().unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(bytes)
            .unwrap(),
        record.signal().unwrap()
    );
    let hex = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    assert!(hex(json["signal"]["sha256"].as_str().unwrap()));
    assert!(hex(json["signer"]["fingerprint_sha256"].as_str().unwrap()));

    let back: AuditRecord = serde_json::from_value(json.clone()).expect("reads back");
    assert_eq!(&back, record);
    // Unknown fields are ignored (a record written by a newer version).
    let mut newer = json;
    newer["field_from_the_future"] = Value::Bool(true);
    let back: AuditRecord = serde_json::from_value(newer).expect("unknown fields are ignored");
    assert_eq!(&back, record);
}

/// Records from two independent clients ("two processes") into one store
/// never share an id.
#[tokio::test]
async fn record_ids_are_unique_across_clients() {
    let p = pair(Preset::Edelivery);
    let sink = MemoryAuditSink::new();
    // Every response is unverifiable, and still leaves an `indeterminate` record.
    p.loopback
        .intercept(|resp| *resp.body_mut() = bytes::Bytes::from_static(b"x"));
    let clients: Vec<_> = (0..2)
        .map(|_| {
            ported::client(
                Preset::Edelivery.profile(),
                &p.ca,
                &p.a,
                p.to_b.clone(),
                &p.loopback,
                |b| b.audit(sink.clone()),
            )
        })
        .collect();
    const PER_CLIENT: usize = 50;
    for client in &clients {
        for _ in 0..PER_CLIENT {
            let _ = client.send(Preset::Edelivery.message(&p.to_b, b"x")).await;
        }
    }
    let records = sink.records();
    assert_eq!(records.len(), 2 * PER_CLIENT);
    let ids: std::collections::HashSet<&str> = records.iter().map(AuditRecord::record_id).collect();
    assert_eq!(ids.len(), 2 * PER_CLIENT);
    assert!(ids.iter().all(|id| &id[14..15] == "7"));
}
