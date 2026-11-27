//! The receipt across Berlin midnight (GPKE Teil 1 Kap. 7: the time of
//! receipt is taken from the positive AS4 receipt). A manual clock makes the
//! handler return after the midnight it started before; the record must say
//! which instant is the handoff and which the receipt, and both must equal
//! what the signed receipt carries. A retransmission gets a fresh receipt
//! with its own record.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::as4::{As4, Message, UserMessage};
use crate::clock::{ManualClock, SharedClock};
use crate::testkit::audit::MemoryAuditSink;
use crate::testkit::loopback::Loopback;
use crate::testkit::pki::TestCa;
use crate::{AuditOutcome, MemoryDedup, Payload, Profile, Reject, Verified};

const A_URL: &str = "https://a.example/as4";
const B_URL: &str = "https://b.example/as4";
const EB: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/";

/// Unix seconds of a proleptic-Gregorian civil date (Howard Hinnant).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Unix seconds of the last Sunday of `month`, 01:00 UTC (the EU DST switch).
fn last_sunday_0100_utc(year: i64, month: i64) -> i64 {
    let last = days_from_civil(year, month + 1, 1) - 1;
    // 1970-01-01 was a Thursday: (days + 4) % 7 == 0 is a Sunday.
    let sunday = last - (last + 4).rem_euclid(7);
    sunday * 86_400 + 3600
}

/// Europe/Berlin's UTC offset at `utc` (CET +1 h, CEST +2 h).
fn berlin_offset(utc: i64) -> i64 {
    let (year, _, _) = civil_from_days(utc.div_euclid(86_400));
    let summer = last_sunday_0100_utc(year, 3) <= utc && utc < last_sunday_0100_utc(year, 10);
    if summer { 7200 } else { 3600 }
}

/// Berlin's calendar date at `t`.
fn berlin_date(t: SystemTime) -> (i64, i64, i64) {
    let utc = t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    civil_from_days((utc + berlin_offset(utc)).div_euclid(86_400))
}

/// The first Berlin midnight after `now`, as a UTC instant.
fn next_berlin_midnight(now: SystemTime) -> SystemTime {
    let utc = now.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let local_day = (utc + berlin_offset(utc)).div_euclid(86_400);
    let local_midnight = (local_day + 1) * 86_400;
    // The offset in force just after midnight (DST never switches at 00:00).
    let midnight = local_midnight - berlin_offset(local_midnight - 3600);
    UNIX_EPOCH + Duration::from_secs(midnight as u64)
}

/// `(eb:MessageId, eb:Timestamp)` of the receipt bytes, by a plain
/// `roxmltree` read of `eb:SignalMessage/eb:MessageInfo` — not through the
/// library's receipt builder or parser.
fn receipt_identity(wire: &[u8]) -> (String, String) {
    let doc = roxmltree::Document::parse(std::str::from_utf8(wire).unwrap()).unwrap();
    let info = doc
        .descendants()
        .find(|n| n.has_tag_name((EB, "SignalMessage")))
        .and_then(|n| n.children().find(|c| c.has_tag_name((EB, "MessageInfo"))))
        .expect("eb:SignalMessage/eb:MessageInfo");
    let text = |name| {
        info.children()
            .find(|c| c.has_tag_name((EB, name)))
            .and_then(|c| c.text())
            .unwrap()
            .to_string()
    };
    (text("MessageId"), text("Timestamp"))
}

#[test]
fn berlin_midnight_helpers() {
    // 2026-11-27 is CET: midnight is 23:00 UTC the day before.
    let nov = UNIX_EPOCH + Duration::from_secs(days_from_civil(2026, 11, 27) as u64 * 86_400);
    assert_eq!(
        next_berlin_midnight(nov + Duration::from_secs(12 * 3600)),
        UNIX_EPOCH + Duration::from_secs((days_from_civil(2026, 11, 28) * 86_400 - 3600) as u64)
    );
    // 2026-07-01 is CEST: 22:00 UTC.
    let jul = UNIX_EPOCH + Duration::from_secs(days_from_civil(2026, 7, 1) as u64 * 86_400);
    assert_eq!(
        next_berlin_midnight(jul + Duration::from_secs(12 * 3600)),
        UNIX_EPOCH + Duration::from_secs((days_from_civil(2026, 7, 2) * 86_400 - 7200) as u64)
    );
    assert_eq!(
        last_sunday_0100_utc(2026, 3),
        days_from_civil(2026, 3, 29) * 86_400 + 3600
    );
    assert_eq!(
        last_sunday_0100_utc(2026, 10),
        days_from_civil(2026, 10, 25) * 86_400 + 3600
    );
}

/// A handler that starts 600 ms before Berlin midnight and returns 300 ms
/// after it: the record keeps the handoff on the old day and the receipt on
/// the new one, both equal to what the wire carries, under one `record_id`.
/// The retransmission gets a fresh receipt and its own `duplicate` record.
#[tokio::test]
async fn a_receipt_after_berlin_midnight_is_recorded_on_the_new_day() {
    let midnight = next_berlin_midnight(crate::clock::system().now());
    let start = midnight - Duration::from_millis(600);
    let manual = ManualClock::at(start);
    let clock: SharedClock = manual.clone();

    let ca = TestCa::sm_pki();
    let (a, b) = (
        ca.bdew_party_at("9900000000001", A_URL),
        ca.bdew_party_at("9900000000002", B_URL),
    );
    let loopback = Loopback::new();
    let sender = As4::builder(Profile::bdew())
        .clock(clock.clone())
        .local(a.local())
        .trust_anchor(ca.anchor())
        .partner(b.partner(B_URL))
        .http_client(loopback.clone())
        .build()
        .expect("sender builds");
    let sink = MemoryAuditSink::new();
    let receiver = As4::builder(Profile::bdew())
        .clock(clock.clone())
        .local(b.local())
        .trust_anchor(ca.anchor())
        .partner(a.partner(A_URL))
        .http_client(loopback.clone())
        .audit(sink.clone())
        .build()
        .expect("receiver builds");
    let handler_ids: Arc<Mutex<Vec<String>>> = Arc::default();
    let inbound = {
        let (ids, manual) = (handler_ids.clone(), manual.clone());
        receiver.inbound(MemoryDedup::default(), move |m: Verified<UserMessage>| {
            ids.lock()
                .unwrap()
                .push(m.evidence().record_id().to_string());
            // The application works across midnight.
            manual.advance(Duration::from_millis(900));
            async { Ok::<(), Reject>(()) }
        })
    };
    loopback.mount(B_URL, inbound);
    let responses: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    {
        let responses = responses.clone();
        loopback.intercept(move |r| responses.lock().unwrap().push(r.body().to_vec()));
    }

    let payload = Payload::new(&b"UNB+UNOC:3"[..], "application/octet-stream")
        .named("UTILMD.txt")
        .property("BDEWDocumentType", "UTILMD")
        .property("BDEWDocumentDate", "2026-11-27")
        .property("BDEWDocumentNo", "MIDNIGHT1");
    let message = Message::to(&b.partner(B_URL))
        .service("https://www.bdew.de/as4/communication/services/MP")
        .message_id("midnight@asx.test")
        .payload(payload);
    let receipt = sender.send(message).await.expect("receipted");
    let request = loopback.last_request().unwrap();

    // ── The accepted leg ────────────────────────────────────────────────
    let records = sink.records();
    assert_eq!(records.len(), 1);
    let accepted = &records[0];
    assert_eq!(accepted.outcome(), AuditOutcome::Accepted);
    assert_eq!(accepted.message_id(), "midnight@asx.test");
    assert_eq!(
        handler_ids.lock().unwrap().as_slice(),
        [accepted.record_id()]
    );
    let handed_off = accepted.handed_off_at().expect("the handler ran");
    assert_eq!(handed_off, start, "the handoff instant");
    let issued = accepted.receipt().expect("the issued receipt");
    let issued_at = issued.timestamp().unwrap();
    assert_eq!(
        issued_at,
        start + Duration::from_millis(900),
        "after the handler"
    );
    assert!(handed_off < midnight && midnight <= issued_at);
    assert_ne!(
        berlin_date(handed_off),
        berlin_date(issued_at),
        "two Berlin days"
    );
    // The record equals the signed receipt on the wire, and the sender's
    // verified receipt.
    let wire = responses.lock().unwrap()[0].clone();
    assert_eq!(accepted.signal(), Some(wire.as_slice()));
    let (wire_id, wire_ts) = receipt_identity(&wire);
    assert_eq!(issued.message_id(), Some(wire_id.as_str()));
    assert_eq!(
        crate::time_utils::parse_xsd_datetime(&wire_ts),
        Some(issued_at)
    );
    assert_eq!(wire_ts.len(), "2026-11-27T23:00:00.300Z".len(), "{wire_ts}");
    assert_eq!(*receipt, issued);

    // ── The retransmission ──────────────────────────────────────────────
    manual.advance(Duration::from_secs(30));
    let again = loopback.exchange(request).await.expect("answered");
    assert_eq!(again.status(), http::StatusCode::OK);
    let records = sink.records();
    assert_eq!(records.len(), 2);
    let duplicate = &records[1];
    assert_eq!(duplicate.outcome(), AuditOutcome::Duplicate);
    assert_eq!(duplicate.message_id(), "midnight@asx.test");
    assert_ne!(duplicate.record_id(), accepted.record_id());
    assert_eq!(duplicate.handed_off_at(), None, "the handler did not run");
    assert_eq!(handler_ids.lock().unwrap().len(), 1);
    let fresh = duplicate.receipt().unwrap();
    let (dup_id, dup_ts) = receipt_identity(again.body());
    assert_eq!(fresh.message_id(), Some(dup_id.as_str()));
    assert_ne!(fresh.message_id(), issued.message_id(), "a fresh receipt");
    assert_eq!(
        crate::time_utils::parse_xsd_datetime(&dup_ts),
        fresh.timestamp()
    );
    assert_eq!(fresh.timestamp(), Some(issued_at + Duration::from_secs(30)));
}
