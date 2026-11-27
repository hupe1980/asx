//! What the library verified (`Verified<T>`), a partner's acknowledgement
//! (`Receipt`) and one payload part (`Payload`).

use crate::audit::AuditRecord;
use crate::keys::Certificate;

/// A value the library verified: signature, signer authorization,
/// revocation, replay window, decryption and digests passed. There is no
/// public constructor.
///
/// ```compile_fail,E0624
/// // Only the library creates a `Verified`: the constructor is private.
/// let _forge = asx::Verified::<u8>::new;
/// ```
pub struct Verified<T> {
    inner: T,
    signer: Certificate,
    evidence: AuditRecord,
}

impl<T> Verified<T> {
    /// The single constructor. Called by exactly four pipelines: AS4 inbound,
    /// AS4 receipt verification, AS2 inbound and AS2 MDN verification
    /// (`tests/source_gates.rs` counts the call sites).
    #[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
    pub(crate) fn new(inner: T, signer: Certificate, evidence: AuditRecord) -> Self {
        Self {
            inner,
            signer,
            evidence,
        }
    }

    /// The certificate that made the verified signature (pinned or
    /// anchor-and-subject bound).
    pub fn signer(&self) -> &Certificate {
        &self.signer
    }

    /// The audit record of this leg.
    ///
    /// On send, the record the `AuditSink` received, with the partner's
    /// receipt or MDN. In a handler, the record at handoff: no signal yet,
    /// `recorded_at` equal to [`handed_off_at`](AuditRecord::handed_off_at).
    /// The sink later stores the final record, with the issued receipt, under
    /// the same [`record_id`](AuditRecord::record_id). Do not write this one to
    /// the sink yourself: the sink is idempotent on `record_id` and would keep
    /// it instead.
    pub fn evidence(&self) -> &AuditRecord {
        &self.evidence
    }

    /// The verified value.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> std::ops::Deref for Verified<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Verified<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verified")
            .field("inner", &self.inner)
            .field("signer", &self.signer)
            .field("record_id", &self.evidence.record_id())
            .finish()
    }
}

/// A positive acknowledgement: an AS4 `eb:Receipt` or an AS2 `processed` MDN.
///
/// `As4::send` and `As2::send` return the partner's as `Verified<Receipt>`;
/// [`AuditRecord::receipt`] returns the same value from the stored record, on
/// the send side and for the receipts the library issues on receive. Its
/// values are read from the verified, signed signal only.
///
/// Under GPKE Teil 1 Kap. 7 the time of receipt (ÜZ) is taken from the
/// positive AS4 receipt: [`timestamp`](Self::timestamp). It is a UTC instant;
/// converting it to German legal time and counting days is the caller's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    message_id: Option<String>,
    timestamp: Option<std::time::SystemTime>,
}

impl Receipt {
    /// The receipt's own message id (AS4 `eb:MessageId`; an issued AS2 MDN's
    /// `Message-ID`). `None` for a received AS2 MDN, whose `Message-ID` is an
    /// unsigned header, and for an AS4 receipt that omits it.
    pub fn message_id(&self) -> Option<&str> {
        self.message_id.as_deref()
    }

    /// The receipt's own time, with the wire value's precision (AS4
    /// `eb:Timestamp`, milliseconds when the library issued it; an issued AS2
    /// MDN's CMS `signingTime`, whole seconds). `None` for a received AS2 MDN
    /// and for an AS4 receipt that omits it (only possible with the receipt
    /// freshness window disabled).
    pub fn timestamp(&self) -> Option<std::time::SystemTime> {
        self.timestamp
    }

    /// The positive receipt a record carries: outcome delivered, accepted or
    /// duplicate with a signal; `None` otherwise.
    pub(crate) fn from_record(record: &AuditRecord) -> Option<Self> {
        use crate::audit::AuditOutcome as O;
        if !matches!(record.outcome(), O::Delivered | O::Accepted | O::Duplicate) {
            return None;
        }
        let (message_id, timestamp) = record.signal_identity()?;
        Some(Self {
            message_id: message_id.map(str::to_owned),
            timestamp: timestamp.and_then(crate::time_utils::parse_xsd_datetime),
        })
    }

    /// The receipt of a delivered record; a record without one (which `send`
    /// never returns) gives an empty receipt rather than a panic.
    #[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
    pub(crate) fn of_delivered(record: &AuditRecord) -> Self {
        Self::from_record(record).unwrap_or(Self {
            message_id: None,
            timestamp: None,
        })
    }
}

/// One payload part (AS4 `eb:PartInfo` / AS2 body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    bytes: bytes::Bytes,
    mime_type: String,
    name: Option<String>,
    properties: Vec<(String, String)>,
}

impl Payload {
    /// `mime_type` is validated (no CR/LF, RFC 2045 token syntax) at `send`.
    pub fn new(bytes: impl Into<bytes::Bytes>, mime_type: impl Into<String>) -> Payload {
        Payload {
            bytes: bytes.into(),
            mime_type: mime_type.into(),
            name: None,
            properties: Vec::new(),
        }
    }

    /// A file name, sent as the part's `Content-Disposition` (RFC 6266).
    /// Refused under `Profile::peppol()` (Peppol AS4 2.0.3 §4.10: "SHALL NOT
    /// be used"); the other profiles neither require nor forbid it.
    /// Validated at `send`.
    pub fn named(self, name: impl Into<String>) -> Payload {
        Payload {
            name: Some(name.into()),
            ..self
        }
    }

    /// Add an AS4 part property: an `eb:Property` in this part's
    /// `eb:PartProperties`, after the library's `MimeType` and
    /// `CompressionType`, in the order added (ebMS3 Core §5.2.2.13).
    ///
    /// Any profile: the names and values are the embedder's — for example the
    /// BDEW metadata of RzÜ AS4 2.6 Kap. 6 (`BDEWDocumentType`,
    /// `BDEWDocumentDate`, `BDEWDocumentNo`, `BDEWApplicationReference`),
    /// which comes from the EDIFACT envelope the library does not read.
    /// Validated at `send`: `MimeType` and `CompressionType` are the
    /// library's, a name or value is non-empty without CR/LF, a name has no
    /// whitespace and is not repeated in the part. AS2 has no part properties
    /// and refuses a payload carrying any.
    pub fn property(mut self, name: impl Into<String>, value: impl Into<String>) -> Payload {
        self.properties.push((name.into(), value.into()));
        self
    }

    /// The part properties: on a sent payload, those added; on a received
    /// one, those the signed `eb:PartInfo` carried, in document order,
    /// without `MimeType` and `CompressionType`.
    pub fn properties(&self) -> &[(String, String)] {
        &self.properties
    }

    /// The payload octets.
    pub fn bytes(&self) -> &bytes::Bytes {
        &self.bytes
    }

    /// The business media type.
    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }

    /// The file name, if any.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_fields_are_stored_verbatim() {
        let p = Payload::new(&b"x"[..], "text/plain\r\nX: y").named("a\"b");
        assert_eq!(p.mime_type(), "text/plain\r\nX: y");
        assert_eq!(p.name(), Some("a\"b"));
        assert_eq!(&p.bytes()[..], b"x");
    }
}
