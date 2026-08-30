//! Mock hardware attestation, shaped after AWS Nitro Enclaves' attestation
//! document (module_id, timestamp, PCR measurement, nonce, user_data,
//! signature) but self-signed by a locally-derived key instead of a real
//! hardware-rooted certificate chain.
//!
//! This exists so the attestation-bound predicate proof protocol proposed
//! in `HLD.md` §7 -- mutual binding, nonce unification, the verification
//! chain -- can be built and exercised by real tests without an
//! enclave-capable host or a cloud account. Per §7's "Validation strategy":
//! swap this whole module for a real Nitro/Confidential Space attestation
//! call once the protocol is proven correct against the mock; nothing
//! outside this module should need to change.
//!
//! The "measurement" here (`current_measurement`) stands in for a real
//! PCR0 (which measures actual enclave image bytes) -- it is a fixed
//! constant representing "this build", not a live measurement of anything.
//! The "root" signing key is derived from a fixed, publicly-known seed --
//! there is no secret here and there must never be one; a real deployment
//! trusts the AWS/GCP hardware root instead, not an embedded constant.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256, Sha384};

const MODULE_ID: &str = "zkgw-mock-enclave-v1";

/// Stand-in for Nitro's PCR0: a fixed digest representing "the measured
/// enclave image", constant across the mock's lifetime. Not a real
/// measurement of any binary -- see module docs.
pub fn current_measurement() -> [u8; 48] {
    digest384(b"zkgw/mock-enclave-build/v1")
}

fn digest384(msg: &[u8]) -> [u8; 48] {
    let out = Sha384::digest(msg);
    out.as_slice().try_into().expect("SHA-384 is 48 bytes")
}

fn digest256(msg: &[u8]) -> [u8; 32] {
    let out = Sha256::digest(msg);
    out.as_slice().try_into().expect("SHA-256 is 32 bytes")
}

/// report_data (direction A): binds the attestation to the exact proof
/// commitment and request context, so a valid attestation cannot be
/// replayed alongside a different commitment, predicate, or request. `ctx`
/// is the same canonical context string already bound into the Bulletproofs
/// transcript (zkctx.Context.Canonical() on the Go side) -- it already
/// carries predicate_id, predicate_version, nonce, and action_ref, so
/// hashing it together with the commitment covers every field HLD.md §7
/// names without re-parsing them here.
fn report_data(commit_v: &[u8], ctx: &str) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(commit_v);
    h.update(ctx.as_bytes());
    h.finalize().as_slice().try_into().expect("SHA-384 is 48 bytes")
}

fn root_signing_key() -> SigningKey {
    // Fixed, publicly-derivable seed -- stands in for a hardware root of
    // trust that (in a real deployment) this process would never hold.
    let seed = digest256(b"zkgw/mock-attestation-root/v1");
    SigningKey::from_bytes(&seed)
}

fn root_verifying_key() -> VerifyingKey {
    root_signing_key().verifying_key()
}

/// A mock attestation document. `nonce` is the full canonical request
/// context (not a bare nonce) -- reusing it directly satisfies nonce
/// unification (HLD.md §7) by construction: attestation freshness is
/// checked against literally the same value the proof transcript binds to.
pub struct AttestationDoc {
    pub module_id: String,
    pub timestamp: u64,
    pub measurement: [u8; 48],
    pub nonce: Vec<u8>,
    pub user_data: [u8; 48],
    pub signature: [u8; 64],
}

impl AttestationDoc {
    fn signed_bytes(
        module_id: &str,
        timestamp: u64,
        measurement: &[u8; 48],
        nonce: &[u8],
        user_data: &[u8; 48],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(module_id.len() as u32).to_be_bytes());
        buf.extend_from_slice(module_id.as_bytes());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        buf.extend_from_slice(measurement);
        buf.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
        buf.extend_from_slice(nonce);
        buf.extend_from_slice(user_data);
        buf
    }

    /// Produces an attestation for this exact commitment and request
    /// context. Mirrors what a real enclave's attestation call (Nitro
    /// `NsmProcessAttestation`, GCP Confidential Space token issuance)
    /// would be asked to do: measure the running image, bind in caller-
    /// supplied user_data, sign with the platform root.
    pub fn generate(commit_v: &[u8], ctx: &str) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let measurement = current_measurement();
        let nonce = ctx.as_bytes().to_vec();
        let user_data = report_data(commit_v, ctx);
        let msg = Self::signed_bytes(MODULE_ID, timestamp, &measurement, &nonce, &user_data);
        let signature = root_signing_key().sign(&msg).to_bytes();
        AttestationDoc {
            module_id: MODULE_ID.to_string(),
            timestamp,
            measurement,
            nonce,
            user_data,
            signature,
        }
    }

    /// Verification chain step 1 (mock): stands in for validating the
    /// attestation's certificate chain to the platform root. Real Nitro/GCP
    /// verification also checks certificate validity periods and chain
    /// structure; the mock has neither, only a single signature.
    pub fn verify_signature(&self) -> bool {
        let msg = Self::signed_bytes(
            &self.module_id,
            self.timestamp,
            &self.measurement,
            &self.nonce,
            &self.user_data,
        );
        let sig = Signature::from_bytes(&self.signature);
        root_verifying_key().verify(&msg, &sig).is_ok()
    }

    /// Step 2: measurement must match the governance-registered expectation.
    pub fn check_measurement(&self, expected: &[u8; 48]) -> bool {
        self.measurement == *expected
    }

    /// Step 3: nonce unification -- freshness checked against the exact
    /// request context, not a bare nonce.
    pub fn check_nonce(&self, ctx: &str) -> bool {
        self.nonce == ctx.as_bytes()
    }

    /// Step 4: report_data must commit to this exact proof commitment.
    pub fn check_report_data(&self, commit_v: &[u8], ctx: &str) -> bool {
        self.user_data == report_data(commit_v, ctx)
    }

    /// SHA-256 of the full encoded document -- what direction B absorbs
    /// into the Bulletproofs Merlin transcript before any challenge is
    /// drawn (step 5), so a valid proof cannot be presented under a
    /// substituted attestation.
    pub fn digest(&self) -> [u8; 32] {
        digest256(&self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Self::signed_bytes(
            &self.module_id,
            self.timestamp,
            &self.measurement,
            &self.nonce,
            &self.user_data,
        );
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut pos = 0usize;
        let mod_len = u32::from_be_bytes(bytes.get(pos..pos + 4)?.try_into().ok()?) as usize;
        pos += 4;
        let module_id = String::from_utf8(bytes.get(pos..pos + mod_len)?.to_vec()).ok()?;
        pos += mod_len;
        let timestamp = u64::from_be_bytes(bytes.get(pos..pos + 8)?.try_into().ok()?);
        pos += 8;
        let measurement: [u8; 48] = bytes.get(pos..pos + 48)?.try_into().ok()?;
        pos += 48;
        let nonce_len = u32::from_be_bytes(bytes.get(pos..pos + 4)?.try_into().ok()?) as usize;
        pos += 4;
        let nonce = bytes.get(pos..pos + nonce_len)?.to_vec();
        pos += nonce_len;
        let user_data: [u8; 48] = bytes.get(pos..pos + 48)?.try_into().ok()?;
        pos += 48;
        let signature: [u8; 64] = bytes.get(pos..pos + 64)?.try_into().ok()?;
        pos += 64;
        if pos != bytes.len() {
            return None;
        }
        Some(AttestationDoc { module_id, timestamp, measurement, nonce, user_data, signature })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.encode())
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        hex::decode(s).ok().and_then(|b| Self::decode(&b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honest_doc_verifies_and_roundtrips_through_hex() {
        let doc = AttestationDoc::generate(b"some-commitment-bytes", "ctxA");
        assert!(doc.verify_signature());
        assert!(doc.check_measurement(&current_measurement()));
        assert!(doc.check_nonce("ctxA"));
        assert!(doc.check_report_data(b"some-commitment-bytes", "ctxA"));

        let hex = doc.to_hex();
        let back = AttestationDoc::from_hex(&hex).expect("decode");
        assert!(back.verify_signature());
        assert_eq!(doc.digest(), back.digest());
    }

    #[test]
    fn tampered_signature_rejected() {
        let mut doc = AttestationDoc::generate(b"commitment", "ctxA");
        doc.signature[0] ^= 0xff;
        assert!(!doc.verify_signature());
    }

    #[test]
    fn tampered_measurement_rejected() {
        // Flipping the measurement after signing must invalidate the
        // signature, since signed_bytes() recomputes over the (now
        // different) measurement field.
        let mut doc = AttestationDoc::generate(b"commitment", "ctxA");
        doc.measurement[0] ^= 0xff;
        assert!(!doc.verify_signature());
    }

    #[test]
    fn wrong_context_fails_nonce_and_report_data_checks() {
        let doc = AttestationDoc::generate(b"commitment", "ctxA");
        assert!(!doc.check_nonce("ctxB"));
        assert!(!doc.check_report_data(b"commitment", "ctxB"));
    }

    #[test]
    fn wrong_commitment_fails_report_data_check() {
        let doc = AttestationDoc::generate(b"commitment-A", "ctxA");
        assert!(!doc.check_report_data(b"commitment-B", "ctxA"));
    }

    #[test]
    fn decode_rejects_malformed_bytes_without_panicking() {
        assert!(AttestationDoc::decode(&[1, 2, 3]).is_none());
        assert!(AttestationDoc::from_hex("not-hex").is_none());
    }
}
