use smoldot::libp2p::{
    connection::{noise, webrtc_framing},
    read_write::ReadWrite,
    PeerId,
};

use rand::{RngCore, rngs::StdRng, SeedableRng};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
use web_sys::console;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn dialWebRtcDirect(addr: String, glue: JsValue) -> Result<JsValue, JsValue>;
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn run_client(peer_address: String) -> Result<String, String> {
    console::log_1(&format!("Dialing: {}", peer_address).into());

    // Build the glue object that JS will call back into.
    // Replace the stubs with real Smoldot integration: feed bytes in/out of the state machine.
    let glue = js_sys::Object::new();

    // onOpen(localCertSha256)
    {
        let func = Closure::<dyn Fn(js_sys::Uint8Array)>::new(move |local_sha256: js_sys::Uint8Array| {
            let mut bytes = vec![0u8; local_sha256.length() as usize];
            local_sha256.copy_to(&mut bytes[..]);
            console::log_1(&format!("Local DTLS cert sha256: {:02x?}", bytes).into());
            // TODO: Initialize Smoldot connection here if needed.
        });
        js_sys::Reflect::set(
            &glue,
            &JsValue::from_str("onOpen"),
            func.as_ref().unchecked_ref(),
        )
            .unwrap();
        func.forget();
    }

    // onMessage(data)
    {
        let func = Closure::<dyn Fn(js_sys::Uint8Array)>::new(move |data: js_sys::Uint8Array| {
            let mut bytes = vec![0u8; data.length() as usize];
            data.copy_to(&mut bytes[..]);
            // TODO: Feed 'bytes' into Smoldot's connection read_write().incoming_buffer, then drive the state.
            console::log_1(&format!("RX {} bytes", bytes.len()).into());
        });
        js_sys::Reflect::set(
            &glue,
            &JsValue::from_str("onMessage"),
            func.as_ref().unchecked_ref(),
        )
            .unwrap();
        func.forget();
    }

    // nextOutbound() -> Uint8Array|null
    {
        let func = Closure::<dyn Fn() -> JsValue>::new(move || {
            // TODO: Pull next outbound chunk from Smoldot (e.g., drain write_buffers)
            // For now, return null to indicate no data to send.
            JsValue::NULL
        });
        js_sys::Reflect::set(
            &glue,
            &JsValue::from_str("nextOutbound"),
            func.as_ref().unchecked_ref(),
        )
            .unwrap();
        func.forget();
    }

    // onClose(reason?)
    {
        let func = Closure::<dyn Fn(JsValue)>::new(move |reason| {
            console::log_1(&format!("Closed: {:?}", reason).into());
            // TODO: Propagate shutdown to Smoldot state machine if needed.
        });
        js_sys::Reflect::set(
            &glue,
            &JsValue::from_str("onClose"),
            func.as_ref().unchecked_ref(),
        )
            .unwrap();
        func.forget();
    }

    dialWebRtcDirect(peer_address, JsValue::from(glue))
        .await
        .map_err(|e| format!("Dial error: {:?}", e))?;

    Ok("WebRTC-direct dialing started".to_owned())
}

// step 1: build the noise prologue
// build the noise prologue for libp2p WebRTC.
// In the WebRTC handshake, the Noise prologue must be set to `"libp2p-webrtc-noise:"`
// followed with the multihash-encoded fingerprints of the initiator's certificate
// and the receiver's certificate.
fn build_webrtc_noise_prologue(
    webrtc_is_initiator: bool,
    local_mh: &[u8],
    remote_mh: &[u8],
) -> Vec<u8> {
    const PREFIX: &[u8] = b"libp2p-webrtc-noise:";
    let mut out = Vec::with_capacity(PREFIX.len() + local_mh.len() + remote_mh.len());
    out.extend_from_slice(PREFIX);
    if webrtc_is_initiator {
        out.extend_from_slice(local_mh);
        out.extend_from_slice(remote_mh);
    } else {
        out.extend_from_slice(remote_mh);
        out.extend_from_slice(local_mh);
    }
    out
}

// libp2p webrtc requires a multihash of a TLS certificate SHA-256 fingerprint
fn cert_sha256_to_multihash_helper(cert_sha256: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(34);
    out.extend_from_slice(&[0x12, 32]); // sha2-256 multihash header
    out.extend_from_slice(cert_sha256);
    out
}

// step 2: build the noise key
fn build_noise_key(ed25519_private: &[u8; 32], noise_static_private: &[u8; 32]) -> noise::NoiseKey {
    noise::NoiseKey::new(ed25519_private, noise_static_private)
}

// step 3: Initialize WebRTC framing and Noise handshake
// libp2p WebRTC framing + Noise handshakes
pub struct WebRtcHandshaker {
    framing: webrtc_framing::WebRtcFraming,
    hs: Option<noise::HandshakeInProgress>,
    pub remote_peer_id: Option<PeerId>,
    pub cipher: Option<noise::Noise>,
}

impl WebRtcHandshaker {
    pub fn new(
        webrtc_is_initiator: bool,
        local_cert_sha256: [u8; 32],
        remote_cert_sha256: [u8; 32],
        noise_key: &noise::NoiseKey,
        ephemeral_secret: [u8; 32],
    ) -> Self {
        let local_mh = cert_sha256_to_multihash_helper(&local_cert_sha256);
        let remote_mh = cert_sha256_to_multihash_helper(&remote_cert_sha256);
        let prologue = build_webrtc_noise_prologue(webrtc_is_initiator, &local_mh, &remote_mh);
        let hs = noise::HandshakeInProgress::new(noise::Config {
            key: noise_key,
            is_initiator: !webrtc_is_initiator, // answerer = Noise initiator
            prologue: &prologue,
            ephemeral_secret_key: &ephemeral_secret,
        });
        WebRtcHandshaker {
            framing: webrtc_framing::WebRtcFraming::new(),
            hs: Some(hs),
            remote_peer_id: None,
            cipher: None,
        }
    }

    // step 4: drive the handshaker over the DataChannel message flow
    // 1. feed the incoming bytes to the handshaker
    // 2. drive the handshaker
    // 3. send the outgoing bytes to the handshaker
    // 4. if the handshaker finished, return the remote peer id
    // 5. if the handshaker not finished, return false
    pub fn drive_once<TNow: Clone>(
        &mut self,
        rw: &mut ReadWrite<TNow>,
    ) -> Result<bool, noise::HandshakeError> {
        let mut inner = self
            .framing
            .read_write(rw)
            .map_err(|_| noise::HandshakeError::WriteClosed)?;
        if let Some(hs) = self.hs.take() {
            match hs.read_write(&mut inner)? {
                // On success, get the negotiated libp2p PeerId and a Noise cipher for post‑handshake traffic
                // smoldot does this before upgrading to multiplexing
                noise::NoiseHandshake::InProgress(next) => {
                    self.hs = Some(next);
                    Ok(false)
                }
                noise::NoiseHandshake::Success { cipher, remote_peer_id } => {
                    self.cipher = Some(cipher);
                    self.remote_peer_id = Some(remote_peer_id);
                    Ok(true)
                }
            }
        } else {
            Ok(true)
        }
    }

    pub fn is_finished(&self) -> bool {
        self.cipher.is_some()
    }
}

// step 5: wire the handshaker to the DataChannel
// Returns the negotiated PeerId on success.
pub fn handshake_with_webrtc_dc(
    webrtc_is_initiator: bool,
    local_cert_sha256: [u8; 32],
    remote_cert_sha256: [u8; 32],
    noise_key: &noise::NoiseKey,
    ephemeral_secret: [u8; 32],
    mut recv: impl FnMut() -> Option<Vec<u8>>,
    mut send: impl FnMut(&[u8]),
) -> Result<PeerId, noise::HandshakeError> {
    let mut handshaker = WebRtcHandshaker::new(
        webrtc_is_initiator,
        local_cert_sha256,
        remote_cert_sha256,
        noise_key,
        ephemeral_secret,
    );

    let mut rw = ReadWrite {
        now: 0u64, // this is for WASM compatibility
        incoming_buffer: Vec::new(),
        expected_incoming_bytes: Some(0),
        read_bytes: 0,
        write_buffers: Vec::new(),
        write_bytes_queued: 0,
        write_bytes_queueable: Some(128 * 1024),
        wake_up_after: None,
    };

    loop {
        if let Some(mut msg) = recv() {
            rw.incoming_buffer.append(&mut msg);
        }
        let finished = handshaker.drive_once(&mut rw)?;

        if !rw.write_buffers.is_empty() {
            for buf in rw.write_buffers.drain(..) {
                if !buf.is_empty() {
                    send(&buf);
                }
            }
            rw.write_bytes_queueable = Some(128 * 1024);
            rw.write_bytes_queued = 0;
        }
        if finished {
            return Ok(handshaker.remote_peer_id.unwrap());
        }
    }
}

// simulate a local connection with two peers and sends bytes between them
mod demo {
    use std::str::FromStr;
    use super::*;

    // to mimics the post-DataChannel steps smoldot performs:
    // WebRTC framing over a message channel.
    // Noise XX with WebRTC prologue and role inversion.
    // Exchange proceeds in small steps, driven by available inbound messages and producing outbound messages.
    // we need this Duplex for now to mimic what smoldot is doing without the read data channel
    struct Duplex<TNow: Clone> {
        a: ReadWrite<TNow>,
        b: ReadWrite<TNow>,
        max_queueable: usize,
    }
    impl<TNow: Clone> Duplex<TNow> {
        fn new(now: TNow, max_queueable: usize) -> Self {
            let mk = |now: TNow| ReadWrite {
                now,
                incoming_buffer: Vec::new(),
                expected_incoming_bytes: Some(0),
                read_bytes: 0,
                write_buffers: Vec::new(),
                write_bytes_queued: 0,
                write_bytes_queueable: Some(max_queueable),
                wake_up_after: None,
            };
            Self { a: mk(now.clone()), b: mk(now), max_queueable }
        }
        fn pump(&mut self) {
            let max = self.max_queueable;
            if self.a.write_buffers.iter().any(|b| !b.is_empty()) {
                for buf in self.a.write_buffers.drain(..) {
                    if !buf.is_empty() {
                        self.b.incoming_buffer.extend_from_slice(&buf);
                    }
                }
                self.a.write_bytes_queueable = Some(max);
                self.a.write_bytes_queued = 0;
            }
            if self.b.write_buffers.iter().any(|b| !b.is_empty()) {
                for buf in self.b.write_buffers.drain(..) {
                    if !buf.is_empty() {
                        self.a.incoming_buffer.extend_from_slice(&buf);
                    }
                }
                self.b.write_bytes_queueable = Some(max);
                self.b.write_bytes_queued = 0;
            }
        }
    }

    fn random_32(rng: &mut impl RngCore) -> [u8; 32] {
        let mut out = [0u8; 32];
        rng.fill_bytes(&mut out);
        out
    }

    // simulate the e2e local handshake
    pub fn run() -> Result<String, String> {
        let mut rng = StdRng::seed_from_u64(42);

        // address generation and noise key generation
        let ed25519_priv_a = random_32(&mut rng);
        let ed25519_priv_b = random_32(&mut rng);

        let noise_static_a = random_32(&mut rng);
        let noise_static_b = random_32(&mut rng);

        let noise_key_a = build_noise_key(&ed25519_priv_a, &noise_static_a);
        let noise_key_b = build_noise_key(&ed25519_priv_b, &noise_static_b);

        // get the certificate
        let cert_sha256_a = random_32(&mut rng);
        let cert_sha256_b = random_32(&mut rng);

        // initialize the webRTC handshaker
        let mut ws_a = WebRtcHandshaker::new(true, cert_sha256_a, cert_sha256_b, &noise_key_a, random_32(&mut rng));
        let mut ws_b = WebRtcHandshaker::new(false, cert_sha256_b, cert_sha256_a, &noise_key_b, random_32(&mut rng));

        let now = 0u64;
        let mut pipe: Duplex<_> = Duplex::new(now, 128 * 1024);

        for step in 0..10_000 {
            let _ = ws_a.drive_once(&mut pipe.a);
            pipe.pump();
            let _ = ws_b.drive_once(&mut pipe.b);
            pipe.pump();
            if ws_a.is_finished() && ws_b.is_finished() {
                let msg = format!(
                    "Both sides established after {} steps; A sees {}, B sees {}",
                    step,
                    ws_a.remote_peer_id.unwrap(),
                    ws_b.remote_peer_id.unwrap()
                );
                return Ok(msg);
            }
        }
        Err("Handshake did not complete in time".to_string())
    }
}
