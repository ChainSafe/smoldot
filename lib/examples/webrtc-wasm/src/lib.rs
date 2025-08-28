use smoldot::libp2p::{
    connection::{noise, webrtc_framing},
    read_write::ReadWrite,
    PeerId,
};

use rand::{rngs::StdRng, RngCore, SeedableRng};

use wasm_bindgen::prelude::*;
use web_sys::console;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn dialWebRtcDirect(addr: String, glue: JsValue) -> Result<JsValue, JsValue>;
}

#[wasm_bindgen]
pub async fn run_client(peer_address: String) -> Result<String, String> {
    console::log_1(&format!("Dialing: {}", peer_address).into());

    // Parse remote certhash (32-byte SHA-256) from the multiaddr.
    let remote_cert_sha256 = parse_remote_cert_sha256_from_multiaddr(&peer_address)
        .map_err(|e| format!("Bad certhash in multiaddr: {e}"))?;

    use std::cell::RefCell;
    use std::rc::Rc;

    let glue = js_sys::Object::new();
    let glue_rc = Rc::new(glue);
    let handshaker: Rc<RefCell<Option<WebRtcHandshaker>>> = Rc::new(RefCell::new(None));

    // onMessage(data, localCertSha256)
    {
        let outbound_glue = Rc::clone(&glue_rc);
        let handshaker = Rc::clone(&handshaker);

        let func = Closure::<dyn Fn(js_sys::Uint8Array, js_sys::Uint8Array)>::new(
            move |data_js: js_sys::Uint8Array, local_sha256: js_sys::Uint8Array| {
                // TODO: if handshake already finished, send pings instead

                if handshaker.borrow().is_none() {
                    if local_sha256.length() != 32 {
                        console::log_1(&"onMessage: expected 32-byte SHA-256".into());
                        return;
                    }

                    let mut local_cert_sha256 = [0u8; 32];
                    local_sha256.copy_to(&mut local_cert_sha256);

                    *handshaker.borrow_mut() = Some(WebRtcHandshaker::new_with_random_keys(
                        local_cert_sha256,
                        remote_cert_sha256,
                    ));
                }

                let data = js_sys::Uint8Array::new(&data_js);
                let mut bytes = vec![0u8; data.length() as usize];
                data.copy_to(&mut bytes[..]);
                {
                    let mut rw = ReadWrite {
                        now: 0u64, // this is for WASM compatibility
                        incoming_buffer: data.to_vec(),
                        expected_incoming_bytes: Some(0),
                        read_bytes: 0,
                        write_buffers: Vec::new(),
                        write_bytes_queued: 0,
                        write_bytes_queueable: Some(128 * 1024),
                        wake_up_after: None,
                    };

                    match handshaker
                        .borrow_mut()
                        .as_mut()
                        .unwrap()
                        .drive_once(&mut rw)
                    {
                        Err(e) => {
                            console::log_1(&format!("Handshake error: {e:?}").into());
                        }
                        Ok(true) => {
                            console::log_1(&"Hand successfully shaken 🤝".into());
                        }
                        Ok(false) => {
                            console::log_1(&"Handshake in progress...".into());
                            let outbound_glue = Rc::clone(&outbound_glue);

                            // Prepare a JS send(...) function from glue
                            let send_fn = js_sys::Reflect::get(
                                outbound_glue.as_ref(),
                                &JsValue::from_str("send"),
                            )
                            .expect("glue.send must exist");

                            let send_fn = send_fn
                                .dyn_into::<js_sys::Function>()
                                .expect("send must be function");

                            let send = move |chunk: &[u8]| {
                                // Call JS send(Uint8Array)
                                let arr = js_sys::Uint8Array::from(chunk);
                                // Ignore returned boolean for now.
                                let _ = send_fn.call1(&JsValue::UNDEFINED, &arr.into());
                            };

                            for buf in rw.write_buffers.drain(..) {
                                if !buf.is_empty() {
                                    send(&buf);
                                }
                            }
                        }
                    }
                }
            },
        );
        js_sys::Reflect::set(
            glue_rc.as_ref(),
            &JsValue::from_str("onMessage"),
            func.as_ref().unchecked_ref(),
        )
        .unwrap();
        func.forget();
    }

    // onClose(reason?)
    {
        let func = Closure::<dyn Fn(JsValue)>::new(move |reason| {
            console::log_1(&format!("Closed: {:?}", reason).into());
        });
        js_sys::Reflect::set(
            glue_rc.as_ref(),
            &JsValue::from_str("onClose"),
            func.as_ref().unchecked_ref(),
        )
        .unwrap();
        func.forget();
    }

    dialWebRtcDirect(peer_address, glue_rc.as_ref().clone().into())
        .await
        .map_err(|e| format!("Dial error: {:?}", e))?;

    Ok("WebRTC-direct dialing started".to_owned())
}

// step 1: build the noise prologue
// build the noise prologue for libp2p WebRTC.
// In the WebRTC handshake, the Noise prologue must be set to `"libp2p-webrtc-noise:"`
// followed with the multihash-encoded fingerprints of the initiator's certificate
// and the receiver's certificate.
fn build_webrtc_noise_prologue(local_mh: &[u8], remote_mh: &[u8]) -> Vec<u8> {
    const PREFIX: &[u8] = b"libp2p-webrtc-noise:";
    let mut out = Vec::with_capacity(PREFIX.len() + local_mh.len() + remote_mh.len());
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(local_mh);
    out.extend_from_slice(remote_mh);
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
        local_cert_sha256: [u8; 32],
        remote_cert_sha256: [u8; 32],
        noise_key: &noise::NoiseKey,
        ephemeral_secret: [u8; 32],
    ) -> Self {
        let local_mh = cert_sha256_to_multihash_helper(&local_cert_sha256);
        let remote_mh = cert_sha256_to_multihash_helper(&remote_cert_sha256);
        let prologue = build_webrtc_noise_prologue(&local_mh, &remote_mh);
        let hs = noise::HandshakeInProgress::new(noise::Config {
            key: noise_key,
            is_initiator: false, // answerer = Noise initiator
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

    pub fn new_with_random_keys(local_cert_sha256: [u8; 32], remote_cert_sha256: [u8; 32]) -> Self {
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        let ed25519_private = {
            let mut x = [0u8; 32];
            rng.fill_bytes(&mut x);
            x
        };
        let noise_static_private = {
            let mut x = [0u8; 32];
            rng.fill_bytes(&mut x);
            x
        };
        let noise_key = build_noise_key(&ed25519_private, &noise_static_private);
        let ephemeral_secret = {
            let mut x = [0u8; 32];
            rng.fill_bytes(&mut x);
            x
        };

        Self::new(
            local_cert_sha256,
            remote_cert_sha256,
            &noise_key,
            ephemeral_secret,
        )
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

        console::log_1(&format!("Payload size without framing: {:?}", inner.incoming_buffer.len()).into());

        if let Some(hs) = self.hs.take() {
            match hs.read_write(&mut inner)? {
                // On success, get the negotiated libp2p PeerId and a Noise cipher for post‑handshake traffic
                // smoldot does this before upgrading to multiplexing
                noise::NoiseHandshake::InProgress(next) => {
                    self.hs = Some(next);
                    Ok(false)
                }
                noise::NoiseHandshake::Success {
                    cipher,
                    remote_peer_id,
                } => {
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
    local_cert_sha256: [u8; 32],
    remote_cert_sha256: [u8; 32],
    noise_key: &noise::NoiseKey,
    ephemeral_secret: [u8; 32],
    mut recv: impl FnMut() -> Option<Vec<u8>>,
    mut send: impl FnMut(&[u8]),
) -> Result<PeerId, noise::HandshakeError> {
    let mut handshaker = WebRtcHandshaker::new(
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

fn parse_remote_cert_sha256_from_multiaddr(addr: &str) -> Result<[u8; 32], String> {
    // Find "/certhash/<mbase>" and decode the multibase base64url (no padding),
    // then verify multihash header 0x12 0x20 and extract the 32-byte digest.
    let key = "/certhash/";
    let start = addr.find(key).ok_or("multiaddr missing /certhash/")? + key.len();
    let end = addr[start..]
        .find('/')
        .map(|i| start + i)
        .unwrap_or(addr.len());
    let mbase = &addr[start..end];
    if !mbase.starts_with('u') {
        return Err("certhash must be base64url multibase (prefix 'u')".into());
    }
    let b64 = &mbase[1..];

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let decoded = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| format!("base64url decode: {e}"))?;
    if decoded.len() != 34 || decoded[0] != 0x12 || decoded[1] != 0x20 {
        return Err("certhash must be multihash sha2-256/32".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded[2..]);
    Ok(out)
}
