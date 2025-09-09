use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use smoldot::libp2p::{
    PeerId,
    connection::{noise, webrtc_framing},
    read_write::ReadWrite,
};

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{console, window};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn dialWebRtcDirect(
        address: String,
        certificate: JsValue,
        glue: js_sys::Object,
    ) -> Result<JsValue, JsValue>;

    async fn generateCertificate() -> JsValue;

    #[wasm_bindgen(catch)]
    fn getCertificateFingerprint(certificate: JsValue) -> Result<js_sys::Uint8Array, JsValue>;
}

#[wasm_bindgen]
pub async fn run_client(peer_address: String, send_fn: js_sys::Function) -> Result<String, String> {
    console::log_1(&format!("dialing: {}", peer_address).into());

    let mut client = Client::new(peer_address, send_fn)
        .await
        .map_err(|e| format!("client error: {:?}", e))?;

    client
        .run()
        .await
        .map_err(|e| format!("client run() error: {:?}", e))?;

    Ok("doin' the ting...".to_owned())
}

struct Client {
    inner: Rc<RefCell<ClientInner>>,
}

impl Client {
    async fn new(peer_address: String, send_fn: js_sys::Function) -> Result<Self, String> {
        let local_cert = generateCertificate().await;

        let cert_fp =
            getCertificateFingerprint(local_cert.clone()).map_err(|e| format!("{:?}", e))?;

        let mut local_cert_sha256 = [0u8; 32];
        cert_fp.copy_to(&mut local_cert_sha256);

        let remote_cert_sha256 = parse_remote_cert_sha256_from_multiaddr(&peer_address)
            .map_err(|e| format!("bad certhash in multiaddr: {e}"))?;

        let handshaker =
            WebRtcHandshaker::new_with_random_keys(local_cert_sha256, remote_cert_sha256);

        Ok(Self {
            inner: Rc::new(RefCell::new(ClientInner {
                peer_address,
                send_fn,
                local_cert,
                handshaker,
                hand_shaken: false,
                streams: HashMap::new(),
            })),
        })
    }

    async fn run(&mut self) -> Result<(), String> {
        let glue = js_sys::Object::new();
        let inner_rc = Rc::clone(&self.inner);

        let func = Closure::<dyn FnMut(js_sys::Number, js_sys::Uint8Array)>::new(
            move |channel_id: js_sys::Number, data: js_sys::Uint8Array| {
                let channel_id = channel_id.as_f64().unwrap() as u64;
                let data = data.to_vec();
                let mut this = inner_rc.borrow_mut();

                if channel_id == 0 {
                    this.drive_handshake(channel_id, &data);
                } else {
                    this.drive_substream(channel_id, &data);
                }
            },
        );

        js_sys::Reflect::set(
            glue.as_ref(),
            &JsValue::from_str("onMessage"),
            func.as_ref().unchecked_ref(),
        )
        .unwrap();
        func.forget();

        let (peer_address, local_cert) = {
            let this = self.inner.borrow();
            (this.peer_address.clone(), this.local_cert.clone())
        };

        dialWebRtcDirect(peer_address, local_cert, glue)
            .await
            .map_err(|e| format!("dial error: {:?}", e))?;

        Ok(())
    }
}

struct ClientInner {
    peer_address: String,
    send_fn: js_sys::Function,
    local_cert: JsValue,
    handshaker: WebRtcHandshaker,
    hand_shaken: bool,
    streams: HashMap<u64, ReadWrite<u64>>,
}

impl ClientInner {
    fn drive_handshake(&mut self, channel_id: u64, data: &[u8]) {
        if self.hand_shaken {
            // TODO check FIN flag and respond with FIN_ACK using WebRtcFraming::read_write()
            console::log_1(&"handshake already done".into());
            return;
        }

        let mut rw = self.streams.entry(channel_id).or_insert_with(empty_read_write);
        rw.incoming_buffer.extend_from_slice(data);

        match self.handshaker.drive_once(rw) {
            Err(e) => {
                console::log_1(&format!("handshake error: {e:?}").into());
            }
            Ok(true) => {
                console::log_1(&"outer hand successfully shaken 🤝".into());
                self.hand_shaken = true;
            }
            Ok(false) => {
                console::log_1(&"handshake in progress...".into());
                let wake_up_now = rw.wake_up_after.is_some_and(|wua| wua <= rw.now);
                if rw.write_buffers.is_empty() && wake_up_now {
                    match self.handshaker.drive_once(&mut rw) {
                        Ok(true) => {
                            console::log_1(&"inner hand successfully shaken 🤝".into());
                            self.hand_shaken = true;
                        }
                        Ok(false) => {
                            // 🤷‍♂️
                        }
                        Err(e) => {
                            console::log_1(&format!("handshake error: {e:?}").into());
                            return;
                        }
                    }
                }

                if rw.write_buffers.is_empty() {
                    console::log_1(
                        &"still nothing to send, nothing more to read. waiting for more data..."
                            .into(),
                    );
                    return;
                }

                for chunk in rw.write_buffers.drain(..) {
                    send(channel_id, &chunk, self.send_fn.clone());
                }
            }
        }
    }

    fn drive_substream(&mut self, channel_id: u64, data: &[u8]) {
        if !self.hand_shaken {
            console::log_1(
                &format!(
                    "got message on channel {channel_id} before completing handshake. ignoring"
                )
                    .into(),
            );
        }

        let rw = self.streams.entry(channel_id).or_insert_with(empty_read_write);
        rw.incoming_buffer.extend_from_slice(data);

        let mut framing = webrtc_framing::WebRtcFraming::new();

        match framing.read_write(rw) {
            Err(e) => {
                console::log_1(&format!("Framing error: {e:?}").into());
            }
            Ok(mut inner) => {
                for chunk in inner.write_buffers.drain(..) {
                    send(channel_id, &chunk, self.send_fn.clone());
                }
            }
        }
    }
}

fn send(channel_id: u64, data: &[u8], send_fn: js_sys::Function) {
    let arr = js_sys::Uint8Array::from(data);

    if let Err(e) = send_fn.call2(&JsValue::UNDEFINED, &JsValue::from(channel_id), &arr.into()) {
        console::log_1(&format!("sending to data channel {channel_id} failed: {e:?}").into());
    }
}

pub async fn async_sleep(millis: i32) {
    let window = window().expect("should have a window");
    let promise = JsFuture::from(js_sys::Promise::new(&mut |resolve, _reject| {
        window
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, millis)
            .unwrap();
    }));

    promise.await.unwrap();
}

fn empty_read_write() -> ReadWrite<u64> {
    ReadWrite {
        now: 0u64, // this is for WASM compatibility
        incoming_buffer: Vec::new(),
        expected_incoming_bytes: None,
        read_bytes: 0,
        write_buffers: Vec::new(),
        write_bytes_queued: 0,
        write_bytes_queueable: Some(128 * 1024),
        wake_up_after: None,
    }
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
    // 1. extract message from framing
    // 2. feed message to the handshaker
    // 3. return true if handshaker finished, false otherwise
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

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
