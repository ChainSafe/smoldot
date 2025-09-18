use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use smoldot::libp2p::{
    PeerId, collection,
    connection::{noise, webrtc_framing},
    read_write::ReadWrite,
};

use smoldot::libp2p::collection::ConnectionId;
use wasm_bindgen::prelude::*;
use web_sys::console;

#[wasm_bindgen]
extern "C" {
    async fn generateCertificate() -> JsValue;

    #[wasm_bindgen(catch)]
    fn getCertificateMultihash(certificate: JsValue) -> Result<js_sys::Uint8Array, JsValue>;

    fn setGlue(glue: js_sys::Object);

    #[wasm_bindgen(catch)]
    async fn dialWebRtcDirect(
        address: String,
        certificate: JsValue,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch)]
    fn sendTo(channel_id: u64, data: &[u8]) -> Result<(), JsValue>;

    #[wasm_bindgen(catch)]
    fn createDatachannel() -> Result<js_sys::Number, JsValue>;

    fn now() -> js_sys::Number;
}

#[wasm_bindgen]
pub async fn run_client(peer_address: String) -> Result<String, String> {
    console::log_1(&format!("dialing: {}", peer_address).into());

    let mut client = Client::new(peer_address)
        .await
        .map_err(|e| format!("client error: {:?}", e))?;

    client
        .run()
        .await
        .map_err(|e| format!("client run() error: {:?}", e))?;

    Ok("doin' the ting...".to_owned())
}

type DatachannelId = u64;

// A wasm-safe monotonic time type compatible with smoldot's Duration arithmetic.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Instant(u64);

impl Instant {
    fn now() -> Self {
        Self(now().as_f64().unwrap() as u64)
    }
}

impl core::ops::Add<std::time::Duration> for Instant {
    type Output = Self;
    fn add(self, rhs: std::time::Duration) -> Self::Output {
        Self(self.0.saturating_add(rhs.as_millis() as u64))
    }
}

impl core::ops::Sub<std::time::Duration> for Instant {
    type Output = Self;
    fn sub(self, rhs: std::time::Duration) -> Self::Output {
        Self(self.0.saturating_sub(rhs.as_millis() as u64))
    }
}

impl core::ops::Sub for Instant {
    type Output = std::time::Duration;
    fn sub(self, rhs: Self) -> Self::Output {
        std::time::Duration::from_millis(self.0.saturating_sub(rhs.0))
    }
}

struct Client {
    noise_key: noise::NoiseKey,
    local_certhash: Vec<u8>,
    remote_certhash: Vec<u8>,
    inner: Rc<RefCell<ClientInner>>,
}

impl Client {
    async fn new(peer_address: String) -> Result<Self, String> {
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        let mut randomness_seed = [0u8; 32];
        rng.fill_bytes(&mut randomness_seed);

        let config = collection::Config {
            randomness_seed,
            capacity: 4,
            max_inbound_substreams: 8,
            max_protocol_name_len: 64,
            handshake_timeout: std::time::Duration::from_secs(10),
            ping_protocol: "/ipfs/ping/1.0.0".to_string(),
        };

        let mut ed25519_private = [0u8; 32];
        rng.fill_bytes(&mut ed25519_private);
        let mut noise_key = [0u8; 32];
        rng.fill_bytes(&mut noise_key);
        let noise_key = build_noise_key(&ed25519_private, &noise_key);

        let local_cert = generateCertificate().await;

        let cert_fp =
            getCertificateMultihash(local_cert.clone()).map_err(|e| format!("{:?}", e))?;

        let mut local_certhash = [0u8; 34];
        cert_fp.copy_to(&mut local_certhash);
        let local_certhash = Vec::from(local_certhash);

        let remote_certhash = parse_certhash_from_multiaddr(&peer_address)
            .map_err(|e| format!("bad certhash in multiaddr: {e}"))?;

        let network = collection::Network::new(config);

        Ok(Self {
            noise_key,
            local_certhash,
            remote_certhash,
            inner: Rc::new(RefCell::new(ClientInner {
                peer_address,
                local_cert,
                network,
                task: None,
                connection_id: None,
                buffers: HashMap::new(),
                handshake_done: false,
            })),
        })
    }

    async fn run(&mut self) -> Result<(), String> {
        let glue = js_sys::Object::new();

        // onDatachannelOpen()
        {
            let inner_rc = Rc::clone(&self.inner);

            let func =
                Closure::<dyn FnMut(js_sys::Number)>::new(move |channel_id: js_sys::Number| {
                    let channel_id = channel_id.as_f64().unwrap() as DatachannelId;
                    let mut this = inner_rc.borrow_mut();
                    this.on_datachannel_open(channel_id);
                });
            js_sys::Reflect::set(
                glue.as_ref(),
                &JsValue::from_str("onDatachannelOpen"),
                func.as_ref().unchecked_ref(),
            )
            .unwrap();
            func.forget();
        }

        // onDatachannelClose()
        {
            let inner_rc = Rc::clone(&self.inner);

            let func =
                Closure::<dyn FnMut(js_sys::Number)>::new(move |channel_id: js_sys::Number| {
                    let channel_id = channel_id.as_f64().unwrap() as DatachannelId;
                    let mut this = inner_rc.borrow_mut();
                    this.on_datachannel_close(channel_id);
                });
            js_sys::Reflect::set(
                glue.as_ref(),
                &JsValue::from_str("onDatachannelClose"),
                func.as_ref().unchecked_ref(),
            )
            .unwrap();
            func.forget();
        }

        // onDatachannelError()
        {
            let inner_rc = Rc::clone(&self.inner);

            let func = Closure::<dyn FnMut(js_sys::Number, js_sys::JsString)>::new(
                move |channel_id: js_sys::Number, msg: js_sys::JsString| {
                    let channel_id = channel_id.as_f64().unwrap() as DatachannelId;
                    let mut this = inner_rc.borrow_mut();
                    this.on_datachannel_error(channel_id, msg);
                },
            );
            js_sys::Reflect::set(
                glue.as_ref(),
                &JsValue::from_str("onDatachannelError"),
                func.as_ref().unchecked_ref(),
            )
            .unwrap();
            func.forget();
        }

        // onMessage()
        {
            let inner_rc = Rc::clone(&self.inner);

            let func = Closure::<dyn FnMut(js_sys::Number, js_sys::Uint8Array)>::new(
                move |channel_id: js_sys::Number, data: js_sys::Uint8Array| {
                    let channel_id = channel_id.as_f64().unwrap() as DatachannelId;
                    let data = data.to_vec();
                    let mut this = inner_rc.borrow_mut();
                    this.on_message(channel_id, &data);
                },
            );
            js_sys::Reflect::set(
                glue.as_ref(),
                &JsValue::from_str("onMessage"),
                func.as_ref().unchecked_ref(),
            )
            .unwrap();
            func.forget();
        }

        setGlue(glue);

        let (peer_address, local_cert) = {
            let this = self.inner.borrow();
            (this.peer_address.clone(), this.local_cert.clone())
        };

        dialWebRtcDirect(peer_address, local_cert)
            .await
            .map_err(|e| format!("dial error: {:?}", e))?;

        {
            let mut inner = self.inner.borrow_mut();
            let (connection_id, mut task) = inner.network.insert_multi_stream(
                Instant(0),
                collection::MultiStreamHandshakeKind::WebRtc {
                    is_initiator: true,
                    noise_key: &self.noise_key,
                    local_tls_certificate_multihash: self.local_certhash.clone(),
                    remote_tls_certificate_multihash: self.remote_certhash.clone(),
                },
                16,
                None,
            );

            // on_message() inserts a ReadWrite if none exists for a channel. We add one for channel
            // 0 here so that we can refuse to handle any more messages on channel 0 after the
            // handshake. This is done by removing the ReadWrite from the map in on_message() when
            // handshake completion is detected.
            inner.buffers.insert(0, empty_read_write());

            task.add_substream(0, true);
            let (task_update, msg) = task.pull_message_to_coordinator(); // TODO: call in a loop until msg is None
            if let Some(msg) = msg {
                console::log_1(&"Client::run(): got an msg for coordinator from task".into());
                inner.network.inject_connection_message(connection_id, msg)
            }

            inner.task = task_update;
            inner.connection_id = Some(connection_id);
        }
        Ok(())
    }
}

struct ClientInner {
    peer_address: String,
    local_cert: JsValue,
    network: collection::Network<Option<String>, Instant>,
    task: Option<collection::MultiStreamConnectionTask<Instant, DatachannelId>>,
    connection_id: Option<ConnectionId>,
    buffers: HashMap<DatachannelId, ReadWrite<Instant>>,
    handshake_done: bool,
}

impl ClientInner {
    // datachannel was opened by the remote
    fn on_datachannel_open(&mut self, channel_id: DatachannelId) {
        // console::log_1(&format!("data channel {channel_id} opened").into());

        match &mut self.task {
            Some(task) => {
                task.add_substream(channel_id, false);

                let subs_wanted = task.desired_outbound_substreams();
                if subs_wanted > 0 {
                    console::log_1(&format!(
                        "ClientInner::on_data_channel_open(channel_id={channel_id}): desired outbound substreams {subs_wanted} after task.add_substream()"
                    ).into());

                    // for _ in 0..subs_wanted {
                    //     match createDatachannel() {
                    //         Ok(n) => {
                    //             let sub_id = n.as_f64().unwrap() as DatachannelId;
                    //             task.add_substream(sub_id, true);
                    //
                    //             let mut rw = empty_read_write();
                    //             let _ /* FIXME */ = task.substream_read_write(&sub_id, &mut rw);
                    //
                    //             // TODO are we really supposed to call this again?
                    //             let subs_wanted = task.desired_outbound_substreams();
                    //             if subs_wanted > 0 {
                    //                 console::log_1(&format!(
                    //                     "ClientInner::on_data_channel_open(channel_id={channel_id}): desired outbound substreams {subs_wanted} after *second* task.add_substream()"
                    //                 ).into());
                    //             }
                    //         },
                    //         Err(err) => {
                    //             console::log_1(&format!(
                    //                 "ClientInner::on_data_channel_open(channel_id={channel_id}): createDatachannel() failed: {err:?}"
                    //             ).into());
                    //         }
                    //     };
                    // }
                }
            },
            None => {
                console::log_1(&format!(
                    "ClientInner::on_data_channel_open(channel_id={channel_id}): no task, bailing out"
                ).into());
                return;
            }
        };

        self.task = loop {
            let task = match self.task.take() {
                Some(task) => task,
                None => {
                    console::log_1(&format!(
                        "ClientInner::on_data_channel_open(channel_id={channel_id}): task disappeared, bailing out"
                    ).into());
                    return;
                }
            };

            let mut got_coordinator_msg = true;
            let mut got_connection_msg = true;
            let mut got_network_event = true;

            let mut task = match task.pull_message_to_coordinator() {
                (Some(task), Some(msg)) => {
                        console::log_1( & format!(
                        "ClientInner::on_datachannel_open(channel_id={channel_id}): got a msg for coordinator from task"
                        ).into());
                        self.network.inject_connection_message( self.connection_id.unwrap(), msg);
                        task
                },
                (Some(task), None) => {
                    got_coordinator_msg = false;
                    task
                },
                (None, _) => {
                    console::log_1( & format ! (
                        "ClientInner::on_data_channel_open(channel_id={channel_id}): task consumed itself in pull_messages_to_coordinator() 🤷"
                    ).into());
                    return;
                }
            };

            match self.network.next_event() {
                Some(collection::Event::HandshakeFinished { id, peer_id }) => {
                    console::log_1(&format!(
                        "ClientInner::on_datachannel_open(channel_id={channel_id}): handshake on connection {id:?} finished! peer ID: {peer_id}",
                    ).into());
                }
                Some(collection::Event::InboundNegotiated {
                    protocol_name,
                    substream_id,
                    ..
                }) => {
                    console::log_1(&format!(
                        "ClientInner::on_datachannel_open(channel_id={channel_id}): inbound negotiated protocol {protocol_name}",
                    ).into());
                    if protocol_name == "/ipfs/ping/1.0.0" {
                        self.network.accept_inbound(substream_id, collection::InboundTy::Ping);
                    } else {
                        self.network.reject_inbound(substream_id);
                    }
                }
                None => {
                    got_network_event = false;
                }
                _ => {
                    console::log_1(&format!(
                        "ClientInner::on_datachannel_open(channel_id={channel_id}): some other stuff happened, will keep pumping messages and events"
                    ).into());
                }
            }

            match self.network.pull_message_to_connection() {
                Some((_, msg)) => {
                    let now = Instant::now();
                    task.inject_coordinator_message(&now, msg);
                }
                None => got_connection_msg = false
            }

            let subs_wanted = task.desired_outbound_substreams();
            if subs_wanted > 0 {
                console::log_1(&format!(
                    "ClientInner::on_datachannel_open(channel_id={channel_id}): desired outbound substreams {subs_wanted} after task.inject_coordinator_message()"
                ).into());
            }

            if !got_coordinator_msg && !got_connection_msg && !got_network_event {
                console::log_1(&format!(
                    "ClientInner::on_datachannel_open(channel_id={channel_id}): no messages or events left"
                ).into());
                break Some(task);
            }

            self.task = Some(task);
        }
    }

    fn on_datachannel_close(&mut self, channel_id: DatachannelId) {
        console::log_1(&format!("data channel {channel_id} closed").into());
        if let Some(task) = &mut self.task {
            task.reset_substream(&channel_id); // TODO pull msg for coordinator
            self.buffers.remove(&channel_id);
        }
    }

    fn on_datachannel_error(&mut self, channel_id: DatachannelId, msg: js_sys::JsString) {
        console::log_1(&format!("data channel {channel_id} error: {msg}").into());
        if let Some(task) = &mut self.task {
            task.reset_substream(&channel_id); // TODO pull msg for coordinator
            self.buffers.remove(&channel_id);
        }
    }

    fn on_message(&mut self, channel_id: DatachannelId, data: &[u8]) {
        console::log_1(
            &format!(
                "ClientInner::on_message(channel_id={channel_id}): {} bytes received",
                data.len()
            )
            .into(),
        );

        if channel_id == 0 && self.handshake_done {
            // console::log_1(
            //     &"ClientInner::on_message(): not touching channel 0 again after handshake".into(),
            // );
            return;
        }

        let mut is_ping = channel_id != 0 && data.len() == 35; // HACK HACK HACK 🚨

        // let mut rw = make_read_write_with(data);
        let rw = self
            .buffers
            .entry(channel_id)
            .or_insert_with(empty_read_write);

        rw.incoming_buffer.extend_from_slice(data);
        rw.now = Instant::now();

        self.task = loop {
            let mut task = match self.task.take() {
                Some(task) => task,
                None => {
                    console::log_1(&format!(
                        "ClientInner::on_message(channel_id={channel_id}): task disappeared, bailing out"
                    ).into());
                    break None;
                }
            };

            if matches!(
                task.substream_read_write(&channel_id, rw),
                collection::SubstreamFate::Reset,
            ) {
                console::log_1(&format!(
                    "ClientInner::on_message(channel_id={channel_id}): channel has been reset"
                ).into());
                self.handshake_done = channel_id == 0; // HACK HACK HACK 🚨
                // self.buffers.remove(&channel_id); // FIXME
                self.task = Some(task);
                return;
            }

            let mut got_coordinator_msg = true;
            let mut got_connection_msg = true;
            let mut got_network_event = true;

            let mut task = match task.pull_message_to_coordinator() {
                (Some(task), Some(msg)) => {
                    self.network.inject_connection_message( self.connection_id.unwrap(), msg);
                    task
                }
                (Some(task), None) => {
                    got_coordinator_msg = false;
                    task
                }
                (None, _) => {
                    console::log_1(&format!(
                        "ClientInner::on_message(channel_id={channel_id}): task consumed itself in pull_message_to_coordinator() 🤷"
                    ).into());
                    return;
                }
            };

            match self.network.next_event() {
                Some(collection::Event::HandshakeFinished { id, peer_id }) => {
                    console::log_1(&format!(
                        "ClientInner::on_message(channel_id={channel_id}): handshake on connection {id:?} finished! peer ID: {peer_id}"
                    ).into());
                }
                Some(collection::Event::InboundNegotiated {
                         protocol_name,
                         substream_id,
                         ..
                     }) => {
                    // console::log_1(&format!(
                    //     "ClientInner::on_message(channel_id={channel_id}): inbound negotiated protocol {protocol_name}"
                    // ).into());
                    if protocol_name == "/ipfs/ping/1.0.0" {
                        self.network.accept_inbound(substream_id, collection::InboundTy::Ping);
                    } else {
                        self.network.reject_inbound(substream_id);
                    }
                }
                None => {
                    got_network_event = false;
                }
                _ => {
                    console::log_1(&format!(
                        "ClientInner::on_message(channel_id={channel_id}): some other stuff happened, will keep looping"
                    ).into());
                }
            }

            match self.network.pull_message_to_connection() {
                Some((_, msg)) => {
                    let now = Instant::now();
                    task.inject_coordinator_message(&now, msg);

                    let subs_wanted = task.desired_outbound_substreams();
                    if subs_wanted > 0 {
                        console::log_1(&format!(
                            "ClientInner::on_message(channel_id={channel_id}): desired outbound substreams {subs_wanted} after task.inject_coordinator_message()"
                        ).into());
                    }
                }
                None => got_connection_msg = false
            }

            // HACK HACK HACK 🚨
            if is_ping {
                if matches!(
                    task.substream_read_write(&channel_id, rw),
                    collection::SubstreamFate::Reset,
                ) {
                    console::log_1(&format!(
                        "ClientInner::on_message(channel_id={channel_id}): channel has been reset during ping bonus round"
                    ).into());
                    // self.buffers.remove(&channel_id); // FIXME
                    self.task = Some(task);
                    return;
                }
                is_ping = false;

                let subs_wanted = task.desired_outbound_substreams();
                if subs_wanted > 0 {
                    console::log_1(&format!(
                        "ClientInner::on_message(channel_id={channel_id}): desired outbound substreams {subs_wanted} after task.substream_read_write()"
                    ).into());
                }
            }

            if !got_coordinator_msg && !got_connection_msg && !got_network_event {
                // console::log_1(&format!(
                //     "ClientInner::on_message(channel_id={channel_id}): no messages or events left"
                // ).into());
                break Some(task);
            }

            self.task = Some(task);
        };

        let mut total = 0;

        // let mut all_the_bytes = Vec::new();

        for chunk in rw.write_buffers.drain(..) {
            // TODO: figure out how this happens and why sending 0 bytes breaks pings 🤪
            if chunk.is_empty() {
                // console::log_1(&format!(
                //     "ClientInner::on_message(channel_id={channel_id}): empty chunk in write_buffers, skipping"
                // ).into());
                continue;
            }
            send(channel_id, &chunk);
            // all_the_bytes.extend_from_slice(&chunk);
            total += chunk.len();
        }

        // if total > 0 {
        //     console::log_1(&format!(
        //         "ClientInner::on_message(channel_id={channel_id}): sent {total} bytes" //: {all_the_bytes:?}"
        //     ).into());
        // }
    }
}

fn send(channel_id: u64, data: &[u8]) {
    if let Err(e) = sendTo(channel_id, data) {
        console::error_1(&format!(
            "sending {} bytes to channel {channel_id} failed: {e:?}",
            data.len(),
        ).into());
    }
}

fn empty_read_write() -> ReadWrite<Instant> {
    ReadWrite {
        now: Instant::now(),
        incoming_buffer: Vec::new(),
        expected_incoming_bytes: Some(0),
        read_bytes: 0,
        write_buffers: Vec::new(),
        write_bytes_queued: 0,
        write_bytes_queueable: Some(128 * 1024),
        wake_up_after: None,
    }
}

fn make_read_write_with(data: &[u8]) -> ReadWrite<Instant> {
    ReadWrite {
        now: Instant::now(),
        incoming_buffer: Vec::from(data),
        expected_incoming_bytes: Some(0),
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

fn parse_certhash_from_multiaddr(addr: &str) -> Result<Vec<u8>, String> {
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
    Ok(decoded)
}
