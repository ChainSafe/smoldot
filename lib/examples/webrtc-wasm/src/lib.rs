mod perf;

use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::rc::Rc;
use std::time::Duration;
use smoldot::libp2p::{
    collection,
    connection::{noise, webrtc_framing},
    read_write::ReadWrite,
};

use smoldot::libp2p::collection::ConnectionId;
use wasm_bindgen::prelude::*;
use web_sys::console;
use smoldot::libp2p::connection::webrtc_framing::Error;

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
pub async fn run_client(peer_address: String) -> Result<(), String> {
    console::log_1(&format!("dialing: {}", peer_address).into());

    let mut client = Client::new(peer_address)
        .await
        .map_err(|e| format!("client error: {:?}", e))?;

    client
        .run()
        .await
        .map_err(|e| format!("client run() error: {:?}", e))?;

    Ok(())
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

impl Display for Instant {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl core::ops::Add<Duration> for Instant {
    type Output = Self;
    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0.saturating_add(rhs.as_millis() as u64))
    }
}

impl core::ops::Sub<Duration> for Instant {
    type Output = Self;
    fn sub(self, rhs: Duration) -> Self::Output {
        Self(self.0.saturating_sub(rhs.as_millis() as u64))
    }
}

impl core::ops::Sub for Instant {
    type Output = Duration;
    fn sub(self, rhs: Self) -> Self::Output {
        Duration::from_millis(self.0.saturating_sub(rhs.0))
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
            handshake_timeout: Duration::from_secs(10),
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
                handshake_channel: 0,
                handshake_done: false,
                handshake_rw: empty_read_write(),
                perf_channel: None,
                perf_rw: empty_read_write(),
                perf_framing: webrtc_framing::WebRtcFraming::new(),
                perf_stream: Some(perf::PerfStream::new()),
            })),
        })
    }

    async fn run(&mut self) -> Result<(), String> {
        let glue = js_sys::Object::new();

        // onDatachannelOpen(channelId: Number)
        {
            let func =
                Closure::<dyn FnMut(js_sys::Number)>::new(move |_channel_id: js_sys::Number| {
                    console::log_1(&"remote unexpectedly opened a substream. ignoring".into());
                });
            js_sys::Reflect::set(
                glue.as_ref(),
                &JsValue::from_str("onDatachannelOpen"),
                func.as_ref().unchecked_ref(),
            )
                .unwrap();
            func.forget();
        }

        // onDatachannelReady(channelId: Number)
        {
            let inner_rc = Rc::clone(&self.inner);

            let func =
                Closure::<dyn FnMut(js_sys::Number)>::new(move |channel_id: js_sys::Number| {
                    let channel_id = channel_id.as_f64().unwrap() as DatachannelId;
                    let mut this = inner_rc.borrow_mut();
                    this.on_datachannel_ready(channel_id);
                });
            js_sys::Reflect::set(
                glue.as_ref(),
                &JsValue::from_str("onDatachannelReady"),
                func.as_ref().unchecked_ref(),
            )
                .unwrap();
            func.forget();
        }

        // onDatachannelClose(channelId: Number)
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

        // onDatachannelError(channelId: Number, message: String)
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

        // onMessage(channelId: Number, data: Uint8Array)
        {
            let inner_rc = Rc::clone(&self.inner);

            let func = Closure::<dyn FnMut(js_sys::Number, js_sys::Uint8Array)>::new(
                move |channel_id: js_sys::Number, data: js_sys::Uint8Array| {
                    let channel_id = channel_id.as_f64().unwrap() as DatachannelId;
                    let data = data.to_vec();
                    let mut this = inner_rc.borrow_mut();

                    if channel_id == this.handshake_channel && !this.handshake_done {
                        this.drive_handshake(channel_id, &data);
                    } else if this.perf_channel.is_some_and(|c| c == channel_id) {
                        this.on_message(channel_id, &data);
                    } else if !this.handshake_done {
                        console::log_1(&format!(
                            "got message on unknown channel {channel_id}. ignoring"
                        ).into());
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
        }

        // onTimeElapsed()
        {
            let inner_rc = Rc::clone(&self.inner);

            let func =
                Closure::<dyn FnMut()>::new(move || {
                    inner_rc.borrow_mut().on_time_elapsed();
                });
            js_sys::Reflect::set(
                glue.as_ref(),
                &JsValue::from_str("onTimeElapsed"),
                func.as_ref().unchecked_ref(),
            )
                .unwrap();
            func.forget();
        }

        setGlue(glue);

        // This is put in a scope so that `inner` is not "held across an await point".
        {
            let mut inner = self.inner.borrow_mut();
            let (connection_id, mut task) = inner.network.insert_multi_stream(
                Instant::now(),
                collection::MultiStreamHandshakeKind::WebRtc {
                    is_initiator: true,
                    noise_key: &self.noise_key,
                    local_tls_certificate_multihash: self.local_certhash.clone(),
                    remote_tls_certificate_multihash: self.remote_certhash.clone(),
                },
                16,
                None,
            );

            task.add_substream(inner.handshake_channel, true);
            inner.task = Some(task);
            inner.connection_id = Some(connection_id);
        }

        let (peer_address, local_cert) = {
            let this = self.inner.borrow();
            (this.peer_address.clone(), this.local_cert.clone())
        };

        dialWebRtcDirect(peer_address, local_cert)
            .await
            .map_err(|e| format!("dial error: {:?}", e))?;

        Ok(())
    }
}

struct ClientInner {
    peer_address: String,
    local_cert: JsValue,
    network: collection::Network<Option<String>, Instant>,
    task: Option<collection::MultiStreamConnectionTask<Instant, DatachannelId>>,
    connection_id: Option<ConnectionId>,
    handshake_channel: DatachannelId,
    handshake_done: bool,
    handshake_rw: ReadWrite<Instant>,
    perf_channel: Option<DatachannelId>,
    perf_rw: ReadWrite<Instant>,
    perf_framing: webrtc_framing::WebRtcFraming,
    perf_stream: Option<perf::PerfStream>,
}

impl ClientInner {
    fn on_datachannel_ready(&mut self, channel_id: DatachannelId) {
        // perf channel should be the only one opened after handshake
        self.perf_channel = Some(channel_id);

        self.perf_rw.now = Instant::now();
        self.perf_rw.wake_up_after = None;

        match self.perf_framing.read_write(&mut self.perf_rw) {
            Ok(mut framing) => {
                let Some(stream) = self.perf_stream.take() else { return; };
                self.perf_stream = stream.read_write(&mut framing);
            }
            Err(err) => {
                if !matches!(err, Error::RemoteResetDesired) {
                    console::log_1(&format!(
                        "ClientInner::on_datachannel_ready(channel_id={channel_id}): framing error: {err:?}"
                    ).into());
                }
                return;
            }
        } // on drop, `framing` adds the protobuf frame to `self.perf_rw.write_buffers`

        send(channel_id, self.perf_rw.write_buffers.as_mut());
    }

    fn on_datachannel_close(&mut self, channel_id: DatachannelId) {
        console::log_1(&format!("data channel {channel_id} closed").into());

        let Some(task) = self.task.as_mut() else { return; };

        if channel_id == self.handshake_channel {
            task.reset_substream(&channel_id);
        }
    }

    fn on_datachannel_error(&mut self, channel_id: DatachannelId, msg: js_sys::JsString) {
        console::log_1(&format!("data channel {channel_id} error: {msg}").into());

        let Some(task) = self.task.as_mut() else { return; };

        if channel_id == self.handshake_channel {
            task.reset_substream(&channel_id);
        }
    }

    fn on_message(&mut self, channel_id: DatachannelId, data: &[u8]) {
        console::log_1(&format!(
            "ClientInner::on_message(channel_id={channel_id}): got {} bytes",
            data.len(),
        ).into());

        let rw = &mut self.perf_rw;
        rw.now = Instant::now();
        rw.wake_up_after = None;
        rw.incoming_buffer.extend_from_slice(data);

        match self.perf_framing.read_write(rw) {
            Ok(mut framing) => {
                let Some(stream) = self.perf_stream.take() else { return; };
                self.perf_stream = stream.read_write(&mut framing);
            }
            Err(err) => {
                if !matches!(err, Error::RemoteResetDesired) {
                    console::log_1(&format!(
                        "ClientInner::on_message(channel_id={channel_id}): framing error: {err:?}"
                    ).into());
                }
                return;
            }
        } // on drop, `framing` adds the protobuf frame to `self.perf_rw.write_buffers`

        send(channel_id, rw.write_buffers.as_mut());
    }

    fn on_time_elapsed(&mut self) {
        let Some(channel_id) = self.perf_channel else { return; };
        let rw = &mut self.perf_rw;

        while rw.wake_up_after.map_or(false, |wua| rw.now >= wua) {
            rw.now = Instant::now();
            rw.wake_up_after = None;

            match self.perf_framing.read_write(rw) {
                Ok(mut framing) => {
                    let Some(stream) = self.perf_stream.take() else { return; };
                    self.perf_stream = stream.read_write(&mut framing);

                    if self.perf_stream.is_none() {
                        self.perf_channel = None;
                    }
                }
                Err(err) => {
                    if !matches!(err, Error::RemoteResetDesired) {
                        console::log_1(&format!(
                            "ClientInner::on_time_elapsed(): framing error: {err:?}"
                        ).into());
                    }
                    return;
                }
            } // on drop, `framing` adds the protobuf frame to `rw.write_buffers`

            send(channel_id, rw.write_buffers.as_mut());
        }
    }

    fn drive_handshake(&mut self, channel_id: DatachannelId, data: &[u8]) {
        console::log_1(&"ClientInner::drive_handshake(): doin' the ting".into());

        let Some(task) = self.task.as_mut() else { return; };
        let rw = &mut self.handshake_rw;
        rw.incoming_buffer.extend_from_slice(data);
        rw.now = Instant::now();

        // let mut remove_buffer = false;

        // self.task = loop {
        //     let mut task = match self.task.take() {
        //         Some(task) => task,
        //         None => {
        //             console::log_1(
        //                 &"ClientInner::drive_handshake(): task disappeared, bailing out".into()
        //             );
        //             break None;
        //         }
        //     };

            if matches!(
                task.substream_read_write(&channel_id, rw),
                collection::SubstreamFate::Reset,
            ) {
                self.handshake_done = true;

                match createDatachannel() {
                    Ok(n) => {
                        self.perf_channel = Some(n.as_f64().unwrap() as DatachannelId);
                    }
                    Err(err) => {
                        console::log_1(&format!(
                            "ClientInner::drive_handshake(): createDatachannel() failed: {err:?}"
                        ).into());
                    }
                }

                // remove_buffer = true;
                // break Some(task);
            }

        //     let mut got_coordinator_msg = true;
        //     let mut got_connection_msg = true;
        //     let mut got_network_event = true;
        //
        //     let mut task = match task.pull_message_to_coordinator() {
        //         (Some(task), Some(msg)) => {
        //             self.network.inject_connection_message( self.connection_id.unwrap(), msg);
        //             task
        //         }
        //         (Some(task), None) => {
        //             got_coordinator_msg = false;
        //             task
        //         }
        //         (None, _) => {
        //             console::log_1(
        //                 &"ClientInner::drive_handshake(): task consumed itself in pull_message_to_coordinator() 🤷".into()
        //             );
        //             break None;
        //         }
        //     };
        //
        //     match self.network.next_event() {
        //         Some(collection::Event::HandshakeFinished { id, peer_id }) => {
        //             console::log_1(&format!(
        //                 "ClientInner::drive_handshake(): handshake on connection {id:?} finished! peer ID: {peer_id}"
        //             ).into());
        //
        //             if let Err(err) = createDatachannel() {
        //                 console::log_1(&format!(
        //                     "ClientInner::drive_handshake(): createDatachannel() failed: {err:?}"
        //                 ).into());
        //             }
        //         }
        //         None => {
        //             got_network_event = false;
        //         }
        //         _ => {
        //             console::log_1(
        //                 &"ClientInner::drive_handshake(): some other stuff happened, will keep looping".into()
        //             );
        //         }
        //     }
        //
        //     match self.network.pull_message_to_connection() {
        //         Some((_, msg)) => {
        //             task.inject_coordinator_message(&Instant::now(), msg);
        //         }
        //         None => got_connection_msg = false
        //     }
        //
        //     if !got_coordinator_msg && !got_connection_msg && !got_network_event {
        //         break Some(task);
        //     }
        //
        //     self.task = Some(task);
        // };

        // if remove_buffer {
        //     self.buffers.remove(&channel_id);
        // } else {
            send(channel_id, rw.write_buffers.as_mut());
        // }
    }
}

fn send(channel_id: DatachannelId, write_buffers: &mut Vec<Vec<u8>>) {
    write_buffers
        .drain(..)
        .filter(|chunk| !chunk.is_empty())
        .for_each(|chunk| {
            if let Err(e) = sendTo(channel_id, &chunk) {
                console::error_1(&format!(
                    "sending {} bytes to channel {channel_id} failed: {e:?}",
                    chunk.len(),
                ).into());
            }
        }
    );
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

fn build_noise_key(ed25519_private: &[u8; 32], noise_static_private: &[u8; 32]) -> noise::NoiseKey {
    noise::NoiseKey::new(ed25519_private, noise_static_private)
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
