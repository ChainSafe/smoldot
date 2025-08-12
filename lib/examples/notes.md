## How smoldot is using webRTC ##

High-level
Smoldot uses the libp2p WebRTC-direct transport. The browser side (wasm) dials a UDP host, generates/uses DTLS certificates, crafts SDP, opens an SCTP data channel, then runs libp2p Noise on top and multiplexes substreams with a custom WebRTC framing.

Full WebRTC dialing flow: address → platform connect → browser SDP/certificate handling → SCTP DataChannel setup → Noise prologue and initiator swap → substream multiplexing and framing → shutdown semantics.

Major steps that smoldot set up the webRTC and establish the handshake with the data channel:
1. Parse address and prepare platform connect, dial addresses encode IP, UDP port, and the remote DTLS certificate hash (libp2p certhash) into a “webrtc-direct” multiaddr, which becomes   
MultiStreamAddress::WebRtc { ip, port, remote_certificate_sha256 }.

code: network_service.rs L2640 platfrom.rs L454

2. Browser creates WebRTC transport with a fixed certificate
Generate certificate, create RTCPeerConnection(certificates: [cert]), extract local cert fingerprint/sha256.  
code: no-auto-bytecode-browser.ts L306


3. Create SDP offer, set libp2p ICE ufrag/pwd
   Build an offer, replace ice-ufrag and ice-pwd with the same value prefixed `libp2p+webrtc+v1/`  
   code: no-auto-bytecode-browser.ts L397


4. Construct and apply the “answer” (webrtc-direct)  
Use the remote cert hash to set a=fingerprint:sha-256, ICE-lite, DTLS setup:passive, SCTP port 5000, a=max-message-size:16384, and a single host candidate to the given IP/port; set as remote description.  
code: no-auto-bytecode-browser.ts  L463

5. DataChannels and first substream
code: no-auto-bytecode-browser.ts  L466. L505


6. Inform the Rust side of the local cert and insert the connection
The platform returns `local_tls_certificate_sha256` and a connection handle; the network builds multihashes of both local and remote certs and inserts a WebRTC multi-stream connection.
code: network_service.rs L2673


7. libp2p Noise prologue and initiator role swap
Noise prologue is `b"libp2p-webrtc-noise:" ++ initiator_cert_multihash ++ receiver_cert_multihash`. In WebRTC libp2p, the WebRTC “server” (receiver) acts as the Noise initiator to save a round-trip.
code: Collection.rs L439


8. Multiplexing over SCTP with WebRTC framing:  
After Noise, the multi-stream state machine manages substreams and pings; the platform task opens outbound substreams as requested.
WebRTC framing wraps each substream message in a small protobuf envelope; max message size is 16384 (matches SDP setup). Resets are signaled via a flag; sides never half-close in WebRTC.   
code: tasks.rs L299  Webrtc_framing.rs L70


9. Closing
WebRTC connections or individual channels are reset via the platform’s reset hook; for WebRTC, write sides are not gracefully closed. streams are abruptly destroyed
code: no-auto-bytecode-browser.ts  L478

