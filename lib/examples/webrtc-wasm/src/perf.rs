use smoldot::libp2p::connection::multistream_select;
use smoldot::libp2p::read_write::ReadWrite;
use crate::Instant;
use crate::perf::PerfStreamInner::Negotiating;
use web_sys::console;

pub const PROTOCOL_NAME: &str = "/litep2p-perf/1.0.0";

pub(crate) struct PerfStream {
    inner: PerfStreamInner
}

impl PerfStream {
    pub fn new() -> Self {
        Self {
            inner: PerfStreamInner::new(),
        }
    }

    pub fn read_write(
        self,
        read_write: &mut ReadWrite<Instant>,
    ) -> Option<Self> {
        self.read_write2(read_write).map(|inner| PerfStream {
            inner,
        })
    }

    fn read_write2(
        self,
        read_write: &mut ReadWrite<Instant>,
    ) -> Option<PerfStreamInner> {
        match self.inner {
            Negotiating(nego) => {
                console::log_1(&"PerfStream::read_write2(): negotiating...".into());

                match nego.read_write(read_write) {
                    Ok(multistream_select::Negotiation::InProgress(nego)) =>
                        Some(Negotiating(nego)),
                    Ok(multistream_select::Negotiation::Success) => {
                        console::log_1(&"PerfStream::read_write2(): done negotiating!".into());
                        // read_write.wake_up_asap();
                        Some(PerfStreamInner::NumberOfBytesUpload)
                    },
                    Ok(multistream_select::Negotiation::NotAvailable) => None, // log?
                    Err(_) => None, // FIXME: handle error
                    _ => unreachable!("probably...")
                }
            }
            PerfStreamInner::NumberOfBytesUpload => {
                console::log_1(&"PerfStream::read_write2(): sending number of bytes, upload".into());
                let num_bytes = 1024_u64; // FIXME: make configurable
                read_write.write_out(Vec::from(num_bytes.to_be_bytes()));
                read_write.wake_up_asap();
                Some(PerfStreamInner::BytesUpload)
            },
            PerfStreamInner::BytesUpload => {
                console::log_1(&"PerfStream::read_write2(): sending bytes, upload".into());
                read_write.write_out(vec![0u8; 1024]);
                read_write.wake_up_asap();
                Some(PerfStreamInner::NumberOfBytesDownload)
            },
            PerfStreamInner::NumberOfBytesDownload => {
                console::log_1(&"PerfStream::read_write2(): sending number of bytes, download".into());
                let num_bytes = 1024_u64; // FIXME: make configurable
                read_write.write_out(Vec::from(num_bytes.to_be_bytes()));

                // This causes WebRtcFraming to include the FIN flag in the outgoing message.
                read_write.write_bytes_queueable = None;

                Some(PerfStreamInner::BytesDownload)
            },
            PerfStreamInner::BytesDownload => {
                console::log_1(&"PerfStream::read_write2(): receiving bytes, download".into());
                if read_write.incoming_buffer.len() != 1024 {
                    console::log_1(&format!(
                        "PerfStream::read_write2(): expected 1024 bytes in incoming_buffer but got {}",
                        read_write.incoming_buffer.len(),
                    ).into());
                }
                None
            },
        }
    }
}

enum PerfStreamInner {
    Negotiating(multistream_select::InProgress<String>),
    NumberOfBytesUpload,
    BytesUpload,
    NumberOfBytesDownload,
    BytesDownload,
}

impl PerfStreamInner {
    fn new() -> Self {
        Negotiating(multistream_select::InProgress::new(multistream_select::Config::Dialer {
            requested_protocol: PROTOCOL_NAME.to_string(),
        }))
    }
}