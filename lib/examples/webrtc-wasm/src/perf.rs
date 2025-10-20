use smoldot::libp2p::connection::multistream_select;
use smoldot::libp2p::read_write::ReadWrite;
use crate::Instant;
use crate::perf::PerfStreamInner::Negotiating;
use web_sys::console;

pub const PROTOCOL_NAME: &str = "/litep2p-perf/1.0.0";

pub(crate) struct PerfStream {
    upload_bytes: u64,
    download_bytes: u64,
    inner: PerfStreamInner
}

impl PerfStream {
    pub fn new(upload_bytes: u64, download_bytes: u64) -> Self {
        Self {
            upload_bytes,
            download_bytes,
            inner: PerfStreamInner::new(),
        }
    }

    pub fn read_write(
        self,
        read_write: &mut ReadWrite<Instant>,
    ) -> Option<Self> {
        let upload_bytes = self.upload_bytes;
        let download_bytes = self.download_bytes;

        self.read_write2(read_write).map(|inner| PerfStream {
            upload_bytes,
            download_bytes,
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
                    Err(err) => {
                        console::log_1(&format!("kaput: {:?}", err).into());
                        None
                    },
                    _ => unreachable!("probably...")
                }
            }
            PerfStreamInner::NumberOfBytesUpload => {
                console::log_1(&"PerfStream::read_write2(): sending number of bytes, upload".into());
                read_write.write_out(Vec::from(self.upload_bytes.to_be_bytes()));
                read_write.wake_up_asap();
                Some(PerfStreamInner::BytesUpload)
            },
            PerfStreamInner::BytesUpload => {
                console::log_1(&"PerfStream::read_write2(): sending bytes, upload".into());
                read_write.write_out(vec![0u8; self.upload_bytes as usize]);
                read_write.wake_up_asap();
                Some(PerfStreamInner::NumberOfBytesDownload)
            },
            PerfStreamInner::NumberOfBytesDownload => {
                console::log_1(&"PerfStream::read_write2(): sending number of bytes, download".into());
                read_write.write_out(Vec::from(self.download_bytes.to_be_bytes()));

                // FIXME: Including this breaks receiving the download bytes.
                // It should mean that this side won't send any more data, but the libp2p remote
                // seems to interpret it as "substream closed".
                // This should cause WebRtcFraming to include the FIN flag in the outgoing message.
                // read_write.write_bytes_queueable = None;

                Some(PerfStreamInner::BytesDownload)
            },
            PerfStreamInner::BytesDownload => {
                console::log_1(&"PerfStream::read_write2(): receiving bytes, download".into());
                if read_write.incoming_buffer.len() != self.download_bytes as usize {
                    console::log_1(&format!(
                        "PerfStream::read_write2(): expected {} bytes in incoming_buffer but got {}",
                        self.download_bytes,
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