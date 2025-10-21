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
                        read_write.wake_up_asap();
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
                Some(PerfStreamInner::BytesUpload(self.upload_bytes))
            },
            PerfStreamInner::BytesUpload(expected_bytes) => {
                if expected_bytes == self.upload_bytes {
                    console::log_1(&format!(
                        "PerfStream::read_write2(): starting upload of {} bytes",
                        self.upload_bytes,
                    ).into());
                }

                let chunk_size: usize = match read_write.write_bytes_queueable {
                    Some(wbq) => {
                        if wbq == 0 {
                            console::log_1(&"PerfStream::read_write2(): zero bytes queueable".into());
                            return Some(PerfStreamInner::BytesUpload(expected_bytes));
                        }
                        std::cmp::min(wbq, 1024)
                    },
                    None => {
                        console::log_1(&"PerfStream::read_write2(): no bytes queueable".into());
                        return None;
                    }
                };

                read_write.write_out(vec![0u8; chunk_size]);
                read_write.wake_up_asap();

                let remaining_bytes = expected_bytes.saturating_sub(chunk_size as u64);
                if remaining_bytes > 0 {
                    Some(PerfStreamInner::BytesUpload(remaining_bytes))
                } else {
                    console::log_1(&"PerfStream::read_write2(): done uploading".into());
                    Some(PerfStreamInner::NumberOfBytesDownload)
                }
            },
            PerfStreamInner::NumberOfBytesDownload => {
                console::log_1(&"PerfStream::read_write2(): sending number of bytes, download".into());
                read_write.write_out(Vec::from(self.download_bytes.to_be_bytes()));

                // FIXME: Including this breaks receiving the download bytes.
                // It should mean that this side won't send any more data, but the libp2p remote
                // seems to interpret it as "substream closed".
                // This should cause WebRtcFraming to include the FIN flag in the outgoing message.
                // read_write.write_bytes_queueable = None;

                Some(PerfStreamInner::BytesDownload(self.download_bytes))
            },
            PerfStreamInner::BytesDownload(expected_bytes) => {
                if expected_bytes == self.download_bytes {
                    console::log_1(&format!(
                        "PerfStream::read_write2(): starting download of {} bytes",
                        self.download_bytes,
                    ).into());
                }

                let remaining_bytes = expected_bytes.saturating_sub(read_write.incoming_buffer.len() as u64);
                if remaining_bytes > 0 {
                    read_write.discard_all_incoming();
                    Some(PerfStreamInner::BytesDownload(remaining_bytes))
                } else {
                    console::log_1(&"PerfStream::read_write2(): done downloading".into());
                    None
                }
            },
        }
    }
}

enum PerfStreamInner {
    Negotiating(multistream_select::InProgress<String>),
    NumberOfBytesUpload,
    BytesUpload(u64),
    NumberOfBytesDownload,
    BytesDownload(u64),
}

impl PerfStreamInner {
    fn new() -> Self {
        Negotiating(multistream_select::InProgress::new(multistream_select::Config::Dialer {
            requested_protocol: PROTOCOL_NAME.to_string(),
        }))
    }
}