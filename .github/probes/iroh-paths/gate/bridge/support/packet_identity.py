"""CI-only exact ciphertext identity in the pinned Noq qlog packet event."""
from pathlib import Path


def apply(root: Path):
    packet = root / "src/connection/packet_builder.rs"
    qlog = root / "src/connection/qlog.rs"
    packet_text = packet.read_text(encoding="utf-8")
    qlog_text = qlog.read_text(encoding="utf-8")
    call = "        self.qlog.finalize(packet_len);"
    before = """    pub(super) fn finalize(&mut self, len: usize) {
        #[cfg(feature = "qlog")]
        {
            self.inner.header.length = Some(len as u16);
        }
    }"""
    after = """    pub(super) fn finalize(&mut self, len: usize, ciphertext: &[u8]) {
        #[cfg(not(feature = "qlog"))]
        let _ = ciphertext;
        #[cfg(feature = "qlog")]
        {
            use std::fmt::Write as _;
            self.inner.header.length = Some(len as u16);
            let mut data = String::with_capacity(ciphertext.len() * 2);
            for byte in ciphertext {
                write!(&mut data, "{byte:02x}").expect("writing to String cannot fail");
            }
            self.inner.raw = Some(RawInfo {
                length: Some(len as u64),
                payload_length: None,
                data: Some(Box::new(data)),
            });
        }
    }"""
    if packet_text.count(call) != 1 or qlog_text.count(before) != 1:
        raise ValueError("pinned Noq encrypted-packet identity boundary changed")
    packet.write_text(packet_text.replace(call,
        "        self.qlog.finalize(packet_len, &self.buf.as_mut_slice()[encode_start..]);"), encoding="utf-8")
    qlog.write_text(qlog_text.replace(before, after), encoding="utf-8")
