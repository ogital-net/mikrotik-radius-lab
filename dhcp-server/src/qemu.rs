use anyhow::{anyhow, Context, Result};
use std::io::{Read, Write};
use std::net::TcpStream;

/// QEMU's `-netdev socket,...,listen=PORT` speaks "raw Ethernet frames over
/// TCP." Wire format per frame is dead simple:
///
///     4 bytes : frame length, big-endian uint32
///     N bytes : the Ethernet frame, header included
///
/// One TCP connection = one virtual cable. Connecting from this side makes
/// us peer-to-peer with whichever guest QEMU spawned with the matching
/// `listen=` option.
pub struct Link {
    stream: TcpStream,
}

impl Link {
    pub fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .with_context(|| format!("connecting to QEMU socket-netdev at {addr}"))?;
        // Tiny writes are normal (DHCP is small); turn off Nagle so replies
        // don't get held in the kernel waiting for more data.
        stream.set_nodelay(true).ok();
        log::info!("qemu link: connected to {addr}");
        Ok(Self { stream })
    }

    pub fn read_frame(&mut self) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .context("reading qemu frame length")?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 65535 {
            return Err(anyhow!("qemu frame: implausible length {len}"));
        }
        let mut buf = vec![0u8; len];
        self.stream
            .read_exact(&mut buf)
            .context("reading qemu frame body")?;
        Ok(buf)
    }

    pub fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        let len = (frame.len() as u32).to_be_bytes();
        self.stream.write_all(&len)?;
        self.stream.write_all(frame)?;
        Ok(())
    }
}
