use abootimg_oxide::{binrw::io::Cursor, Header, HeaderV0Versioned, HeaderV3};
use anyhow::{anyhow, Context, Result};
use sha1::{Digest, Sha1};
use std::fs;
use std::path::Path;

/// A boot image, of header version 0 through 4 (`boot`, `init_boot`,
/// `recovery`), split into its header and the parts after it.
pub struct BootImage {
    pub header: Header,
    pub kernel: Vec<u8>,
    pub ramdisk: Vec<u8>,
    /// The second stage bootloader, which versions 0 through 2 may hold.
    pub second: Vec<u8>,
    /// The recovery DTBO, which versions 1 and 2 may hold.
    pub recovery_dtbo: Vec<u8>,
    /// The device tree blob, which version 2 may hold.
    pub dtb: Vec<u8>,
}

fn section(bytes: &[u8], at: usize, len: u32, what: &str) -> Result<Vec<u8>> {
    let end = at + len as usize;
    bytes.get(at..end).map(<[u8]>::to_vec).ok_or_else(|| anyhow!("{what} runs past the end of the image"))
}

impl BootImage {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        BootImage::parse(&bytes).with_context(|| format!("read {}", path.display()))
    }

    /// The image `bytes` hold, as a partition holds it: the image, then
    /// whatever fills the partition after it.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        match Header::parse(&mut Cursor::new(bytes)).context("header")? {
            Header::V3(header) => {
                let kernel = section(bytes, HeaderV3::kernel_position(), header.kernel_size, "kernel")?;
                let ramdisk = section(bytes, header.ramdisk_position(), header.ramdisk_size, "ramdisk")?;
                Ok(BootImage {
                    header: Header::V3(header),
                    kernel,
                    ramdisk,
                    second: Vec::new(),
                    recovery_dtbo: Vec::new(),
                    dtb: Vec::new(),
                })
            }
            Header::V0(header) => {
                let kernel = section(bytes, header.kernel_position(), header.kernel_size, "kernel")?;
                let ramdisk = section(bytes, header.ramdisk_position(), header.ramdisk_size, "ramdisk")?;
                let second = section(bytes, header.second_bootloader_position(), header.second_bootloader_size, "second stage bootloader")?;
                let (recovery_dtbo, dtb) = match header.versioned {
                    HeaderV0Versioned::V0 => (Vec::new(), Vec::new()),
                    HeaderV0Versioned::V1 { recovery_dtbo_size, .. } => {
                        (section(bytes, header.recovery_dtbo_position(), recovery_dtbo_size, "recovery DTBO")?, Vec::new())
                    }
                    HeaderV0Versioned::V2 { recovery_dtbo_size, dtb_size, .. } => {
                        let recovery_dtbo = section(bytes, header.recovery_dtbo_position(), recovery_dtbo_size, "recovery DTBO")?;
                        let dtb = section(bytes, header.dtb_position().expect("version 2 has a device tree"), dtb_size, "device tree")?;
                        (recovery_dtbo, dtb)
                    }
                };
                Ok(BootImage { header: Header::V0(header), kernel, ramdisk, second, recovery_dtbo, dtb })
            }
        }
    }

    /// The image with sizes taken from its parts. A version 4 header keeps its
    /// version but carries no boot signature; unlocked bootloaders do not ask
    /// for one.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match &self.header {
            Header::V3(header) => {
                let mut header = header.clone();
                header.kernel_size = u32::try_from(self.kernel.len()).context("kernel size")?;
                header.ramdisk_size = u32::try_from(self.ramdisk.len()).context("ramdisk size")?;
                header.v4_signature_size = header.v4_signature_size.map(|_| 0);
                let mut out = Vec::new();
                Header::V3(header).write(&mut out).context("write header")?;
                pad(&mut out, 4096);
                out.extend_from_slice(&self.kernel);
                pad(&mut out, 4096);
                out.extend_from_slice(&self.ramdisk);
                pad(&mut out, 4096);
                Ok(out)
            }
            Header::V0(header) => {
                let page = header.page_size as usize;
                let mut header = header.clone();
                header.kernel_size = u32::try_from(self.kernel.len()).context("kernel size")?;
                header.ramdisk_size = u32::try_from(self.ramdisk.len()).context("ramdisk size")?;
                header.second_bootloader_size = u32::try_from(self.second.len()).context("second stage bootloader size")?;
                let recovery_dtbo_offset = header.recovery_dtbo_position() as u64;
                match &mut header.versioned {
                    HeaderV0Versioned::V0 => {}
                    HeaderV0Versioned::V1 { recovery_dtbo_size, recovery_dtbo_addr, .. } => {
                        *recovery_dtbo_size = u32::try_from(self.recovery_dtbo.len()).context("recovery DTBO size")?;
                        *recovery_dtbo_addr = recovery_dtbo_offset;
                    }
                    HeaderV0Versioned::V2 { recovery_dtbo_size, recovery_dtbo_addr, dtb_size, .. } => {
                        *recovery_dtbo_size = u32::try_from(self.recovery_dtbo.len()).context("recovery DTBO size")?;
                        *recovery_dtbo_addr = recovery_dtbo_offset;
                        *dtb_size = u32::try_from(self.dtb.len()).context("device tree size")?;
                    }
                }
                // The hash the header keeps of its parts, which older
                // bootloaders read, over each part and then its size.
                let mut parts: Vec<&[u8]> = vec![&self.kernel, &self.ramdisk, &self.second];
                if !matches!(header.versioned, HeaderV0Versioned::V0) {
                    parts.push(&self.recovery_dtbo);
                }
                if matches!(header.versioned, HeaderV0Versioned::V2 { .. }) {
                    parts.push(&self.dtb);
                }
                let mut hash = Sha1::new();
                for part in parts {
                    hash.update(part);
                    hash.update(u32::try_from(part.len()).context("part size")?.to_le_bytes());
                }
                let digest = hash.finalize();
                header.hash_digest = [0u8; 32];
                header.hash_digest[..digest.len()].copy_from_slice(&digest);
                let mut out = Vec::new();
                Header::V0(header).write(&mut out).context("write header")?;
                pad(&mut out, page);
                out.extend_from_slice(&self.kernel);
                pad(&mut out, page);
                out.extend_from_slice(&self.ramdisk);
                pad(&mut out, page);
                out.extend_from_slice(&self.second);
                pad(&mut out, page);
                out.extend_from_slice(&self.recovery_dtbo);
                pad(&mut out, page);
                out.extend_from_slice(&self.dtb);
                pad(&mut out, page);
                Ok(out)
            }
        }
    }
}

fn pad(out: &mut Vec<u8>, page: usize) {
    out.resize(out.len().div_ceil(page) * page, 0);
}
