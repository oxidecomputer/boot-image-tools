use anyhow::{bail, Result};
use bitflags::bitflags;
use bytes::{Buf, BufMut, BytesMut};

pub const DISK_VERSION: u32 = 2;
pub const DISK_MAGIC: u32 = 0x1DEB0075;
pub const DISK_CSUMLEN_SHA256: usize = 32;
pub const DISK_DATASET_SIZE: usize = 128;
pub const DISK_HEADER_LENGTH: usize = 4096;

bitflags! {
    #[derive(Default)]
    pub struct Flags: u64 {
        const COMPRESSED = 1;
    }
}

pub struct Header {
    pub flags: Flags,
    pub data_size: u64,
    pub image_size: u64,
    pub target_size: u64,
    pub dataset_name: String,
    pub sha256: [u8; 32],
}

impl Header {
    pub fn to_bytes(&self) -> Result<BytesMut> {
        let mut hdr = BytesMut::new();
        hdr.put_u32_le(DISK_MAGIC);
        hdr.put_u32_le(DISK_VERSION);
        hdr.put_u64_le(self.flags.bits() as u64);
        hdr.put_u64_le(self.data_size as u64);
        hdr.put_u64_le(self.image_size as u64);
        hdr.put_u64_le(self.target_size as u64);

        assert_eq!(self.sha256.len(), DISK_CSUMLEN_SHA256);
        for i in 0..DISK_CSUMLEN_SHA256 {
            hdr.put_u8(self.sha256[i]);
        }

        let dsb = self.dataset_name.as_bytes();
        if dsb.len() > DISK_DATASET_SIZE - 1 {
            bail!("dataset name {:?} is too long", self.dataset_name);
        }
        for i in 0..(DISK_DATASET_SIZE - 1) {
            if i < dsb.len() {
                hdr.put_u8(dsb[i]);
            } else {
                hdr.put_u8(0);
            }
        }
        /*
         * Ensure the string is null-terminated:
         */
        hdr.put_u8(0);

        /*
         * Pad the header out to the full 4K block size:
         */
        while hdr.len() < DISK_HEADER_LENGTH {
            hdr.put_u8(0);
        }

        Ok(hdr)
    }

    pub fn from_bytes(mut input: &[u8]) -> Result<Header> {
        if input.len() != DISK_HEADER_LENGTH {
            bail!("wrong header length");
        }

        let magic = input.get_u32_le();
        if magic != DISK_MAGIC {
            bail!("wrong magic: {:x} != expected {:x}", magic, DISK_MAGIC);
        }

        let version = input.get_u32_le();
        if version != DISK_VERSION {
            bail!(
                "wrong version: {:x} != expected {:x}",
                version,
                DISK_VERSION
            );
        }

        let flags =
            Flags::from_bits_truncate(input.get_u64_le().try_into().unwrap());
        let data_size = input.get_u64_le().try_into().unwrap();
        let image_size = input.get_u64_le().try_into().unwrap();
        let target_size = input.get_u64_le().try_into().unwrap();
        if image_size > target_size {
            bail!("image size {} > target size {}", image_size, target_size);
        }

        let mut sha256 = [0u8; 32];
        for i in 0..DISK_CSUMLEN_SHA256 {
            sha256[i] = input.get_u8();
        }

        let mut s = Vec::new();
        loop {
            if s.len() >= DISK_HEADER_LENGTH {
                bail!("dataset name string not properly terminated");
            }

            let b = input.get_u8();
            if b == 0 {
                break;
            }
            s.push(b);
        }
        let dataset_name = String::from_utf8(s)?;

        Ok(Header {
            flags,
            data_size,
            image_size,
            target_size,
            dataset_name,
            sha256,
        })
    }

    pub fn checksum_str(&self) -> String {
        self.sha256.iter().map(|x| format!("{:02x}", x)).collect::<String>()
    }
}
