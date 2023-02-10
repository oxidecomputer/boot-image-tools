use anyhow::{bail, Result};
use bitflags::bitflags;
use bytes::{Buf, BufMut, BytesMut};

pub const DISK_VERSION: u32 = 2;
pub const DISK_MAGIC: u32 = 0x1DEB0075;
pub const DISK_CSUMLEN_SHA256: usize = 32;
pub const DISK_DATASET_SIZE: usize = 128;
pub const DISK_IMAGENAME_SIZE: usize = 128;
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
    pub image_name: String,
    pub sha256: [u8; 32],
}

trait PaddedString {
    fn write_padded_string(&mut self, val: &str, len: usize);
}

impl PaddedString for BytesMut {
    fn write_padded_string(&mut self, val: &str, len: usize) {
        let dsb = val.as_bytes();
        assert!(dsb.len() < len, "string {val:?} is too long");
        let prev_len = self.len();
        self.extend_from_slice(dsb);
        // Since dsb < len, this always appends a 0-terminating byte.
        self.resize(prev_len + len, 0);
    }
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

        hdr.write_padded_string(&self.dataset_name, DISK_DATASET_SIZE);
        hdr.write_padded_string(&self.image_name, DISK_IMAGENAME_SIZE);

        /*
         * Pad the header out to the full 4K block size:
         */
        hdr.resize(DISK_HEADER_LENGTH, 0);

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

        let mut s = vec![0; DISK_DATASET_SIZE];
        if input.remaining() < s.len() {
            bail!("insufficient data for dataset name");
        }
        input.copy_to_slice(&mut s);
        let dataset_name =
            String::from_utf8(s)?.trim_matches(char::from(0)).to_string();

        let mut s = vec![0; DISK_IMAGENAME_SIZE];
        if input.remaining() < s.len() {
            bail!("insufficient data for image name");
        }
        input.copy_to_slice(&mut s);
        let image_name =
            String::from_utf8(s)?.trim_matches(char::from(0)).to_string();

        Ok(Header {
            flags,
            data_size,
            image_size,
            target_size,
            dataset_name,
            image_name,
            sha256,
        })
    }

    pub fn checksum_str(&self) -> String {
        self.sha256.iter().map(|x| format!("{:02x}", x)).collect::<String>()
    }
}
