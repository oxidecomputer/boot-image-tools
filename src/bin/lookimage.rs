use flate2::read::ZlibDecoder;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::prelude::FileExt;

use anyhow::{bail, Result};
use sha2::Digest;

use bootserver::diskimage;

fn main() -> Result<()> {
    let opts = getopts::Options::new();

    let a = opts.parse(std::env::args().skip(1))?;

    if a.free.len() != 1 {
        bail!("which image file do you want to inspect?");
    }

    let mut fi = std::fs::File::open(&a.free[0])?;

    /*
     * Read the image header first.
     */
    let mut buf = vec![0u8; diskimage::DISK_HEADER_LENGTH];
    fi.read_exact_at(&mut buf, 0)?;
    let h = diskimage::Header::from_bytes(&buf)?;
    let hsum = h.checksum_str();

    println!("image name = {}", h.image_name);
    println!("flags = {:#x} ({:?})", h.flags.bits(), h.flags);
    println!("data size = {}", h.data_size);
    println!("image size = {}", h.image_size);
    println!("target size = {}", h.target_size);
    println!("image sum = {}", hsum);
    println!("dataset name = {}", h.dataset_name);
    if h.data_size == 0 {
        bail!("data size is {}", h.data_size);
    }
    if h.image_size < h.data_size {
        bail!("image size {} < data size {}", h.image_size, h.data_size);
    }
    if h.flags.contains(diskimage::Flags::COMPRESSED) {
        println!("ratio = {:.2}x", h.image_size as f64 / h.data_size as f64);
    }

    /*
     * Confirm that the data portion of the image matches the checksum in the
     * header.
     */
    let mut sum = sha2::Sha256::new();
    let mut buf = vec![0u8; 128 * 1024];
    let mut total = 0usize;

    if h.flags.contains(diskimage::Flags::COMPRESSED) {
        fi.seek(SeekFrom::Start(diskimage::DISK_HEADER_LENGTH as u64))?;
        let mut decoder = ZlibDecoder::new(fi);

        loop {
            let sz = decoder.read(&mut buf)?;
            if sz == 0 {
                break;
            }

            sum.update(&buf[0..sz]);

            total += sz;
        }
    } else {
        loop {
            let inpos = {
                let total: u64 = total.try_into().unwrap();
                total
                    .checked_add(
                        diskimage::DISK_HEADER_LENGTH.try_into().unwrap(),
                    )
                    .unwrap()
            };
            let sz = fi.read_at(&mut buf, inpos)?;
            if sz == 0 {
                break;
            }

            sum.update(&buf[0..sz]);

            total += sz;
        }
    }

    if h.image_size != total.try_into().unwrap() {
        bail!(
            "read {} bytes of image, but header says there should be {}",
            total,
            h.image_size
        );
    }

    let sum =
        sum.finalize().iter().map(|x| format!("{:02x}", x)).collect::<String>();

    if sum != hsum {
        bail!("image sum {} does not match sum from header {}", sum, hsum);
    }

    Ok(())
}
