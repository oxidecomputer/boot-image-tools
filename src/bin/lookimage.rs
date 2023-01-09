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

    let fi = std::fs::File::open(&a.free[0])?;

    /*
     * Read the image header first.
     */
    let mut buf = vec![0u8; diskimage::DISK_HEADER_LENGTH];
    fi.read_exact_at(&mut buf, 0)?;
    let h = diskimage::Header::from_bytes(&buf)?;

    /*
     * Confirm that the data portion of the image matches the checksum in the
     * header.
     */
    let mut sum = sha2::Sha256::new();
    let mut buf = vec![0u8; 128 * 1024];
    let mut total = 0usize;
    loop {
        let inpos = {
            let total: u64 = total.try_into().unwrap();
            total
                .checked_add(diskimage::DISK_HEADER_LENGTH.try_into().unwrap())
                .unwrap()
        };
        let sz = fi.read_at(&mut buf, inpos)?;
        if sz == 0 {
            break;
        }

        sum.update(&buf[0..sz]);

        total += sz;
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
    let hsum =
        h.sha256.iter().map(|x| format!("{:02x}", x)).collect::<String>();

    if sum != hsum {
        bail!("image sum {} does not match sum from header {}", sum, hsum);
    }

    println!("image sum = {}", sum);
    println!("image size = {}", h.image_size);
    println!("target size = {}", h.target_size);
    println!("dataset name = {}", h.dataset_name);

    Ok(())
}
