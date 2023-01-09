use std::os::unix::prelude::FileExt;

use anyhow::{bail, Result};
use sha2::Digest;

use bootserver::diskimage;

fn main() -> Result<()> {
    let mut opts = getopts::Options::new();
    opts.reqopt("i", "", "input raw image file", "RAW");
    opts.reqopt("o", "", "output image file with header", "IMAGE");
    opts.optopt("O", "", "output boot_image_csum file", "CSUM_FILE");
    opts.optopt("s", "", "target ramdisk size (MiB)", "MEBIBYTES");

    let a = opts.parse(std::env::args().skip(1))?;

    let fi = std::fs::File::open(&a.opt_str("i").unwrap())?;
    let fo = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&a.opt_str("o").unwrap())?;
    let target_size = if let Some(arg) = a.opt_str("s") {
        arg.parse::<u64>()? * 1024 * 1024
    } else {
        4 * 1024 * 1024 * 1024
    };

    let mut sum = sha2::Sha256::new();
    let mut buf = vec![0u8; 128 * 1024];
    let mut total = 0usize;
    loop {
        let inpos = total.try_into().unwrap();
        let sz = fi.read_at(&mut buf, inpos)?;
        if sz == 0 {
            break;
        }

        sum.update(&buf[0..sz]);

        let outpos = total
            .checked_add(diskimage::DISK_HEADER_LENGTH)
            .unwrap()
            .try_into()
            .unwrap();
        fo.write_at(&buf[0..sz], outpos)?;

        total += sz;
    }

    let image_size: u64 = total.try_into().unwrap();
    if image_size > target_size {
        bail!(
            "target size of {} bytes is less than image size of {}",
            target_size,
            image_size,
        );
    }

    let h = diskimage::Header {
        image_size,
        target_size,
        dataset_name: "rpool/ROOT/ramdisk".into(), /* XXX */
        sha256: sum.finalize().into(),
    };

    let hb = h.to_bytes()?;

    fo.write_all_at(&hb, 0)?;

    println!("ok, image written!");

    if let Some(path) = a.opt_str("O") {
        let fo = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)?;

        fo.write_all_at(&h.sha256, 0)?;
        println!("ok, boot_image_csum file written!");
    }

    Ok(())
}
