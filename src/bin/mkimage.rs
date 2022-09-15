use std::os::unix::prelude::FileExt;

use anyhow::Result;
use sha2::Digest;

use bootserver::diskimage;

fn main() -> Result<()> {
    let mut opts = getopts::Options::new();
    opts.reqopt("i", "", "input raw image file", "RAW");
    opts.reqopt("o", "", "output image file with header", "IMAGE");

    let a = opts.parse(std::env::args().skip(1))?;

    let fi = std::fs::File::open(&a.opt_str("i").unwrap())?;
    let fo = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&a.opt_str("o").unwrap())?;

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

    let h = diskimage::Header {
        image_size: total.try_into().unwrap(),
        target_size: 4 * 1024 * 1024 * 1024, /* XXX */
        dataset_name: "rpool/ROOT/ramdisk".into(), /* XXX */
        sha256: sum.finalize().into(),
    };

    let hb = h.to_bytes()?;

    fo.write_all_at(&hb, 0)?;

    println!("ok, image written!");

    Ok(())
}
