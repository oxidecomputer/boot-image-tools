/*
 * Copyright 2024 Oxide Computer Company
 */

use std::{
    io::Write,
    os::unix::prelude::FileExt,
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use bytes::{Buf, BufMut};

use bootserver::{diskimage, dlpi};

enum Message {
    Hello(String),
    Offer(u64, u64, [u8; 32], String),
    Read(Vec<u64>),
    Data(u64, Vec<u8>),
    Finished,
    Reset,
}

struct Image {
    header: diskimage::Header,
    file: std::fs::File,
}

impl Image {
    fn open<P: AsRef<Path>>(path: P) -> Result<Image> {
        let path = path.as_ref();
        let file = std::fs::File::open(path)?;
        let mut hdr = vec![0u8; diskimage::DISK_HEADER_LENGTH];
        file.read_exact_at(&mut hdr, 0)?;
        let header = diskimage::Header::from_bytes(&hdr)?;
        Ok(Image { header, file })
    }
}

impl std::fmt::Display for Image {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sum = self
            .header
            .sha256
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        write!(
            f,
            "image (data size {}, image size {}, target size {}, \
                hash {}, dataset {})",
            self.header.data_size,
            self.header.image_size,
            self.header.target_size,
            sum,
            self.header.dataset_name,
        )
    }
}

const MAGIC: u32 = 0x1DE12345;

const JMCBOOT_TYPE_HELLO: u32 = 0x9001;
const JMCBOOT_TYPE_OFFER: u32 = 0x9102;
const JMCBOOT_TYPE_READ: u32 = 0x9003;
const JMCBOOT_TYPE_DATA: u32 = 0x9104;
const JMCBOOT_TYPE_FINISHED: u32 = 0x9005;
const JMCBOOT_TYPE_RESET: u32 = 0x9106;

impl TryFrom<&dlpi::Frame> for Message {
    type Error = anyhow::Error;

    fn try_from(frame: &dlpi::Frame) -> Result<Self, Self::Error> {
        let mut data = frame.data();
        if data.remaining() < 4 {
            bail!("frame too short");
        }
        let magic = data.get_u32();
        if magic != MAGIC {
            bail!("frame magic {:08X} not the expected {:08X}", magic, MAGIC);
        }

        if data.remaining() < 8 {
            bail!("frame too short");
        }
        let typecode = data.get_u32().try_into().unwrap();
        let len = data.get_u32().try_into().unwrap();
        if len >= 34 && data.remaining() != len {
            bail!(
                "payload length {} not the expected {}",
                data.remaining(),
                len
            );
        }

        match typecode {
            JMCBOOT_TYPE_HELLO => {
                let msg = String::from_utf8_lossy(&data.get(0..).unwrap())
                    .trim_end_matches('\0')
                    .to_string();
                Ok(Message::Hello(msg))
            }
            JMCBOOT_TYPE_READ => {
                if data.remaining() < 8 {
                    bail!("payload too short ({})", data.remaining());
                }
                let count = data.get_u64();
                if count > 160 {
                    bail!("too many slots ({})", count);
                }
                if data.remaining() < (count as usize) * 8 {
                    bail!(
                        "payload length {} should have been {}",
                        data.remaining(),
                        count * 8,
                    );
                }
                let mut offsets = Vec::new();
                for _ in 0..count {
                    offsets.push(data.get_u64());
                }
                Ok(Message::Read(offsets))
            }
            JMCBOOT_TYPE_FINISHED => Ok(Message::Finished),
            other => {
                bail!("unexpected frame type code {:04X}", other);
            }
        }
    }
}

impl Message {
    fn pack(&self) -> Result<Vec<u8>> {
        match self {
            Message::Offer(image_size, target_size, sha256, dataset) => {
                let mut buf = Vec::new();
                buf.put_u32(MAGIC);
                buf.put_u32(JMCBOOT_TYPE_OFFER);
                buf.put_u32(2 * 8 + 32 + 128);
                buf.put_u64(*target_size);
                buf.put_u64(*image_size);
                for b in sha256.iter() {
                    buf.put_u8(*b);
                }
                let sz = dataset.as_bytes().len();
                if sz > 127 {
                    bail!("dataset name is too long ({} > 127)", sz);
                }
                for b in dataset.as_bytes() {
                    buf.put_u8(*b);
                }
                for _ in 0..(128 - sz) {
                    buf.put_u8(0);
                }
                Ok(buf)
            }
            Message::Data(offset, data) => {
                if data.len() > 1476 - 8 {
                    bail!("data {} too long for frame", data.len());
                }

                let mut buf = Vec::with_capacity(data.len() + 2 * 4 + 2 * 8);
                buf.put_u32(MAGIC);
                buf.put_u32(JMCBOOT_TYPE_DATA);
                buf.put_u32(8 + data.len() as u32);
                buf.put_u64(*offset);
                buf.put_slice(&data);
                Ok(buf)
            }
            Message::Reset => {
                let mut buf = Vec::new();
                buf.put_u32(MAGIC);
                buf.put_u32(JMCBOOT_TYPE_RESET);
                buf.put_u32(0);
                Ok(buf)
            }
            _ => bail!("cannot pack this message type"),
        }
    }
}

fn main() -> Result<()> {
    let mut opts = getopts::Options::new();
    opts.parsing_style(getopts::ParsingStyle::StopAtFirstFree);
    opts.optflag("", "help", "usage information");
    opts.optflag("s", "", "exit after a single boot has been completed");
    opts.optopt(
        "t",
        "",
        "exit with failure if no broadcast received in N seconds",
        "SECONDS",
    );

    let prog = "bootserver";
    let usage = |err: Option<&str>| {
        let mut top = opts.short_usage(prog);
        top += " LINK_NAME IMAGE_FILE MAC_ADDRESS";
        if let Some(err) = err {
            eprintln!("{}\nERROR: {}", top.trim(), err);
        } else {
            println!("{}", opts.usage(top.trim()));
        }
    };
    let a = match opts.parse(std::env::args().skip(1)) {
        Ok(a) if a.free.len() <= 3 => {
            if a.opt_present("help") {
                usage(None);
                return Ok(());
            }
            a
        }
        Ok(_) => {
            usage(Some("unexpected arguments"));
            std::process::exit(1);
        }
        Err(e) => {
            usage(Some(&e.to_string()));
            std::process::exit(1);
        }
    };

    let Some(linkname) = a.free.get(0) else {
        usage(Some("specify link name; e.g., axf0"));
        std::process::exit(1);
    };
    let filename = if let Some(filename) = a.free.get(1) {
        PathBuf::from(filename)
    } else {
        usage(Some("specify ramdisk image file name"));
        std::process::exit(1);
    };
    let mut macaddr = if let Some(macaddr) = a.free.get(2) {
        if macaddr == "any" {
            None
        } else {
            match dlpi::Address::from_str(macaddr) {
                Ok(addr) => Some(addr),
                Err(e) => {
                    usage(Some(&format!("MAC address not valid: {}", e)));
                    std::process::exit(1);
                }
            }
        }
    } else {
        usage(Some("specify MAC address of target system"));
        std::process::exit(1);
    };

    let one_boot_only = a.opt_present("s");
    let one_boot_check = || -> Result<()> {
        if one_boot_only {
            bail!("failures are fatal in one-boot mode");
        } else {
            Ok(())
        }
    };

    let timeout_seconds =
        a.opt_str("t").map(|s| s.parse::<u64>()).transpose()?;
    let deadline = timeout_seconds
        .as_ref()
        .map(|&n| Instant::now().checked_add(Duration::from_secs(n)).unwrap());

    println!("boot server starting on link {}...\n", linkname);

    let mut dl = dlpi::Dlpi::open(&linkname)?;
    dl.bind_ethertype(0x1DE0)?;

    let mut file: Option<Image> = None;
    let mut last_read_status = Instant::now();
    let mut last_read_offset: Option<u64> = None;

    loop {
        let now = Instant::now();

        if let Some(deadline) = deadline {
            if now > deadline {
                bail!(
                    "boot server gave up after {} seconds without a client",
                    timeout_seconds.unwrap(),
                );
            }
        }

        if let Some(img) = &file {
            if now.checked_duration_since(last_read_status).unwrap().as_secs()
                > 1
            {
                if let Some(last_read_offset) = last_read_offset {
                    let pct = 100 * last_read_offset / img.header.image_size;

                    print!(
                        "\rprogress: sent up to offset {} ({}%)",
                        last_read_offset, pct,
                    );
                    std::io::stdout().flush().unwrap();
                    last_read_status = Instant::now();
                }
            }
        }

        if let Some(frame) = dl.recv(Some(1000))? {
            if let Some(macaddr) = macaddr {
                /*
                 * We were provided a MAC address by the caller, or we have
                 * already settled on one based on broadcasts.
                 */
                if frame.src() != Some(macaddr) {
                    println!(
                        "\nreceived data from wrong host: src {} dst {} len {}",
                        frame.src().unwrap_or_default(),
                        frame.dst().unwrap_or_default(),
                        frame.data().len(),
                    );
                    continue;
                }
            }

            let msg = match Message::try_from(&frame) {
                Ok(msg) => msg,
                Err(e) => {
                    println!("frame decode error: {:?}", e);
                    continue;
                }
            };

            if macaddr.is_none() && !matches!(&msg, Message::Hello(_)) {
                continue;
            }

            match msg {
                Message::Hello(msg) => {
                    println!(
                        "\nreceived hello! src {} dst {} len {}",
                        frame.src().unwrap_or_default(),
                        frame.dst().unwrap_or_default(),
                        frame.data().len(),
                    );

                    if macaddr.is_none() {
                        macaddr = Some(frame.src().unwrap());
                    }

                    println!("msg = {:?}", msg);

                    /*
                     * When a system says hello, we want to offer the image we
                     * have available.  If we cannot open the ramdisk file we'll
                     * just drop the request for now.
                     */
                    match Image::open(&filename) {
                        Ok(img) => {
                            println!("opened image {:?}: {}", filename, img);
                            if img
                                .header
                                .flags
                                .contains(diskimage::Flags::COMPRESSED)
                            {
                                println!("cannot serve compressed images");
                                one_boot_check()?;
                            } else {
                                dl.send(
                                    macaddr.unwrap(),
                                    &Message::Offer(
                                        img.header.image_size,
                                        img.header.target_size,
                                        img.header.sha256,
                                        img.header.dataset_name.to_string(),
                                    )
                                    .pack()
                                    .unwrap(),
                                )?;
                                file = Some(img);
                                last_read_status = Instant::now();
                                last_read_offset = None;
                            }
                        }
                        Err(e) => {
                            file = None;
                            println!("failed to open {:?}: {:?}", filename, e);
                            one_boot_check()?;
                        }
                    }
                }
                Message::Read(offsets) => {
                    if let Some(img) = &mut file {
                        for offset in offsets {
                            let mut buf = vec![0u8; 1024];
                            let fileoffset = offset
                                .checked_add(
                                    diskimage::DISK_HEADER_LENGTH
                                        .try_into()
                                        .unwrap(),
                                )
                                .unwrap();

                            last_read_offset =
                                Some(if let Some(last) = last_read_offset {
                                    last.max(offset)
                                } else {
                                    offset
                                });

                            /*
                             * XXX short reads?
                             */
                            match img.file.read_at(&mut buf, fileoffset) {
                                Ok(sz) => {
                                    if sz < 1024 {
                                        println!(
                                            "short read {} at offset {}",
                                            sz, offset,
                                        );
                                    }
                                    buf.truncate(sz);
                                    dl.send(
                                        macaddr.unwrap(),
                                        &Message::Data(offset, buf)
                                            .pack()
                                            .unwrap(),
                                    )?;
                                }
                                Err(e) => {
                                    println!("read {} error: {:?}", offset, e);
                                    file = None;
                                    dl.send(
                                        macaddr.unwrap(),
                                        &Message::Reset.pack().unwrap(),
                                    )?;
                                    one_boot_check()?;
                                    break;
                                }
                            }
                        }
                    } else {
                        /*
                         * File not open implies we missed the Hello, and
                         * should reset the boot process.
                         */
                        println!("read without open file; reset!");
                        dl.send(
                            macaddr.unwrap(),
                            &Message::Reset.pack().unwrap(),
                        )?;
                        one_boot_check()?;
                    }
                }
                Message::Finished => {
                    println!(
                        "\nreceived finished! src {} dst {} len {}",
                        frame.src().unwrap_or_default(),
                        frame.dst().unwrap_or_default(),
                        frame.data().len(),
                    );

                    file = None;
                    println!("finished copying!");

                    if one_boot_only {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
    }
}
