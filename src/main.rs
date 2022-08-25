use std::{
    io::{Read, Seek},
    path::PathBuf,
    str::FromStr,
};

use anyhow::{anyhow, bail, Result};
use bytes::{Buf, BufMut};

mod dlpi;

enum Message {
    Hello(String),
    Offer(u64),
    Read { offset: u64, length: u64 },
    Data(u64, Vec<u8>),
    Finished,
    Reset,
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
        if data.remaining() != len {
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
                if data.remaining() != 2 * 8 {
                    bail!(
                        "payload length {} should have been {}",
                        data.remaining(),
                        16
                    );
                }
                let offset = data.get_u64();
                let length = data.get_u64();
                Ok(Message::Read { offset, length })
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
            Message::Offer(size) => {
                let mut buf = Vec::new();
                buf.put_u32(MAGIC);
                buf.put_u32(JMCBOOT_TYPE_OFFER);
                buf.put_u32(8);
                buf.put_u64(*size);
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
    let linkname =
        std::env::args().nth(1).ok_or_else(|| anyhow!("what link name?"))?;
    let filename = PathBuf::from(
        &std::env::args().nth(2).ok_or_else(|| anyhow!("ramdisk filename"))?,
    );
    let macaddr = dlpi::Address::from_str(
        &std::env::args()
            .nth(3)
            .ok_or_else(|| anyhow!("system MAC address?"))?,
    )?;

    println!("boot server starting on link {}...\n", linkname);

    let mut dl = dlpi::Dlpi::open(&linkname)?;
    dl.bind_ethertype(0x1DE0)?;

    let mut file = None;

    loop {
        if let Some(frame) = dl.recv(Some(1000))? {
            if frame.src() != Some(macaddr) {
                println!(
                    "\nreceived data from wrong host: src {} dst {} len {}",
                    frame.src().unwrap_or_default(),
                    frame.dst().unwrap_or_default(),
                    frame.data().len(),
                );
                continue;
            }

            let msg = match Message::try_from(&frame) {
                Ok(msg) => msg,
                Err(e) => {
                    println!("frame decode error: {:?}", e);
                    continue;
                }
            };

            match msg {
                Message::Hello(msg) => {
                    println!(
                        "\nreceived hello! src {} dst {} len {}",
                        frame.src().unwrap_or_default(),
                        frame.dst().unwrap_or_default(),
                        frame.data().len(),
                    );

                    println!("msg = {:?}", msg);

                    /*
                     * When a system says hello, we want to offer the image we
                     * have available.  If we cannot open the ramdisk file we'll
                     * just drop the request for now.
                     */
                    match std::fs::File::open(&filename) {
                        Ok(f) => match f.metadata() {
                            Ok(md) => {
                                file = Some(f);
                                println!(
                                    "opened file {:?}, size {}",
                                    filename,
                                    md.len()
                                );
                                dl.send(
                                    macaddr,
                                    &Message::Offer(md.len()).pack().unwrap(),
                                )?;
                            }
                            Err(e) => {
                                println!(
                                    "failed to stat {:?}: {:?}",
                                    filename, e
                                );
                            }
                        },
                        Err(e) => {
                            file = None;
                            println!("failed to open {:?}: {:?}", filename, e);
                        }
                    }
                }
                Message::Read { offset, mut length } => {
                    let msg = if let Some(ff) = &mut file {
                        if length > 1024 {
                            length = 1024;
                        }
                        let mut buf = vec![0u8; length.try_into().unwrap()];

                        if let Err(e) =
                            ff.seek(std::io::SeekFrom::Start(offset))
                        {
                            println!("seek {} error: {:?}", offset, e);
                            file = None;
                            Message::Reset
                        } else {
                            match ff.read(&mut buf) {
                                Ok(sz) => {
                                    buf.truncate(sz);
                                    Message::Data(offset, buf)
                                }
                                Err(e) => {
                                    println!("read {} error: {:?}", offset, e);
                                    file = None;
                                    Message::Reset
                                }
                            }
                        }
                    } else {
                        /*
                         * File not open implies we missed the Hello, and should
                         * reset the boot process.
                         */
                        Message::Reset
                    };
                    dl.send(macaddr, &msg.pack().unwrap())?;
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
                }
                _ => {}
            }
        }
    }
}
