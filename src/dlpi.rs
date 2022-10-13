#![allow(non_camel_case_types)]
#![allow(dead_code)]

use libdlpi_sys::*;

use anyhow::{bail, Result};
use std::{
    ffi::CString,
    os::raw::{c_uint, c_void},
    str::FromStr,
};

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct Address {
    pub addr: [u8; 6],
}

impl FromStr for Address {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 6 * 2 + 5 {
            bail!("invalid MAC address");
        }

        let t = s.splitn(6, ':').collect::<Vec<_>>();
        if t.len() != 6 {
            bail!("invalid MAC address");
        }

        let res = t
            .iter()
            .map(|s| Ok(u8::from_str_radix(s, 16)?))
            .collect::<Result<Vec<u8>>>()?;
        Ok(Address { addr: [res[0], res[1], res[2], res[3], res[4], res[5]] })
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.addr[0],
            self.addr[1],
            self.addr[2],
            self.addr[3],
            self.addr[4],
            self.addr[5]
        )
    }
}

impl Address {
    fn is_broadcast(&self) -> bool {
        self.addr.iter().all(|x| *x == 0xFF)
    }
}

pub struct Frame {
    data: Vec<u8>,
    addr: Vec<u8>,
    ri: dlpi_recvinfo_t,
}

impl Frame {
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn src(&self) -> Option<Address> {
        if self.addr.len() == 6 {
            let mut addr = Address { addr: Default::default() };
            for i in 0..6 {
                addr.addr[i] = self.addr[i];
            }
            Some(addr)
        } else {
            None
        }
    }

    pub fn dst(&self) -> Option<Address> {
        if self.ri.dri_destaddrlen == 6 {
            let mut addr = Address { addr: Default::default() };
            for i in 0..6 {
                addr.addr[i] = self.ri.dri_destaddr[i];
            }
            Some(addr)
        } else {
            None
        }
    }
}

pub struct Dlpi {
    handle: *mut dlpi_handle_t,
}

impl Dlpi {
    pub fn open(linkname: &str) -> Result<Dlpi> {
        let cs = CString::new(linkname).unwrap();

        let mut handle = std::ptr::null_mut();
        let r = unsafe { dlpi_open(cs.as_ptr(), &mut handle, 0) };
        if r != DLPI_SUCCESS {
            bail!("dlpi_open(\"{}\") failed ({})", linkname, r);
        }

        Ok(Dlpi { handle })
    }

    pub fn bind_ethertype(&mut self, ethertype: c_uint) -> Result<()> {
        if ethertype < 1536 || ethertype > 0xFFFF {
            bail!("invalid ethertype 0x{:04X}", ethertype);
        }

        let r = unsafe {
            dlpi_bind(
                self.handle,
                ethertype.try_into().unwrap(),
                std::ptr::null_mut(),
            )
        };
        if r != DLPI_SUCCESS {
            bail!("dlpi_bind(0x{:04X}) failed ({})", ethertype, r);
        }

        Ok(())
    }

    pub fn recv(&mut self, msec: Option<u32>) -> Result<Option<Frame>> {
        let mut f = Frame {
            data: Vec::with_capacity(1500),
            addr: Vec::with_capacity(DLPI_PHYSADDR_MAX),
            ri: unsafe { std::mem::zeroed() },
        };
        let mut msglen = f.data.capacity();
        let mut addrlen = f.addr.capacity();
        let r = unsafe {
            dlpi_recv(
                self.handle,
                f.addr.as_mut_ptr() as *mut c_void,
                &mut addrlen,
                f.data.as_mut_ptr() as *mut c_void,
                &mut msglen,
                if let Some(msec) = msec {
                    msec.try_into().unwrap()
                } else {
                    -1
                },
                &mut f.ri,
            )
        };

        if r == DLPI_ETIMEDOUT {
            Ok(None)
        } else if r != DLPI_SUCCESS {
            bail!("dlpi_recv() failed ({})", r);
        } else if msglen != f.ri.dri_totmsglen {
            bail!(
                "message truncated (got {}, total message was {} bytes)",
                msglen,
                f.ri.dri_totmsglen
            );
        } else {
            unsafe { f.data.set_len(msglen) };
            unsafe { f.addr.set_len(addrlen) };
            Ok(Some(f))
        }
    }

    pub fn send(&mut self, dst: Address, data: &[u8]) -> Result<()> {
        let r = unsafe {
            dlpi_send(
                self.handle,
                dst.addr.as_ptr() as *const c_void,
                dst.addr.len(),
                data.as_ptr() as *const c_void,
                data.len(),
                std::ptr::null(),
            )
        };
        if r != DLPI_SUCCESS {
            bail!("send failed ({})", r);
        }
        Ok(())
    }
}

impl Drop for Dlpi {
    fn drop(&mut self) {
        unsafe { dlpi_close(self.handle) };
    }
}
