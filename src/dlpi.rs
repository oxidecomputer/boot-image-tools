/*
 * Copyright 2024 Oxide Computer Company
 */

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use anyhow::{bail, Result};
use std::{
    ffi::CString,
    os::raw::{c_char, c_int, c_uchar, c_uint, c_void},
    str::FromStr,
};

enum dlpi_handle_t {}

const DLPI_PHYSADDR_MAX: usize = 64;

const DL_SYSERR: c_int = 0x04;

const DLPI_SUCCESS: c_int = 10000; /* DLPI operation succeeded */
const DLPI_EINVAL: c_int = 10001; /* invalid argument */
const DLPI_ELINKNAMEINVAL: c_int = 10002; /* invalid DLPI linkname */
const DLPI_ENOLINK: c_int = 10003; /* DLPI link does not exist */
const DLPI_EBADLINK: c_int = 10004; /* bad DLPI link */
const DLPI_EINHANDLE: c_int = 10005; /* invalid DLPI handle */
const DLPI_ETIMEDOUT: c_int = 10006; /* DLPI operation timed out */
const DLPI_EVERNOTSUP: c_int = 10007; /* unsupported DLPI Version */
const DLPI_EMODENOTSUP: c_int = 10008; /* unsupported DLPI connection mode */
const DLPI_EUNAVAILSAP: c_int = 10009; /* unavailable DLPI SAP */
const DLPI_FAILURE: c_int = 10010; /* DLPI operation failed */
const DLPI_ENOTSTYLE2: c_int = 10011; /* DLPI style-2 node reports style-1 */
const DLPI_EBADMSG: c_int = 10012; /* bad DLPI message */
const DLPI_ERAWNOTSUP: c_int = 10013; /* DLPI raw mode not supported */
const DLPI_ENOTEINVAL: c_int = 10014; /* invalid DLPI notification type */
const DLPI_ENOTENOTSUP: c_int = 10015; /* DLPI notif. not supported by link */
const DLPI_ENOTEIDINVAL: c_int = 10016; /* invalid DLPI notification id */
const DLPI_EIPNETINFONOTSUP: c_int = 10017; /* DLPI_IPNETINFO not supported */

#[repr(C)]
struct dlpi_recvinfo_t {
    dri_destaddr: [c_uchar; DLPI_PHYSADDR_MAX],
    dri_destaddrlen: c_uchar,
    dri_destaddrtype: c_uint,
    dri_totmsglen: usize,
}

#[repr(C)]
struct dlpi_sendinfo_t {
    dsi_sap: c_uint,
    dsi_prio: dl_priority_t,
}

#[repr(C)]
struct dl_priority_t {
    dl_min: i32,
    dl_max: i32,
}

#[repr(C)]
enum dlpi_addrtype_t {
    DLPI_ADDRTYPE_UNICAST,
    DLPI_ADDRTYPE_GROUP,
}

/// Promiscuous mode at phys level
const DL_PROMISC_PHYS: c_uint = 0x01;

/// Promiscuous mode at SAP level
const DL_PROMISC_SAP: c_uint = 0x02;

/// Promiscuous mode for multicast
const DL_PROMISC_MULTI: c_uint = 0x03;

/// Above promiscuous modes only enabled for rx
const DL_PROMISC_RX_ONLY: c_uint = 0x04;

#[link(name = "dlpi")]
extern "C" {
    fn dlpi_open(
        linkname: *const c_char,
        dhp: *mut *mut dlpi_handle_t,
        flags: c_uint,
    ) -> c_int;
    fn dlpi_close(dhp: *mut dlpi_handle_t);
    fn dlpi_bind(
        dhp: *mut dlpi_handle_t,
        sap: c_uint,
        boundsap: *mut c_uint,
    ) -> c_int;
    fn dlpi_recv(
        dhp: *mut dlpi_handle_t,
        saddrp: *mut c_void,
        saddrlenp: *mut usize,
        msgbuf: *mut c_void,
        msglenp: *mut usize,
        msec: c_int,
        recvp: *mut dlpi_recvinfo_t,
    ) -> c_int;
    fn dlpi_send(
        dhp: *mut dlpi_handle_t,
        daddrp: *const c_void,
        daddrlen: usize,
        msgbuf: *const c_void,
        msglen: usize,
        sendp: *const dlpi_sendinfo_t,
    ) -> c_int;
    fn dlpi_promiscon(dhp: *mut dlpi_handle_t, promisc: c_uint) -> c_int;
    fn dlpi_promiscoff(dhp: *mut dlpi_handle_t, promisc: c_uint) -> c_int;
}

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

    /// Enables promiscuous mode (rx only) on the DLPI handle
    pub fn promisc_on(&mut self) -> Result<()> {
        let r = unsafe { dlpi_promiscon(self.handle, DL_PROMISC_RX_ONLY) };
        if r != DLPI_SUCCESS {
            bail!("failed to set DL_PROMISC_RX_ONLY ({r})");
        }
        let r = unsafe { dlpi_promiscon(self.handle, DL_PROMISC_PHYS) };
        if r != DLPI_SUCCESS {
            bail!("failed to set DL_PROMISC_PHYS ({r})");
        }
        Ok(())
    }
}

impl Drop for Dlpi {
    fn drop(&mut self) {
        unsafe { dlpi_close(self.handle) };
    }
}
