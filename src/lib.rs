//! Hashes anything to a private MAC address

#![no_std]

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

use core::hash::{Hash, Hasher};

/// A common MAC address in networks
pub type HwAddr = [u8; 6];

struct HwAddrHasher {
    addr: HwAddr,
    pos: usize,
}

impl HwAddrHasher {
    /// Produce a new hasher
    pub fn new() -> HwAddrHasher {
        HwAddrHasher {
            addr: [0; 6],
            pos: 0,
        }
    }

    /// Obtain the resulting address
    pub fn unwrap(mut self) -> HwAddr {
        self.addr[0] = 0b10 | (self.addr[0] & 0b1111_1100);
        self.addr
    }
}

impl Hasher for HwAddrHasher {
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.write_u8(*byte);
        }
    }

    fn write_u8(&mut self, byte: u8) {
        self.addr[self.pos] ^= byte;

        self.pos += 1;
        if self.pos >= self.addr.len() {
            self.pos = 0;
        }
    }

    fn finish(&self) -> u64 {
        // Actual hash result is not important
        0
    }
}

/// Generate a private MAC address by hashing something
pub fn generate_hwaddr<H: Hash>(input: &H) -> HwAddr {
    let mut hasher = HwAddrHasher::new();
    input.hash(&mut hasher);
    hasher.unwrap()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use super::generate_hwaddr;

    #[test]
    fn it_works() {
        let hwaddr = generate_hwaddr(&23);
        assert_eq!(hwaddr.len(), 6);
        assert_eq!(hwaddr[0] & 0b11, 0b10);
    }

    quickcheck! {
        fn prop(xs: Vec<isize>) -> bool {
            let hwaddr = generate_hwaddr(&xs);
            hwaddr.len() == 6 &&
                hwaddr[0] & 0b11 == 0b10
        }
    }
}
