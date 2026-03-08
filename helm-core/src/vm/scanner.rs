/*! Scanner for VM bytecode

`Scanner` is an iterator over a byte slice (`&[u8]`) that yields fully-decoded
`Op` instances from `op.rs`. It consumes any payload bytes that follow opcodes
that require them (e.g. `OP_PUSH_1`, `OP_PUSH_U32`).
*/

use super::op::{
    OP_LOAD, OP_OUT_AMT, OP_OUT_COMM, OP_OUT_DATA, OP_PUSH_BYTE, OP_PUSH_BYTES, OP_PUSH_U32,
    OP_SPLIT, OP_STORE, Op,
};

/// An iterator that reads opcodes (and their payloads) from a byte slice.
pub struct Scanner<'a> {
    bytes: &'a [u8],
    idx: usize,
}

impl<'a> Scanner<'a> {
    /// Create a new scanner over the provided byte slice.
    pub fn new(bytes: &'a [u8]) -> Self {
        Scanner { bytes, idx: 0 }
    }

    // pub fn remaining(&self) -> usize {
    //     self.bytes.len().saturating_sub(self.idx)
    // }

    fn read_u8(&mut self) -> Option<u8> {
        if self.idx < self.bytes.len() {
            let b = self.bytes[self.idx];
            self.idx += 1;
            Some(b)
        } else {
            None
        }
    }

    fn read_u32_le(&mut self) -> Option<u32> {
        if self.idx + 4 <= self.bytes.len() {
            let b0 = self.bytes[self.idx];
            let b1 = self.bytes[self.idx + 1];
            let b2 = self.bytes[self.idx + 2];
            let b3 = self.bytes[self.idx + 3];
            self.idx += 4;
            Some(u32::from_le_bytes([b0, b1, b2, b3]))
        } else {
            None
        }
    }
}

impl<'a> Iterator for Scanner<'a> {
    type Item = Op<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Read next byte (opcode)
        let b = match self.read_u8() {
            Some(v) => v,
            None => return None,
        };

        // Handle opcodes that carry payloads first, so we can consume payload
        // bytes and return fully-formed `Op` variants.
        match b {
            OP_PUSH_U32 => match self.read_u32_le() {
                Some(v) => Some(Op::PushU32(v)),
                None => {
                    self.idx = self.bytes.len();
                    None
                }
            },
            OP_PUSH_BYTE => match self.read_u8() {
                Some(v) => Some(Op::PushByte(v)),
                None => {
                    self.idx = self.bytes.len();
                    None
                }
            },
            OP_OUT_AMT => match self.read_u8() {
                Some(v) => Some(Op::OutAmt(v)),
                None => {
                    self.idx = self.bytes.len();
                    None
                }
            },
            OP_OUT_DATA => match self.read_u8() {
                Some(v) => Some(Op::OutData(v)),
                None => {
                    self.idx = self.bytes.len();
                    None
                }
            },
            OP_OUT_COMM => match self.read_u8() {
                Some(v) => Some(Op::OutComm(v)),
                None => {
                    self.idx = self.bytes.len();
                    None
                }
            },
            OP_SPLIT => match self.read_u8() {
                Some(v) => Some(Op::Split(v)),
                None => {
                    self.idx = self.bytes.len();
                    None
                }
            },
            OP_LOAD => match self.read_u8() {
                Some(v) => Some(Op::Load(v)),
                None => {
                    self.idx = self.bytes.len();
                    None
                }
            },
            OP_STORE => match self.read_u8() {
                Some(v) => Some(Op::Store(v)),
                None => {
                    self.idx = self.bytes.len();
                    None
                }
            },
            OP_PUSH_BYTES => match self.read_u8() {
                Some(n) => {
                    if self.idx + n as usize <= self.bytes.len() {
                        let slice = &self.bytes[self.idx..self.idx + n as usize];
                        self.idx += n as usize;
                        Some(Op::PushBytes(slice))
                    } else {
                        self.idx = self.bytes.len();
                        None
                    }
                }
                None => {
                    self.idx = self.bytes.len();
                    None
                }
            },
            // For other single-byte opcodes rely on Op::try_from
            other => Op::try_from(other).ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::op::Op;
    use super::super::op::r#const::*;
    use super::*;

    #[test]
    fn scan_push_u32() {
        let bytes = [OP_PUSH_U32, 0x78, 0x56, 0x34, 0x12]; // 0x12345678 little-endian
        let mut s = Scanner::new(&bytes);
        let got = s.next().unwrap();
        assert_eq!(got, Op::PushU32(0x12345678));
        assert!(s.next().is_none());
    }

    #[test]
    fn scan_push_byte() {
        let bytes = [OP_PUSH_BYTE, 0x42]; // Push the byte 0x42
        let mut s = Scanner::new(&bytes);
        let got = s.next().unwrap();
        assert_eq!(got, Op::PushByte(0x42));
        assert!(s.next().is_none());
    }

    #[test]
    fn scan_sequence_with_out_ops() {
        let bytes = [
            OP_TRUE,
            OP_PUSH_U32,
            1,
            0,
            0,
            0,
            OP_PUSH_SUPPLY,
            OP_PUSH_HEIGHT,
            OP_FALSE,
            OP_OUT_AMT,
            0x01,
            OP_OUT_DATA,
            0x02,
            OP_OUT_COMM,
            0x03,
            OP_SIGHASH_ALL,
            OP_SPLIT,
            1,
            OP_PUSH_BYTES,
            3,
            0xAA,
            0xBB,
            0xCC,
        ];

        let collected: Vec<Op> = Scanner::new(&bytes).collect();
        let v = collected;
        assert_eq!(
            v,
            vec![
                Op::True,
                Op::PushU32(1),
                Op::Supply,
                Op::Height,
                Op::False,
                Op::OutAmt(1),
                Op::OutData(2),
                Op::OutComm(3),
                Op::SighashAll,
                Op::Split(1),
                Op::PushBytes(&[0xAA, 0xBB, 0xCC])
            ]
        );
    }

    #[test]
    fn eof_in_payload_returns_error() {
        let bytes = [OP_PUSH_U32, 1, 2]; // incomplete 4-byte payload
        let mut s = Scanner::new(&bytes);
        match s.next() {
            None => {}
            other => panic!("expected None, got {:?}", other),
        }
        // after an error, iterator should continue from end (no more bytes)
        assert!(s.next().is_none());
    }

    #[test]
    fn unknown_opcode_returns_error() {
        let bytes = [0x99u8];
        let mut s = Scanner::new(&bytes);
        match s.next() {
            None => {}
            other => panic!("expected None, got {:?}", other),
        }
    }

    #[test]
    fn scan_load() {
        let bytes = [OP_LOAD, 0x07];
        let mut s = Scanner::new(&bytes);
        assert_eq!(s.next(), Some(Op::Load(0x07)));
        assert!(s.next().is_none());
    }

    #[test]
    fn scan_store() {
        let bytes = [OP_STORE, 0xFF];
        let mut s = Scanner::new(&bytes);
        assert_eq!(s.next(), Some(Op::Store(0xFF)));
        assert!(s.next().is_none());
    }

    #[test]
    fn scan_load_store_sequence() {
        let bytes = [OP_PUSH_BYTE, 0x42, OP_STORE, 0x00, OP_LOAD, 0x00];
        let collected: Vec<Op> = Scanner::new(&bytes).collect();
        assert_eq!(
            collected,
            vec![Op::PushByte(0x42), Op::Store(0x00), Op::Load(0x00),]
        );
    }

    #[test]
    fn eof_in_load_payload_returns_none() {
        let bytes = [OP_LOAD]; // missing register byte
        let mut s = Scanner::new(&bytes);
        assert!(s.next().is_none());
        assert!(s.next().is_none());
    }

    #[test]
    fn eof_in_store_payload_returns_none() {
        let bytes = [OP_STORE]; // missing register byte
        let mut s = Scanner::new(&bytes);
        assert!(s.next().is_none());
        assert!(s.next().is_none());
    }
}
