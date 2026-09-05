//! multiformats unsigned varint (unsigned LEB128) reading, shared by both
//! `did:key` codecs this crate speaks.

/// Reads one multiformats unsigned varint off the front of `bytes`.
///
/// Returns the code and how many bytes it occupied. multiformats caps
/// unsigned varints at nine bytes / 63 bits — that cap bounds the work an
/// attacker-supplied DID can demand, and keeps the shift below from ever
/// exceeding 56.
pub fn read_unsigned(bytes: &[u8]) -> Result<(u64, usize), MalformedVarint> {
    const MAX_LEN: usize = 9;
    let mut code: u64 = 0;
    let mut shift: u32 = 0;

    for (offset, &byte) in bytes.iter().take(MAX_LEN).enumerate() {
        code |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((code, offset + 1));
        }
        shift += 7;
    }

    // Either the input ran out mid-varint or the varint never terminated.
    // Either way the length prefix is unreadable, and guessing where the
    // payload begins is how a fixed-size window gets taken from the wrong
    // offset.
    Err(MalformedVarint)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedVarint;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_p256_pub_multicodec() {
        assert_eq!(read_unsigned(&[0x80, 0x24]), Ok((0x1200, 2)));
    }

    #[test]
    fn reads_the_jwk_jcs_pub_multicodec() {
        assert_eq!(read_unsigned(&[0xD1, 0xD6, 0x03]), Ok((0xEB51, 3)));
    }

    #[test]
    fn rejects_a_varint_that_never_terminates() {
        for length in [1, 2, 9, 12] {
            let bytes = vec![0x80u8; length];
            assert_eq!(
                read_unsigned(&bytes),
                Err(MalformedVarint),
                "length {length}"
            );
        }
    }

    #[test]
    fn rejects_an_empty_input() {
        assert_eq!(read_unsigned(&[]), Err(MalformedVarint));
    }
}
