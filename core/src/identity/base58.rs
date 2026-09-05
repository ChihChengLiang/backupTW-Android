//! base58btc, as referenced by multibase (draft-msporny-base58).
//!
//! Hand-rolled rather than pulled in as a dependency, mirroring the same call
//! made on the iOS side (`backupTW/Crypto/DIDKey.swift`): this is the one
//! function that turns a key into an identity, and a supply-chain dependency
//! for it is a poor trade for twenty-odd lines of code.

/// The Bitcoin alphabet: 0, O, I and l are omitted so that a human reading a
/// DID aloud cannot introduce an ambiguity.
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn digit_value(c: u8) -> Option<u8> {
    ALPHABET.iter().position(|&a| a == c).map(|i| i as u8)
}

/// Encodes `data` as base58btc.
///
/// Base conversion treats the input as one big integer, which throws away
/// leading zero bytes — they carry no numeric value but they are part of the
/// encoded data. Each one is re-attached as a literal `'1'`, the alphabet's
/// zero digit.
pub fn encode(data: &[u8]) -> String {
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    let mut buffer: Vec<u8> = data[leading_zeros..].to_vec();
    let mut digits: Vec<u8> = Vec::with_capacity(buffer.len() * 137 / 100 + 1);

    // Repeated long division by 58, in place: each pass emits one digit
    // (least significant first) and shortens the buffer by any leading zero
    // the division produced.
    let mut start = 0;
    while start < buffer.len() {
        let mut remainder: u32 = 0;
        for b in buffer[start..].iter_mut() {
            let accumulator = (remainder << 8) | *b as u32;
            *b = (accumulator / 58) as u8;
            remainder = accumulator % 58;
        }
        digits.push(remainder as u8);
        if buffer[start] == 0 {
            start += 1;
        }
    }

    let mut out = String::with_capacity(leading_zeros + digits.len());
    out.extend(std::iter::repeat_n('1', leading_zeros));
    out.extend(digits.iter().rev().map(|&d| ALPHABET[d as usize] as char));
    out
}

/// The inverse of [`encode`].
///
/// Any character outside the alphabet is rejected — quietly folding the
/// excluded look-alikes onto their neighbours (0 -> O, l -> 1) would be a
/// kindness that yields a different key from the one written down, which is
/// the ambiguity the alphabet exists to remove.
pub fn decode(s: &str) -> Result<Vec<u8>, InvalidBase58> {
    let leading_zeros = s.chars().take_while(|&c| c == '1').count();

    let mut bytes: Vec<u8> = Vec::with_capacity(s.len() * 733 / 1000 + 1);

    for c in s.chars().skip(leading_zeros) {
        if !c.is_ascii() {
            return Err(InvalidBase58);
        }
        let digit = digit_value(c as u8).ok_or(InvalidBase58)?;

        // bytes = bytes * 58 + digit, big-endian, carrying up from the low end.
        let mut carry = digit as u32;
        for b in bytes.iter_mut().rev() {
            let accumulator = *b as u32 * 58 + carry;
            *b = (accumulator & 0xff) as u8;
            carry = accumulator >> 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut out = vec![0u8; leading_zeros];
    out.extend(bytes);
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidBase58;

impl std::fmt::Display for InvalidBase58 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid base58 character")
    }
}

impl std::error::Error for InvalidBase58 {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors from draft-msporny-base58, which multibase references for the
    /// "z" prefix.
    #[test]
    fn encodes_base58_reference_vectors() {
        assert_eq!(encode(b"Hello World!"), "2NEpo7TZRRrLZSi2U");
        assert_eq!(
            encode(b"The quick brown fox jumps over the lazy dog."),
            "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z"
        );
    }

    #[test]
    fn decodes_base58_reference_vectors() {
        assert_eq!(decode("2NEpo7TZRRrLZSi2U").unwrap(), b"Hello World!");
        assert_eq!(
            decode("USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z").unwrap(),
            b"The quick brown fox jumps over the lazy dog."
        );
        assert_eq!(decode("2g").unwrap(), vec![0x61]);
        assert_eq!(decode("5Q").unwrap(), vec![0xff]);
        assert_eq!(decode("LUv").unwrap(), vec![0xff, 0xff]);
    }

    /// Leading zero bytes carry no numeric value, so big-integer division
    /// drops them; base58btc re-attaches each one as a literal "1".
    #[test]
    fn preserves_leading_zero_bytes_encoding() {
        assert_eq!(encode(&[]), "");
        assert_eq!(encode(&[0x00]), "1");
        assert_eq!(encode(&[0x00, 0x00]), "11");
        assert_eq!(encode(&[0x00, 0x00, 0x00]), "111");
        // draft-msporny-base58 test vectors: two leading zeros plus a payload.
        assert_eq!(encode(&[0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd]), "11233QC4");
        // A zero byte that is not leading must not produce a "1".
        assert_eq!(encode(&[0x00, 0x01]), "12");
    }

    #[test]
    fn restores_leading_zero_bytes_decoding() {
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode("1").unwrap(), vec![0x00]);
        assert_eq!(decode("11").unwrap(), vec![0x00, 0x00]);
        assert_eq!(decode("111").unwrap(), vec![0x00, 0x00, 0x00]);
        assert_eq!(
            decode("11233QC4").unwrap(),
            vec![0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd]
        );
        // A "1" that is not leading is the digit zero, not a byte.
        assert_eq!(decode("12").unwrap(), vec![0x00, 0x01]);
        assert_eq!(decode("21").unwrap(), vec![0x3a]);
    }

    /// 0, O, I and l are absent so that a DID read aloud stays unambiguous.
    #[test]
    fn uses_the_bitcoin_alphabet() {
        // 0x61 is 97 == 1*58 + 39, i.e. digits [1, 39] -> "2g".
        assert_eq!(encode(&[0x61]), "2g");
        assert_eq!(encode(&[0xff]), "5Q");
        assert_eq!(encode(&[0xff, 0xff]), "LUv");

        let all_bytes: Vec<u8> = (0..=255).collect();
        let encoded = encode(&all_bytes);
        assert!(!encoded.contains(['0', 'O', 'I', 'l']));
    }

    #[test]
    fn rejects_characters_outside_the_alphabet() {
        for c in ['0', 'O', 'I', 'l', '+', '/', '=', ' ', '-'] {
            let s = format!("2g{c}");
            assert_eq!(decode(&s), Err(InvalidBase58), "char {c:?}");
        }
    }

    /// Round trip in the direction the encoder's own tests cannot check, over
    /// inputs chosen for the leading-zero boundary rather than at random.
    #[test]
    fn round_trips_arbitrary_bytes() {
        let mut cases: Vec<Vec<u8>> = vec![
            vec![],
            (0..=255).collect(),
            vec![0x00],
            vec![0x00, 0x00, 0x01],
        ];
        for length in 0..=40usize {
            let mut bytes: Vec<u8> = (0..length).map(|i| ((i * 37 + 11) % 256) as u8).collect();
            cases.push(bytes.clone());
            if length > 0 {
                bytes[0] = 0;
                cases.push(bytes.clone());
            }
            if length > 1 {
                bytes[1] = 0;
                cases.push(bytes.clone());
            }
        }

        for bytes in cases {
            let encoded = encode(&bytes);
            assert_eq!(decode(&encoded).unwrap(), bytes, "{bytes:?}");
        }
    }
}
