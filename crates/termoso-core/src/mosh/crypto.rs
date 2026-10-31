//! Mosh datagram encryption: AES-128 in OCB3 mode, 12-byte nonce made of
//! four zero bytes plus the 64-bit direction|sequence counter, 16-byte tag,
//! no associated data. A wire message is the low 8 nonce bytes followed by
//! the ciphertext and tag.

use aes9::Aes128;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ocb3::aead::consts::{U12, U16};
use ocb3::aead::inout::InOutBuf;
use ocb3::{AeadInOut, KeyInit, Nonce, Ocb3, Tag};
use zeroize::Zeroizing;

use super::MoshError;

/// Bytes the cipher adds to a payload (8-byte nonce + 16-byte tag).
pub const ADDED_BYTES: usize = 8 + 16;

/// Bit 63 of the sequence marks server→client traffic.
pub const DIRECTION_MASK: u64 = 1 << 63;
pub const SEQUENCE_MASK: u64 = u64::MAX >> 1;

type Cipher = Ocb3<Aes128, U12, U16>;

/// A parsed `MOSH CONNECT` key.
pub struct Key(Zeroizing<[u8; 16]>);

impl Key {
    /// 22 base64 characters without padding, as printed by `mosh-server`.
    pub fn parse(printable: &str) -> Result<Self, MoshError> {
        if printable.len() != 22 {
            return Err(MoshError::Key);
        }
        let mut padded = Zeroizing::new(String::with_capacity(24));
        padded.push_str(printable);
        padded.push_str("==");
        let raw = Zeroizing::new(
            STANDARD
                .decode(padded.as_bytes())
                .map_err(|_| MoshError::Key)?,
        );
        let bytes: [u8; 16] = raw.as_slice().try_into().map_err(|_| MoshError::Key)?;
        // Reject keys with stray bits after the 128th (the reference client
        // does the same: re-encode and compare).
        let again = STANDARD.encode(bytes);
        if again.trim_end_matches('=') != printable {
            return Err(MoshError::Key);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }
}

/// One encryption context; `encrypt` numbers outgoing datagrams itself.
pub struct Session {
    cipher: Cipher,
    to_server: bool,
    next_seq: u64,
}

impl Session {
    pub fn new(key: &Key, to_server: bool) -> Self {
        Self {
            cipher: Cipher::new(key.0.as_slice().try_into().expect("16-byte key")),
            to_server,
            next_seq: 0,
        }
    }

    fn nonce(direction_seq: u64) -> Nonce<U12> {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&direction_seq.to_be_bytes());
        n.into()
    }

    /// Seal `plaintext` as the next datagram in our direction.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, MoshError> {
        let seq = self.next_seq;
        self.next_seq = seq.checked_add(1).ok_or(MoshError::CounterWrapped)?;
        if seq & DIRECTION_MASK != 0 {
            return Err(MoshError::CounterWrapped);
        }
        let direction_seq = if self.to_server {
            seq
        } else {
            seq | DIRECTION_MASK
        };
        let nonce = Self::nonce(direction_seq);
        let mut out = Vec::with_capacity(plaintext.len() + ADDED_BYTES);
        out.extend_from_slice(&nonce[4..]);
        out.extend_from_slice(plaintext);
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce, &[], InOutBuf::from(&mut out[8..]))
            .map_err(|_| MoshError::Cipher)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Open a datagram; returns the raw `direction|seq` and the plaintext.
    pub fn decrypt(&self, wire: &[u8]) -> Result<(u64, Vec<u8>), MoshError> {
        if wire.len() < ADDED_BYTES {
            return Err(MoshError::Cipher);
        }
        let direction_seq = u64::from_be_bytes(wire[..8].try_into().expect("8 bytes"));
        let nonce = Self::nonce(direction_seq);
        let (body, tag) = wire[8..].split_at(wire.len() - 8 - 16);
        let tag = Tag::<U16>::try_from(tag).map_err(|_| MoshError::Cipher)?;
        let mut out = body.to_vec();
        self.cipher
            .decrypt_inout_detached(&nonce, &[], InOutBuf::from(out.as_mut_slice()), &tag)
            .map_err(|_| MoshError::Cipher)?;
        Ok((direction_seq, out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_parsing_is_strict() {
        assert!(
            Key::parse("aBcDeFgHiJkLmNoPqRsTuV").is_err(),
            "stray low bits"
        );
        assert!(Key::parse("AAAAAAAAAAAAAAAAAAAAAA").is_ok());
        assert!(Key::parse("AAAAAAAAAAAAAAAAAAAAA").is_err());
        assert!(Key::parse("AAAAAAAAAAAAAAAAAAAAA!").is_err());
        // Any 16 bytes re-encode to something we accept.
        let k = STANDARD.encode([7u8; 16]);
        assert!(Key::parse(k.trim_end_matches('=')).is_ok());
    }

    #[test]
    fn round_trip_between_directions_and_reject_tampering() {
        let key = Key::parse("AAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let mut client = Session::new(&key, true);
        let server = Session::new(&key, false);
        let wire = client.encrypt(b"hello").unwrap();
        assert_eq!(wire.len(), 5 + ADDED_BYTES);
        assert_eq!(
            &wire[..8],
            &0u64.to_be_bytes(),
            "first client packet is seq 0"
        );
        let (seq, pt) = server.decrypt(&wire).unwrap();
        assert_eq!((seq & DIRECTION_MASK, seq & SEQUENCE_MASK), (0, 0));
        assert_eq!(pt, b"hello");
        let wire2 = client.encrypt(b"").unwrap();
        assert_eq!(&wire2[..8], &1u64.to_be_bytes());
        let mut bad = wire.clone();
        bad[10] ^= 1;
        assert!(server.decrypt(&bad).is_err());
        assert!(server.decrypt(&wire[..20]).is_err());
        let mut srv = Session::new(&key, false);
        let w = srv.encrypt(b"x").unwrap();
        assert_eq!(&w[..8], &DIRECTION_MASK.to_be_bytes());
    }

    #[test]
    fn matches_rfc7253_vector_shape() {
        // RFC 7253 test vector (AES-128-OCB, 96-bit nonce, empty P & A):
        // K = 000102030405060708090A0B0C0D0E0F, N = BBAA99887766554433221100
        // C (tag only) = 785407BFFFC8AD9EDCC5520AC9111EE6
        let key = Key(Zeroizing::new([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ]));
        let cipher = Cipher::new(key.0.as_slice().try_into().expect("16-byte key"));
        let nonce: Nonce<U12> = [
            0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        ]
        .into();
        let mut buf = Vec::new();
        let tag = cipher
            .encrypt_inout_detached(&nonce, &[], InOutBuf::from(&mut buf[..]))
            .unwrap();
        assert_eq!(
            hex::encode(tag).to_uppercase(),
            "785407BFFFC8AD9EDCC5520AC9111EE6"
        );
    }
}
