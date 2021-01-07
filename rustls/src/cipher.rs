use crate::error::TLSError;
use crate::key_schedule::{derive_traffic_iv, derive_traffic_key};
use crate::msgs::codec;
use crate::msgs::codec::Codec;
use crate::msgs::enums::{ContentType, ProtocolVersion};
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
use crate::msgs::message::{BorrowMessage, Message, MessagePayload};
use crate::session::SessionSecrets;
use crate::suites::{BulkAlgorithm, SupportedCipherSuite};
use ring::{aead, hkdf};
use std::convert::TryInto;
use std::io::Write;

/// Objects with this trait can decrypt TLS messages.
pub trait MessageDecrypter: Send + Sync {
    fn decrypt(&self, m: Message, seq: u64) -> Result<Message, TLSError>;
}

/// Objects with this trait can encrypt TLS messages.
pub trait MessageEncrypter: Send + Sync {
    fn encrypt(&self, m: BorrowMessage, seq: u64) -> Result<Message, TLSError>;
}

impl dyn MessageEncrypter {
    pub fn invalid() -> Box<dyn MessageEncrypter> {
        Box::new(InvalidMessageEncrypter {})
    }
}

impl dyn MessageDecrypter {
    pub fn invalid() -> Box<dyn MessageDecrypter> {
        Box::new(InvalidMessageDecrypter {})
    }
}

pub type MessageCipherPair = (Box<dyn MessageDecrypter>, Box<dyn MessageEncrypter>);

const TLS12_AAD_SIZE: usize = 8 + 1 + 2 + 2;
fn make_tls12_aad(
    seq: u64,
    typ: ContentType,
    vers: ProtocolVersion,
    len: usize,
) -> ring::aead::Aad<[u8; TLS12_AAD_SIZE]> {
    let mut out = [0; TLS12_AAD_SIZE];
    codec::put_u64(seq, &mut out[0..]);
    out[8] = typ.get_u8();
    codec::put_u16(vers.get_u16(), &mut out[9..]);
    codec::put_u16(len as u16, &mut out[11..]);
    ring::aead::Aad::from(out)
}

/// Make a `MessageCipherPair` based on the given supported ciphersuite `scs`,
/// and the session's `secrets`.
pub fn new_tls12(
    scs: &'static SupportedCipherSuite,
    secrets: &SessionSecrets,
) -> MessageCipherPair {
    // Make a key block, and chop it up.
    // nb. we don't implement any ciphersuites with nonzero mac_key_len.
    let key_block = secrets.make_key_block(scs.key_block_len());

    let mut offs = 0;
    let client_write_key = &key_block[offs..offs + scs.enc_key_len];
    offs += scs.enc_key_len;
    let server_write_key = &key_block[offs..offs + scs.enc_key_len];
    offs += scs.enc_key_len;
    let client_write_iv = &key_block[offs..offs + scs.fixed_iv_len];
    offs += scs.fixed_iv_len;
    let server_write_iv = &key_block[offs..offs + scs.fixed_iv_len];

    let (write_key, write_iv) = if secrets.randoms.we_are_client {
        (client_write_key, client_write_iv)
    } else {
        (server_write_key, server_write_iv)
    };

    let (read_key, read_iv) = if secrets.randoms.we_are_client {
        (server_write_key, server_write_iv)
    } else {
        (client_write_key, client_write_iv)
    };

    let aead_alg = scs.get_aead_alg();

    match scs.bulk {
        BulkAlgorithm::AES_128_GCM | BulkAlgorithm::AES_256_GCM => {
            // The GCM nonce is constructed from a 32-bit 'salt' derived
            // from the master-secret, and a 64-bit explicit part,
            // with no specified construction.  Thanks for that.
            //
            // We use the same construction as TLS1.3/ChaCha20Poly1305:
            // a starting point extracted from the key block, xored with
            // the sequence number.
            let write_iv = {
                offs += scs.fixed_iv_len;
                let explicit_nonce_offs = &key_block[offs..offs + scs.explicit_nonce_len];

                let mut iv = Iv(Default::default());
                iv.0[..scs.fixed_iv_len].copy_from_slice(write_iv);
                iv.0[scs.fixed_iv_len..].copy_from_slice(&explicit_nonce_offs);
                iv
            };

            (
                Box::new(GCMMessageDecrypter::new(aead_alg, read_key, read_iv)),
                Box::new(GCMMessageEncrypter::new(aead_alg, write_key, write_iv)),
            )
        }

        BulkAlgorithm::CHACHA20_POLY1305 => {
            let read_iv = Iv::new(read_iv.try_into().unwrap());
            let write_iv = Iv::new(write_iv.try_into().unwrap());
            (
                Box::new(ChaCha20Poly1305MessageDecrypter::new(
                    aead_alg, read_key, read_iv,
                )),
                Box::new(ChaCha20Poly1305MessageEncrypter::new(
                    aead_alg, write_key, write_iv,
                )),
            )
        }

        BulkAlgorithm::SM4_CBC => {
            let write_iv = {
                let mut iv = SMIv(Default::default());
                iv.0[..scs.fixed_iv_len].copy_from_slice(write_iv);
                iv
            };

            let read_iv = {
                let mut iv = SMIv(Default::default());
                iv.0[..scs.fixed_iv_len].copy_from_slice(read_iv);
                iv
            };

            let write_key = {
                let mut iv = SMKey(Default::default());
                iv.0[..scs.fixed_iv_len].copy_from_slice(write_key);
                iv
            };

            let read_key = {
                let mut iv = SMKey(Default::default());
                iv.0[..scs.fixed_iv_len].copy_from_slice(read_key);
                iv
            };

            (
                Box::new(CBCMessageDecrypter::new(read_key, read_iv)),
                Box::new(CBCMessageEncrypter::new(write_key, write_iv)),
            )
        }
    }
}

pub fn new_tls13_read(
    scs: &'static SupportedCipherSuite,
    secret: &hkdf::Prk,
) -> Box<dyn MessageDecrypter> {
    let key = derive_traffic_key(secret, scs.get_aead_alg());
    let iv = derive_traffic_iv(secret);

    Box::new(TLS13MessageDecrypter::new(key, iv))
}

pub fn new_tls13_write(
    scs: &'static SupportedCipherSuite,
    secret: &hkdf::Prk,
) -> Box<dyn MessageEncrypter> {
    let key = derive_traffic_key(secret, scs.get_aead_alg());
    let iv = derive_traffic_iv(secret);

    Box::new(TLS13MessageEncrypter::new(key, iv))
}

/// A `MessageEncrypter` for AES-GCM AEAD ciphersuites. TLS 1.2 only.
pub struct GCMMessageEncrypter {
    enc_key: aead::LessSafeKey,
    iv: Iv,
}

/// A `MessageDecrypter` for AES-GCM AEAD ciphersuites.  TLS1.2 only.
pub struct GCMMessageDecrypter {
    dec_key: aead::LessSafeKey,
    dec_salt: [u8; 4],
}

const GCM_EXPLICIT_NONCE_LEN: usize = 8;
const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + 16;

impl MessageDecrypter for GCMMessageDecrypter {
    fn decrypt(&self, mut msg: Message, seq: u64) -> Result<Message, TLSError> {
        let payload = msg.take_opaque_payload().ok_or(TLSError::DecryptError)?;
        let mut buf = payload.0;

        if buf.len() < GCM_OVERHEAD {
            return Err(TLSError::DecryptError);
        }

        let nonce = {
            let mut nonce = [0u8; 12];
            nonce.as_mut().write_all(&self.dec_salt).unwrap();
            nonce[4..].as_mut().write_all(&buf[..8]).unwrap();
            aead::Nonce::assume_unique_for_key(nonce)
        };

        let aad = make_tls12_aad(seq, msg.typ, msg.version, buf.len() - GCM_OVERHEAD);

        let plain_len = self
            .dec_key
            .open_within(nonce, aad, &mut buf, GCM_EXPLICIT_NONCE_LEN..)
            .map_err(|_| TLSError::DecryptError)?
            .len();

        if plain_len > MAX_FRAGMENT_LEN {
            return Err(TLSError::PeerSentOversizedRecord);
        }

        buf.truncate(plain_len);

        Ok(Message {
            typ: msg.typ,
            version: msg.version,
            payload: MessagePayload::new_opaque(buf),
        })
    }
}

impl MessageEncrypter for GCMMessageEncrypter {
    fn encrypt(&self, msg: BorrowMessage, seq: u64) -> Result<Message, TLSError> {
        let nonce = make_tls13_nonce(&self.iv, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());

        let total_len = msg.payload.len() + self.enc_key.algorithm().tag_len();
        let mut payload = Vec::with_capacity(GCM_EXPLICIT_NONCE_LEN + total_len);
        payload.extend_from_slice(&nonce.as_ref()[4..]);
        payload.extend_from_slice(&msg.payload);

        self.enc_key
            .seal_in_place_separate_tag(nonce, aad, &mut payload[GCM_EXPLICIT_NONCE_LEN..])
            .map(|tag| payload.extend(tag.as_ref()))
            .map_err(|_| TLSError::General("encrypt failed".to_string()))?;

        Ok(Message {
            typ: msg.typ,
            version: msg.version,
            payload: MessagePayload::new_opaque(payload),
        })
    }
}

impl GCMMessageEncrypter {
    fn new(alg: &'static aead::Algorithm, enc_key: &[u8], iv: Iv) -> GCMMessageEncrypter {
        let key = aead::UnboundKey::new(alg, enc_key).unwrap();
        GCMMessageEncrypter {
            enc_key: aead::LessSafeKey::new(key),
            iv,
        }
    }
}

impl GCMMessageDecrypter {
    fn new(alg: &'static aead::Algorithm, dec_key: &[u8], dec_iv: &[u8]) -> GCMMessageDecrypter {
        let key = aead::UnboundKey::new(alg, dec_key).unwrap();
        let mut ret = GCMMessageDecrypter {
            dec_key: aead::LessSafeKey::new(key),
            dec_salt: [0u8; 4],
        };

        debug_assert_eq!(dec_iv.len(), 4);
        ret.dec_salt.as_mut().write_all(dec_iv).unwrap();
        ret
    }
}

/// A TLS 1.3 write or read IV.
pub(crate) struct Iv([u8; ring::aead::NONCE_LEN]);

impl Iv {
    pub(crate) fn new(value: [u8; ring::aead::NONCE_LEN]) -> Self {
        Self(value)
    }

    #[cfg(test)]
    pub(crate) fn value(&self) -> &[u8; 12] {
        &self.0
    }
}

pub(crate) struct SMIv([u8; 16]);

impl SMIv {
    fn value(&self) -> &[u8; 16] {
        &self.0
    }
}

pub(crate) struct SMKey([u8; 16]);

impl SMKey {
    fn value(&self) -> &[u8; 16] {
        &self.0
    }
}

pub(crate) struct IvLen;

impl hkdf::KeyType for IvLen {
    fn len(&self) -> usize {
        aead::NONCE_LEN
    }
}

impl From<hkdf::Okm<'_, IvLen>> for Iv {
    fn from(okm: hkdf::Okm<IvLen>) -> Self {
        let mut r = Iv(Default::default());
        okm.fill(&mut r.0[..]).unwrap();
        r
    }
}

struct TLS13MessageEncrypter {
    enc_key: aead::LessSafeKey,
    iv: Iv,
}

struct TLS13MessageDecrypter {
    dec_key: aead::LessSafeKey,
    iv: Iv,
}

fn unpad_tls13(v: &mut Vec<u8>) -> ContentType {
    loop {
        match v.pop() {
            Some(0) => {}

            Some(content_type) => return ContentType::read_bytes(&[content_type]).unwrap(),

            None => return ContentType::Unknown(0),
        }
    }
}

fn make_tls13_nonce(iv: &Iv, seq: u64) -> ring::aead::Nonce {
    let mut nonce = [0u8; ring::aead::NONCE_LEN];
    codec::put_u64(seq, &mut nonce[4..]);

    nonce.iter_mut().zip(iv.0.iter()).for_each(|(nonce, iv)| {
        *nonce ^= *iv;
    });

    aead::Nonce::assume_unique_for_key(nonce)
}

fn make_tls13_aad(len: usize) -> ring::aead::Aad<[u8; 1 + 2 + 2]> {
    ring::aead::Aad::from([
        0x17, // ContentType::ApplicationData
        0x3,  // ProtocolVersion (major)
        0x3,  // ProtocolVersion (minor)
        (len >> 8) as u8,
        len as u8,
    ])
}

impl MessageEncrypter for TLS13MessageEncrypter {
    fn encrypt(&self, msg: BorrowMessage, seq: u64) -> Result<Message, TLSError> {
        let total_len = msg.payload.len() + 1 + self.enc_key.algorithm().tag_len();
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&msg.payload);
        msg.typ.encode(&mut buf);

        let nonce = make_tls13_nonce(&self.iv, seq);
        let aad = make_tls13_aad(total_len);

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut buf)
            .map_err(|_| TLSError::General("encrypt failed".to_string()))?;

        Ok(Message {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::new_opaque(buf),
        })
    }
}

impl MessageDecrypter for TLS13MessageDecrypter {
    fn decrypt(&self, mut msg: Message, seq: u64) -> Result<Message, TLSError> {
        let payload = msg.take_opaque_payload().ok_or(TLSError::DecryptError)?;
        let mut buf = payload.0;

        if buf.len() < self.dec_key.algorithm().tag_len() {
            return Err(TLSError::DecryptError);
        }

        let nonce = make_tls13_nonce(&self.iv, seq);
        let aad = make_tls13_aad(buf.len());
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, &mut buf)
            .map_err(|_| TLSError::DecryptError)?
            .len();

        buf.truncate(plain_len);

        if buf.len() > MAX_FRAGMENT_LEN + 1 {
            return Err(TLSError::PeerSentOversizedRecord);
        }

        let content_type = unpad_tls13(&mut buf);
        if content_type == ContentType::Unknown(0) {
            let msg = "peer sent bad TLSInnerPlaintext".to_string();
            return Err(TLSError::PeerMisbehavedError(msg));
        }

        if buf.len() > MAX_FRAGMENT_LEN {
            return Err(TLSError::PeerSentOversizedRecord);
        }

        Ok(Message {
            typ: content_type,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::new_opaque(buf),
        })
    }
}

impl TLS13MessageEncrypter {
    fn new(key: aead::UnboundKey, enc_iv: Iv) -> TLS13MessageEncrypter {
        TLS13MessageEncrypter {
            enc_key: aead::LessSafeKey::new(key),
            iv: enc_iv,
        }
    }
}

impl TLS13MessageDecrypter {
    fn new(key: aead::UnboundKey, dec_iv: Iv) -> TLS13MessageDecrypter {
        TLS13MessageDecrypter {
            dec_key: aead::LessSafeKey::new(key),
            iv: dec_iv,
        }
    }
}

/// The RFC7905/RFC7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses `TLS13MessageEncrypter`.
pub struct ChaCha20Poly1305MessageEncrypter {
    enc_key: aead::LessSafeKey,
    enc_offset: Iv,
}

/// The RFC7905/RFC7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses `TLS13MessageDecrypter`.
pub struct ChaCha20Poly1305MessageDecrypter {
    dec_key: aead::LessSafeKey,
    dec_offset: Iv,
}

impl ChaCha20Poly1305MessageEncrypter {
    fn new(
        alg: &'static aead::Algorithm,
        enc_key: &[u8],
        enc_iv: Iv,
    ) -> ChaCha20Poly1305MessageEncrypter {
        let key = aead::UnboundKey::new(alg, enc_key).unwrap();
        ChaCha20Poly1305MessageEncrypter {
            enc_key: aead::LessSafeKey::new(key),
            enc_offset: enc_iv,
        }
    }
}

impl ChaCha20Poly1305MessageDecrypter {
    fn new(
        alg: &'static aead::Algorithm,
        dec_key: &[u8],
        dec_iv: Iv,
    ) -> ChaCha20Poly1305MessageDecrypter {
        let key = aead::UnboundKey::new(alg, dec_key).unwrap();
        ChaCha20Poly1305MessageDecrypter {
            dec_key: aead::LessSafeKey::new(key),
            dec_offset: dec_iv,
        }
    }
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;

impl MessageDecrypter for ChaCha20Poly1305MessageDecrypter {
    fn decrypt(&self, mut msg: Message, seq: u64) -> Result<Message, TLSError> {
        let payload = msg.take_opaque_payload().ok_or(TLSError::DecryptError)?;
        let mut buf = payload.0;

        if buf.len() < CHACHAPOLY1305_OVERHEAD {
            return Err(TLSError::DecryptError);
        }

        let nonce = make_tls13_nonce(&self.dec_offset, seq);
        let aad = make_tls12_aad(
            seq,
            msg.typ,
            msg.version,
            buf.len() - CHACHAPOLY1305_OVERHEAD,
        );

        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, &mut buf)
            .map_err(|_| TLSError::DecryptError)?
            .len();

        if plain_len > MAX_FRAGMENT_LEN {
            return Err(TLSError::PeerSentOversizedRecord);
        }

        buf.truncate(plain_len);

        Ok(Message {
            typ: msg.typ,
            version: msg.version,
            payload: MessagePayload::new_opaque(buf),
        })
    }
}

impl MessageEncrypter for ChaCha20Poly1305MessageEncrypter {
    fn encrypt(&self, msg: BorrowMessage, seq: u64) -> Result<Message, TLSError> {
        let nonce = make_tls13_nonce(&self.enc_offset, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());

        let total_len = msg.payload.len() + self.enc_key.algorithm().tag_len();
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&msg.payload);

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut buf)
            .map_err(|_| TLSError::General("encrypt failed".to_string()))?;

        Ok(Message {
            typ: msg.typ,
            version: msg.version,
            payload: MessagePayload::new_opaque(buf),
        })
    }
}

/// A `MessageEncrypter` for SM4_CBC ciphersuites.
pub struct CBCMessageEncrypter {
    enc_key: SMKey,
    enc_iv: SMIv,
}

/// A `MessageDecrypter` for SM4_CBC ciphersuites.
pub struct CBCMessageDecrypter {
    dec_key: SMKey,
    dec_iv: SMIv,
}

impl CBCMessageEncrypter {
    fn new(enc_key: SMKey, enc_iv: SMIv) -> Self {
        let ret = CBCMessageEncrypter {
            enc_key,
            enc_iv,
        };
        ret
    }
}

impl CBCMessageDecrypter {
    fn new(dec_key: SMKey, dec_iv: SMIv) -> Self {
        let ret = CBCMessageDecrypter {
            dec_key,
            dec_iv,
        };
        ret
    }
}

impl MessageEncrypter for CBCMessageEncrypter {
    fn encrypt(&self, msg: BorrowMessage, _seq: u64) -> Result<Message, TLSError> {
        let cmode = libsm::sm4::Cipher::new(
            self.enc_key.value(), libsm::sm4::Mode::Cbc);
        let buf = cmode.encrypt(msg.payload, self.enc_iv.value());

        Ok(Message {
            typ: msg.typ,
            version: msg.version,
            payload: MessagePayload::new_opaque(buf),
        })
    }
}

impl MessageDecrypter for CBCMessageDecrypter {
    fn decrypt(&self, mut msg: Message, _seq: u64) -> Result<Message, TLSError> {
        let payload = msg.take_opaque_payload().ok_or(TLSError::DecryptError)?;
        let cmode = libsm::sm4::Cipher::new(
            self.dec_key.value(), libsm::sm4::Mode::Cbc);
        let buf = cmode.decrypt(&payload.0, self.dec_iv.value());

        Ok(Message {
            typ: msg.typ,
            version: msg.version,
            payload: MessagePayload::new_opaque(buf),
        })
    }
}

/// A `MessageEncrypter` which doesn't work.
pub struct InvalidMessageEncrypter {}

impl MessageEncrypter for InvalidMessageEncrypter {
    fn encrypt(&self, _m: BorrowMessage, _seq: u64) -> Result<Message, TLSError> {
        Err(TLSError::General("encrypt not yet available".to_string()))
    }
}

/// A `MessageDecrypter` which doesn't work.
pub struct InvalidMessageDecrypter {}

impl MessageDecrypter for InvalidMessageDecrypter {
    fn decrypt(&self, _m: Message, _seq: u64) -> Result<Message, TLSError> {
        Err(TLSError::DecryptError)
    }
}
