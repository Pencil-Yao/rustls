// Copyright 2020-2021 Yao Pengfei.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use crate::handshake::{check_handshake_message, check_message};
#[cfg(feature = "logging")]
use crate::log::{debug, trace, warn};
use crate::msgs::base::Payload;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::Codec;
use crate::msgs::enums::{
    ClientCertificateType, Compression, ContentType, HandshakeType, NamedGroup, ProtocolVersion,
};
use crate::msgs::handshake::{
    CertificateRequestGmtlsPayload,
    DigitallySignedStruct, ECDHEServerKeyExchange, HandshakeMessagePayload, HandshakePayload,
    Random, ServerECDHParams, ServerHelloGmtlsPayload,
    ServerKeyExchangePayload,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::server::common::{ClientCertDetails, HandshakeDetails, ServerKXDetails};
use crate::server::hs::{
    CheckResult, ExpectClientHello, NextState, NextStateOrError, State,
};
use crate::server::ServerSessionImpl;
use crate::session::SessionSecrets;
use crate::{sign, suites, verify, SignatureScheme, TLSError};
use ring::constant_time;

pub struct ExpectCertificate {
    pub handshake: HandshakeDetails,
    pub server_kx: ServerKXDetails,
}

impl ExpectCertificate {
    fn into_expect_client_kx(self, cert: Option<ClientCertDetails>) -> NextState {
        Box::new(ExpectClientKX {
            handshake: self.handshake,
            server_kx: self.server_kx,
            client_cert: cert,
        })
    }
}

impl State for ExpectCertificate {
    fn check_message(&self, m: &Message) -> CheckResult {
        check_handshake_message(m, &[HandshakeType::Certificate])
    }

    fn handle(mut self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> NextStateOrError {
        let cert_chain = extract_handshake!(m, HandshakePayload::Certificate).unwrap();
        self.handshake.transcript.add_message(&m);

        if cert_chain.is_empty() {
            return Err(TLSError::NoCertificatesPresented);
        }
        trace!("smtls certs {:?}", cert_chain);

        sess.config
            .verifier
            .verify_client_cert(cert_chain, None)
            .or_else(|err| Err(err))?;

        let cert = ClientCertDetails::new(cert_chain.clone());
        Ok(self.into_expect_client_kx(Some(cert)))
    }
}

// --- Process client's KeyExchange ---
pub struct ExpectClientKX {
    pub handshake: HandshakeDetails,
    pub server_kx: ServerKXDetails,
    pub client_cert: Option<ClientCertDetails>,
}

impl ExpectClientKX {
    fn into_expect_certificate_verify(self, secrets: SessionSecrets) -> NextState {
        Box::new(ExpectCertificateVerify {
            secrets,
            handshake: self.handshake,
            client_cert: self.client_cert.unwrap(),
        })
    }
}

impl State for ExpectClientKX {
    fn check_message(&self, m: &Message) -> CheckResult {
        check_handshake_message(m, &[HandshakeType::ClientKeyExchange])
    }

    fn handle(mut self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> NextStateOrError {
        let client_kx = extract_handshake!(m, HandshakePayload::ClientKeyExchangeGmtls).unwrap();
        self.handshake.transcript.add_message(&m);

        // Complete key agreement, and set up encryption with the
        // resulting premaster secret.
        let kx = self.server_kx.take_kx();
        let client_kx_p = client_kx.unwrap_payload();

        let kxd = {
            if let Some(ckxp) = client_kx_p {
                let mut kx_parm = Vec::new();
                ckxp.encode_params(&mut kx_parm);
                kx.server_complete(&kx_parm).ok_or_else(|| {
                    TLSError::PeerMisbehavedError("key exchange completion failed".to_string())
                })?
            } else {
                return Err(TLSError::PeerMisbehavedError(
                    "client key exchange payload is none".to_string(),
                ));
            }
        };

        let hashalg = sess.common.get_suite_assert().get_hash();
        let secrets = SessionSecrets::new(&self.handshake.randoms, hashalg, &kxd.shared_secret);
        sess.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            &secrets.master_secret,
        );
        sess.common.start_encryption_tls12(&secrets);

        Ok(self.into_expect_certificate_verify(secrets))
    }
}

// --- Process client's certificate proof ---
pub struct ExpectCertificateVerify {
    secrets: SessionSecrets,
    handshake: HandshakeDetails,
    client_cert: ClientCertDetails,
}

impl ExpectCertificateVerify {
    fn into_expect_ccs(self) -> NextState {
        Box::new(ExpectCCS {
            secrets: self.secrets,
            handshake: self.handshake,
            resuming: false,
        })
    }
}

impl State for ExpectCertificateVerify {
    fn check_message(&self, m: &Message) -> CheckResult {
        check_handshake_message(m, &[HandshakeType::CertificateVerify])
    }

    fn handle(mut self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> NextStateOrError {
        let rc = {
            let sig = extract_handshake!(m, HandshakePayload::CertificateVerify).unwrap();
            let handshake_msgs = self.handshake.transcript.take_handshake_buf();
            let certs = &self.client_cert.cert_chain;

            verify::verify_signed_struct(&handshake_msgs, &certs[0], sig)
        };

        if let Err(e) = rc {
            return Err(e);
        }

        trace!("client CertificateVerify OK");
        sess.client_cert_chain = Some(self.client_cert.take_chain());

        self.handshake.transcript.add_message(&m);
        Ok(self.into_expect_ccs())
    }
}

// --- Process client's ChangeCipherSpec ---
pub struct ExpectCCS {
    pub secrets: SessionSecrets,
    pub handshake: HandshakeDetails,
    pub resuming: bool,
}

impl ExpectCCS {
    fn into_expect_finished(self) -> NextState {
        Box::new(ExpectFinished {
            secrets: self.secrets,
            handshake: self.handshake,
            resuming: self.resuming,
        })
    }
}

impl State for ExpectCCS {
    fn check_message(&self, m: &Message) -> CheckResult {
        check_message(m, &[ContentType::ChangeCipherSpec], &[])
    }

    fn handle(self: Box<Self>, sess: &mut ServerSessionImpl, _m: Message) -> NextStateOrError {
        // CCS should not be received interleaved with fragmented handshake-level
        // message.
        if !sess.common.handshake_joiner.is_empty() {
            warn!("CCS received interleaved with fragmented handshake");
            return Err(TLSError::InappropriateMessage {
                expect_types: vec![ContentType::Handshake],
                got_type: ContentType::ChangeCipherSpec,
            });
        }

        sess.common.record_layer.start_decrypting();
        Ok(self.into_expect_finished())
    }
}

// --- Process client's Finished ---
fn get_server_session_value(
    secrets: &SessionSecrets,
    sess: &ServerSessionImpl,
) -> persist::ServerSessionValue {
    let scs = sess.common.get_suite_assert();
    let secret = secrets.get_master_secret();

    let v = persist::ServerSessionValue::new(
        None,
        ProtocolVersion::SMTLSv1_1,
        scs.suite,
        secret,
        &sess.client_cert_chain,
        sess.alpn_protocol.clone(),
        sess.resumption_data.clone(),
    );

    v
}

pub fn emit_ccs(sess: &mut ServerSessionImpl) {
    let m = Message {
        typ: ContentType::ChangeCipherSpec,
        version: ProtocolVersion::SMTLSv1_1,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };

    sess.common.send_msg(m, false);
}

pub fn emit_finished(
    secrets: &SessionSecrets,
    handshake: &mut HandshakeDetails,
    sess: &mut ServerSessionImpl,
) {
    let vh = handshake.transcript.get_current_hash();
    let verify_data = secrets.server_verify_data(&vh);
    let verify_data_payload = Payload::new(verify_data);

    let f = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::SMTLSv1_1,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    handshake.transcript.add_message(&f);
    sess.common.send_msg(f, true);
}

pub struct ExpectFinished {
    secrets: SessionSecrets,
    handshake: HandshakeDetails,
    resuming: bool,
}

impl ExpectFinished {
    fn into_expect_traffic(self, fin: verify::FinishedMessageVerified) -> NextState {
        Box::new(ExpectTraffic {
            secrets: self.secrets,
            _fin_verified: fin,
        })
    }
}

impl State for ExpectFinished {
    fn check_message(&self, m: &Message) -> CheckResult {
        check_handshake_message(m, &[HandshakeType::Finished])
    }

    fn handle(mut self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> NextStateOrError {
        let finished = extract_handshake!(m, HandshakePayload::Finished).unwrap();

        let vh = self.handshake.transcript.get_current_hash();
        let expect_verify_data = self.secrets.client_verify_data(&vh);

        let fin = constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
            .map_err(|_| TLSError::DecryptError)
            .map(|_| verify::FinishedMessageVerified::assertion())?;

        // Save session, perhaps
        if !self.resuming && !self.handshake.session_id.is_empty() {
            let value = get_server_session_value(&self.secrets, sess);

            let worked = sess.config.session_storage.put(
                self.handshake.session_id.get_encoding(),
                value.get_encoding(),
            );
            if worked {
                debug!("Session saved");
            } else {
                debug!("Session not saved");
            }
        }

        // Send our CCS and Finished.
        self.handshake.transcript.add_message(&m);
        emit_ccs(sess);
        sess.common.record_layer.start_encrypting();
        emit_finished(&self.secrets, &mut self.handshake, sess);

        sess.common.start_traffic();
        Ok(self.into_expect_traffic(fin))
    }
}

// --- Process traffic ---
pub struct ExpectTraffic {
    secrets: SessionSecrets,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {}

impl State for ExpectTraffic {
    fn check_message(&self, m: &Message) -> CheckResult {
        check_message(m, &[ContentType::ApplicationData], &[])
    }

    fn handle(self: Box<Self>, sess: &mut ServerSessionImpl, mut m: Message) -> NextStateOrError {
        sess.common
            .take_received_plaintext(m.take_opaque_payload().unwrap());
        Ok(self)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), TLSError> {
        self.secrets.export_keying_material(output, label, context);
        Ok(())
    }
}

pub fn emit_server_hello(
    client_hello: &mut ExpectClientHello,
    sess: &mut ServerSessionImpl,
) -> Result<(), TLSError> {
    let sh = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::SMTLSv1_1,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerHello,
            payload: HandshakePayload::ServerHelloGmtls(ServerHelloGmtlsPayload {
                server_version: ProtocolVersion::SMTLSv1_1,
                random: Random::from_slice(&client_hello.handshake.randoms.server),
                session_id: client_hello.handshake.session_id,
                cipher_suite: sess.common.get_suite_assert().suite,
                compression_method: Compression::Null,
            }),
        }),
    };

    trace!("sending smtls server hello {:?}", sh);
    client_hello.handshake.transcript.add_message(&sh);
    sess.common.send_msg(sh, false);
    Ok(())
}

pub fn emit_certificate(
    client_hello: &mut ExpectClientHello,
    sess: &mut ServerSessionImpl,
    server_certkey: &mut sign::CertifiedKey,
) {
    let cert_chain = server_certkey.take_cert();

    let c = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::SMTLSv1_1,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::Certificate(cert_chain),
        }),
    };

    client_hello.handshake.transcript.add_message(&c);
    sess.common.send_msg(c, false);
}

pub fn emit_server_kx(
    client_hello: &mut ExpectClientHello,
    sess: &mut ServerSessionImpl,
    server_certkey: &mut sign::CertifiedKey,
) -> Result<suites::KeyExchange, TLSError> {
    let signing_key = &server_certkey.key;
    let signer = signing_key
        .choose_scheme(&[SignatureScheme::ECDSA_SM2P256_SM3])
        .ok_or_else(|| TLSError::PeerMisbehavedError("incompatible signing key".to_string()))?;

    let privkey = sess.config.encrypt_cert_key.extract().ok_or_else(|| {
        TLSError::PeerMisbehavedError("not given server encrypt cert".to_string())
    })?;
    let kx = suites::KeyExchange {
        group: NamedGroup::sm2p256,
        alg: &ring::agreement::ECDH_SM2P256,
        pubkey: privkey.compute_public_key().unwrap(),
        privkey,
    };

    let secdh = ServerECDHParams::new(NamedGroup::sm2p256, kx.pubkey.as_ref());

    let mut msg = Vec::new();
    msg.extend(&client_hello.handshake.randoms.client);
    msg.extend(&client_hello.handshake.randoms.server);
    secdh.encode(&mut msg);

    let sig = signer.sign(&msg)?;
    let skx = ServerKeyExchangePayload::ECDHE(ECDHEServerKeyExchange {
        params: secdh,
        dss: DigitallySignedStruct::new(SignatureScheme::ECDSA_SM2P256_SM3, sig),
    });

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::SMTLSv1_1,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerKeyExchange,
            payload: HandshakePayload::ServerKeyExchange(skx),
        }),
    };

    client_hello.handshake.transcript.add_message(&m);
    sess.common.send_msg(m, false);
    Ok(kx)
}

pub fn emit_certificate_req(
    client_hello: &mut ExpectClientHello,
    sess: &mut ServerSessionImpl,
) -> Result<bool, TLSError> {
    let client_auth = &sess.config.verifier;

    if !client_auth.offer_client_auth() {
        return Ok(false);
    }

    let names = client_auth
        .client_auth_root_subjects(None)
        .ok_or_else(|| TLSError::General("client rejected by client_auth_root_subjects".into()))?;

    let cr = CertificateRequestGmtlsPayload {
        certtypes: vec![ClientCertificateType::ECDSASign],
        canames: names,
    };

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::SMTLSv1_1,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateRequest,
            payload: HandshakePayload::CertificateRequestGmtls(cr),
        }),
    };

    trace!("Sending CertificateRequest {:?}", m);
    client_hello.handshake.transcript.add_message(&m);
    sess.common.send_msg(m, false);
    Ok(true)
}

pub fn emit_server_hello_done(client_hello: &mut ExpectClientHello, sess: &mut ServerSessionImpl) {
    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::SMTLSv1_1,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerHelloDone,
            payload: HandshakePayload::ServerHelloDone,
        }),
    };

    client_hello.handshake.transcript.add_message(&m);
    sess.common.send_msg(m, false);
}
