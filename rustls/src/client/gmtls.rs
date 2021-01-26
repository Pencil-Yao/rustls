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

use crate::client::common::{
    ClientAuthDetails, ClientHelloDetails, HandshakeDetails, ServerCertDetails, ServerKXDetails,
};
use crate::client::hs::{
    illegal_param, send_cert_error_alert, CheckResult, NextState, NextStateOrError, State,
};
use crate::client::ClientSessionImpl;
use crate::handshake::{check_handshake_message, check_message};
use crate::internal::msgs::message::Message;
use crate::key_schedule::KeyScheduleEarly;
#[cfg(feature = "logging")]
use crate::log::{debug, trace, warn};
use crate::msgs::base::Payload;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{
    ClientCertificateType, Compression, ContentType, HandshakeType, NamedGroup,
};
use crate::msgs::handshake::{ClientKeyExchangeGmtlsPayload, DecomposedSignatureScheme, HandshakeMessagePayload, HandshakePayload, ServerECDHParams, ServerKeyExchangePayload, DigitallySignedStruct};
use crate::msgs::message::MessagePayload;
use crate::session::SessionSecrets;
use crate::{suites, verify, ProtocolVersion, SignatureScheme, TLSError};
use ring::constant_time;

pub struct ExpectCertificate {
    pub handshake: HandshakeDetails,
    pub server_cert: ServerCertDetails,
    pub may_send_cert_status: bool,
}

impl ExpectCertificate {
    fn into_expect_server_kx(self) -> NextState {
        Box::new(ExpectServerKX {
            handshake: self.handshake,
            server_cert: self.server_cert,
        })
    }
}

impl State for ExpectCertificate {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::Certificate])
    }

    fn handle(mut self: Box<Self>, _sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let cert_chain = extract_handshake!(m, HandshakePayload::Certificate).unwrap();
        self.handshake.transcript.add_message(&m);

        self.server_cert.cert_chain = cert_chain.clone();
        Ok(self.into_expect_server_kx())
    }
}

pub struct ExpectServerHelloGmtls {
    pub handshake: HandshakeDetails,
    pub early_key_schedule: Option<KeyScheduleEarly>,
    pub hello: ClientHelloDetails,
    pub server_cert: ServerCertDetails,
    pub may_send_cert_status: bool,
}

impl ExpectServerHelloGmtls {
    fn into_expect_certificate(self) -> NextState {
        Box::new(ExpectCertificate {
            handshake: self.handshake,
            server_cert: self.server_cert,
            may_send_cert_status: self.may_send_cert_status,
        })
    }
}

impl State for ExpectServerHelloGmtls {
    fn check_message(&self, m: &Message) -> CheckResult {
        check_handshake_message(m, &[HandshakeType::ServerHello])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let server_hello = extract_handshake!(m, HandshakePayload::ServerHelloGmtls).unwrap();
        trace!("We got Gmtls ServerHello {:#?}", server_hello);

        if sess.early_data.is_enabled() && sess.common.early_traffic {
            // The client must fail with a dedicated error code if the server
            // responds with TLS 1.2 when offering 0-RTT.
            return Err(TLSError::PeerMisbehavedError(
                "server chose smtlsv1.1 when offering 0-rtt".to_string(),
            ));
        }
        sess.common.negotiated_version = Some(ProtocolVersion::SMTLSv1_1);

        if server_hello.compression_method != Compression::Null {
            return Err(illegal_param(sess, "server chose non-Null compression"));
        }

        let scs = sess.find_cipher_suite(server_hello.cipher_suite);

        if scs.is_none() {
            return Err(TLSError::PeerMisbehavedError(
                "server chose non-offered ciphersuite".to_string(),
            ));
        }

        debug!("Using ciphersuite {:?}", server_hello.cipher_suite);
        if !sess.common.set_suite(scs.unwrap()) {
            return Err(illegal_param(sess, "server varied selected ciphersuite"));
        }

        let version = sess.common.negotiated_version.unwrap();
        if !sess.common.get_suite_assert().usable_for_version(version) {
            return Err(illegal_param(
                sess,
                "server chose unusable ciphersuite for version",
            ));
        }

        // Start our handshake hash, and input the server-hello.
        let starting_hash = sess.common.get_suite_assert().get_hash();
        self.handshake.transcript.start_hash(starting_hash);
        self.handshake.transcript.add_message(&m);

        server_hello
            .random
            .write_slice(&mut self.handshake.randoms.server);
        self.handshake.session_id = server_hello.session_id;

        Ok(self.into_expect_certificate())
    }
}

struct ExpectServerKX {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
}

impl ExpectServerKX {
    fn into_expect_server_certreq(self, skx: ServerKXDetails) -> NextState {
        Box::new(ExpectServerCertReq {
            handshake: self.handshake,
            server_cert: self.server_cert,
            server_kx: skx,
        })
    }
}

impl State for ExpectServerKX {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::ServerKeyExchange])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let opaque_kx = extract_handshake!(m, HandshakePayload::ServerKeyExchange).unwrap();
        let maybe_decoded_kx = opaque_kx.unwrap_given_kxa(&sess.common.get_suite_assert().kx);
        self.handshake.transcript.add_message(&m);

        if maybe_decoded_kx.is_none() {
            return Err(TLSError::CorruptMessagePayload(ContentType::Handshake));
        }

        let decoded_kx = maybe_decoded_kx.unwrap();

        // Save the signature and signed parameters for later verification.
        let mut kx_params = Vec::new();
        decoded_kx.encode_params(&mut kx_params);
        let skx = ServerKXDetails::new(kx_params, decoded_kx.get_sig().unwrap());

        #[cfg_attr(not(feature = "logging"), allow(unused_variables))]
        {
            if let ServerKeyExchangePayload::ECDHE(ecdhe) = decoded_kx {
                debug!("ECDHE curve is {:?}", ecdhe.params.curve_params);
            }
        }

        Ok(self.into_expect_server_certreq(skx))
    }
}

struct ExpectServerCertReq {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    server_kx: ServerKXDetails,
}

impl ExpectServerCertReq {
    fn into_expect_certificate_req(self) -> NextState {
        Box::new(ExpectCertificateRequest {
            handshake: self.handshake,
            server_cert: self.server_cert,
            server_kx: self.server_kx,
        })
    }
}

impl State for ExpectServerCertReq {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::CertificateRequest])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        self.into_expect_certificate_req().handle(sess, m)
    }
}

struct ExpectCertificateRequest {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    server_kx: ServerKXDetails,
}

impl ExpectCertificateRequest {
    fn into_expect_server_done(self, client_auth: ClientAuthDetails) -> NextState {
        Box::new(ExpectServerDone {
            handshake: self.handshake,
            server_cert: self.server_cert,
            server_kx: self.server_kx,
            client_auth: Some(client_auth),
        })
    }
}

impl State for ExpectCertificateRequest {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::CertificateRequest])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let certreq = extract_handshake!(m, HandshakePayload::CertificateRequestGmtls).unwrap();
        self.handshake.transcript.add_message(&m);
        debug!("Got CertificateRequest {:?}", certreq);

        let mut client_auth = ClientAuthDetails::new();

        let canames = certreq
            .canames
            .iter()
            .map(|p| p.0.as_slice())
            .collect::<Vec<&[u8]>>();
        let maybe_certkey = sess
            .config
            .client_auth_cert_resolver
            .resolve(&canames, &[SignatureScheme::ECDSA_SM2P256_SM3]);

        if let Some(mut certkey) = maybe_certkey {
            debug!("Attempting client auth");
            let maybe_signer = certkey
                .key
                .choose_scheme(&[SignatureScheme::ECDSA_SM2P256_SM3]);
            client_auth.cert = Some(certkey.take_cert());
            client_auth.signer = maybe_signer;
        } else {
            debug!("Client auth requested but no cert/sigscheme available");
        }

        Ok(self.into_expect_server_done(client_auth))
    }
}

struct ExpectServerDone {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    server_kx: ServerKXDetails,
    client_auth: Option<ClientAuthDetails>,
}

impl ExpectServerDone {
    fn into_expect_ccs(
        self,
        secrets: SessionSecrets,
        certv: verify::ServerCertVerified,
        sigv: verify::HandshakeSignatureValid,
    ) -> NextState {
        Box::new(ExpectCCS {
            secrets,
            handshake: self.handshake,
            resuming: false,
            cert_verified: certv,
            sig_verified: sigv,
        })
    }
}

impl State for ExpectServerDone {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::ServerHelloDone])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let mut st = *self;
        st.handshake.transcript.add_message(&m);

        debug!("Server cert is {:?}", st.server_cert.cert_chain);
        debug!("Server DNS name is {:?}", st.handshake.dns_name);

        // 1. Verify the cert chain.
        // 2. Verify any SCTs provided with the certificate.
        // 3. Verify that the top certificate signed their kx.
        // 4. If doing client auth, send our Certificate.
        // 5. Complete the key exchange:
        //    a) generate our kx pair
        //    b) emit a ClientKeyExchange containing it
        //    c) if doing client auth, emit a CertificateVerify
        //    d) emit a CCS
        //    e) derive the shared keys, and start encryption
        // 6. emit a Finished, our first encrypted message under the new keys.

        // 1.
        if st.server_cert.cert_chain.is_empty() {
            return Err(TLSError::NoCertificatesPresented);
        }

        let certv = sess
            .config
            .get_verifier()
            .verify_server_cert(
                &sess.config.root_store,
                &st.server_cert.cert_chain,
                st.handshake.dns_name.as_ref(),
                &st.server_cert.ocsp_response,
            )
            .map_err(|err| send_cert_error_alert(sess, err))?;

        // 2. Verify any included SCTs.
        match (st.server_cert.scts.as_ref(), sess.config.ct_logs) {
            (Some(scts), Some(logs)) => {
                verify::verify_scts(&st.server_cert.cert_chain[0], scts, logs)?;
            }
            (_, _) => {}
        }

        // 3.
        // Build up the contents of the signed message.
        // It's ClientHello.random || ServerHello.random || ServerKeyExchange.params
        let sigv = {
            let mut message = Vec::new();
            message.extend_from_slice(&st.handshake.randoms.client);
            message.extend_from_slice(&st.handshake.randoms.server);
            message.extend_from_slice(&st.server_kx.kx_params);

            // Check the signature is compatible with the ciphersuite.
            let sig = &st.server_kx.kx_sig;
            let scs = sess.common.get_suite_assert();
            if scs.sign != sig.scheme.sign() {
                let error_message = format!(
                    "peer signed kx with wrong algorithm (got {:?} expect {:?})",
                    sig.scheme.sign(),
                    scs.sign
                );
                return Err(TLSError::PeerMisbehavedError(error_message));
            }

            verify::verify_signed_struct(&message, &st.server_cert.cert_chain[0], sig)
                .map_err(|err| send_cert_error_alert(sess, err))?
        };
        sess.server_cert_chain = st.server_cert.take_chain();

        // 4.
        if st.client_auth.is_some() {
            emit_certificate(&mut st.handshake, st.client_auth.as_mut().unwrap(), sess);
        }

        // 5a.
        let kxd = {
            if st.client_auth.is_none()
                || st.client_auth.as_ref().unwrap().get_signer_sig_scheme()
                    != Some(SignatureScheme::ECDSA_SM2P256_SM3)
            {
                return Err(TLSError::PeerIncompatibleError(
                    "server not given sm ecdsa cert at sm tls".to_string(),
                ));
            }

            let encrypt_cert = webpki::EndEntityCert::from(&sess.server_cert_chain[1].0)
                .map_err(TLSError::WebPKIError)?;
            let server_en_pubkey = encrypt_cert.get_public_key().map_err(|_| {
                TLSError::PeerMisbehavedError("can't parse server encrypt cert".to_string())
            })?;
            let mut rd = Reader::init(&st.server_kx.kx_params);
            let ecdh_params = ServerECDHParams::read(&mut rd).ok_or_else(|| {
                TLSError::PeerMisbehavedError("key exchange failed on sm mode".to_string())
            })?;
            let kx_pubkey: &[u8] = ecdh_params.public.0.as_ref();

            // verify kx pubkey == the second cert of server cert chain
            if server_en_pubkey != kx_pubkey {
                return Err(TLSError::PeerMisbehavedError(
                    "server encrypt cert is not consistent with kx params".to_string(),
                ));
            }

            let privkey = sess.config.encrypt_cert_key.extract().ok_or_else(|| {
                TLSError::PeerMisbehavedError("not given client encrypt cert".to_string())
            })?;
            suites::KeyExchange {
                group: NamedGroup::sm2p256,
                alg: &ring::agreement::ECDH_SM2P256,
                pubkey: privkey.compute_public_key().unwrap(),
                privkey,
            }
            .complete(server_en_pubkey)
            .ok_or_else(|| {
                TLSError::PeerMisbehavedError("key exchange failed on sm mode".to_string())
            })?
        };

        // 5b.
        emit_clientkx(&mut st.handshake, sess, &kxd);

        // 5c.
        if st.client_auth.is_some() {
            emit_certverify(&mut st.handshake, st.client_auth.as_mut().unwrap(), sess)?;
        }

        // 5d.
        emit_ccs(sess);

        // 5e. Now commit secrets.
        let hashalg = sess.common.get_suite_assert().get_hash();
        let secrets = SessionSecrets::new(&st.handshake.randoms, hashalg, &kxd.shared_secret);
        sess.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            &secrets.master_secret,
        );
        sess.common.start_encryption_tls12(&secrets); // todo gmtls wrapping in this
        sess.common.record_layer.start_encrypting();

        // 6.
        emit_finished(&secrets, &mut st.handshake, sess);

        Ok(st.into_expect_ccs(secrets, certv, sigv))
    }
}

// -- Waiting for their CCS --
struct ExpectCCS {
    pub secrets: SessionSecrets,
    pub handshake: HandshakeDetails,
    pub resuming: bool,
    pub cert_verified: verify::ServerCertVerified,
    pub sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectCCS {
    fn into_expect_finished(self) -> NextState {
        Box::new(ExpectFinished {
            secrets: self.secrets,
            handshake: self.handshake,
            resuming: self.resuming,
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        })
    }
}

impl State for ExpectCCS {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_message(m, &[ContentType::ChangeCipherSpec], &[])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, _m: Message) -> NextStateOrError {
        // CCS should not be received interleaved with fragmented handshake-level
        // message.
        if !sess.common.handshake_joiner.is_empty() {
            warn!("CCS received interleaved with fragmented handshake");
            return Err(TLSError::InappropriateMessage {
                expect_types: vec![ContentType::Handshake],
                got_type: ContentType::ChangeCipherSpec,
            });
        }

        // nb. msgs layer validates trivial contents of CCS
        sess.common.record_layer.start_decrypting();

        Ok(self.into_expect_finished())
    }
}

struct ExpectFinished {
    handshake: HandshakeDetails,
    secrets: SessionSecrets,
    resuming: bool,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectFinished {
    fn into_expect_traffic(self, fin: verify::FinishedMessageVerified) -> NextState {
        Box::new(ExpectTraffic {
            secrets: self.secrets,
            _cert_verified: self.cert_verified,
            _sig_verified: self.sig_verified,
            _fin_verified: fin,
        })
    }
}

impl State for ExpectFinished {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::Finished])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> NextStateOrError {
        let mut st = *self;
        let finished = extract_handshake!(m, HandshakePayload::Finished).unwrap();

        let vh = st.handshake.transcript.get_current_hash();
        let expect_verify_data = st.secrets.server_verify_data(&vh);

        // Constant-time verification of this is relatively unimportant: they only
        // get one chance.  But it can't hurt.
        let fin = constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
            .map_err(|_| TLSError::DecryptError)
            .map(|_| verify::FinishedMessageVerified::assertion())?;

        // Hash this message too.
        st.handshake.transcript.add_message(&m);

        if st.resuming {
            emit_ccs(sess);
            sess.common.record_layer.start_encrypting();
            emit_finished(&st.secrets, &mut st.handshake, sess);
        }

        sess.common.start_traffic();
        Ok(st.into_expect_traffic(fin))
    }
}

// -- Traffic transit state --
struct ExpectTraffic {
    secrets: SessionSecrets,
    _cert_verified: verify::ServerCertVerified,
    _sig_verified: verify::HandshakeSignatureValid,
    _fin_verified: verify::FinishedMessageVerified,
}

impl State for ExpectTraffic {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_message(m, &[ContentType::ApplicationData], &[])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, mut m: Message) -> NextStateOrError {
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

fn emit_certificate(
    handshake: &mut HandshakeDetails,
    client_auth: &mut ClientAuthDetails,
    sess: &mut ClientSessionImpl,
) {
    let chosen_cert = client_auth.cert.take();
    let cert = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::SMTLSv1_1,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::Certificate(chosen_cert.unwrap()),
        }),
    };

    handshake.transcript.add_message(&cert);
    sess.common.send_msg(cert, false);
}

fn emit_clientkx(
    handshake: &mut HandshakeDetails,
    sess: &mut ClientSessionImpl,
    kxd: &suites::KeyExchangeResult,
) {
    let secdh = ServerECDHParams::new(NamedGroup::sm2p256, kxd.pubkey.as_ref());

    let ckx = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::SMTLSv1_1,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientKeyExchange,
            payload: HandshakePayload::ClientKeyExchangeGmtls(
                ClientKeyExchangeGmtlsPayload::ECDHE(vec![secdh]),
            ),
        }),
    };

    handshake.transcript.add_message(&ckx);
    sess.common.send_msg(ckx, false);
}

fn emit_certverify(
    handshake: &mut HandshakeDetails,
    client_auth: &mut ClientAuthDetails,
    sess: &mut ClientSessionImpl,
) -> Result<(), TLSError> {
    if client_auth.signer.is_none() {
        trace!("Not sending CertificateVerify, no key");
        handshake.transcript.abandon_client_auth();
        return Ok(());
    }

    let message = handshake.transcript.take_handshake_buf();
    let signer = client_auth.signer.take().unwrap();
    let scheme = signer.get_scheme();
    let sig = signer.sign(&message)?;
    let body = DigitallySignedStruct::new(scheme, sig);

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::SMTLSv1_1,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(body),
        }),
    };

    handshake.transcript.add_message(&m);
    sess.common.send_msg(m, false);
    Ok(())
}

fn emit_ccs(sess: &mut ClientSessionImpl) {
    let ccs = Message {
        typ: ContentType::ChangeCipherSpec,
        version: ProtocolVersion::SMTLSv1_1,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };

    sess.common.send_msg(ccs, false);
}

fn emit_finished(
    secrets: &SessionSecrets,
    handshake: &mut HandshakeDetails,
    sess: &mut ClientSessionImpl,
) {
    let vh = handshake.transcript.get_current_hash();
    let verify_data = secrets.client_verify_data(&vh);
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
