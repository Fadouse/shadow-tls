#[cfg(feature = "logging")]
use crate::bs_debug;
use crate::check::inappropriate_handshake_message;
use crate::conn::{CommonState, ConnectionRandoms, State};
use crate::enums::{CipherSuite, ProtocolVersion};
use crate::error::Error;
use crate::hash_hs::HandshakeHashBuffer;
use crate::kx;
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::msgs::base::Payload;
#[cfg(feature = "quic")]
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{AlertDescription, Compression, ContentType};
use crate::msgs::enums::{ECPointFormat, PSKKeyExchangeMode};
use crate::msgs::enums::{ExtensionType, HandshakeType};
use crate::msgs::handshake::{CertificateStatusRequest, ClientSessionTicket, SCTList};
use crate::msgs::handshake::{ClientExtension, HasServerExtensions};
use crate::msgs::handshake::{ClientHelloPayload, HandshakeMessagePayload, HandshakePayload};
use crate::msgs::handshake::{ConvertProtocolNameList, ProtocolNameList};
use crate::msgs::handshake::{ECPointFormatList, SupportedPointFormats};
use crate::msgs::handshake::{HelloRetryRequest, KeyShareEntry};
use crate::msgs::handshake::{Random, SessionID, UnknownExtension};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::ticketer::TimeBase;
use crate::tls13::key_schedule::KeyScheduleEarly;
use crate::SupportedCipherSuite;

#[cfg(feature = "tls12")]
use super::tls12;
use crate::client::client_conn::ClientConnectionData;
use crate::client::common::ClientHelloDetails;
use crate::client::{tls13, ClientConfig, ServerName};

use std::sync::Arc;

pub(super) type NextState = Box<dyn State<ClientConnectionData>>;
pub(super) type NextStateOrError = Result<NextState, Error>;
pub(super) type ClientContext<'a> = crate::conn::Context<'a, ClientConnectionData>;

fn find_session(
    server_name: &ServerName,
    config: &ClientConfig,
    #[cfg(feature = "quic")] cx: &mut ClientContext<'_>,
) -> Option<persist::Retrieved<persist::ClientSessionValue>> {
    let key = persist::ClientSessionKey::session_for_server_name(server_name);
    let key_buf = key.get_encoding();

    let value = config
        .session_storage
        .get(&key_buf)
        .or_else(|| {
            debug!("No cached session for {:?}", server_name);
            None
        })?;

    #[allow(unused_mut)]
    let mut reader = Reader::init(&value[2..]);
    #[allow(clippy::bind_instead_of_map)] // https://github.com/rust-lang/rust-clippy/issues/8082
    CipherSuite::read_bytes(&value[..2])
        .and_then(|suite| {
            persist::ClientSessionValue::read(&mut reader, suite, &config.cipher_suites)
        })
        .and_then(|resuming| {
            let retrieved = persist::Retrieved::new(resuming, TimeBase::now().ok()?);
            match retrieved.has_expired() {
                false => Some(retrieved),
                true => None,
            }
        })
        .and_then(|resuming| {
            #[cfg(feature = "quic")]
            if cx.common.is_quic() {
                let params = PayloadU16::read(&mut reader)?;
                cx.common.quic.params = Some(params.0);
            }
            Some(resuming)
        })
}

pub(super) fn start_handshake(
    server_name: ServerName,
    extra_exts: Vec<ClientExtension>,
    config: Arc<ClientConfig>,
    cx: &mut ClientContext<'_>,
    session_id_generator: (bool, impl Fn(&[u8]) -> [u8; 32]),
) -> NextStateOrError {
    let mut transcript_buffer = HandshakeHashBuffer::new();
    if config
        .client_auth_cert_resolver
        .has_certs()
    {
        transcript_buffer.set_client_auth_enabled();
    }

    let support_tls13 = config.supports_version(ProtocolVersion::TLSv1_3);

    let mut session_id: Option<SessionID> = None;
    let mut resuming_session = find_session(
        &server_name,
        &config,
        #[cfg(feature = "quic")]
        cx,
    );

    let key_share = if support_tls13 {
        Some(tls13::initial_key_share(&config, &server_name)?)
    } else {
        None
    };

    if let Some(_resuming) = &mut resuming_session {
        #[cfg(feature = "tls12")]
        if let persist::ClientSessionValue::Tls12(inner) = &mut _resuming.value {
            // If we have a ticket, we use the sessionid as a signal that
            // we're  doing an abbreviated handshake.  See section 3.4 in
            // RFC5077.
            if !inner.ticket().is_empty() {
                inner.session_id = SessionID::random()?;
            }
            session_id = Some(inner.session_id);
        }

        debug!("Resuming session");
    } else {
        debug!("Not resuming any session");
    }

    // https://tools.ietf.org/html/rfc8446#appendix-D.4
    // https://tools.ietf.org/html/draft-ietf-quic-tls-34#section-8.4
    if session_id.is_none() && !cx.common.is_quic() {
        session_id = Some(SessionID::random()?);
    }

    let random = Random::new()?;
    let hello_details = ClientHelloDetails::new();
    let sent_tls13_fake_ccs = false;
    let may_send_sct_list = config.verifier.request_scts();
    Ok(emit_client_hello_for_retry(
        config,
        cx,
        resuming_session,
        random,
        false,
        transcript_buffer,
        sent_tls13_fake_ccs,
        hello_details,
        session_id,
        session_id_generator.0,
        session_id_generator.1,
        None,
        server_name,
        key_share,
        extra_exts,
        may_send_sct_list,
        None,
    ))
}

struct ExpectServerHello {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Retrieved<persist::ClientSessionValue>>,
    server_name: ServerName,
    random: Random,
    using_ems: bool,
    transcript_buffer: HandshakeHashBuffer,
    early_key_schedule: Option<KeyScheduleEarly>,
    hello: ClientHelloDetails,
    offered_key_share: Option<kx::KeyExchange>,
    session_id: SessionID,
    sent_tls13_fake_ccs: bool,
    suite: Option<SupportedCipherSuite>,
}

struct ExpectServerHelloOrHelloRetryRequest {
    next: ExpectServerHello,
    extra_exts: Vec<ClientExtension>,
}

fn emit_client_hello_for_retry(
    config: Arc<ClientConfig>,
    cx: &mut ClientContext<'_>,
    resuming_session: Option<persist::Retrieved<persist::ClientSessionValue>>,
    random: Random,
    using_ems: bool,
    mut transcript_buffer: HandshakeHashBuffer,
    mut sent_tls13_fake_ccs: bool,
    mut hello: ClientHelloDetails,
    session_id: Option<SessionID>,
    use_session_id_generator: bool,
    session_id_generator: impl Fn(&[u8]) -> [u8; 32],
    retryreq: Option<&HelloRetryRequest>,
    server_name: ServerName,
    key_share: Option<kx::KeyExchange>,
    extra_exts: Vec<ClientExtension>,
    may_send_sct_list: bool,
    suite: Option<SupportedCipherSuite>,
) -> NextState {
    // Do we have a SessionID or ticket cached for this host?
    let (ticket, resume_version) = if let Some(resuming) = &resuming_session {
        match &resuming.value {
            persist::ClientSessionValue::Tls13(inner) => {
                (inner.ticket().to_vec(), ProtocolVersion::TLSv1_3)
            }
            #[cfg(feature = "tls12")]
            persist::ClientSessionValue::Tls12(inner) => {
                (inner.ticket().to_vec(), ProtocolVersion::TLSv1_2)
            }
        }
    } else {
        (Vec::new(), ProtocolVersion::Unknown(0))
    };

    let support_tls12 = config.supports_version(ProtocolVersion::TLSv1_2) && !cx.common.is_quic();
    let support_tls13 = config.supports_version(ProtocolVersion::TLSv1_3);

    let mut supported_versions = Vec::new();
    if support_tls13 {
        supported_versions.push(ProtocolVersion::TLSv1_3);
    }

    if support_tls12 {
        supported_versions.push(ProtocolVersion::TLSv1_2);
    }

    // should be unreachable thanks to config builder
    assert!(!supported_versions.is_empty());

    // --- Chrome 131+ fingerprint-aligned extension ordering ---
    // Extension order matches Chrome/Chromium to produce consistent JA3/JA4 fingerprints.
    // GREASE values per RFC 8701 are injected at the positions Chrome uses them.

    // Generate GREASE values: 0xXaXa where X is a random nibble (0-15).
    // Chrome picks independent GREASE values for each slot per connection.
    let mut grease_seed = [0u8; 5];
    let _ = crate::rand::fill_random(&mut grease_seed);

    fn make_grease(seed: u8) -> u16 {
        let idx = (seed % 16) as u16;
        let hi = (idx << 4) | 0x0a;
        (hi << 8) | hi
    }

    let grease_ext_type = make_grease(grease_seed[0]);
    let grease_ext_type2 = {
        let val = make_grease(grease_seed[1]);
        if val == grease_ext_type { make_grease(grease_seed[1].wrapping_add(1)) } else { val }
    };
    let grease_cipher = make_grease(grease_seed[2]);
    let grease_version = make_grease(grease_seed[3]);

    let mut exts = Vec::with_capacity(20);

    // 1. GREASE extension (Chrome always leads with one)
    exts.push(ClientExtension::Unknown(UnknownExtension {
        typ: ExtensionType::Unknown(grease_ext_type),
        payload: Payload::new(vec![0x00]),
    }));

    // 2. server_name (0x0000)
    if let (Some(sni_name), true) = (server_name.for_sni(), config.enable_sni) {
        exts.push(ClientExtension::make_sni(sni_name));
    }

    // 3. extended_master_secret (0x0017)
    exts.push(ClientExtension::ExtendedMasterSecretRequest);

    // 4. renegotiation_info (0xff01) — Chrome sends empty renegotiation_info
    {
        // renegotiation_info: length=1, renegotiated_connection=empty (0x00)
        exts.push(ClientExtension::Unknown(UnknownExtension {
            typ: ExtensionType::RenegotiationInfo,
            payload: Payload::new(vec![0x00]),
        }));
    }

    // 5. supported_groups / named_groups (0x000a)
    exts.push(ClientExtension::NamedGroups(
        config
            .kx_groups
            .iter()
            .map(|skxg| skxg.name)
            .collect(),
    ));

    // 6. ec_point_formats (0x000b)
    exts.push(ClientExtension::ECPointFormats(ECPointFormatList::supported()));

    // 7. session_ticket (0x0023) — placed here in Chrome's order
    // (PSK/ticket content filled at the end, but the extension position matters)
    // We'll collect the ticket extension separately and insert here.
    let has_ticket_ext = config.enable_tickets;

    // 8. application_layer_protocol_negotiation (0x0010)
    if !config.alpn_protocols.is_empty() {
        exts.push(ClientExtension::Protocols(ProtocolNameList::from_slices(
            &config
                .alpn_protocols
                .iter()
                .map(|proto| &proto[..])
                .collect::<Vec<_>>(),
        )));
    }

    // 9. status_request / OCSP (0x0005)
    exts.push(ClientExtension::CertificateStatusRequest(CertificateStatusRequest::build_ocsp()));

    // 10. signature_algorithms (0x000d) — Chrome order
    // Chrome 131 signature_algorithms:
    //   ecdsa_secp256r1_sha256 (0x0403), rsa_pss_rsae_sha256 (0x0804),
    //   rsa_pkcs1_sha256 (0x0401), ecdsa_secp384r1_sha384 (0x0503),
    //   rsa_pss_rsae_sha384 (0x0805), rsa_pkcs1_sha384 (0x0501),
    //   rsa_pss_rsae_sha512 (0x0806), rsa_pkcs1_sha512 (0x0601)
    {
        use crate::enums::SignatureScheme;
        let chrome_sigalgs = vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,    // 0x0403
            SignatureScheme::RSA_PSS_SHA256,            // 0x0804
            SignatureScheme::RSA_PKCS1_SHA256,          // 0x0401
            SignatureScheme::ECDSA_NISTP384_SHA384,    // 0x0503
            SignatureScheme::RSA_PSS_SHA384,            // 0x0805
            SignatureScheme::RSA_PKCS1_SHA384,          // 0x0501
            SignatureScheme::RSA_PSS_SHA512,            // 0x0806
            SignatureScheme::RSA_PKCS1_SHA512,          // 0x0601
        ];
        exts.push(ClientExtension::SignatureAlgorithms(chrome_sigalgs));
    }

    // 11. signed_certificate_timestamp (0x0012)
    if may_send_sct_list {
        exts.push(ClientExtension::SignedCertificateTimestampRequest);
    }

    // 12. key_share (0x0033)
    if let Some(key_share_ref) = &key_share {
        debug_assert!(support_tls13);
        let ks_entry = KeyShareEntry::new(key_share_ref.group(), key_share_ref.pubkey.as_ref());
        exts.push(ClientExtension::KeyShare(vec![ks_entry]));
    }

    // 13. psk_key_exchange_modes (0x002d)
    if support_tls13 && config.enable_tickets {
        let psk_modes = vec![PSKKeyExchangeMode::PSK_DHE_KE];
        exts.push(ClientExtension::PresharedKeyModes(psk_modes));
    }

    // 14. supported_versions (0x002b) — with GREASE version prepended
    {
        let mut sv = Vec::with_capacity(supported_versions.len() + 1);
        // Chrome prepends a GREASE version
        sv.push(ProtocolVersion::Unknown(grease_version));
        sv.extend_from_slice(&supported_versions);
        exts.push(ClientExtension::SupportedVersions(sv));
    }

    // 15. compress_certificate (0x001b) — Chrome supports brotli (0x0002)
    {
        // Extension data: algorithms list length (u8) + algorithm (u16)
        // Chrome: length=2 (1 algorithm), algorithm=0x0002 (brotli)
        let mut data = Vec::new();
        // CertificateCompressionAlgorithms: u8-length-prefixed list of u16
        data.push(0x02); // length = 2 bytes (one u16 algorithm)
        data.push(0x00); // brotli high byte
        data.push(0x02); // brotli low byte
        exts.push(ClientExtension::Unknown(UnknownExtension {
            typ: ExtensionType::Unknown(0x001b),
            payload: Payload::new(data),
        }));
    }

    // Cookie (only on HelloRetryRequest)
    if let Some(cookie) = retryreq.and_then(HelloRetryRequest::get_cookie) {
        exts.push(ClientExtension::Cookie(cookie.clone()));
    }

    // Extra extensions from caller (before GREASE2 and padding)
    exts.extend(extra_exts.iter().cloned());

    // 16. Second GREASE extension (Chrome puts another near the end)
    exts.push(ClientExtension::Unknown(UnknownExtension {
        typ: ExtensionType::Unknown(grease_ext_type2),
        payload: Payload::new(vec![]),
    }));

    // --- Session ticket / PSK handling ---
    // Insert session_ticket at position 7 (after ec_point_formats, before ALPN)
    // and handle PSK (must be last).
    let fill_in_binder = if support_tls13
        && config.enable_tickets
        && resume_version == ProtocolVersion::TLSv1_3
        && !ticket.is_empty()
    {
        // For TLS 1.3 resumption, session_ticket is not used; PSK is added instead.
        resuming_session
            .as_ref()
            .and_then(|resuming| match (suite, resuming.tls13()) {
                (Some(suite), Some(resuming)) => {
                    suite
                        .tls13()?
                        .can_resume_from(resuming.suite())?;
                    Some(resuming)
                }
                (None, Some(resuming)) => Some(resuming),
                _ => None,
            })
            .map(|resuming| {
                tls13::prepare_resumption(
                    &config,
                    cx,
                    ticket,
                    &resuming,
                    &mut exts,
                    retryreq.is_some(),
                );
                resuming
            })
    } else if has_ticket_ext {
        // Insert session_ticket at the Chrome position (index 7, after ec_point_formats)
        // Find the position after ECPointFormats
        let ticket_ext = if ticket.is_empty() {
            ClientExtension::SessionTicket(ClientSessionTicket::Request)
        } else {
            ClientExtension::SessionTicket(ClientSessionTicket::Offer(Payload::new(ticket)))
        };
        // Find ECPointFormats index and insert after it
        if let Some(pos) = exts.iter().position(|e| matches!(e.get_type(), ExtensionType::ECPointFormats)) {
            exts.insert(pos + 1, ticket_ext);
        } else {
            exts.push(ticket_ext);
        }
        None
    } else {
        None
    };

    // Note what extensions we sent.
    hello.sent_extensions = exts
        .iter()
        .map(ClientExtension::get_type)
        .collect();

    let mut session_id = session_id.unwrap_or_else(SessionID::empty);

    // Chrome cipher suite order: GREASE + real suites + SCSV
    let mut cipher_suites: Vec<CipherSuite> = Vec::with_capacity(config.cipher_suites.len() + 2);
    // Prepend GREASE cipher suite
    cipher_suites.push(CipherSuite::Unknown(grease_cipher));
    cipher_suites.extend(config.cipher_suites.iter().map(|cs| cs.suite()));
    // Append SCSV
    cipher_suites.push(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

    // --- Padding extension (0x0015) ---
    // Chrome pads ClientHello to a multiple of 512 bytes (or to avoid
    // 256-511 byte range which some middleboxes handle poorly).
    // We compute the size without padding, then add padding to reach 512.
    {
        // Build a temporary CHPayload to measure size
        let tmp_chp = ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random,
            session_id,
            cipher_suites: cipher_suites.clone(),
            compression_methods: vec![Compression::Null],
            extensions: exts.clone(),
        };
        let mut tmp_bytes = Vec::new();
        tmp_chp.encode(&mut tmp_bytes);
        // Total ClientHello message = 4 (handshake header) + payload
        // Total TLS record = 5 (record header) + 4 (handshake header) + payload
        let total_len = 4 + tmp_bytes.len();
        // Chrome targets: if 0 < total_len < 256, pad to 512
        //                 if 256 <= total_len < 512, pad to 512
        //                 otherwise no padding needed
        // Actually Chrome pads to multiple of 512 when ClientHello < 512
        // The padding extension itself has 4 bytes overhead (type u16 + length u16)
        if total_len < 512 {
            let pad_needed = 512 - total_len - 4; // 4 = extension header overhead
            let pad_data = vec![0u8; pad_needed.max(0)];
            // Insert padding before the last extension (which might be PSK or GREASE2)
            // Chrome puts padding as the second-to-last non-PSK extension
            let pad_ext = ClientExtension::Unknown(UnknownExtension {
                typ: ExtensionType::Padding,
                payload: Payload::new(pad_data),
            });
            // Insert before the last element (PSK must stay last if present)
            let has_psk = exts.last().map_or(false, |e| matches!(e.get_type(), ExtensionType::PreSharedKey));
            if has_psk {
                let pos = exts.len() - 1;
                exts.insert(pos, pad_ext);
            } else {
                exts.push(pad_ext);
            }
        }
    }

    let mut chp = HandshakeMessagePayload {
        typ: HandshakeType::ClientHello,
        payload: HandshakePayload::ClientHello(ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random,
            session_id,
            cipher_suites,
            compression_methods: vec![Compression::Null],
            extensions: exts,
        }),
    };

    let early_key_schedule = if let Some(resuming) = fill_in_binder {
        let schedule = tls13::fill_in_psk_binder(&resuming, &transcript_buffer, &mut chp);
        Some((resuming.suite(), schedule))
    } else {
        None
    };

    // hack: sign chp and overwrite session id
    if use_session_id_generator {
        let mut buffer = Vec::new();
        match &mut chp.payload {
            HandshakePayload::ClientHello(c) => {
                c.session_id = SessionID::zero();
            }
            _ => unreachable!(),
        }
        chp.encode(&mut buffer);
        session_id = SessionID {
            len: 32,
            data: session_id_generator(&buffer),
        };
        match &mut chp.payload {
            HandshakePayload::ClientHello(c) => {
                c.session_id = session_id;
            }
            _ => unreachable!(),
        }
    }

    let ch = Message {
        // "This value MUST be set to 0x0303 for all records generated
        //  by a TLS 1.3 implementation other than an initial ClientHello
        //  (i.e., one not generated after a HelloRetryRequest)"
        version: if retryreq.is_some() {
            ProtocolVersion::TLSv1_2
        } else {
            ProtocolVersion::TLSv1_0
        },
        payload: MessagePayload::handshake(chp),
    };

    if retryreq.is_some() {
        // send dummy CCS to fool middleboxes prior
        // to second client hello
        tls13::emit_fake_ccs(&mut sent_tls13_fake_ccs, cx.common);
    }

    trace!("Sending ClientHello {:#?}", ch);

    transcript_buffer.add_message(&ch);
    cx.common.send_msg(ch, false);

    // Calculate the hash of ClientHello and use it to derive EarlyTrafficSecret
    let early_key_schedule = early_key_schedule.map(|(resuming_suite, schedule)| {
        if !cx.data.early_data.is_enabled() {
            return schedule;
        }

        tls13::derive_early_traffic_secret(
            &*config.key_log,
            cx,
            resuming_suite,
            &schedule,
            &mut sent_tls13_fake_ccs,
            &transcript_buffer,
            &random.0,
        );
        schedule
    });

    let next = ExpectServerHello {
        config,
        resuming_session,
        server_name,
        random,
        using_ems,
        transcript_buffer,
        early_key_schedule,
        hello,
        offered_key_share: key_share,
        session_id,
        sent_tls13_fake_ccs,
        suite,
    };

    if support_tls13 && retryreq.is_none() {
        Box::new(ExpectServerHelloOrHelloRetryRequest { next, extra_exts })
    } else {
        Box::new(next)
    }
}

pub(super) fn process_alpn_protocol(
    common: &mut CommonState,
    config: &ClientConfig,
    proto: Option<&[u8]>,
) -> Result<(), Error> {
    common.alpn_protocol = proto.map(ToOwned::to_owned);

    if let Some(alpn_protocol) = &common.alpn_protocol {
        if !config
            .alpn_protocols
            .contains(alpn_protocol)
        {
            return Err(common.illegal_param("server sent non-offered ALPN protocol"));
        }
    }

    #[cfg(feature = "quic")]
    {
        // RFC 9001 says: "While ALPN only specifies that servers use this alert, QUIC clients MUST
        // use error 0x0178 to terminate a connection when ALPN negotiation fails." We judge that
        // the user intended to use ALPN (rather than some out-of-band protocol negotiation
        // mechanism) iff any ALPN protocols were configured. This defends against badly-behaved
        // servers which accept a connection that requires an application-layer protocol they do not
        // understand.
        if common.is_quic() && common.alpn_protocol.is_none() && !config.alpn_protocols.is_empty() {
            common.send_fatal_alert(AlertDescription::NoApplicationProtocol);
            return Err(Error::NoApplicationProtocol);
        }
    }

    debug!(
        "ALPN protocol is {:?}",
        common
            .alpn_protocol
            .as_ref()
            .map(|v| bs_debug::BsDebug(v))
    );
    Ok(())
}

pub(super) fn sct_list_is_invalid(scts: &SCTList) -> bool {
    scts.is_empty() || scts.iter().any(|sct| sct.0.is_empty())
}

impl State<ClientConnectionData> for ExpectServerHello {
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> NextStateOrError {
        let server_hello =
            require_handshake_msg!(m, HandshakeType::ServerHello, HandshakePayload::ServerHello)?;
        trace!("We got ServerHello {:#?}", server_hello);

        use crate::ProtocolVersion::{TLSv1_2, TLSv1_3};
        let tls13_supported = self.config.supports_version(TLSv1_3);

        let server_version = if server_hello.legacy_version == TLSv1_2 {
            server_hello
                .get_supported_versions()
                .unwrap_or(server_hello.legacy_version)
        } else {
            server_hello.legacy_version
        };

        let version = match server_version {
            TLSv1_3 if tls13_supported => TLSv1_3,
            TLSv1_2 if self.config.supports_version(TLSv1_2) => {
                if cx.data.early_data.is_enabled() && cx.common.early_traffic {
                    // The client must fail with a dedicated error code if the server
                    // responds with TLS 1.2 when offering 0-RTT.
                    return Err(Error::PeerMisbehavedError(
                        "server chose v1.2 when offering 0-rtt".to_string(),
                    ));
                }

                if server_hello
                    .get_supported_versions()
                    .is_some()
                {
                    return Err(cx
                        .common
                        .illegal_param("server chose v1.2 using v1.3 extension"));
                }

                TLSv1_2
            }
            _ => {
                cx.common
                    .send_fatal_alert(AlertDescription::ProtocolVersion);
                let msg = match server_version {
                    TLSv1_2 | TLSv1_3 => "server's TLS version is disabled in client",
                    _ => "server does not support TLS v1.2/v1.3",
                };
                return Err(Error::PeerIncompatibleError(msg.to_string()));
            }
        };

        if server_hello.compression_method != Compression::Null {
            return Err(cx
                .common
                .illegal_param("server chose non-Null compression"));
        }

        if server_hello.has_duplicate_extension() {
            cx.common
                .send_fatal_alert(AlertDescription::DecodeError);
            return Err(Error::PeerMisbehavedError(
                "server sent duplicate extensions".to_string(),
            ));
        }

        let allowed_unsolicited = [ExtensionType::RenegotiationInfo];
        if self
            .hello
            .server_sent_unsolicited_extensions(&server_hello.extensions, &allowed_unsolicited)
        {
            cx.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(Error::PeerMisbehavedError(
                "server sent unsolicited extension".to_string(),
            ));
        }

        cx.common.negotiated_version = Some(version);

        // Extract ALPN protocol
        if !cx.common.is_tls13() {
            process_alpn_protocol(cx.common, &self.config, server_hello.get_alpn_protocol())?;
        }

        // If ECPointFormats extension is supplied by the server, it must contain
        // Uncompressed.  But it's allowed to be omitted.
        if let Some(point_fmts) = server_hello.get_ecpoints_extension() {
            if !point_fmts.contains(&ECPointFormat::Uncompressed) {
                cx.common
                    .send_fatal_alert(AlertDescription::HandshakeFailure);
                return Err(Error::PeerMisbehavedError(
                    "server does not support uncompressed points".to_string(),
                ));
            }
        }

        let suite = self
            .config
            .find_cipher_suite(server_hello.cipher_suite)
            .ok_or_else(|| {
                cx.common
                    .send_fatal_alert(AlertDescription::HandshakeFailure);
                Error::PeerMisbehavedError("server chose non-offered ciphersuite".to_string())
            })?;

        if version != suite.version().version {
            return Err(cx
                .common
                .illegal_param("server chose unusable ciphersuite for version"));
        }

        match self.suite {
            Some(prev_suite) if prev_suite != suite => {
                return Err(cx
                    .common
                    .illegal_param("server varied selected ciphersuite"));
            }
            _ => {
                debug!("Using ciphersuite {:?}", suite);
                self.suite = Some(suite);
                cx.common.suite = Some(suite);
            }
        }

        // Start our handshake hash, and input the server-hello.
        let mut transcript = self
            .transcript_buffer
            .start_hash(suite.hash_algorithm());
        transcript.add_message(&m);

        let randoms = ConnectionRandoms::new(self.random, server_hello.random);
        // For TLS1.3, start message encryption using
        // handshake_traffic_secret.
        match suite {
            SupportedCipherSuite::Tls13(suite) => {
                let resuming_session = self
                    .resuming_session
                    .and_then(|resuming| match resuming.value {
                        persist::ClientSessionValue::Tls13(inner) => Some(inner),
                        #[cfg(feature = "tls12")]
                        persist::ClientSessionValue::Tls12(_) => None,
                    });

                tls13::handle_server_hello(
                    self.config,
                    cx,
                    server_hello,
                    resuming_session,
                    self.server_name,
                    randoms,
                    suite,
                    transcript,
                    self.early_key_schedule,
                    self.hello,
                    // We always send a key share when TLS 1.3 is enabled.
                    self.offered_key_share.unwrap(),
                    self.sent_tls13_fake_ccs,
                )
            }
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(suite) => {
                let resuming_session = self
                    .resuming_session
                    .and_then(|resuming| match resuming.value {
                        persist::ClientSessionValue::Tls12(inner) => Some(inner),
                        persist::ClientSessionValue::Tls13(_) => None,
                    });

                tls12::CompleteServerHelloHandling {
                    config: self.config,
                    resuming_session,
                    server_name: self.server_name,
                    randoms,
                    using_ems: self.using_ems,
                    transcript,
                }
                .handle_server_hello(cx, suite, server_hello, tls13_supported)
            }
        }
    }
}

impl ExpectServerHelloOrHelloRetryRequest {
    fn into_expect_server_hello(self) -> NextState {
        Box::new(self.next)
    }

    fn handle_hello_retry_request(
        self,
        cx: &mut ClientContext<'_>,
        m: Message,
    ) -> NextStateOrError {
        let hrr = require_handshake_msg!(
            m,
            HandshakeType::HelloRetryRequest,
            HandshakePayload::HelloRetryRequest
        )?;
        trace!("Got HRR {:?}", hrr);

        cx.common.check_aligned_handshake()?;

        let cookie = hrr.get_cookie();
        let req_group = hrr.get_requested_key_share_group();

        // We always send a key share when TLS 1.3 is enabled.
        let offered_key_share = self.next.offered_key_share.unwrap();

        // A retry request is illegal if it contains no cookie and asks for
        // retry of a group we already sent.
        if cookie.is_none() && req_group == Some(offered_key_share.group()) {
            return Err(cx
                .common
                .illegal_param("server requested hrr with our group"));
        }

        // Or has an empty cookie.
        if let Some(cookie) = cookie {
            if cookie.0.is_empty() {
                return Err(cx
                    .common
                    .illegal_param("server requested hrr with empty cookie"));
            }
        }

        // Or has something unrecognised
        if hrr.has_unknown_extension() {
            cx.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(Error::PeerIncompatibleError(
                "server sent hrr with unhandled extension".to_string(),
            ));
        }

        // Or has the same extensions more than once
        if hrr.has_duplicate_extension() {
            return Err(cx
                .common
                .illegal_param("server send duplicate hrr extensions"));
        }

        // Or asks us to change nothing.
        if cookie.is_none() && req_group.is_none() {
            return Err(cx
                .common
                .illegal_param("server requested hrr with no changes"));
        }

        // Or asks us to talk a protocol we didn't offer, or doesn't support HRR at all.
        match hrr.get_supported_versions() {
            Some(ProtocolVersion::TLSv1_3) => {
                cx.common.negotiated_version = Some(ProtocolVersion::TLSv1_3);
            }
            _ => {
                return Err(cx
                    .common
                    .illegal_param("server requested unsupported version in hrr"));
            }
        }

        // Or asks us to use a ciphersuite we didn't offer.
        let maybe_cs = self
            .next
            .config
            .find_cipher_suite(hrr.cipher_suite);
        let cs = match maybe_cs {
            Some(cs) => cs,
            None => {
                return Err(cx
                    .common
                    .illegal_param("server requested unsupported cs in hrr"));
            }
        };

        // HRR selects the ciphersuite.
        cx.common.suite = Some(cs);

        // This is the draft19 change where the transcript became a tree
        let transcript = self
            .next
            .transcript_buffer
            .start_hash(cs.hash_algorithm());
        let mut transcript_buffer = transcript.into_hrr_buffer();
        transcript_buffer.add_message(&m);

        // Early data is not allowed after HelloRetryrequest
        if cx.data.early_data.is_enabled() {
            cx.data.early_data.rejected();
        }

        let may_send_sct_list = self
            .next
            .hello
            .server_may_send_sct_list();

        let key_share = match req_group {
            Some(group) if group != offered_key_share.group() => {
                let group = kx::KeyExchange::choose(group, &self.next.config.kx_groups)
                    .ok_or_else(|| {
                        cx.common
                            .illegal_param("server requested hrr with bad group")
                    })?;
                kx::KeyExchange::start(group).ok_or(Error::FailedToGetRandomBytes)?
            }
            _ => offered_key_share,
        };

        let session_id = self.next.session_id.data;
        Ok(emit_client_hello_for_retry(
            self.next.config,
            cx,
            self.next.resuming_session,
            self.next.random,
            self.next.using_ems,
            transcript_buffer,
            self.next.sent_tls13_fake_ccs,
            self.next.hello,
            Some(self.next.session_id),
            false,
            move |_| session_id,
            Some(hrr),
            self.next.server_name,
            Some(key_share),
            self.extra_exts,
            may_send_sct_list,
            Some(cs),
        ))
    }
}

impl State<ClientConnectionData> for ExpectServerHelloOrHelloRetryRequest {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> NextStateOrError {
        match m.payload {
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        payload: HandshakePayload::ServerHello(..),
                        ..
                    },
                ..
            } => self
                .into_expect_server_hello()
                .handle(cx, m),
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        payload: HandshakePayload::HelloRetryRequest(..),
                        ..
                    },
                ..
            } => self.handle_hello_retry_request(cx, m),
            payload => Err(inappropriate_handshake_message(
                &payload,
                &[ContentType::Handshake],
                &[HandshakeType::ServerHello, HandshakeType::HelloRetryRequest],
            )),
        }
    }
}

pub(super) fn send_cert_error_alert(common: &mut CommonState, err: Error) -> Error {
    match err {
        Error::InvalidCertificateEncoding => {
            common.send_fatal_alert(AlertDescription::DecodeError);
        }
        Error::PeerMisbehavedError(_) => {
            common.send_fatal_alert(AlertDescription::IllegalParameter);
        }
        _ => {
            common.send_fatal_alert(AlertDescription::BadCertificate);
        }
    };

    err
}
