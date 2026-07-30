use clap::App;
use hbb_common::{
    allow_err,
    anyhow::{Context, Result},
    bytes::Bytes,
    get_version_number, log,
    rendezvous_proto::OnGrowDeviceAttestation,
    sha2::{Digest, Sha256},
    tokio, ResultType,
};
use ini::Ini;
use sodiumoxide::crypto::sign;
use std::{
    io::prelude::*,
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Instant, SystemTime},
};

pub fn parse_bind_address(value: &str) -> Result<Option<IpAddr>> {
    let value = value.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        value
            .parse()
            .with_context(|| format!("Invalid bind address: {value}"))
            .map(Some)
    }
}

pub async fn listen_tcp(
    bind_addr: Option<IpAddr>,
    port: u16,
) -> ResultType<hbb_common::tokio::net::TcpListener> {
    if let Some(bind_addr) = bind_addr {
        hbb_common::tcp::new_listener(SocketAddr::new(bind_addr, port), true).await
    } else {
        hbb_common::tcp::listen_any(port).await
    }
}

pub fn console_addr(bind_addr: Option<IpAddr>, port: u16) -> Option<SocketAddr> {
    let bind_addr = bind_addr?;
    if bind_addr.is_unspecified() || bind_addr == IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return None;
    }
    Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
}

// The runtime console (check_cmd) is reached via 127.0.0.1, so when the bind
// address does not already accept connections to 127.0.0.1 (it is neither the
// any-address nor 127.0.0.1 itself), the console gets a dedicated listener
// there; it is never bound to the external bind address.
pub async fn listen_console(
    bind_addr: Option<IpAddr>,
    port: u16,
) -> ResultType<Option<hbb_common::tokio::net::TcpListener>> {
    match console_addr(bind_addr, port) {
        Some(addr) => {
            let listener = hbb_common::tcp::new_listener(addr, true).await?;
            log::info!("Listening on tcp {} for the console", addr);
            Ok(Some(listener))
        }
        None => Ok(None),
    }
}

pub async fn accept_or_pending(
    listener: Option<&hbb_common::tokio::net::TcpListener>,
) -> std::io::Result<(hbb_common::tokio::net::TcpStream, SocketAddr)> {
    match listener {
        Some(listener) => listener.accept().await,
        None => std::future::pending().await,
    }
}

const ONGROW_CUSTOM_ID_PROOF_CONTEXT_V1: &[u8] = b"ongrow-rustdesk-custom-id-v1";
const ONGROW_CUSTOM_ID_PROOF_CONTEXT_V2: &[u8] = b"ongrow-rustdesk-custom-id-v2";
const ONGROW_DEVICE_ATTESTATION_CONTEXT: &[u8] =
    b"ongrow-rustdesk-device-attestation-v1";
pub(crate) const ONGROW_ATTESTATION_NONCE_BYTES: usize = 32;
const ONGROW_ATTESTATION_VALIDITY_SECONDS: i64 = 300;

pub(crate) fn is_valid_ongrow_custom_id(id: &str) -> bool {
    id.len() == 7
        && id.starts_with("OG-")
        && id.as_bytes()[3..].iter().all(u8::is_ascii_digit)
}

fn ongrow_custom_id_proof_payload(old_id: &str, new_id: &str, uuid: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        ONGROW_CUSTOM_ID_PROOF_CONTEXT_V1.len() + old_id.len() + new_id.len() + uuid.len() + 12,
    );
    payload.extend_from_slice(ONGROW_CUSTOM_ID_PROOF_CONTEXT_V1);
    for field in [old_id.as_bytes(), new_id.as_bytes(), uuid] {
        append_ongrow_field(&mut payload, field);
    }
    payload
}

fn ongrow_custom_id_proof_payload_v2(
    old_id: &str,
    new_id: &str,
    uuid: &[u8],
    nonce: &[u8],
) -> Option<Vec<u8>> {
    if nonce.len() != ONGROW_ATTESTATION_NONCE_BYTES {
        return None;
    }
    let mut payload = Vec::with_capacity(
        ONGROW_CUSTOM_ID_PROOF_CONTEXT_V2.len()
            + old_id.len()
            + new_id.len()
            + uuid.len()
            + nonce.len()
            + 16,
    );
    payload.extend_from_slice(ONGROW_CUSTOM_ID_PROOF_CONTEXT_V2);
    for field in [old_id.as_bytes(), new_id.as_bytes(), uuid, nonce] {
        append_ongrow_field(&mut payload, field);
    }
    Some(payload)
}

fn append_ongrow_field(payload: &mut Vec<u8>, field: &[u8]) {
    payload.extend_from_slice(&(field.len() as u32).to_be_bytes());
    payload.extend_from_slice(field);
}

pub(crate) fn verify_ongrow_custom_id_proof(
    old_id: &str,
    new_id: &str,
    uuid: &[u8],
    proof: &[u8],
    public_key: &[u8],
) -> bool {
    if public_key.len() != sign::PUBLICKEYBYTES {
        return false;
    }
    let mut public_key_bytes = [0; sign::PUBLICKEYBYTES];
    public_key_bytes.copy_from_slice(public_key);
    sign::verify(proof, &sign::PublicKey(public_key_bytes))
        .map(|signed_payload| {
            signed_payload == ongrow_custom_id_proof_payload(old_id, new_id, uuid)
        })
        .unwrap_or(false)
}

pub(crate) fn verify_ongrow_custom_id_proof_v2(
    old_id: &str,
    new_id: &str,
    uuid: &[u8],
    nonce: &[u8],
    proof: &[u8],
    public_key: &[u8],
) -> bool {
    if public_key.len() != sign::PUBLICKEYBYTES {
        return false;
    }
    let Some(expected_payload) =
        ongrow_custom_id_proof_payload_v2(old_id, new_id, uuid, nonce)
    else {
        return false;
    };
    let mut public_key_bytes = [0; sign::PUBLICKEYBYTES];
    public_key_bytes.copy_from_slice(public_key);
    sign::verify(proof, &sign::PublicKey(public_key_bytes))
        .map(|signed_payload| signed_payload == expected_payload)
        .unwrap_or(false)
}

pub(crate) fn hash_ongrow_device_uuid(uuid: &[u8]) -> Bytes {
    Bytes::from(Sha256::digest(uuid).to_vec())
}

pub(crate) fn ongrow_device_attestation_payload(
    id: &str,
    device_pk: &[u8],
    uuid_sha256: &[u8],
    issued_at: i64,
    expires_at: i64,
    nonce: &[u8],
) -> Option<Vec<u8>> {
    if !is_valid_ongrow_custom_id(id)
        || device_pk.len() != sign::PUBLICKEYBYTES
        || uuid_sha256.len() != 32
        || nonce.len() != ONGROW_ATTESTATION_NONCE_BYTES
    {
        return None;
    }
    let issued_at_bytes = issued_at.to_be_bytes();
    let expires_at_bytes = expires_at.to_be_bytes();
    let mut payload = Vec::with_capacity(
        ONGROW_DEVICE_ATTESTATION_CONTEXT.len()
            + id.len()
            + device_pk.len()
            + uuid_sha256.len()
            + nonce.len()
            + 6 * 4
            + 16,
    );
    payload.extend_from_slice(ONGROW_DEVICE_ATTESTATION_CONTEXT);
    for field in [
        id.as_bytes(),
        device_pk,
        uuid_sha256,
        issued_at_bytes.as_slice(),
        expires_at_bytes.as_slice(),
        nonce,
    ] {
        append_ongrow_field(&mut payload, field);
    }
    Some(payload)
}

pub(crate) fn issue_ongrow_device_attestation(
    id: &str,
    device_pk: &[u8],
    uuid: &[u8],
    nonce: &[u8],
    issued_at: i64,
    secret_key: &sign::SecretKey,
) -> Option<OnGrowDeviceAttestation> {
    let expires_at = issued_at.checked_add(ONGROW_ATTESTATION_VALIDITY_SECONDS)?;
    let uuid_sha256 = hash_ongrow_device_uuid(uuid);
    let payload = ongrow_device_attestation_payload(
        id,
        device_pk,
        &uuid_sha256,
        issued_at,
        expires_at,
        nonce,
    )?;
    Some(OnGrowDeviceAttestation {
        id: id.to_owned(),
        device_pk: device_pk.to_vec().into(),
        uuid_sha256,
        issued_at,
        expires_at,
        nonce: nonce.to_vec().into(),
        signed_payload: sign::sign(&payload, secret_key).into(),
        ..Default::default()
    })
}

pub(crate) fn verify_ongrow_device_attestation(
    attestation: &OnGrowDeviceAttestation,
    server_public_key: &[u8],
) -> bool {
    if server_public_key.len() != sign::PUBLICKEYBYTES
        || attestation.expires_at.checked_sub(attestation.issued_at)
            != Some(ONGROW_ATTESTATION_VALIDITY_SECONDS)
    {
        return false;
    }
    let Some(expected_payload) = ongrow_device_attestation_payload(
        &attestation.id,
        &attestation.device_pk,
        &attestation.uuid_sha256,
        attestation.issued_at,
        attestation.expires_at,
        &attestation.nonce,
    ) else {
        return false;
    };
    let mut public_key_bytes = [0; sign::PUBLICKEYBYTES];
    public_key_bytes.copy_from_slice(server_public_key);
    sign::verify(
        &attestation.signed_payload,
        &sign::PublicKey(public_key_bytes),
    )
    .map(|payload| payload == expected_payload)
    .unwrap_or(false)
}

#[allow(dead_code)]
pub(crate) fn get_expired_time() -> Instant {
    let now = Instant::now();
    now.checked_sub(std::time::Duration::from_secs(3600))
        .unwrap_or(now)
}

#[cfg(test)]
mod ongrow_custom_id_tests {
    use super::*;

    #[test]
    fn accepts_only_ongrow_four_digit_ids() {
        assert!(is_valid_ongrow_custom_id("OG-0001"));
        assert!(is_valid_ongrow_custom_id("OG-9999"));
        assert!(!is_valid_ongrow_custom_id("og-0001"));
        assert!(!is_valid_ongrow_custom_id("OG-123"));
        assert!(!is_valid_ongrow_custom_id("OG-12345"));
        assert!(!is_valid_ongrow_custom_id("OG-12A4"));
    }

    #[test]
    fn verifies_proof_for_exact_change_only() {
        sodiumoxide::init().unwrap();
        let (public_key, secret_key) = sign::gen_keypair();
        let uuid = b"test-machine-uuid";
        let proof = sign::sign(
            &ongrow_custom_id_proof_payload("123456789", "OG-0001", uuid),
            &secret_key,
        );

        assert!(verify_ongrow_custom_id_proof(
            "123456789",
            "OG-0001",
            uuid,
            &proof,
            &public_key.0,
        ));
        assert!(!verify_ongrow_custom_id_proof(
            "123456789",
            "OG-0002",
            uuid,
            &proof,
            &public_key.0,
        ));
        assert!(!verify_ongrow_custom_id_proof(
            "987654321",
            "OG-0001",
            uuid,
            &proof,
            &public_key.0,
        ));
    }

    #[test]
    fn verifies_nonce_bound_v2_proof() {
        sodiumoxide::init().unwrap();
        let (public_key, secret_key) = sign::keypair_from_seed(&sign::Seed([7; 32]));
        let uuid = b"test-machine-uuid";
        let nonce = [9; ONGROW_ATTESTATION_NONCE_BYTES];
        let payload =
            ongrow_custom_id_proof_payload_v2("OG-0001", "OG-0001", uuid, &nonce).unwrap();
        let proof = sign::sign(&payload, &secret_key);

        assert!(verify_ongrow_custom_id_proof_v2(
            "OG-0001",
            "OG-0001",
            uuid,
            &nonce,
            &proof,
            &public_key.0,
        ));
        let mut changed_nonce = nonce;
        changed_nonce[0] ^= 1;
        assert!(!verify_ongrow_custom_id_proof_v2(
            "OG-0001",
            "OG-0001",
            uuid,
            &changed_nonce,
            &proof,
            &public_key.0,
        ));
        assert!(!verify_ongrow_custom_id_proof_v2(
            "OG-0001",
            "OG-0002",
            uuid,
            &nonce,
            &proof,
            &public_key.0,
        ));
        assert!(!verify_ongrow_custom_id_proof_v2(
            "OG-0001",
            "OG-0001",
            b"different-machine-uuid",
            &nonce,
            &proof,
            &public_key.0,
        ));
        let (different_public_key, _) =
            sign::keypair_from_seed(&sign::Seed([8; 32]));
        assert!(!verify_ongrow_custom_id_proof_v2(
            "OG-0001",
            "OG-0001",
            uuid,
            &nonce,
            &proof,
            &different_public_key.0,
        ));
        assert!(!verify_ongrow_custom_id_proof_v2(
            "OG-0001",
            "OG-0001",
            uuid,
            &nonce[..31],
            &proof,
            &public_key.0,
        ));
    }

    #[test]
    fn issues_and_verifies_short_lived_device_attestation() {
        sodiumoxide::init().unwrap();
        let (server_public_key, server_secret_key) =
            sign::keypair_from_seed(&sign::Seed([11; 32]));
        let (device_public_key, _) = sign::keypair_from_seed(&sign::Seed([7; 32]));
        let uuid = b"raw-test-machine-uuid";
        let nonce = [9; ONGROW_ATTESTATION_NONCE_BYTES];
        let attestation = issue_ongrow_device_attestation(
            "OG-0001",
            &device_public_key.0,
            uuid,
            &nonce,
            1_722_345_600,
            &server_secret_key,
        )
        .unwrap();

        assert_eq!(attestation.expires_at - attestation.issued_at, 300);
        assert_eq!(attestation.uuid_sha256, hash_ongrow_device_uuid(uuid));
        assert_ne!(attestation.uuid_sha256.as_ref(), uuid);
        assert!(verify_ongrow_device_attestation(
            &attestation,
            &server_public_key.0,
        ));

        let mut changed = attestation.clone();
        changed.id = "OG-0002".to_owned();
        assert!(!verify_ongrow_device_attestation(
            &changed,
            &server_public_key.0,
        ));
    }

    #[test]
    fn attestation_payload_matches_cross_fork_test_vector() {
        let device_pk: Vec<u8> = (0..32).collect();
        let uuid_sha256 = hash_ongrow_device_uuid(b"raw-test-machine-uuid");
        let payload = ongrow_device_attestation_payload(
            "OG-0001",
            &device_pk,
            &uuid_sha256,
            1_722_345_600,
            1_722_345_900,
            &[9; ONGROW_ATTESTATION_NONCE_BYTES],
        )
        .unwrap();
        let actual: String = payload.iter().map(|byte| format!("{byte:02x}")).collect();

        assert_eq!(
            actual,
            "6f6e67726f772d727573746465736b2d6465766963652d6174746573746174696f6e2d7631000000074f472d3030303100000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000020c0d751187c93edea0572d744031fe1cf82b9a18fd8c9bd414bcdd0c1ea266116000000080000000066a8e880000000080000000066a8e9ac000000200909090909090909090909090909090909090909090909090909090909090909"
        );
    }
}

#[allow(dead_code)]
pub(crate) fn test_if_valid_server(host: &str, name: &str) -> ResultType<SocketAddr> {
    use std::net::ToSocketAddrs;
    let res = if host.contains(':') {
        host.to_socket_addrs()?.next().context("")
    } else {
        format!("{}:{}", host, 0)
            .to_socket_addrs()?
            .next()
            .context("")
    };
    if res.is_err() {
        log::error!("Invalid {} {}: {:?}", name, host, res);
    }
    res
}

#[allow(dead_code)]
pub(crate) fn get_servers(s: &str, tag: &str) -> Vec<String> {
    let servers: Vec<String> = s
        .split(',')
        .filter(|x| !x.is_empty() && test_if_valid_server(x, tag).is_ok())
        .map(|x| x.to_owned())
        .collect();
    log::info!("{}={:?}", tag, servers);
    servers
}

#[allow(dead_code)]
#[inline]
fn arg_name(name: &str) -> String {
    name.to_uppercase().replace('_', "-")
}

#[allow(dead_code)]
#[inline]
pub fn set_arg(name: &str, value: &str) {
    std::env::set_var(arg_name(name), value);
}

#[allow(dead_code)]
pub fn init_args(args: &str, name: &str, about: &str) {
    let matches = App::new(name)
        .version(crate::version::VERSION)
        .author("Purslane Ltd. <info@rustdesk.com>")
        .about(about)
        .args_from_usage(args)
        .get_matches();
    if let Ok(v) = Ini::load_from_file(".env") {
        if let Some(section) = v.section(None::<String>) {
            section
                .iter()
                .for_each(|(k, v)| set_arg(k, v));
        }
    }
    if let Some(config) = matches.value_of("config") {
        if let Ok(v) = Ini::load_from_file(config) {
            if let Some(section) = v.section(None::<String>) {
                section
                    .iter()
                    .for_each(|(k, v)| set_arg(k, v));
            }
        }
    }
    for (k, v) in matches.args {
        if let Some(v) = v.vals.first() {
            set_arg(k, &v.to_string_lossy());
        }
    }
}

#[allow(dead_code)]
pub fn get_arg_opt(name: &str) -> Option<String> {
    let dashed = arg_name(name);
    let underscored = dashed.replace('-', "_");
    let lower_dashed = dashed.to_lowercase();
    let lower_underscored = underscored.to_lowercase();
    for alias in [&dashed, &underscored, &lower_dashed, &lower_underscored] {
        if let Ok(value) = std::env::var(alias) {
            return Some(value);
        }
    }
    let mut aliases = std::env::vars_os()
        .filter_map(|(key, value)| {
            let key = key.into_string().ok()?;
            if arg_name(&key) == dashed {
                Some((key, value.into_string().ok()?))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    aliases.sort_by(|a, b| a.0.cmp(&b.0));
    aliases.into_iter().next().map(|(_, value)| value)
}

#[allow(dead_code)]
#[inline]
pub fn get_arg(name: &str) -> String {
    get_arg_or(name, "".to_owned())
}

#[allow(dead_code)]
#[inline]
pub fn get_arg_or(name: &str, default: String) -> String {
    get_arg_opt(name).unwrap_or(default)
}

#[allow(dead_code)]
#[inline]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|x| x.as_secs())
        .unwrap_or_default()
}

pub fn gen_sk(wait: u64) -> (String, Option<sign::SecretKey>) {
    let sk_file = "id_ed25519";
    if wait > 0 && !std::path::Path::new(sk_file).exists() {
        std::thread::sleep(std::time::Duration::from_millis(wait));
    }
    if let Ok(mut file) = std::fs::File::open(sk_file) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            let contents = contents.trim();
            let sk = base64::decode(contents).unwrap_or_default();
            if sk.len() == sign::SECRETKEYBYTES {
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                let pk = base64::encode(&tmp[sign::SECRETKEYBYTES / 2..]);
                log::info!("Private key comes from {}", sk_file);
                return (pk, Some(sign::SecretKey(tmp)));
            } else {
                // don't use log here, since it is async
                println!("Fatal error: malformed private key in {sk_file}.");
                std::process::exit(1);
            }
        }
    } else {
        let gen_func = || {
            let (tmp, sk) = sign::gen_keypair();
            (base64::encode(tmp), sk)
        };
        let (mut pk, mut sk) = gen_func();
        for _ in 0..300 {
            if !pk.contains('/') && !pk.contains(':') {
                break;
            }
            (pk, sk) = gen_func();
        }
        let pub_file = format!("{sk_file}.pub");
        if let Ok(mut f) = std::fs::File::create(&pub_file) {
            f.write_all(pk.as_bytes()).ok();
            if let Ok(mut f) = std::fs::File::create(sk_file) {
                let s = base64::encode(&sk);
                if f.write_all(s.as_bytes()).is_ok() {
                    log::info!("Private/public key written to {}/{}", sk_file, pub_file);
                    log::debug!("Public key: {}", pk);
                    return (pk, Some(sk));
                }
            }
        }
    }
    ("".to_owned(), None)
}

#[cfg(unix)]
pub async fn listen_signal() -> Result<()> {
    use hbb_common::tokio;
    use hbb_common::tokio::signal::unix::{signal, SignalKind};

    tokio::spawn(async {
        let mut s = signal(SignalKind::terminate())?;
        let terminate = s.recv();
        let mut s = signal(SignalKind::interrupt())?;
        let interrupt = s.recv();
        let mut s = signal(SignalKind::quit())?;
        let quit = s.recv();

        tokio::select! {
            _ = terminate => {
                log::info!("signal terminate");
            }
            _ = interrupt => {
                log::info!("signal interrupt");
            }
            _ = quit => {
                log::info!("signal quit");
            }
        }
        Ok(())
    })
    .await?
}

#[cfg(not(unix))]
pub async fn listen_signal() -> Result<()> {
    let () = std::future::pending().await;
    unreachable!();
}


pub fn check_software_update() {
    const ONE_DAY_IN_SECONDS: u64 = 60 * 60 * 24;
    std::thread::spawn(move || loop {
        std::thread::spawn(move || allow_err!(check_software_update_()));
        std::thread::sleep(std::time::Duration::from_secs(ONE_DAY_IN_SECONDS));
    });
}

#[tokio::main(flavor = "current_thread")]
async fn check_software_update_() -> hbb_common::ResultType<()> {
    let (request, url) = hbb_common::version_check_request(hbb_common::VER_TYPE_RUSTDESK_SERVER.to_string());
    let latest_release_response = reqwest::Client::builder().build()?
        .post(url)
        .json(&request)
        .send()
        .await?;

    let bytes = latest_release_response.bytes().await?;
    let resp: hbb_common::VersionCheckResponse = serde_json::from_slice(&bytes)?;
    let response_url = resp.url;
    let latest_release_version = response_url.rsplit('/').next().unwrap_or_default();
    if get_version_number(&latest_release_version) > get_version_number(crate::version::VERSION) {
       log::info!("new version is available: {}", latest_release_version);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn argument_names_ignore_case_and_separator() {
        let aliases = [
            "RUSTDESK-CONFIG-ALIAS-TEST",
            "RUSTDESK_CONFIG_ALIAS_TEST",
            "rustdesk-config-alias-test",
            "rustdesk_config_alias_test",
            "RustDesk_Config-Alias_Test",
        ];
        for alias in aliases {
            std::env::remove_var(alias);
        }
        for alias in aliases {
            std::env::set_var(alias, alias);
            assert_eq!(get_arg("RUSTDESK_CONFIG_ALIAS_TEST"), alias);
            std::env::remove_var(alias);
        }
        set_arg("rustdesk_config_alias_test", "normalized");
        assert_eq!(
            std::env::var("RUSTDESK-CONFIG-ALIAS-TEST").unwrap(),
            "normalized"
        );
        std::env::set_var("RUSTDESK_CONFIG_ALIAS_TEST", "inherited");
        set_arg("rustdesk-config-alias-test", "higher-priority");
        assert_eq!(get_arg("rustdesk_config_alias_test"), "higher-priority");
        std::env::remove_var("RUSTDESK-CONFIG-ALIAS-TEST");
        std::env::remove_var("RUSTDESK_CONFIG_ALIAS_TEST");
    }

    #[test]
    fn parses_bind_address() {
        assert_eq!(parse_bind_address("").unwrap(), None);
        assert_eq!(
            parse_bind_address("127.0.0.1").unwrap(),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            parse_bind_address("::1").unwrap(),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert!(parse_bind_address("not-an-ip").is_err());
    }

    #[hbb_common::tokio::test]
    async fn tcp_listener_uses_bind_address() {
        let bind_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let listener = listen_tcp(Some(bind_addr), 0).await.unwrap();
        assert_eq!(listener.local_addr().unwrap().ip(), bind_addr);
    }

    #[test]
    fn console_addr_only_when_bind_does_not_cover_ipv4_localhost() {
        for bind_addr in [
            None,
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ] {
            assert_eq!(console_addr(bind_addr, 21117), None);
        }
        for bind_addr in [
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            Some("2001:db8::1".parse().unwrap()),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ] {
            assert_eq!(
                console_addr(bind_addr, 21117),
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 21117))
            );
        }
    }

    #[hbb_common::tokio::test]
    async fn console_listener_binds_ipv4_localhost() {
        let listener = listen_console(Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))), 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            listener.local_addr().unwrap().ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert!(listen_console(None, 0).await.unwrap().is_none());
        assert!(listen_console(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), 0)
            .await
            .unwrap()
            .is_none());
    }
}
