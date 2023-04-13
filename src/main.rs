use std::error::Error;

use base64::Engine;
use ring::signature::{self};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    Pss, RsaPrivateKey, RsaPublicKey, SignatureScheme,
};
use sha2::{Digest, Sha256};

use crate::pem::PemEncodedKey;

mod pem;

pub(crate) fn b64_encode(input: &[u8]) -> String {
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new().with_encode_padding(false),
    );
    engine.encode(input)
}

pub(crate) fn b64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone),
    );
    engine.decode(input)
}

fn sign_rsa(key: &RsaPrivateKey, message: &str) -> Result<String, ()> {
    let digest: Vec<u8> = {
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let d = hasher.finalize();
        d.as_slice().to_vec()
    };

    let signatures_scheme = Pss::new::<Sha256>();

    let mut rng = rand::thread_rng();

    let signature = signatures_scheme
        .sign(Some(&mut rng), key, &digest)
        .expect("failed to sign pss");

    Ok(b64_encode(&signature))
}

fn verify_rsa(
    signature: &str,
    message: &str,
    key: &RsaPublicKey,
) -> Result<bool, base64::DecodeError> {
    let digest: Vec<u8> = {
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let d = hasher.finalize();
        d.iter().copied().collect()
    };

    let signature_bytes = b64_decode(signature)?;

    let signatures_scheme = Pss::new::<Sha256>();

    signatures_scheme
        .verify(key, &digest, &signature_bytes)
        .expect("Invalid signature!");

    Ok(true)
}

fn sign_ring(key: &[u8], message: &str) -> Result<String, ()> {
    let key_pair = signature::RsaKeyPair::from_der(key).expect("Failed to parse private key");

    let mut signature = vec![0; key_pair.public_modulus_len()];
    let rng = ring::rand::SystemRandom::new();
    key_pair
        .sign(
            &signature::RSA_PSS_SHA256,
            &rng,
            message.as_bytes(),
            &mut signature,
        )
        .expect("Failed to sign");

    Ok(b64_encode(&signature))
}

fn verify_ring(signature: &str, message: &str, key: &[u8]) -> Result<bool, base64::DecodeError> {
    let public_key = signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, key);
    let signature_bytes = b64_decode(signature)?;
    let res = public_key.verify(message.as_bytes(), &signature_bytes);
    Ok(res.is_ok())
}

fn main() -> Result<(), Box<dyn Error>> {
    let privkey: rsa::RsaPrivateKey =
        RsaPrivateKey::from_pkcs8_pem(include_str!("private.pem")).unwrap();
    let pubkey: rsa::RsaPublicKey =
        RsaPublicKey::from_public_key_pem(include_str!("public.pem")).unwrap();

    let message = "this is a message to sign that is fairly long.";

    dbg!(message);

    let sig = sign_rsa(&privkey, message).unwrap();
    dbg!(&sig);
    let verified = verify_rsa(&sig, message, &pubkey).unwrap();
    dbg!(verified);

    let privkey_bytes = include_bytes!("private.pem");
    let pubkey_bytes = include_bytes!("public.pem");

    let privkey = PemEncodedKey::new(privkey_bytes);
    let pubkey = PemEncodedKey::new(pubkey_bytes);

    let message = "this is a message to sign that is fairly long.";

    dbg!(message);

    let sig = sign_ring(privkey.as_rsa_key(), message).unwrap();
    dbg!(&sig);
    let verified = verify_ring(&sig, message, pubkey.as_rsa_key()).unwrap();
    dbg!(verified);
    Ok(())
}

#[test]
fn rustcrypto_rsa_pss_rountrip_sig() {
    let privkey: rsa::RsaPrivateKey =
        RsaPrivateKey::from_pkcs8_pem(include_str!("private.pem")).unwrap();
    let pubkey: rsa::RsaPublicKey =
        RsaPublicKey::from_public_key_pem(include_str!("public.pem")).unwrap();

    let message = "this is a message to sign that is fairly long.";

    dbg!(message);

    let sig = sign_rsa(&privkey, message).unwrap();
    dbg!(&sig);
    let verified = verify_rsa(&sig, message, &pubkey).unwrap();
    dbg!(verified);
}

#[test]
fn ring_rsa_pss_rountrip_sig() {
    let privkey_bytes = include_bytes!("private.pem");
    let pubkey_bytes = include_bytes!("public.pem");

    let privkey = PemEncodedKey::new(privkey_bytes);
    let pubkey = PemEncodedKey::new(pubkey_bytes);

    let message = "this is a message to sign that is fairly long.";

    dbg!(message);

    let sig = sign_ring(privkey.as_rsa_key(), message).unwrap();
    dbg!(&sig);
    let verified = verify_ring(&sig, message, pubkey.as_rsa_key()).unwrap();
    dbg!(verified);
}

#[test]
fn rustcrypto_rsa_to_ring_pss_rountrip_sig() {
    let privkey: rsa::RsaPrivateKey =
        RsaPrivateKey::from_pkcs8_pem(include_str!("private.pem")).unwrap();
    let pubkey_bytes = include_bytes!("public.pem");
    let pubkey = PemEncodedKey::new(pubkey_bytes);

    let message = "this is a message to sign that is fairly long.";

    dbg!(message);

    let sig = sign_rsa(&privkey, message).unwrap();
    dbg!(&sig);
    let verified = verify_ring(&sig, message, pubkey.as_rsa_key()).unwrap();
    dbg!(verified);
}

#[test]
fn ring_to_rustcrypto_rsa_pss_rountrip_sig() {
    let pubkey: rsa::RsaPublicKey =
        RsaPublicKey::from_public_key_pem(include_str!("public.pem")).unwrap();

    let privkey_bytes = include_bytes!("private.pem");

    let privkey = PemEncodedKey::new(privkey_bytes);

    let message = "this is a message to sign that is fairly long.";

    dbg!(message);

    let sig = sign_ring(privkey.as_rsa_key(), message).unwrap();
    dbg!(&sig);
    let verified = verify_rsa(&sig, message, &pubkey).unwrap();
    dbg!(verified);
}
