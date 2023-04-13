// ripped from jsonwebtoken-8.3.0

/// Supported PEM files for EC and RSA Public and Private Keys
#[derive(Debug, PartialEq)]
enum PemType {
    EcPublic,
    EcPrivate,
    RsaPublic,
    RsaPrivate,
    EdPublic,
    EdPrivate,
}

#[derive(Debug, PartialEq)]
enum Standard {
    // Only for RSA
    Pkcs1,
    // RSA/EC
    Pkcs8,
}

#[derive(Debug, PartialEq)]
enum Classification {
    Ec,
    Ed,
    Rsa,
}

/// The return type of a successful PEM encoded key with `decode_pem`
///
/// This struct gives a way to parse a string to a key for use in jsonwebtoken.
/// A struct is necessary as it provides the lifetime of the key
///
/// PEM public private keys are encoded PKCS#1 or PKCS#8
/// You will find that with PKCS#8 RSA keys that the PKCS#1 content
/// is embedded inside. This is what is provided to ring via `Key::Der`
/// For EC keys, they are always PKCS#8 on the outside but like RSA keys
/// EC keys contain a section within that ultimately has the configuration
/// that ring uses.
/// Documentation about these formats is at
/// PKCS#1: https://tools.ietf.org/html/rfc8017
/// PKCS#8: https://tools.ietf.org/html/rfc5958
#[derive(Debug)]
pub(crate) struct PemEncodedKey {
    content: Vec<u8>,
    asn1: Vec<simple_asn1::ASN1Block>,
    pem_type: PemType,
    standard: Standard,
}

impl PemEncodedKey {
    /// Read the PEM file for later key use
    pub fn new(input: &[u8]) -> PemEncodedKey {
        match pem::parse(input) {
            Ok(content) => {
                let tag = content.tag().to_owned();
                let pem_contents = content.into_contents();
                let asn1_content = match simple_asn1::from_der(pem_contents.as_slice()) {
                    Ok(asn1) => asn1,
                    Err(e) => panic!("invalid key format, {e}"),
                };

                match tag.as_str() {
                    // This handles a PKCS#1 RSA Private key
                    "RSA PRIVATE KEY" => PemEncodedKey {
                        content: pem_contents,
                        asn1: asn1_content,
                        pem_type: PemType::RsaPrivate,
                        standard: Standard::Pkcs1,
                    },
                    "RSA PUBLIC KEY" => PemEncodedKey {
                        content: pem_contents,
                        asn1: asn1_content,
                        pem_type: PemType::RsaPublic,
                        standard: Standard::Pkcs1,
                    },

                    // No "EC PRIVATE KEY"
                    // https://security.stackexchange.com/questions/84327/converting-ecc-private-key-to-pkcs1-format
                    // "there is no such thing as a "PKCS#1 format" for elliptic curve (EC) keys"

                    // This handles PKCS#8 certificates and public & private keys
                    tag @ "PRIVATE KEY" | tag @ "PUBLIC KEY" | tag @ "CERTIFICATE" => {
                        match classify_pem(&asn1_content) {
                            Some(c) => {
                                let is_private = tag == "PRIVATE KEY";
                                let pem_type = match c {
                                    Classification::Ec => {
                                        if is_private {
                                            PemType::EcPrivate
                                        } else {
                                            PemType::EcPublic
                                        }
                                    }
                                    Classification::Ed => {
                                        if is_private {
                                            PemType::EdPrivate
                                        } else {
                                            PemType::EdPublic
                                        }
                                    }
                                    Classification::Rsa => {
                                        if is_private {
                                            PemType::RsaPrivate
                                        } else {
                                            PemType::RsaPublic
                                        }
                                    }
                                };
                                PemEncodedKey {
                                    content: pem_contents,
                                    asn1: asn1_content,
                                    pem_type,
                                    standard: Standard::Pkcs8,
                                }
                            }
                            None => panic!("invalid key format"),
                        }
                    }

                    // Unknown/unsupported type
                    _ => panic!("invalid key format, unknown type"),
                }
            }
            Err(e) => panic!("invalid key format, {e}"),
        }
    }

    /// Can only be PKCS8
    pub fn as_ec_private_key(&self) -> &[u8] {
        match self.standard {
            Standard::Pkcs1 => panic!("invalid key format"),
            Standard::Pkcs8 => match self.pem_type {
                PemType::EcPrivate => self.content.as_slice(),
                _ => panic!("invalid key format"),
            },
        }
    }

    /// Can only be PKCS8
    pub fn as_ec_public_key(&self) -> &[u8] {
        match self.standard {
            Standard::Pkcs1 => panic!("invalid key format"),
            Standard::Pkcs8 => match self.pem_type {
                PemType::EcPublic => {
                    extract_first_bitstring(&self.asn1).expect("invalid key format")
                }
                _ => panic!("invalid key format"),
            },
        }
    }

    /// Can only be PKCS8
    pub fn as_ed_private_key(&self) -> &[u8] {
        match self.standard {
            Standard::Pkcs1 => panic!("invalid key format"),
            Standard::Pkcs8 => match self.pem_type {
                PemType::EdPrivate => self.content.as_slice(),
                _ => panic!("invalid key format"),
            },
        }
    }

    /// Can only be PKCS8
    pub fn as_ed_public_key(&self) -> &[u8] {
        match self.standard {
            Standard::Pkcs1 => panic!("invalid key format"),
            Standard::Pkcs8 => match self.pem_type {
                PemType::EdPublic => {
                    extract_first_bitstring(&self.asn1).expect("invalid key format")
                }
                _ => panic!("invalid key format"),
            },
        }
    }

    /// Can be PKCS1 or PKCS8
    pub fn as_rsa_key(&self) -> &[u8] {
        match self.standard {
            Standard::Pkcs1 => self.content.as_slice(),
            Standard::Pkcs8 => match self.pem_type {
                PemType::RsaPrivate => {
                    extract_first_bitstring(&self.asn1).expect("invalid key format")
                }
                PemType::RsaPublic => {
                    extract_first_bitstring(&self.asn1).expect("invalid key format")
                }
                _ => panic!("invalid key format"),
            },
        }
    }
}

// This really just finds and returns the first bitstring or octet string
// Which is the x coordinate for EC public keys
// And the DER contents of an RSA key
// Though PKCS#11 keys shouldn't have anything else.
// It will get confusing with certificates.
fn extract_first_bitstring(asn1: &[simple_asn1::ASN1Block]) -> Option<&[u8]> {
    for asn1_entry in asn1.iter() {
        match asn1_entry {
            simple_asn1::ASN1Block::Sequence(_, entries) => {
                if let Some(result) = extract_first_bitstring(entries) {
                    return Some(result);
                }
            }
            simple_asn1::ASN1Block::BitString(_, _, value) => {
                return Some(value.as_ref());
            }
            simple_asn1::ASN1Block::OctetString(_, value) => {
                return Some(value.as_ref());
            }
            _ => (),
        }
    }

    None
}

/// Find whether this is EC, RSA, or Ed
fn classify_pem(asn1: &[simple_asn1::ASN1Block]) -> Option<Classification> {
    // These should be constant but the macro requires
    // #![feature(const_vec_new)]
    let ec_public_key_oid = simple_asn1::oid!(1, 2, 840, 10_045, 2, 1);
    let rsa_public_key_oid = simple_asn1::oid!(1, 2, 840, 113_549, 1, 1, 1);
    let ed25519_oid = simple_asn1::oid!(1, 3, 101, 112);

    for asn1_entry in asn1.iter() {
        match asn1_entry {
            simple_asn1::ASN1Block::Sequence(_, entries) => {
                if let Some(classification) = classify_pem(entries) {
                    return Some(classification);
                }
            }
            simple_asn1::ASN1Block::ObjectIdentifier(_, oid) => {
                if oid == ec_public_key_oid {
                    return Some(Classification::Ec);
                }
                if oid == rsa_public_key_oid {
                    return Some(Classification::Rsa);
                }
                if oid == ed25519_oid {
                    return Some(Classification::Ed);
                }
            }
            _ => {}
        }
    }
    None
}
