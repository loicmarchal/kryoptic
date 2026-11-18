pub mod cipher;
pub mod hash;
pub mod hmac;
pub mod kdf;
pub mod keyex;
pub mod pkey;
pub mod signer;
#[cfg(feature = "tls12")]
pub mod tls12;
pub mod tls13;
pub mod verify;

use ossl::rand::get_random_ex;
use ossl::OsslContext;
use rustls::crypto::{
    CryptoProvider, GetRandomFailed, KeyExchangeAlgorithm, SecureRandom,
};
use rustls::{CipherSuite, CipherSuiteCommon, SupportedCipherSuite};

static OSSL_CONTEXT: std::sync::OnceLock<OsslContext> =
    std::sync::OnceLock::new();

pub fn osslctx() -> &'static OsslContext {
    OSSL_CONTEXT.get_or_init(|| {
        let mut ctx = OsslContext::new_lib_ctx_checked().unwrap();
        ctx.load_default_configuration().unwrap();
        ctx
    })
}

#[derive(Debug)]
pub struct OsslSecureRandom;

impl SecureRandom for OsslSecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        // Must be the provider's own context: `fips()` below reports on that
        // context, and the global default one the non-_ex call would use is
        // left unconfigured by this crate.
        get_random_ex(osslctx(), buf, true).map_err(|_| GetRandomFailed)
    }

    fn fips(&self) -> bool {
        fips()
    }
}

/// Returns a provider built from whatever the library context can supply.
///
/// The key exchange groups and the signature verification algorithms are
/// discovered by probing the context, so a context that cannot supply a class
/// of algorithm yields an empty list rather than an error. Callers that would
/// rather hear about that up front should use [`try_default_provider`].
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: supported_cipher_suites(),
        kx_groups: keyex::supported_kx_groups(),
        signature_verification_algorithms: verify::supported_algorithms(),
        secure_random: &OsslSecureRandom,
        key_provider: &pkey::OsslKeyProvider,
    }
}

/// Checks that a provider carries everything a handshake needs.
///
/// An empty component list is not rejected anywhere downstream. The FIPS
/// flags do not reveal it either, since `CryptoProvider::fips()` and the
/// per-component `fips()` are `all()` over those lists and report true when a
/// list is empty. An empty set of signature verification algorithms is then
/// encoded into the ClientHello as a zero length `signature_algorithms`
/// vector, which peers reject with a `decode_error` alert: the handshake
/// fails with nothing on either side naming the cause.
fn check_provider(provider: &CryptoProvider) -> Result<(), rustls::Error> {
    let mut missing = Vec::new();

    if provider.cipher_suites.is_empty() {
        missing.push("cipher suites");
    }
    if provider.kx_groups.is_empty() {
        missing.push("key exchange groups");
    }
    if provider.signature_verification_algorithms.all.is_empty()
        || provider
            .signature_verification_algorithms
            .mapping
            .is_empty()
    {
        missing.push("signature verification algorithms");
    }

    if missing.is_empty() {
        return Ok(());
    }

    Err(rustls::Error::General(format!(
        "the OpenSSL library context supplies no {}",
        missing.join(", and no ")
    )))
}

/// Returns the default provider, or an error naming what the library context
/// could not supply.
///
/// Fetches are answered by the providers active in the context and filtered
/// by its default properties, so the outcome depends on how the context was
/// configured rather than on how this crate was built. A context in FIPS mode
/// served by a module that implements fewer algorithms than libcrypto knows
/// about is the case worth guarding against.
pub fn try_default_provider() -> Result<CryptoProvider, rustls::Error> {
    let provider = default_provider();
    check_provider(&provider)?;
    Ok(provider)
}

#[cfg(feature = "tls12")]
static SUPPORTED_TLS12_CIPHER_SUITE: std::sync::OnceLock<
    Vec<rustls::Tls12CipherSuite>,
> = std::sync::OnceLock::new();

#[cfg(feature = "tls12")]
fn tls12_cipher_suites() -> &'static [rustls::Tls12CipherSuite] {
    let suites = SUPPORTED_TLS12_CIPHER_SUITE.get_or_init(|| {
        let mut v = Vec::with_capacity(6);

        let rsa_schemes = signer::supported_rsa_sig_schemes();
        if !rsa_schemes.is_empty() {
            /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
            v.push(rustls::Tls12CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    hash_provider: &hash::SHA256,
                    confidentiality_limit: 1 << 23,
                },
                kx: KeyExchangeAlgorithm::ECDHE,
                sign: rsa_schemes,
                aead_alg: &cipher::AES_128_GCM,
                prf_provider: &kdf::PRF_SHA256,
            });

            /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
            v.push(rustls::Tls12CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    hash_provider: &hash::SHA384,
                    confidentiality_limit: 1 << 23,
                },
                kx: KeyExchangeAlgorithm::ECDHE,
                sign: rsa_schemes,
                aead_alg: &cipher::AES_256_GCM,
                prf_provider: &kdf::PRF_SHA384,
            });

            /* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
            v.push(rustls::Tls12CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                    hash_provider: &hash::SHA256,
                    confidentiality_limit: u64::MAX,
                },
                kx: KeyExchangeAlgorithm::ECDHE,
                sign: rsa_schemes,
                aead_alg: &cipher::CHACHA20_POLY1305,
                prf_provider: &kdf::PRF_SHA256,
            });
        }

        let ecc_schemes = signer::supported_ecc_sig_schemes();
        if !ecc_schemes.is_empty() {
            /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
            v.push(rustls::Tls12CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    hash_provider: &hash::SHA256,
                    confidentiality_limit: 1 << 23,
                },
                kx: KeyExchangeAlgorithm::ECDHE,
                sign: ecc_schemes,
                aead_alg: &cipher::AES_128_GCM,
                prf_provider: &kdf::PRF_SHA256,
            });

            /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
            v.push(rustls::Tls12CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    hash_provider: &hash::SHA384,
                    confidentiality_limit: 1 << 23,
                },
                kx: KeyExchangeAlgorithm::ECDHE,
                sign: ecc_schemes,
                aead_alg: &cipher::AES_256_GCM,
                prf_provider: &kdf::PRF_SHA384,
            });

            /* TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */
            v.push(rustls::Tls12CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                    hash_provider: &hash::SHA256,
                    confidentiality_limit: u64::MAX,
                },
                kx: KeyExchangeAlgorithm::ECDHE,
                sign: ecc_schemes,
                aead_alg: &cipher::CHACHA20_POLY1305,
                prf_provider: &kdf::PRF_SHA256,
            });
        }

        v
    });
    &suites
}

static SUPPORTED_TLS13_CIPHER_SUITE: std::sync::OnceLock<
    Vec<rustls::Tls13CipherSuite>,
> = std::sync::OnceLock::new();

fn tls13_cipher_suites() -> &'static [rustls::Tls13CipherSuite] {
    let suites = SUPPORTED_TLS13_CIPHER_SUITE.get_or_init(|| {
        let mut v = Vec::with_capacity(3);

        /* TLS_AES_256_GCM_SHA384 */
        v.push(rustls::Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
                hash_provider: &hash::SHA384,
                confidentiality_limit: 1 << 23,
            },
            hkdf_provider: &kdf::HKDF_SHA384,
            aead_alg: &cipher::AES_256_GCM,
            quic: None, /* TODO */
        });

        /* TLS_AES_128_GCM_SHA256 */
        v.push(rustls::Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                hash_provider: &hash::SHA256,
                confidentiality_limit: 1 << 23,
            },
            hkdf_provider: &kdf::HKDF_SHA256,
            aead_alg: &cipher::AES_128_GCM,
            quic: None, /* TODO */
        });

        /* TLS13_CHACHA20_POLY1305_SHA256 */
        v.push(rustls::Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                hash_provider: &hash::SHA256,
                confidentiality_limit: u64::MAX,
            },
            hkdf_provider: &kdf::HKDF_SHA256,
            aead_alg: &cipher::CHACHA20_POLY1305,
            quic: None, /* TODO */
        });

        v
    });
    &suites
}

fn supported_cipher_suites() -> Vec<SupportedCipherSuite> {
    let mut suites = Vec::with_capacity(9);

    for suite in tls13_cipher_suites() {
        suites.push(SupportedCipherSuite::Tls13(&suite));
    }

    #[cfg(feature = "tls12")]
    {
        for suite in tls12_cipher_suites() {
            suites.push(SupportedCipherSuite::Tls12(&suite));
        }
    }

    if fips() {
        suites.retain(|suite| !is_chacha20_poly1305_suite(suite.suite()));
    }

    suites
}

fn is_chacha20_poly1305_suite(suite: CipherSuite) -> bool {
    matches!(
        suite,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
            | CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            | CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    )
}

pub(crate) fn fips() -> bool {
    osslctx().fips_is_enabled()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_default_provider() {
        try_default_provider().expect("default provider is unusable");
    }

    #[test]
    fn test_check_provider_rejects_empty_components() {
        let mut provider = default_provider();
        provider.cipher_suites.clear();
        let err = check_provider(&provider).unwrap_err().to_string();
        assert!(err.contains("cipher suites"), "{err}");

        let mut provider = default_provider();
        provider.kx_groups.clear();
        let err = check_provider(&provider).unwrap_err().to_string();
        assert!(err.contains("key exchange groups"), "{err}");

        let mut provider = default_provider();
        provider.signature_verification_algorithms =
            rustls::crypto::WebPkiSupportedAlgorithms {
                all: &[],
                mapping: &[],
            };
        let err = check_provider(&provider).unwrap_err().to_string();
        assert!(err.contains("signature verification algorithms"), "{err}");
    }

    #[test]
    fn test_check_provider_names_every_missing_component() {
        let mut provider = default_provider();
        provider.cipher_suites.clear();
        provider.kx_groups.clear();
        let err = check_provider(&provider).unwrap_err().to_string();
        assert!(err.contains("cipher suites"), "{err}");
        assert!(err.contains("key exchange groups"), "{err}");
    }

    #[test]
    fn chacha20_poly1305_aead_is_never_fips() {
        assert!(!cipher::CHACHA20_POLY1305.fips_approved());
        assert_eq!(cipher::AES_128_GCM.fips_approved(), fips());
        assert_eq!(cipher::AES_256_GCM.fips_approved(), fips());
    }

    #[test]
    fn chacha20_poly1305_suites_follow_context_fips_mode() {
        let contains_chacha20_poly1305 = supported_cipher_suites()
            .iter()
            .any(|suite| is_chacha20_poly1305_suite(suite.suite()));

        assert_eq!(contains_chacha20_poly1305, !fips());
    }
}
