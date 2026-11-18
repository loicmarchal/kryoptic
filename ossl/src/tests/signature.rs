// See LICENSE.txt file for terms

use serial_test::parallel;

use crate::bindings::{OSSL_PROVIDER_load, OSSL_PROVIDER_unload};
use crate::signature::{available, SigAlg};
use crate::tests::test_ossl_context;

/// Algorithms that the legacy EVP_DigestSign/EVP_DigestVerify API can drive,
/// whatever the OpenSSL version
const LEGACY_CAPABLE: &[SigAlg] = &[
    SigAlg::RsaSha2_256,
    SigAlg::RsaSha2_384,
    SigAlg::RsaSha2_512,
    SigAlg::RsaPssSha2_256,
    SigAlg::RsaPssSha2_384,
    SigAlg::RsaPssSha2_512,
    SigAlg::EcdsaSha2_256,
    SigAlg::EcdsaSha2_384,
    SigAlg::EcdsaSha2_512,
];

/// The composite EVP_SIGNATURE names ("RSA-SHA2-256" and friends) exist only
/// from OpenSSL 3.5, and only when the provider serving the context
/// implements them, yet every one of these algorithms can also be driven
/// through the legacy API. Reporting them as unavailable leaves callers with
/// no usable signature algorithm at all: rustls-ossl then advertises an empty
/// signature_algorithms extension and the peer rejects the ClientHello with a
/// decode_error alert.
#[test]
#[parallel]
fn test_available_covers_legacy_algorithms() {
    let ctx = test_ossl_context();
    for alg in LEGACY_CAPABLE {
        assert!(available(ctx, *alg), "{:?} reported as unavailable", alg);
    }
}

/// The fallback must not turn into blanket optimism: a context that can
/// supply neither the composite implementation nor the pieces the legacy API
/// needs has to report the algorithms as unavailable.
#[test]
#[parallel]
fn test_available_is_false_without_providers() {
    // Loaded directly rather than through OsslContext::load_provider(),
    // which first calls OSSL_PROVIDER_available(): querying the provider
    // store activates the fallback providers as a side effect, and the
    // default provider would then answer for this context.
    let ctx = crate::OsslContext::new_lib_ctx_checked().unwrap();
    let null_provider =
        unsafe { OSSL_PROVIDER_load(ctx.ptr(), c"null".as_ptr()) };
    assert!(!null_provider.is_null());

    for alg in LEGACY_CAPABLE {
        assert!(!available(&ctx, *alg), "{:?} reported as available", alg);
    }

    assert_eq!(unsafe { OSSL_PROVIDER_unload(null_provider) }, 1);
}
