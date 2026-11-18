// See LICENSE.txt file for terms

use serial_test::parallel;

use crate::bindings::{OSSL_PROVIDER_load, OSSL_PROVIDER_unload};
use crate::rand::{get_random, get_random_ex};
use crate::tests::test_ossl_context;

#[test]
#[parallel]
fn test_get_random_ex() {
    let mut buf = [0u8; 32];
    get_random_ex(test_ossl_context(), &mut buf, true).unwrap();
    assert_ne!(buf, [0u8; 32]);

    let mut buf = [0u8; 32];
    get_random_ex(test_ossl_context(), &mut buf, false).unwrap();
    assert_ne!(buf, [0u8; 32]);
}

#[test]
#[parallel]
fn test_get_random_ex_draws_from_the_given_context() {
    // Activating the null provider leaves the context with no algorithms and
    // suppresses the automatic fallback to the default provider, so no DRBG
    // can be fetched from it.
    //
    // It has to be loaded through OSSL_PROVIDER_load() rather than
    // OsslContext::load_provider(), because the latter first asks
    // OSSL_PROVIDER_available(), and querying the provider store activates
    // the fallback providers as a side effect. The default provider would
    // then be active in this context and able to supply a DRBG after all.
    let ctx = crate::OsslContext::new_lib_ctx_checked().unwrap();
    let null_provider =
        unsafe { OSSL_PROVIDER_load(ctx.ptr(), c"null".as_ptr()) };
    assert!(!null_provider.is_null());

    // A request against that context must fail. Were the call to reach the
    // global default context instead, as the non-_ex OpenSSL functions do, it
    // would succeed and the buffer would be filled.
    let mut buf = [0u8; 32];
    assert!(get_random_ex(&ctx, &mut buf, true).is_err());
    assert_eq!(buf, [0u8; 32]);

    assert!(get_random_ex(&ctx, &mut buf, false).is_err());
    assert_eq!(buf, [0u8; 32]);

    // The default context is unaffected by the one above.
    get_random(&mut buf, true).unwrap();
    assert_ne!(buf, [0u8; 32]);

    assert_eq!(unsafe { OSSL_PROVIDER_unload(null_provider) }, 1);
}
