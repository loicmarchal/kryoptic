use ossl::asymcipher::{EncOp, OsslAsymcipher};
use ossl::derive::EcdhDerive;
use ossl::pkey::{EvpPkey, EvpPkeyType, PkeyData};

use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};

use crate::osslctx;

/* this will need to grow up to 1024 bytes if we ever add support for FFDH groups
 * (we most likely never will) */
const MAX_SHARED_SECRET_SIZE: usize = 128;

#[derive(Debug)]
pub struct OsslEcKxGroup(pub NamedGroup);

/// Size in bytes of one coordinate of a curve point, for the groups whose key
/// exchange value is a point. `None` for the Montgomery curves, whose value is
/// a bare scalar and must be passed through untouched.
fn coordinate_len(group: NamedGroup) -> Option<usize> {
    match group {
        NamedGroup::secp256r1 => Some(32),
        NamedGroup::secp384r1 => Some(48),
        NamedGroup::secp521r1 => Some(66),
        _ => None,
    }
}

/// Returns the point in the uncompressed form, `0x04 || X || Y`.
///
/// RFC 8446 section 4.2.8.2 requires that form of a TLS 1.3 key share, and
/// peers enforce it: Go's crypto/tls rejects anything else with an
/// illegal_parameter alert. Which form a key exports in is the provider's
/// choice, and not one it can be talked out of -- asking for "uncompressed"
/// through the key generation parameters is ignored outright, and setting it
/// on the generated key is honoured by the default provider but not by the
/// FIPS module RHEL 9 ships, frozen at 3.0.7 while libcrypto moves on.
///
/// So rather than ask, rebuild: the coordinates are readable from the key
/// whatever form the encoded point took.
fn uncompressed_point(
    group: NamedGroup,
    key: &EvpPkey,
    point: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let len = match coordinate_len(group) {
        Some(len) => len,
        None => return Ok(point),
    };

    if point.first() == Some(&0x04) && point.len() == 1 + 2 * len {
        return Ok(point);
    }

    /* The buffers are sizing hints: get_params() fills them in place, so they
     * have to be wide enough for any coordinate we support. */
    let x_buffer = [0xff; 128];
    let y_buffer = [0xff; 128];
    let mut params = {
        let mut builder = ossl::OsslParamBuilder::with_capacity(2);
        builder
            .add_bn(c"qx", &x_buffer)
            .and_then(|()| builder.add_bn(c"qy", &y_buffer))
            .map_err(|_| {
                Error::General("Failed to request KX coordinates".into())
            })?;
        builder.finalize()
    };
    key.get_params(&mut params)
        .map_err(|_| Error::General("Failed to read KX coordinates".into()))?;
    let x = params.get_bn(c"qx").map_err(|_| {
        Error::General("Failed to decode KX x coordinate".into())
    })?;
    let y = params.get_bn(c"qy").map_err(|_| {
        Error::General("Failed to decode KX y coordinate".into())
    })?;

    if x.len() > len || y.len() > len {
        return Err(Error::General("KX point is too large".into()));
    }

    /* Left pad each coordinate to the fixed width the curve calls for: a
     * BIGNUM carries no leading zeros, and P-521 produces one most of the
     * time, its top byte holding a single significant bit. */
    let mut encoded = vec![0u8; 1 + 2 * len];
    encoded[0] = 0x04;
    encoded[1 + len - x.len()..1 + len].copy_from_slice(&x);
    encoded[1 + 2 * len - y.len()..].copy_from_slice(&y);
    Ok(encoded)
}

impl SupportedKxGroup for OsslEcKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let key_type = match self.0 {
            NamedGroup::X25519 => EvpPkeyType::X25519,
            NamedGroup::secp256r1 => EvpPkeyType::P256,
            NamedGroup::secp384r1 => EvpPkeyType::P384,
            NamedGroup::secp521r1 => EvpPkeyType::P521,
            _ => return Err(Error::General("Unsupported KX group".into())),
        };

        let privkey = EvpPkey::generate(osslctx(), key_type)
            .map_err(|_| Error::General("Failed to generate KX key".into()))?;

        let pubkey = match privkey.export_public() {
            Ok(PkeyData::Ecc(ecc)) => {
                if let Some(k) = &ecc.pubkey {
                    Some(k.clone())
                } else {
                    None
                }
            }
            _ => None,
        }
        .ok_or_else(|| Error::General("Failed to get KX public key".into()))?;

        let pubkey = uncompressed_point(self.0, &privkey, pubkey)?;

        Ok(Box::new(OsslEcdh {
            group: self.0,
            privkey,
            pubkey,
        }))
    }

    fn name(&self) -> NamedGroup {
        self.0
    }

    fn fips(&self) -> bool {
        match self.0 {
            NamedGroup::X25519 => {
                EvpPkey::available(osslctx(), EvpPkeyType::X25519)
            }
            NamedGroup::secp256r1 => {
                EvpPkey::available(osslctx(), EvpPkeyType::P256)
            }
            NamedGroup::secp384r1 => {
                EvpPkey::available(osslctx(), EvpPkeyType::P384)
            }
            NamedGroup::secp521r1 => {
                EvpPkey::available(osslctx(), EvpPkeyType::P521)
            }
            _ => false,
        }
    }
}

pub struct OsslEcdh {
    group: NamedGroup,
    privkey: EvpPkey,
    pubkey: Vec<u8>,
}

impl ActiveKeyExchange for OsslEcdh {
    fn complete(
        mut self: Box<Self>,
        peer: &[u8],
    ) -> Result<SharedSecret, Error> {
        match self.group {
            NamedGroup::X25519 => {
                if peer.len() != 32 {
                    return Err(Error::PeerMisbehaved(
                        PeerMisbehaved::InvalidKeyShare,
                    ));
                }
            }
            NamedGroup::secp256r1
            | NamedGroup::secp384r1
            | NamedGroup::secp521r1 => {
                if peer.first() != Some(&0x04) {
                    return Err(Error::PeerMisbehaved(
                        PeerMisbehaved::InvalidKeyShare,
                    ));
                }
            }
            _ => {
                return Err(Error::PeerMisbehaved(
                    PeerMisbehaved::InvalidKeyShare,
                ))
            }
        };
        let mut peer_key =
            self.privkey.make_peer(osslctx(), peer).map_err(|_| {
                Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
            })?;

        let mut derive = EcdhDerive::new(osslctx(), &mut self.privkey)
            .map_err(|_| {
                Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
            })?;

        let mut secret = [0u8; MAX_SHARED_SECRET_SIZE];
        let len = derive.derive(&mut peer_key, &mut secret).map_err(|_| {
            Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
        })?;

        Ok(SharedSecret::from(&secret[..len]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pubkey
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

#[derive(Debug)]
pub struct OsslKemKxGroup(pub NamedGroup);

impl SupportedKxGroup for OsslKemKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let key_type = match self.0 {
            NamedGroup::MLKEM768 => EvpPkeyType::MlKem768,
            NamedGroup::MLKEM1024 => EvpPkeyType::MlKem1024,
            _ => return Err(Error::General("Unsupported KX group".into())),
        };

        let privkey = EvpPkey::generate(osslctx(), key_type)
            .map_err(|_| Error::General("Failed to generate KX key".into()))?;

        let pubkey = match privkey.export_public() {
            Ok(PkeyData::Mlkey(mlkem)) => {
                if let Some(k) = &mlkem.pubkey {
                    Some(k.clone())
                } else {
                    None
                }
            }
            _ => None,
        }
        .ok_or_else(|| Error::General("Failed to get KX public key".into()))?;

        Ok(Box::new(OsslKem {
            group: self.0,
            privkey,
            pubkey,
        }))
    }

    fn name(&self) -> NamedGroup {
        self.0
    }
}

pub struct OsslKem {
    group: NamedGroup,
    privkey: EvpPkey,
    pubkey: Vec<u8>,
}

impl ActiveKeyExchange for OsslKem {
    fn complete(
        mut self: Box<Self>,
        peer: &[u8],
    ) -> Result<SharedSecret, Error> {
        let mut cipher = OsslAsymcipher::new(
            osslctx(),
            EncOp::Decapsulate,
            &mut self.privkey,
            None,
        )
        .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;

        let secret = cipher.decapsulate(peer).map_err(|_| {
            Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
        })?;

        Ok(SharedSecret::from(secret.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pubkey
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

pub static X25519: OsslEcKxGroup = OsslEcKxGroup(NamedGroup::X25519);

pub static SECP256R1: OsslEcKxGroup = OsslEcKxGroup(NamedGroup::secp256r1);

pub static SECP384R1: OsslEcKxGroup = OsslEcKxGroup(NamedGroup::secp384r1);

pub static SECP521R1: OsslEcKxGroup = OsslEcKxGroup(NamedGroup::secp521r1);

pub static MLKEM768: OsslKemKxGroup = OsslKemKxGroup(NamedGroup::MLKEM768);

pub static MLKEM1024: OsslKemKxGroup = OsslKemKxGroup(NamedGroup::MLKEM1024);

static SUPPORTED_KX_GROUPS: std::sync::OnceLock<
    Vec<&'static dyn SupportedKxGroup>,
> = std::sync::OnceLock::new();

pub fn supported_kx_groups() -> Vec<&'static dyn SupportedKxGroup> {
    let groups = SUPPORTED_KX_GROUPS.get_or_init(|| {
        let mut v: Vec<&'static dyn SupportedKxGroup> = Vec::with_capacity(5);

        if EvpPkey::available(osslctx(), EvpPkeyType::MlKem1024) {
            v.push(&MLKEM1024);
        }
        if EvpPkey::available(osslctx(), EvpPkeyType::MlKem768) {
            v.push(&MLKEM768);
        }
        if EvpPkey::available(osslctx(), EvpPkeyType::X25519) {
            v.push(&X25519);
        }
        if EvpPkey::available(osslctx(), EvpPkeyType::P521) {
            v.push(&SECP521R1);
        }
        if EvpPkey::available(osslctx(), EvpPkeyType::P384) {
            v.push(&SECP384R1);
        }
        if EvpPkey::available(osslctx(), EvpPkeyType::P256) {
            v.push(&SECP256R1);
        }

        v
    });
    groups.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A point the provider hands back compressed still has to leave as a
    /// key share in the uncompressed form. The FIPS module this was found
    /// against does exactly that; here the format has to be forced onto the
    /// key to reproduce it, since the default provider does not.
    #[test]
    fn test_compressed_point_is_expanded() {
        for (group, key_type, coordinate_len) in [
            (NamedGroup::secp256r1, EvpPkeyType::P256, 32),
            (NamedGroup::secp384r1, EvpPkeyType::P384, 48),
            (NamedGroup::secp521r1, EvpPkeyType::P521, 66),
        ] {
            let mut key = EvpPkey::generate(osslctx(), key_type).unwrap();
            let ret = unsafe {
                ossl::bindings::EVP_PKEY_set_utf8_string_param(
                    key.as_mut_ptr(),
                    c"point-format".as_ptr(),
                    c"compressed".as_ptr(),
                )
            };
            assert_eq!(ret, 1, "could not force the compressed form");

            let compressed = match key.export_public() {
                Ok(PkeyData::Ecc(ecc)) => ecc.pubkey.clone().unwrap(),
                _ => panic!("no public key"),
            };
            assert!(
                matches!(compressed.first(), Some(0x02 | 0x03)),
                "{group:?} was not exported compressed, nothing to expand"
            );

            let expanded =
                uncompressed_point(group, &key, compressed.clone()).unwrap();
            assert_eq!(expanded.first(), Some(&0x04), "{group:?}");
            assert_eq!(expanded.len(), 1 + 2 * coordinate_len, "{group:?}");
            /* the X coordinate is carried over unchanged from the
             * compressed form */
            assert_eq!(
                &expanded[1..1 + coordinate_len],
                &compressed[1..],
                "{group:?} x coordinate was not preserved"
            );
        }
    }

    /// RFC 8446 section 4.2.8.2 requires the key_exchange field of a
    /// TLS 1.3 key share to carry the uncompressed form of the point,
    /// 0x04 || X || Y. Peers that enforce it, Go's crypto/tls among them,
    /// answer a compressed point with an illegal_parameter alert.
    #[test]
    fn test_ec_key_share_is_uncompressed() {
        for (group, coordinate_len) in [
            (&SECP256R1 as &dyn SupportedKxGroup, 32),
            (&SECP384R1 as &dyn SupportedKxGroup, 48),
            (&SECP521R1 as &dyn SupportedKxGroup, 66),
        ] {
            let kx = group.start().unwrap();
            let pub_key = kx.pub_key();
            assert_eq!(
                pub_key.first(),
                Some(&0x04),
                "{:?} key share is not uncompressed: {:02x?}",
                group.name(),
                &pub_key[..1.min(pub_key.len())]
            );
            assert_eq!(
                pub_key.len(),
                1 + 2 * coordinate_len,
                "{:?} key share has the wrong length",
                group.name()
            );
        }
    }
}
