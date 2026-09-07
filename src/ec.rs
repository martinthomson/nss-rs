// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ptr;

use log::{log_enabled, trace};

use crate::{
    PrivateKey, PublicKey, SECItem, SECItemBorrowed, der,
    err::{Error, IntoResult as _, secstatus_to_res},
    init, null_safe_slice,
    p11::{
        self, CK_FLAGS, CK_INVALID_HANDLE, CK_MECHANISM_TYPE, CKA_SIGN, CKA_VALUE, CKD_NULL,
        CKF_DERIVE, CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN,
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKM_ECDH1_DERIVE, CKM_ECDSA, CKM_EDDSA, CKM_SHA512_HMAC,
        KU_ALL, PK11_ATTR_INSENSITIVE, PK11_ATTR_PRIVATE, PK11_ATTR_PUBLIC, PK11_ATTR_SENSITIVE,
        PK11_ATTR_SESSION, PK11_ExportDERPrivateKeyInfo, PK11_GenerateKeyPairWithOpFlags,
        PK11_ImportDERPrivateKeyInfoAndReturnKey, PK11_ImportPublicKey, PK11_PubDeriveWithKDF,
        PK11_ReadRawAttribute, PK11ObjectType::PK11_TypePrivKey,
        SECKEY_DecodeDERSubjectPublicKeyInfo, SECOidTag, Slot,
    },
    ssl::PRBool,
    util::SECItemMut,
};
//
// Constants
//

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcCurve {
    P256,
    P384,
    P521,
    X25519,
    Ed25519,
}

pub type EcdhPublicKey = PublicKey;
pub type EcdhPrivateKey = PrivateKey;

#[derive(Clone, Debug)]
pub struct EcdhKeypair {
    pub public: EcdhPublicKey,
    pub private: EcdhPrivateKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ecdh(EcCurve);

impl Ecdh {
    #[must_use]
    pub const fn new(curve: EcCurve) -> Self {
        Self(curve)
    }

    pub fn generate_keypair(curve: EcCurve) -> Result<EcdhKeypair, Error> {
        ecdh_keygen(curve)
    }
}

#[deprecated = "use der::object_id"]
pub fn object_id(val: &[u8]) -> Result<Vec<u8>, Error> {
    der::object_id(val)
}

fn ec_curve_to_oid(alg: EcCurve) -> SECOidTag::Type {
    match alg {
        EcCurve::X25519 => SECOidTag::SEC_OID_X25519,
        EcCurve::Ed25519 => SECOidTag::SEC_OID_ED25519_SIGNATURE,
        EcCurve::P256 => SECOidTag::SEC_OID_ANSIX962_EC_PRIME256V1,
        EcCurve::P384 => SECOidTag::SEC_OID_SECG_EC_SECP384R1,
        EcCurve::P521 => SECOidTag::SEC_OID_SECG_EC_SECP521R1,
    }
}

const fn ec_curve_to_ckm(alg: EcCurve) -> CK_MECHANISM_TYPE {
    match alg {
        EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => CKM_EC_KEY_PAIR_GEN,
        EcCurve::Ed25519 => CKM_EC_EDWARDS_KEY_PAIR_GEN,
        EcCurve::X25519 => CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    }
}

//
// Curve functions
//

pub fn ecdh_keygen(curve: EcCurve) -> Result<EcdhKeypair, Error> {
    init()?;

    // Get the OID for the Curve
    let oid_tag = ec_curve_to_oid(curve);
    let oid = unsafe { p11::SECOID_FindOIDByTag(oid_tag) }.into_result()?;
    let oid = unsafe { oid.as_mut_unchecked() };
    let oid_bytes = unsafe { null_safe_slice(oid.oid.data, oid.oid.len) };
    let oid_bytes = der::object_id(&oid_bytes)?;
    let mut oid = SECItemBorrowed::wrap(&oid_bytes)?;

    // Get the Mechanism based on the Curve and its use
    let ckm = ec_curve_to_ckm(curve);

    // Get the PKCS11 slot
    let slot = Slot::internal()?;

    // Create a pointer for the public key
    let mut public_ptr = ptr::null_mut();

    let insensitive_secret_ptr = if log_enabled!(log::Level::Trace) {
        unsafe {
            PK11_GenerateKeyPairWithOpFlags(
                *slot,
                ckm,
                oid.as_mut_ptr().cast(), // void* cast
                &raw mut public_ptr,
                PK11_ATTR_SESSION | PK11_ATTR_INSENSITIVE | PK11_ATTR_PUBLIC,
                CK_FLAGS::from(CKF_DERIVE),
                CK_FLAGS::from(CKF_DERIVE),
                ptr::null_mut(),
            )
        }
    } else {
        ptr::null_mut()
    };
    assert_eq!(insensitive_secret_ptr.is_null(), public_ptr.is_null());
    let secret_ptr = if insensitive_secret_ptr.is_null() {
        unsafe {
            PK11_GenerateKeyPairWithOpFlags(
                *slot,
                ckm,
                oid.as_mut_ptr().cast(), // void* cast
                &raw mut public_ptr,
                PK11_ATTR_SESSION | PK11_ATTR_SENSITIVE | PK11_ATTR_PRIVATE,
                CK_FLAGS::from(CKF_DERIVE),
                CK_FLAGS::from(CKF_DERIVE),
                ptr::null_mut(),
            )
        }
    } else {
        insensitive_secret_ptr
    };
    assert_eq!(secret_ptr.is_null(), public_ptr.is_null());

    let sk = PrivateKey::from_ptr(secret_ptr)?;
    let pk = EcdhPublicKey::from_ptr(public_ptr)?;
    trace!("Generated key pair: sk={sk:?} pk={pk:?}");

    Ok(EcdhKeypair {
        public: pk,
        private: sk,
    })
}

pub fn export_ec_private_key_pkcs8(key: &PrivateKey) -> Result<Vec<u8>, Error> {
    init()?;
    unsafe {
        let sk: crate::ScopedSECItem =
            PK11_ExportDERPrivateKeyInfo(**key, ptr::null_mut()).into_result()?;
        Ok(sk.into_vec())
    }
}

pub fn import_ec_public_key_from_spki(spki: &[u8]) -> Result<PublicKey, Error> {
    init()?;
    let mut spki_item = SECItemBorrowed::wrap(spki)?;
    let spki_item_ptr = spki_item.as_mut();
    let slot = Slot::internal()?;
    unsafe {
        let spki = SECKEY_DecodeDERSubjectPublicKeyInfo(spki_item_ptr).into_result()?;
        let pk: PublicKey = p11::SECKEY_ExtractPublicKey(spki.as_mut().ok_or(Error::InvalidInput)?)
            .into_result()?;

        let handle = PK11_ImportPublicKey(*slot, *pk, PRBool::from(false));
        if handle == CK_INVALID_HANDLE {
            return Err(Error::InvalidInput);
        }

        Ok(pk)
    }
}

pub fn import_ec_private_key_pkcs8(pki: &[u8]) -> Result<PrivateKey, Error> {
    init()?;

    // Get the PKCS11 slot
    let slot = Slot::internal()?;
    let mut der_pki = SECItemBorrowed::wrap(pki)?;
    let der_pki_ptr: *mut SECItem = der_pki.as_mut();

    // Create a pointer for the private key
    let mut pk_ptr = ptr::null_mut();

    unsafe {
        secstatus_to_res(PK11_ImportDERPrivateKeyInfoAndReturnKey(
            *slot,
            der_pki_ptr,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            0,
            KU_ALL,
            &raw mut pk_ptr,
            ptr::null_mut(),
        ))?;

        let sk = EcdhPrivateKey::from_ptr(pk_ptr)?;
        Ok(sk)
    }
}

pub fn export_ec_private_key_from_raw(key: &PrivateKey) -> Result<Vec<u8>, Error> {
    init()?;
    let mut key_item = SECItemMut::make_empty();
    unsafe {
        PK11_ReadRawAttribute(PK11_TypePrivKey, key.cast(), CKA_VALUE, key_item.as_mut());
    }
    Ok(key_item.as_slice().to_owned())
}

pub fn ecdh(sk: &PrivateKey, pk: &PublicKey) -> Result<Vec<u8>, Error> {
    init()?;
    let sym_key = unsafe {
        PK11_PubDeriveWithKDF(
            sk.cast(),
            pk.cast(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            CKM_ECDH1_DERIVE,
            CKM_SHA512_HMAC,
            CKA_SIGN,
            0,
            CKD_NULL,
            ptr::null_mut(),
            ptr::null_mut(),
        )
        .into_result()?
    };

    let key = sym_key.key_data()?;
    Ok(key.to_vec())
}

pub fn convert_to_public(sk: &PrivateKey) -> Result<PublicKey, Error> {
    init()?;
    unsafe {
        let pk = p11::SECKEY_ConvertToPublicKey(**sk).into_result()?;
        Ok(pk)
    }
}

pub fn sign(
    private_key: &PrivateKey,
    data: &[u8],
    mechanism: CK_MECHANISM_TYPE,
) -> Result<Vec<u8>, Error> {
    init()?;
    let data_signature = vec![0u8; 0x40];

    let mut data_to_sign = SECItemBorrowed::wrap(data)?;
    let mut signature = SECItemBorrowed::wrap(&data_signature)?;
    unsafe {
        secstatus_to_res(p11::PK11_SignWithMechanism(
            private_key.as_mut().ok_or(Error::InvalidInput)?,
            mechanism,
            ptr::null_mut(),
            signature.as_mut(),
            data_to_sign.as_mut(),
        ))?;

        let signature = signature.as_slice().to_vec();
        Ok(signature)
    }
}

pub fn sign_ecdsa(private_key: &PrivateKey, data: &[u8]) -> Result<Vec<u8>, Error> {
    sign(private_key, data, CKM_ECDSA)
}

pub fn sign_eddsa(private_key: &PrivateKey, data: &[u8]) -> Result<Vec<u8>, Error> {
    sign(private_key, data, CKM_EDDSA)
}

pub fn verify(
    public_key: &PublicKey,
    data: &[u8],
    signature: &[u8],
    mechanism: CK_MECHANISM_TYPE,
) -> Result<bool, Error> {
    init()?;
    unsafe {
        let mut data_to_sign = SECItemBorrowed::wrap(data)?;
        let mut signature = SECItemBorrowed::wrap(signature)?;

        let rv = p11::PK11_VerifyWithMechanism(
            public_key.as_mut().ok_or(Error::InvalidInput)?,
            mechanism,
            ptr::null_mut(),
            signature.as_mut(),
            data_to_sign.as_mut(),
            ptr::null_mut(),
        );

        match rv {
            0 => Ok(true),
            _ => Ok(false),
        }
    }
}

pub fn verify_ecdsa(public_key: &PublicKey, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
    verify(public_key, data, signature, CKM_ECDSA)
}

pub fn verify_eddsa(public_key: &PublicKey, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
    verify(public_key, data, signature, CKM_EDDSA)
}
