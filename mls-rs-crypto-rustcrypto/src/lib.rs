// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod aead;
mod ec;
pub mod ec_signer;
pub mod ecdh;
pub mod kdf;
pub mod mac;
mod random;

#[cfg(feature = "x509")]
pub mod x509;

#[cfg(feature = "x509")]
mod ec_for_x509;

use crate::aead::Aead;
use ec_signer::{EcSigner, EcSignerError};
use ecdh::Ecdh;
use kdf::Kdf;
use mac::{Hash, HashError};
use mls_rs_crypto_hpke::{
    context::{ContextR, ContextS},
    dhkem::DhKem,
    hpke::{Hpke, HpkeError},
};
use mls_rs_crypto_traits::{AeadType, KdfType, KemId, KemType};
pub use random::{RandomSource, SystemRandom};

use mls_rs_core::{
    crypto::{
        CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkePsk, HpkePublicKey,
        HpkeSecretKey, SignaturePublicKey, SignatureSecretKey,
    },
    error::{AnyError, IntoAnyError},
};
use zeroize::Zeroizing;

use alloc::vec;
use alloc::vec::Vec;

#[cfg(all(test, target_arch = "wasm32"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum RustCryptoError {
    #[cfg_attr(feature = "std", error(transparent))]
    AeadError(AnyError),
    #[cfg_attr(feature = "std", error(transparent))]
    HpkeError(HpkeError),
    #[cfg_attr(feature = "std", error(transparent))]
    KdfError(AnyError),
    #[cfg_attr(feature = "std", error(transparent))]
    HashError(HashError),
    #[cfg_attr(feature = "std", error("rand core error: {0:?}"))]
    RandError(getrandom::Error),
    #[cfg_attr(feature = "std", error(transparent))]
    EcSignerError(EcSignerError),
}

impl From<getrandom::Error> for RustCryptoError {
    fn from(value: getrandom::Error) -> Self {
        RustCryptoError::RandError(value)
    }
}

impl From<HpkeError> for RustCryptoError {
    fn from(e: HpkeError) -> Self {
        RustCryptoError::HpkeError(e)
    }
}

impl From<HashError> for RustCryptoError {
    fn from(e: HashError) -> Self {
        RustCryptoError::HashError(e)
    }
}

impl From<EcSignerError> for RustCryptoError {
    fn from(e: EcSignerError) -> Self {
        RustCryptoError::EcSignerError(e)
    }
}

impl IntoAnyError for RustCryptoError {
    #[cfg(feature = "std")]
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

/// Draws its randomness from `R`, the operating system by default.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RustCryptoProvider<R = SystemRandom> {
    pub enabled_cipher_suites: Vec<CipherSuite>,
    random: R,
}

impl RustCryptoProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_enabled_cipher_suites(enabled_cipher_suites: Vec<CipherSuite>) -> Self {
        Self {
            enabled_cipher_suites,
            random: SystemRandom,
        }
    }

    pub fn all_supported_cipher_suites() -> Vec<CipherSuite> {
        vec![
            CipherSuite::P256_AES128,
            CipherSuite::P384_AES256,
            CipherSuite::CURVE25519_AES128,
            CipherSuite::CURVE25519_CHACHA,
        ]
    }
}

impl<R: RandomSource> RustCryptoProvider<R> {
    /// Replaces the source every random value of this provider is drawn from.
    pub fn with_random<S: RandomSource>(self, random: S) -> RustCryptoProvider<S> {
        RustCryptoProvider {
            enabled_cipher_suites: self.enabled_cipher_suites,
            random,
        }
    }
}

impl Default for RustCryptoProvider {
    fn default() -> Self {
        Self::with_enabled_cipher_suites(Self::all_supported_cipher_suites())
    }
}

impl<R: RandomSource> CryptoProvider for RustCryptoProvider<R> {
    type CipherSuiteProvider = RustCryptoCipherSuite<DhKem<Ecdh<R>, Kdf>, Kdf, Aead, R>;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        self.enabled_cipher_suites.clone()
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        if !self.enabled_cipher_suites.contains(&cipher_suite) {
            return None;
        }

        let kdf = Kdf::new(cipher_suite)?;
        let ecdh = Ecdh::with_random(cipher_suite, self.random.clone())?;
        let kem_id = KemId::new(cipher_suite)?;
        let kem = DhKem::new(ecdh, kdf, kem_id as u16, kem_id.n_secret());
        let aead = Aead::new(cipher_suite)?;

        RustCryptoCipherSuite::with_random(cipher_suite, kem, kdf, aead, self.random.clone())
    }
}

#[derive(Clone)]
pub struct RustCryptoCipherSuite<KEM, KDF, AEAD, R = SystemRandom>
where
    KEM: KemType + Clone,
    KDF: KdfType + Clone,
    AEAD: AeadType + Clone,
{
    cipher_suite: CipherSuite,
    aead: AEAD,
    kdf: KDF,
    hash: Hash,
    hpke: Hpke<KEM, KDF, AEAD>,
    ec_signer: EcSigner,
    random: R,
}

impl<KEM, KDF, AEAD> RustCryptoCipherSuite<KEM, KDF, AEAD>
where
    KEM: KemType + Clone,
    KDF: KdfType + Clone,
    AEAD: AeadType + Clone,
{
    pub fn new(cipher_suite: CipherSuite, kem: KEM, kdf: KDF, aead: AEAD) -> Option<Self> {
        Self::with_random(cipher_suite, kem, kdf, aead, SystemRandom)
    }
}

impl<KEM, KDF, AEAD, R> RustCryptoCipherSuite<KEM, KDF, AEAD, R>
where
    KEM: KemType + Clone,
    KDF: KdfType + Clone,
    AEAD: AeadType + Clone,
    R: RandomSource,
{
    /// Like [`RustCryptoCipherSuite::new`], but every random value is drawn from `random`.
    /// `kem` draws its own randomness; give it the same source.
    pub fn with_random(
        cipher_suite: CipherSuite,
        kem: KEM,
        kdf: KDF,
        aead: AEAD,
        random: R,
    ) -> Option<Self> {
        let hpke = Hpke::new(kem, kdf.clone(), Some(aead.clone()));

        Some(Self {
            cipher_suite,
            kdf,
            aead,
            hash: Hash::new(cipher_suite).ok()?,
            hpke,
            ec_signer: EcSigner::new(cipher_suite)?,
            random,
        })
    }

    pub fn random_bytes(&self, out: &mut [u8]) -> Result<(), RustCryptoError> {
        self.random.fill_bytes(out).map_err(Into::into)
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl<KEM, KDF, AEAD, R> CipherSuiteProvider for RustCryptoCipherSuite<KEM, KDF, AEAD, R>
where
    KEM: KemType + Clone + Send + Sync,
    KDF: KdfType + Clone + Send + Sync,
    AEAD: AeadType + Clone + Send + Sync,
    R: RandomSource,
{
    type Error = RustCryptoError;
    // TODO exporter_secret in this struct is not zeroized
    type HpkeContextR = ContextR<KDF, AEAD>;
    type HpkeContextS = ContextS<KDF, AEAD>;

    async fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hash.hash(data))
    }

    async fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hash.mac(key, data)?)
    }

    async fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.aead
            .seal(key, data, aad, nonce)
            .await
            .map_err(|e| RustCryptoError::AeadError(e.into_any_error()))
    }

    async fn aead_open(
        &self,
        key: &[u8],
        cipher_text: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.aead
            .open(key, cipher_text, aad, nonce)
            .await
            .map_err(|e| RustCryptoError::AeadError(e.into_any_error()))
            .map(Zeroizing::new)
    }

    fn aead_key_size(&self) -> usize {
        self.aead.key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.aead.nonce_size()
    }

    async fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf
            .expand(prk, info, len)
            .await
            .map_err(|e| RustCryptoError::KdfError(e.into_any_error()))
            .map(Zeroizing::new)
    }

    async fn kdf_extract(
        &self,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf
            .extract(salt, ikm)
            .await
            .map_err(|e| RustCryptoError::KdfError(e.into_any_error()))
            .map(Zeroizing::new)
    }

    fn kdf_extract_size(&self) -> usize {
        self.kdf.extract_size()
    }

    async fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        Ok(self.hpke.seal(remote_key, info, None, aad, pt).await?)
    }

    async fn hpke_seal_psk(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
        psk: HpkePsk<'_>,
    ) -> Result<HpkeCiphertext, Self::Error> {
        Ok(self.hpke.seal(remote_key, info, Some(psk), aad, pt).await?)
    }

    async fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        Ok(self
            .hpke
            .open(ciphertext, local_secret, local_public, info, None, aad)
            .await?)
    }

    async fn hpke_open_psk(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        psk: HpkePsk<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        Ok(self
            .hpke
            .open(ciphertext, local_secret, local_public, info, Some(psk), aad)
            .await?)
    }

    async fn hpke_setup_r(
        &self,
        enc: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
    ) -> Result<Self::HpkeContextR, Self::Error> {
        Ok(self
            .hpke
            .setup_receiver(enc, local_secret, local_public, info, None)
            .await?)
    }

    async fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        Ok(self.hpke.setup_sender(remote_key, info, None).await?)
    }

    async fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        Ok(self.hpke.derive(ikm).await?)
    }

    async fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        Ok(self.hpke.generate().await?)
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        Ok(self.hpke.public_key_validate(key)?)
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        self.random_bytes(out)
    }

    fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    async fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(self.ec_signer.sign(secret_key, data)?)
    }

    async fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        Ok(self.ec_signer.verify(public_key, signature, data)?)
    }

    async fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        Ok(self.ec_signer.signature_key_generate_from(&self.random)?)
    }

    async fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        Ok(self.ec_signer.signature_key_derive_public(secret_key)?)
    }
}

#[cfg(not(mls_build_async))]
#[test]
fn mls_core_tests() {
    let provider = RustCryptoProvider::new();
    mls_rs_core::crypto::test_suite::verify_tests(&provider, true);

    for cs in RustCryptoProvider::all_supported_cipher_suites() {
        let mut hpke = provider.cipher_suite_provider(cs).unwrap().hpke;

        mls_rs_core::crypto::test_suite::verify_hpke_context_tests(&hpke, cs);
        mls_rs_core::crypto::test_suite::verify_hpke_encap_tests(&mut hpke, cs);
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn mls_rs_core_test() {
    let provider = RustCryptoProvider::new();
    mls_rs_core::crypto::test_suite::verify_tests(&provider, true).await;
}

#[cfg(all(test, not(mls_build_async)))]
mod random_source_tests {
    use super::{RandomSource, RustCryptoProvider};
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};

    #[derive(Clone, Default)]
    struct ConstantCountingSource(Arc<AtomicUsize>);

    impl ConstantCountingSource {
        fn drawn(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl RandomSource for ConstantCountingSource {
        fn fill_bytes(&self, out: &mut [u8]) -> Result<(), getrandom::Error> {
            self.0.fetch_add(out.len(), Ordering::SeqCst);
            out.fill(7);
            Ok(())
        }
    }

    #[test]
    fn every_random_value_comes_from_the_source() {
        for cipher_suite in RustCryptoProvider::all_supported_cipher_suites() {
            let source = ConstantCountingSource::default();
            let provider = RustCryptoProvider::new()
                .with_random(source.clone())
                .cipher_suite_provider(cipher_suite)
                .unwrap();

            let before = source.drawn();
            let (_, first) = provider.kem_generate().unwrap();
            let (_, second) = provider.kem_generate().unwrap();
            assert!(source.drawn() > before, "{cipher_suite:?}: kem_generate");
            assert_eq!(first, second, "{cipher_suite:?}: kem_generate");

            let before = source.drawn();
            let (_, first) = provider.signature_key_generate().unwrap();
            let (_, second) = provider.signature_key_generate().unwrap();
            assert!(
                source.drawn() > before,
                "{cipher_suite:?}: signature_key_generate"
            );
            assert_eq!(first, second, "{cipher_suite:?}: signature_key_generate");

            let (_, remote) = provider.kem_generate().unwrap();
            let before = source.drawn();
            provider.hpke_seal(&remote, b"info", None, b"data").unwrap();
            assert!(source.drawn() > before, "{cipher_suite:?}: hpke_seal");

            let mut bytes = [0; 16];
            provider.random_bytes(&mut bytes).unwrap();
            assert_eq!(bytes, [7; 16], "{cipher_suite:?}: random_bytes");
        }
    }
}
