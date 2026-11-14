// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use getrandom::{
    rand_core::{TryCryptoRng, TryRng},
    SysRng,
};

/// A source of cryptographically secure random bytes.
///
/// Every random value the provider needs, from key generation to the bytes MLS asks for,
/// is drawn from this source. Use it to supply randomness from a source other than the
/// operating system, for example a CSPRNG seeded by the application.
///
/// Clones of a provider share their source by cloning it. A clone must therefore never
/// repeat the output of the value it was cloned from: either share the generator state,
/// for example behind a lock, or draw from an independent stream. A clone that repeats
/// output reuses key material.
pub trait RandomSource: Clone + Send + Sync {
    /// Fills `out` with random bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if no random bytes are available. Custom sources can use
    /// [`getrandom::Error::new_custom`].
    fn fill_bytes(&self, out: &mut [u8]) -> Result<(), getrandom::Error>;
}

/// Draws random bytes from the operating system through `getrandom`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SystemRandom;

impl RandomSource for SystemRandom {
    fn fill_bytes(&self, out: &mut [u8]) -> Result<(), getrandom::Error> {
        SysRng.try_fill_bytes(out)
    }
}

pub(crate) struct RandomSourceRng<'a, R>(pub(crate) &'a R);

impl<R: RandomSource> TryRng for RandomSourceRng<'_, R> {
    type Error = getrandom::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.0.fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.0.fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dst)
    }
}

impl<R: RandomSource> TryCryptoRng for RandomSourceRng<'_, R> {}
