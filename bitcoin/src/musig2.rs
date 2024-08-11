// SPDX-License-Identifier: CC0-1.0

//! Musig2
//!
//! Support for Musig2.
//! 
//! Musig2 is a Schnorr-based multi-signature scheme that is designed to be secure and efficient.
//! It is a two-round protocol that is designed to be secure against rogue-key attacks.
use core::fmt;

use secp256k1::{musig::{new_musig_nonce_pair, MusigAggNonce, MusigKeyAggCache, MusigPubNonce, MusigSecNonce, MusigSession, MusigSessionId, MusigTweakErr}, Message, Scalar, Secp256k1, SecretKey, Signing, Verification};

use crate::{key::TweakedPublicKey, ScriptBuf, XOnlyPublicKey};

use crate::address::script_pubkey::ScriptBufExt;

#[cfg(feature = "rand-std")]
pub use secp256k1::rand;

/// A Musig2 error
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Invalid tweak operation
    TweakErr,
    /// Failed to generate nonce
    NonceGenError,
    /// Public nonce missing from the list of nonces
    PubNonceMissing,
    /// Null session
    NullSession,
    /// Partial signature error
    PartialSignatureError,
}

internals::impl_from_infallible!(Error);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::TweakErr => write!(f, "Invalid tweak operation"),
            Error::NonceGenError => write!(f, "Failed to generate nonce. Supplied a zero session id."),
            Error::PubNonceMissing => write!(f, "Public nonce missing from the list of nonces."),
            Error::NullSession => write!(f, "Null session. Execute MusigData::process_nonces()."),
            Error::PartialSignatureError => write!(f, "Partial signature error."),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error { }

/// Creates a new [`secp256k1::musig::MusigKeyAggCache`] by supplying a list of PublicKeys used in the session.
pub fn create_musig_key_agg_cache<C: Verification>(secp: &Secp256k1<C>, pubkeys: &Vec<secp256k1::PublicKey>) -> MusigKeyAggCache {

    let pubkeys = pubkeys.as_slice();
    
    MusigKeyAggCache::new(&secp, pubkeys)
}

/// Apply "x-only" tweaking to a public key in a [`secp256k1::musig::MusigKeyAggCache`].
pub fn tweak_taproot_key<C: Verification>(secp: &Secp256k1<C>, musig_key_agg_cache: &mut MusigKeyAggCache, tweak: &Scalar) -> Result<secp256k1::PublicKey, Error>
{
    match musig_key_agg_cache.pubkey_xonly_tweak_add(secp, tweak) {
        Ok(tweaked_key) => Ok(tweaked_key),
        Err(MusigTweakErr::InvalidTweak) => Err(Error::TweakErr),
    }
}

/// Create a new [`ScriptBuf`] for a P2TR output with a tweaked x-only public key.
pub fn new_p2tr_script_buf(output_key: XOnlyPublicKey) -> ScriptBuf {
    let tweaked_public_key = TweakedPublicKey::dangerous_assume_tweaked(output_key);
    ScriptBuf::new_p2tr_tweaked(tweaked_public_key)
}

/// First step in a signing session. Generate a new nonce pair.
#[cfg(feature = "rand-std")]
pub fn generate_random_nonce<R: rand::Rng + ?Sized, C: Signing>(
    secp: &Secp256k1<C>, 
    rng: &mut R,
    musig_key_agg_cache: Option<&MusigKeyAggCache>,
    sec_key: Option<SecretKey>, 
    pub_key: secp256k1::PublicKey, 
    msg: Option<Message>, 
    extra_rand: Option<[u8; 32]>
) -> Result<(MusigSecNonce, MusigPubNonce), Error> {

    let musig_session_id = MusigSessionId::new(rng);

    let nonce_pair = new_musig_nonce_pair(
        &secp, 
        musig_session_id, 
        musig_key_agg_cache,
        sec_key, 
        pub_key, 
        msg, 
        extra_rand);

    match nonce_pair {
        Ok(nonce_pair) => Ok(nonce_pair),
        Err(_) => Err(Error::NonceGenError),
    }
}

/// First step in a signing session. Generate a nonce pair from the specified data parameter.
pub fn generate_nonce_from_slice<C: Signing>(
    secp: &Secp256k1<C>, 
    data: [u8; 32],
    musig_key_agg_cache: Option<&MusigKeyAggCache>,
    sec_key: Option<SecretKey>, 
    pub_key: secp256k1::PublicKey, 
    msg: Option<Message>, 
    extra_rand: Option<[u8; 32]>
) -> Result<(MusigSecNonce, MusigPubNonce), Error> {

    let musig_session_id = MusigSessionId::assume_unique_per_nonce_gen(data);

    let nonce_pair = new_musig_nonce_pair(
        &secp, 
        musig_session_id, 
        musig_key_agg_cache,
        sec_key, 
        pub_key, 
        msg, 
        extra_rand);

    match nonce_pair {
        Ok(nonce_pair) => Ok(nonce_pair),
        Err(_) => Err(Error::NonceGenError),
    }
}

/// Creates a new musig signing session.
pub fn create_musig_session<C: Signing>(
    secp: &Secp256k1<C>, 
    musig_key_agg_cache: &MusigKeyAggCache, 
    nonces: &[MusigPubNonce], 
    msg: Message) -> MusigSession {

    let agg_nonce = MusigAggNonce::new(secp, &nonces);

    MusigSession::new(&secp, musig_key_agg_cache, agg_nonce, msg)
}
