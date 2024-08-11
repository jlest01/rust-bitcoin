// SPDX-License-Identifier: CC0-1.0

//! Musig2
//!
//! Support for Musig2.
//! 
//! Musig2 is a Schnorr-based multi-signature scheme that is designed to be secure and efficient.
//! It is a two-round protocol that is designed to be secure against rogue-key attacks.
use core::{convert, fmt, mem};
#[cfg(feature = "std")]
use std::error;

use secp256k1::{musig::{new_musig_nonce_pair, MusigAggNonce, MusigKeyAggCache, MusigPubNonce, MusigSecNonce, MusigSession, MusigSessionId, MusigTweakErr}, Message, Secp256k1, SecretKey, Signing, Verification};

use crate::{key::TweakedPublicKey, PublicKey, ScriptBuf, TapTweakHash, XOnlyPublicKey};

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

/// Lorem Ipsum
pub fn create_musig_key_agg_cache<C: Verification>(secp: &Secp256k1<C>, pubkeys: &Vec<PublicKey>) -> MusigKeyAggCache {

    let ffi_pubkeys: Vec<secp256k1::PublicKey> = pubkeys.iter().map(|pk| pk.inner).collect();

    let ffi_pubkeys = ffi_pubkeys.as_slice();
    
    MusigKeyAggCache::new(&secp, ffi_pubkeys)
}

/// Lorem Ipsum
pub fn tweak_taproot_key<C: Verification>(secp: &Secp256k1<C>, musig_key_agg_cache: &mut MusigKeyAggCache) -> Result<PublicKey, Error>
{
    let tap_tweak = TapTweakHash::from_key_and_tweak(musig_key_agg_cache.agg_pk(), None);
    let tweak = tap_tweak.to_scalar();

    match musig_key_agg_cache.pubkey_xonly_tweak_add(secp, &tweak) {
        Ok(tweaked_key) => Ok(PublicKey::new(tweaked_key)),
        Err(MusigTweakErr::InvalidTweak) => Err(Error::TweakErr),
    }
}

/// Lorem Ipsum
pub fn new_p2tr_script_buf(output_key: XOnlyPublicKey) -> ScriptBuf {
    let tweaked_public_key = TweakedPublicKey::dangerous_assume_tweaked(output_key);
    ScriptBuf::new_p2tr_tweaked(tweaked_public_key)
}

/// Lorem Ipsum
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

/// Lorem Ipsum
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
/// Lorem Ipsum
/* pub fn aggregate_nonces<C: Signing>(
    secp: &Secp256k1<C>, 
    &[MusigPubNonce]) -> MusigAggNonce {

    MusigAggNonce::new(&secp, &nonces)
} */

/// Lorem Ipsum
pub fn create_musig_session<C: Signing>(
    secp: &Secp256k1<C>, 
    musig_key_agg_cache: &MusigKeyAggCache, 
    nonces: &[MusigPubNonce], 
    msg: Message) -> MusigSession {

    let agg_nonce = MusigAggNonce::new(secp, &nonces);

    MusigSession::new(&secp, musig_key_agg_cache, agg_nonce, msg)
}

/* 
pub struct NoncePair {
    sec_nonce: MusigSecNonce,
    pub pub_nonce: MusigPubNonce,
}

pub struct MusigData {
    pub nonce_pair: NoncePair,
    session: Option<MusigSession>,
    pub partial_sign: Option<MusigPartialSignature>,
}
 

impl MusigData {
    

    /// Lorem Ipsum
    pub fn process_nonces<C: Signing>(&mut self, 
        secp: &Secp256k1<C>, 
        musig_key_agg_cache: &MusigKeyAggCache, 
        nonces: &[MusigPubNonce], 
        msg: Message) -> Result<(), Error> {

        if !nonces.contains(&self.nonce_pair.pub_nonce) {
            return Err(Error::PubNonceMissing); 
        }

        let agg_nonce = MusigAggNonce::new(secp, nonces);

        let session = MusigSession::new(&secp, musig_key_agg_cache, agg_nonce, msg);

        self.session = Some(session);

        Ok(())
    }

    /// Lorem Ipsum
    pub fn partial_sign<C: Signing>(mut self, 
        secp: &Secp256k1<C>, 
        keypair: PrivateKey,
        musig_key_agg_cache: &MusigKeyAggCache)-> Result<(), Error> {

            let keypair = Keypair::from_secret_key(secp, &keypair.inner);

            if self.session.is_none() {
                return Err(Error::NullSession);
            }

            let session = self.session.unwrap();

            let sec_nonce = self.nonce_pair.sec_nonce;

            match session.partial_sign(&secp, sec_nonce, &keypair, &musig_key_agg_cache) {
                Ok(partial_sign) => {
                    self.partial_sign = Some(partial_sign);
                    return Ok(())
                },
                Err(_) => {
                    return Err(Error::PartialSignatureError);
                }
            }
        }
}
        */