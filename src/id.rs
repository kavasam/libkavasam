/*
 * Copyright (C) 2021  Aravinth Manivannan <realaravinth@batsense.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
use crate::errors::*;
use base64::{decode, encode};
use lazy_static::lazy_static;
use ring::{
    rand::SystemRandom,
    signature::{
        self, EcdsaKeyPair, KeyPair, Signature, ECDSA_P384_SHA384_FIXED_SIGNING,
    },
};

lazy_static! {
    static ref RNG: SystemRandom = SystemRandom::new();
}

#[derive(Debug, Clone, PartialEq)]
/// Public key of a user in the kavasam system
pub struct PublicKey {
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Public key in raw bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// String representation
    pub fn asci_armor(&self) -> String {
        encode(&self.bytes)
    }

    /// String representation
    pub fn from_ascii_armor(key: &str) -> ServiceResult<Self> {
        let bytes = decode(key)?;
        Ok(Self::from_bytes(&bytes))
    }

    /// load public key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let _pubk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_FIXED,
            bytes,
        );

        Self {
            bytes: bytes.to_owned(),
        }
    }

    /// verify a message against a signature using public key
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let pubk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_FIXED,
            &self.bytes,
        );
        pubk.verify(msg, sig).is_ok()
    }
}

#[derive(Debug)]
/// User-owned ID in the Kavasam system
pub struct Identity {
    key_pair: EcdsaKeyPair,
    pkcs8_bytes: Vec<u8>,
}

impl Default for Identity {
    fn default() -> Self {
        Self::new()
    }
}

impl Identity {
    /// Generate new identity
    pub fn new() -> Self {
        let pkcs8_bytes =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &*RNG)
                .unwrap();
        Self::from_pkcs8(pkcs8_bytes.as_ref())
    }

    /// Load identity from persistence
    pub fn from_pkcs8(pkcs8_bytes: &[u8]) -> Self {
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8_bytes)
                .unwrap();
        Self {
            key_pair,
            pkcs8_bytes: pkcs8_bytes.to_owned(),
        }
    }

    /// Sign message, proxies [Public::sign}(Public::sign)
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.key_pair.sign(&*RNG, msg).unwrap()
    }

    /// Verify message, proxies [Public::verify}(Public::verify)
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        self.pub_key().verify(msg, sig)
    }

    /// Get public key of user
    pub fn pub_key(&self) -> PublicKey {
        PublicKey {
            bytes: self.key_pair.public_key().as_ref().to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_works() {
        let id = Identity::new();
        let public_key = id.pub_key();
        assert_eq!(public_key, Identity::from_pkcs8(&id.pkcs8_bytes).pub_key());
        assert_eq!(public_key, PublicKey::from_bytes(&id.pub_key().to_bytes()));

        const MSG: &[u8] = b"foo";
        let sig = id.sign(MSG);
        assert!(id.verify(MSG, sig.as_ref()));

        assert_eq!(
            PublicKey::from_ascii_armor(&public_key.asci_armor()).unwrap(),
            public_key
        );
    }
}
