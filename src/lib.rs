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
use multihash::derive::Multihash;
use multihash::typenum::{U32, U64};
use multihash::{
    Blake2b256, Blake2bDigest, MultihashDigest, MultihashGeneric, Sha2Digest, Sha2_256,
    Sha3Digest, Sha3_256,
};

use serde::{Deserialize, Serialize};

pub mod id;

#[derive(Deserialize, Serialize, Debug, Clone)]
/// Represents a signed hash message, the hash being the digest of
/// the identifier(phone number,email address, etc.)
pub struct SignedHash {
    hash: MultihashGeneric<U64>,
    sign: Vec<u8>,
}

impl SignedHash {
    /// Generate new signed message
    pub fn new(hash: MultihashGeneric<U64>, id: &id::Identity) -> Self {
        let sign = id.sign(&hash.to_bytes()).as_ref().to_owned();
        Self { hash, sign }
    }

    /// Verify a signed message
    pub fn verify(&self, public_key: &id::PublicKey) -> bool {
        public_key.verify(&self.hash.to_bytes(), &self.sign)
    }
}

#[derive(Clone, Copy, Debug, Eq, Multihash, PartialEq, Deserialize, Serialize)]
#[mh(alloc_size = U64)]
/// Supported hasing algorithms
pub enum Code {
    /// SHA2-256 (32-byte hash size)
    #[mh(code = 0x12, hasher = Sha2_256, digest = Sha2Digest<U32>)]
    Sha2_256,
    /// SHA3-256 (32-byte hash size)
    #[mh(code = 0x16, hasher = Sha3_256, digest = Sha3Digest<U32>)]
    Sha3_256,
    /// BLAKE2b-256 (32-byte hash size)
    #[mh(code = 0xb220, hasher = Blake2b256, digest = Blake2bDigest<U32>)]
    Blake2b256,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
/// Identier type supported by Kavasam
pub enum IDType {
    /// Phone number
    PhoneNumber,
    /// Email ID
    Email,
}

#[derive(Debug, Clone)]
/// A message sent to report an identifer
pub struct ReportMessage {
    /// Identifier type
    pub id_type: IDType,
    /// Hashes of the identifer signed by the reporting agent
    pub hashes: [SignedHash; 3],
    /// public key of reporting agent
    pub public_key: id::PublicKey,
}

impl ReportMessage {
    /// Generate a new message to report an identifier
    pub fn new(data: &[u8], id_type: IDType, id: &id::Identity) -> Self {
        let hashes = [
            SignedHash::new(Code::Sha2_256.digest(data), id),
            SignedHash::new(Code::Sha3_256.digest(data), id),
            SignedHash::new(Code::Blake2b256.digest(data), id),
        ];

        let public_key = id.pub_key();

        Self {
            id_type,
            hashes,
            public_key,
        }
    }

    /// Verify a reported message
    pub fn verify(&self) -> bool {
        for h in self.hashes.iter() {
            if !h.verify(&self.public_key) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash::Code as MCode;

    #[test]
    fn signed_hash_work() {
        let (_pkcs8_bytes, id) = id::Identity::new();
        let public_key = id.pub_key();
        const DATA: &[u8] = b"fooabr";
        let hash1 = Code::Sha3_256.digest(DATA);
        let hash2 = Code::Sha3_256.digest(b"barfoo");
        let mut signed_hash = SignedHash::new(hash1, &id);
        assert!(
            signed_hash.verify(&public_key),
            "signature successfully verified"
        );
        signed_hash.hash = hash2;
        assert!(
            !signed_hash.verify(&public_key),
            "signature verification failed, invalid signature"
        );
    }

    #[test]
    fn report_messages_work() {
        let (_pkcs8_bytes, id) = id::Identity::new();
        const DATA: &[u8] = b"fooabr";
        let mut msg = ReportMessage::new(DATA, IDType::PhoneNumber, &id);
        assert!(msg.verify());

        let hash1 = Code::Sha3_256.digest(DATA);
        let hash2 = Code::Sha3_256.digest(b"barfoo");
        let mut signed_hash = SignedHash::new(hash1, &id);
        signed_hash.hash = hash2;
        msg.hashes[2] = signed_hash;
        assert!(!msg.verify());
    }

    #[test]
    fn custom_table_matches_multihash_impl() {
        let x = b"1234123455";
        assert_eq!(Code::Sha3_256.digest(x), MCode::Sha3_256.digest(x));
        assert_eq!(Code::Sha2_256.digest(x), MCode::Sha2_256.digest(x));
        assert_eq!(Code::Blake2b256.digest(x), MCode::Blake2b256.digest(x));
    }
}
