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
use base64::{decode, encode};
use multihash::derive::Multihash;
use multihash::typenum::{U32, U64};
use multihash::{
    Blake2b256, Blake2bDigest, MultihashDigest, MultihashGeneric, Sha2Digest, Sha2_256,
    Sha3Digest, Sha3_256,
};

use serde::{Deserialize, Serialize};

pub mod errors;
pub mod id;

use errors::*;
use id::Identity;

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
/// Represents a signed hash message, the hash being the digest of
/// the identifier(phone number,email address, etc.)
pub struct SignedHash {
    pub hash: MultihashGeneric<U64>,
    pub sign: Vec<u8>,
}

impl SignedHash {
    /// Generate new signed message
    pub fn new(hash: MultihashGeneric<U64>, id: &Identity) -> Self {
        let sign = id.sign(&hash.to_bytes()).as_ref().to_owned();
        Self { hash, sign }
    }

    /// Verify a signed message
    pub fn verify(&self, public_key: &id::PublicKey) -> bool {
        public_key.verify(&self.hash.to_bytes(), &self.sign)
    }

    /// Get ASCII armored representation of [Self]
    pub fn ascii_armor(&self) -> SignedHashAsciiArmored {
        SignedHashAsciiArmored {
            sign: encode(&self.sign),
            hash: encode(&self.hash.to_bytes()),
        }
    }

    /// String representation
    pub fn from_ascii_armor(
        ascii_armor: &SignedHashAsciiArmored,
    ) -> ServiceResult<Self> {
        ascii_armor.to_signed_hash()
    }
}

#[derive(Deserialize, PartialEq, Serialize, Debug, Clone)]
/// ASCII armored representation of [SignedHash]
pub struct SignedHashAsciiArmored {
    /// Hash in ASCII
    pub hash: String,
    /// Signature in ASCII
    pub sign: String,
}

impl SignedHashAsciiArmored {
    /// Create new [Self] from [SignedHash]
    pub fn new(signed_hash: &SignedHash) -> Self {
        signed_hash.ascii_armor()
    }

    /// Get [SignedHash]
    pub fn to_signed_hash(&self) -> ServiceResult<SignedHash> {
        Ok(SignedHash {
            hash: MultihashGeneric::from_bytes(&decode(&self.hash)?)?,
            sign: decode(&self.sign)?,
        })
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

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
/// Identier type supported by Kavasam
pub enum IDType {
    /// Phone number
    PhoneNumber,
    /// Email ID
    Email,
}

#[derive(Debug, Clone, Default)]
/// Builder struct for [ReportMessage]
pub struct ReportMessageBuilder {
    /// Identifier type
    id_type: Option<IDType>,
    /// Hashes of the identifer signed by the reporting agent
    hashes: Option<[SignedHash; 3]>,
    /// public key of reporting agent
    public_key: Option<id::PublicKey>,

    /// Type of spam(Bank, advertisement, etc.)
    tags: Option<Vec<String>>,
}

impl ReportMessageBuilder {
    /// Set [IDType] for the report message. MANDATORY field.
    pub fn id_type(mut self, id_type: IDType) -> Self {
        self.id_type = Some(id_type);
        self
    }

    /// Compute hashes and and attach publick key to the report message. MANDATORY field.
    pub fn hashes(mut self, id: &Identity, data: &[u8]) -> Self {
        let hashes = [
            SignedHash::new(Code::Sha2_256.digest(data), id),
            SignedHash::new(Code::Sha3_256.digest(data), id),
            SignedHash::new(Code::Blake2b256.digest(data), id),
        ];

        self.hashes = Some(hashes);
        self.public_key = Some(id.pub_key());
        self
    }

    /// Set one or more tags(type of spam) to the report message. Optinal field.
    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.tags = Some(tags);
        self
    }

    /// Bulid report message. This methods performs validation by checking if the necessary fields
    /// have been filled out.
    pub fn build(mut self) -> ServiceResult<ReportMessage> {
        if self.tags.is_none() {
            self.tags = Some(Vec::default());
        }

        if self.hashes.is_none() {
            return Err(ServiceError::MissingField("ReportMessageBuilder.hashes"));
        }

        if self.public_key.is_none() {
            return Err(ServiceError::MissingField(
                "ReportMessageBuilder.public_key",
            ));
        }

        if self.id_type.is_none() {
            return Err(ServiceError::MissingField("ReportMessageBuilder.id_type"));
        }

        Ok(ReportMessage {
            id_type: self.id_type.unwrap(),
            hashes: self.hashes.unwrap(),
            public_key: self.public_key.unwrap(),
            tags: self.tags.unwrap(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A message sent to report an identifer
pub struct ReportMessage {
    /// Identifier type
    pub id_type: IDType,
    /// Hashes of the identifer signed by the reporting agent
    pub hashes: [SignedHash; 3],
    /// public key of reporting agent
    pub public_key: id::PublicKey,

    /// Type of spam(Bank, advertisement, etc.)
    pub tags: Vec<String>,
}

impl ReportMessage {
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

    const DATA: &[u8] = b"fooabr";

    #[test]
    fn signed_hash_work() {
        let id = Identity::new();
        let public_key = id.pub_key();
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
    fn ascii_armor_works() {
        let id = Identity::new();
        let public_key = id.pub_key();
        let hash1 = Code::Sha3_256.digest(DATA);
        let signed_hash = SignedHash::new(hash1, &id);

        let ascii_armored = signed_hash.ascii_armor();
        assert_eq!(ascii_armored, SignedHashAsciiArmored::new(&signed_hash));

        let from_ascii_armor = ascii_armored.to_signed_hash().unwrap();
        assert_eq!(
            SignedHash::from_ascii_armor(&ascii_armored).unwrap(),
            from_ascii_armor
        );

        assert_eq!(from_ascii_armor, signed_hash);
        assert!(from_ascii_armor.verify(&public_key))
    }

    #[test]
    fn report_messages_work() {
        let id = Identity::new();
        let tags = vec![
            "bank fraud".to_string(),
            "advertisement".into(),
            "ACME bank".into(),
        ];
        let mut msg = ReportMessageBuilder::default()
            .id_type(IDType::PhoneNumber)
            .hashes(&id, DATA)
            .tags(tags)
            .build()
            .unwrap();
        //let mut msg = ReportMessage::new(DATA, IDType::PhoneNumber, &id);
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
        assert_eq!(Code::Sha3_256.digest(DATA), MCode::Sha3_256.digest(DATA));
        assert_eq!(Code::Sha2_256.digest(DATA), MCode::Sha2_256.digest(DATA));
        assert_eq!(
            Code::Blake2b256.digest(DATA),
            MCode::Blake2b256.digest(DATA)
        );
    }

    #[test]
    fn test_serde_id_type() {
        let ser_email = serde_json::to_string(&IDType::Email).unwrap();
        let ser_phone = serde_json::to_string(&IDType::PhoneNumber).unwrap();
        assert_eq!(
            serde_json::from_str::<IDType>(&ser_email).unwrap(),
            IDType::Email
        );
        assert_eq!(
            serde_json::from_str::<IDType>(&ser_phone).unwrap(),
            IDType::PhoneNumber
        );
    }

    #[test]
    fn validate_report_message_builder() {
        fn validate_error(res: ReportMessageBuilder, missing_field: &str) -> bool {
            res.build()
                .err()
                .as_ref()
                .unwrap()
                .to_string()
                .contains(missing_field)
        }

        let id = Identity::new();
        let tags = vec![
            "bank fraud".to_string(),
            "advertisement".into(),
            "ACME bank".into(),
        ];
        let id_type = IDType::PhoneNumber;
        let msg = ReportMessageBuilder::default()
            .id_type(id_type)
            .hashes(&id, DATA)
            .tags(tags);

        {
            let mut msg = msg.clone();
            msg.hashes = None;
            assert!(validate_error(msg, "hashes"));
        }

        {
            let mut msg = msg.clone();
            msg.public_key = None;
            assert!(validate_error(msg, "public_key"));
        }

        {
            let mut msg = msg.clone();
            msg.id_type = None;
            assert!(validate_error(msg, "id_type"));
        }

        {
            let mut msg = msg;

            msg.tags = Some(Vec::default());
            let res = msg.clone().build();
            assert!(res.is_ok());
            let res = res.unwrap();
            assert!(res.tags.is_empty());

            msg.tags = None;
            msg.tags = Some(Vec::default());
            let res = msg.build();
            assert!(res.is_ok());
            let res = res.unwrap();
            assert!(res.tags.is_empty());
        }
    }
}
