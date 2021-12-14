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
    Blake2b256, Blake2bDigest, MultihashGeneric, Sha2Digest, Sha2_256, Sha3Digest,
    Sha3_256,
};

use serde::{Deserialize, Serialize};

pub mod id;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum IDType {
    PhoneNumber,
    Email,
}

#[derive(Debug, Clone)]
pub struct ReportMessage {
    pub message_type: IDType,
    pub hashes: [MultihashGeneric<U64>; 3],
    pub public_key: id::PublicKey,
    pub signature: id::PublicKey,
}

#[derive(Clone, Copy, Debug, Eq, Multihash, PartialEq, Deserialize, Serialize)]
#[mh(alloc_size = U64)]
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

//impl Message {
//    pub fn new(id: &[u8], message_type: IDType) -> Self {
//        let hashes = [
//            Code::Sha2_256.digest(id),
//            Code::Sha3_256.digest(id),
//            Code::Blake2b256.digest(id),
//        ];
//
//        Self {
//            message_type,
//            hashes,
//        }
//    }
//}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash::Code as MCode;
    use multihash::MultihashDigest;
    #[test]
    fn custom_table_matches_multihash_impl() {
        let x = b"1234123455";
        assert_eq!(Code::Sha3_256.digest(x), MCode::Sha3_256.digest(x));
        assert_eq!(Code::Sha2_256.digest(x), MCode::Sha2_256.digest(x));
        assert_eq!(Code::Blake2b256.digest(x), MCode::Blake2b256.digest(x));
    }
}
