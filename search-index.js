var searchIndex = JSON.parse('{\
"libkavasam":{"doc":"","t":[13,4,13,4,6,13,3,13,13,3,3,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,0,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,12,12,0,12,11,11,11,11,11,11,11,11,11,11,11,12,11,11,11,11,12,12,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,13,13,4,6,11,11,11,11,11,11,11,11,11,11,11,11,11,12,12,3,3,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11],"n":["Blake2b256","Code","Email","IDType","Multihash","PhoneNumber","ReportMessage","Sha2_256","Sha3_256","SignedHash","SignedHashAsciiArmored","ascii_armor","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","clone","clone","clone","clone","clone","clone_into","clone_into","clone_into","clone_into","clone_into","deserialize","deserialize","deserialize","deserialize","digest","eq","eq","eq","errors","fmt","fmt","fmt","fmt","fmt","from","from","from","from","from","from","from","from","from_ascii_armor","hash","hash","hashes","id","id_type","into","into","into","into","into","multihash_from_digest","ne","ne","new","new","new","public_key","serialize","serialize","serialize","serialize","sign","sign","to_owned","to_owned","to_owned","to_owned","to_owned","to_signed_hash","try_from","try_from","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","type_id","verify","verify","Base64Error","MultihashError","ServiceError","ServiceResult","borrow","borrow_mut","fmt","fmt","from","from","from","into","source","to_string","try_from","try_into","type_id","0","0","Identity","PublicKey","asci_armor","borrow","borrow","borrow_mut","borrow_mut","clone","clone_into","eq","fmt","fmt","from","from","from_ascii_armor","from_bytes","from_pkcs8","into","into","ne","new","pub_key","sign","to_bytes","to_owned","try_from","try_from","try_into","try_into","type_id","type_id","verify","verify"],"q":["libkavasam","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","libkavasam::errors","","","","","","","","","","","","","","","","","libkavasam::errors::ServiceError","","libkavasam::id","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","",""],"d":["BLAKE2b-256 (32-byte hash size)","Supported hasing algorithms","Email ID","Identier type supported by Kavasam","A Multihash with the same allocated size as the …","Phone number","A message sent to report an identifer","SHA2-256 (32-byte hash size)","SHA3-256 (32-byte hash size)","Represents a signed hash message, the hash being the …","ASCII armored representation of SignedHash","Get ASCII armored representation of Self","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","String representation","","Hash in ASCII","Hashes of the identifer signed by the reporting agent","","Identifier type","","","","","","","","","Generate new signed message","Create new Self from SignedHash","Generate a new message to report an identifier","public key of reporting agent","","","","","","Signature in ASCII","","","","","","Get SignedHash","","","","","","","","","","","","","","","","","Verify a signed message","Verify a reported message","","","","","","","","","","","","","","","","","","","","User-owned ID in the Kavasam system","Public key of a user in the kavasam system","String representation","","","","","","","","","","","","String representation","load public key from bytes","Load identity from persistence","","","","Generate new identity","Get public key of user","Sign message, proxies [Public::sign}(Public::sign)","Public key in raw bytes","","","","","","","","verify a message against a signature using public key","Verify message, proxies [Public::verify}(Public::verify)"],"i":[1,0,2,0,0,2,0,1,1,0,0,3,3,4,1,2,5,3,4,1,2,5,3,4,1,2,5,3,4,1,2,5,3,4,1,2,1,3,4,1,0,3,4,1,2,5,3,4,1,1,1,1,2,5,3,3,4,5,0,5,3,4,1,2,5,1,3,4,3,4,5,5,3,4,1,2,3,4,3,4,1,2,5,4,3,4,1,1,2,5,3,4,1,2,5,3,4,1,2,5,3,5,6,6,0,0,6,6,6,6,6,6,6,6,6,6,6,6,6,7,8,0,0,9,9,10,9,10,9,9,9,9,10,9,10,9,9,10,9,10,9,10,10,10,9,9,9,10,9,10,9,10,9,10],"f":[null,null,null,null,null,null,null,null,null,null,null,[[],["signedhashasciiarmored",3]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[],["signedhash",3]],[[],["signedhashasciiarmored",3]],[[],["code",4]],[[],["idtype",4]],[[],["reportmessage",3]],[[]],[[]],[[]],[[]],[[]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["multihash",6]],[[["signedhash",3]],["bool",15]],[[["signedhashasciiarmored",3]],["bool",15]],[[["code",4]],["bool",15]],null,[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[]],[[["blake2bdigest",3]]],[[]],[[["sha3digest",3]]],[[["sha2digest",3]]],[[]],[[]],[[["signedhashasciiarmored",3]],["serviceresult",6]],null,null,null,null,null,[[]],[[]],[[]],[[]],[[]],[[],["multihash",6]],[[["signedhash",3]],["bool",15]],[[["signedhashasciiarmored",3]],["bool",15]],[[["identity",3],["u64",6],["multihashgeneric",3,["u64"]]]],[[["signedhash",3]]],[[["identity",3],["idtype",4]]],null,[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],null,null,[[]],[[]],[[]],[[]],[[]],[[],[["serviceresult",6,["signedhash"]],["signedhash",3]]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[["u64",15]],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[["publickey",3]],["bool",15]],[[],["bool",15]],null,null,null,null,[[]],[[]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[["base64error",4]],["serviceerror",4]],[[["multihasherror",4]],["serviceerror",4]],[[]],[[],[["error",8],["option",4,["error"]]]],[[],["string",3]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],null,null,null,null,[[],["string",3]],[[]],[[]],[[]],[[]],[[],["publickey",3]],[[]],[[["publickey",3]],["bool",15]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[]],[[["str",15]],["serviceresult",6]],[[]],[[]],[[]],[[]],[[["publickey",3]],["bool",15]],[[]],[[],["publickey",3]],[[],["signature",3]],[[],[["u8",15],["vec",3,["u8"]]]],[[]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],[[],["bool",15]],[[],["bool",15]]],"p":[[4,"Code"],[4,"IDType"],[3,"SignedHash"],[3,"SignedHashAsciiArmored"],[3,"ReportMessage"],[4,"ServiceError"],[13,"Base64Error"],[13,"MultihashError"],[3,"PublicKey"],[3,"Identity"]]}\
}');
if (window.initSearch) {window.initSearch(searchIndex)};