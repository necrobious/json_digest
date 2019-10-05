use byteorder::{ByteOrder, NetworkEndian};
use sodiumoxide::crypto::hash::sha512;
use serde_json::Value;

// SHA512 digest of the UTF-8 encoding the word `NULL`(bytes: 0x4e,0x55,0x4c,0x4c)
const NULL  : &'static [u8] = &[
    0x13,0xa7,0xce,0x3d,0xf1,0x60,0x67,0x94,
    0xd0,0x01,0xbc,0xc7,0x35,0x02,0x3f,0x39,
    0x1e,0x42,0xd0,0xae,0x3a,0xdd,0x62,0x7a,
    0xb1,0x45,0x35,0x49,0x26,0x47,0xe9,0x52,
    0x5c,0x4f,0xc5,0x83,0xbf,0x21,0x85,0x6e,
    0x32,0x25,0x68,0xd7,0x0c,0xc6,0x10,0x55,
    0x80,0xe2,0x20,0x33,0x31,0xd8,0x0e,0x59,
    0xf0,0xc9,0xdb,0x73,0x39,0x3d,0xc8,0xb9,
];

// SHA512 digest of the UTF-8 encoding the word `TRUE`(bytes: 0x54,0x52,0x55,0x45)
const TRUE  : &'static [u8] = &[
    0x33,0xb8,0x0f,0xb9,0x5b,0xab,0x15,0x5f,
    0x35,0xcf,0x0f,0xd1,0xf1,0x85,0x05,0x8f,
    0x6d,0xa3,0x1a,0x03,0x66,0xd0,0x5f,0x40,
    0xc7,0xe0,0xf0,0xf2,0x14,0x9f,0xe8,0xb7,
    0x1c,0xf4,0xfc,0x0f,0x2e,0x5c,0x8a,0x56,
    0x6a,0x1c,0xf9,0xde,0x5a,0xf0,0x87,0xc3,
    0xfe,0xf2,0xf9,0x11,0xee,0x7a,0x62,0x81,
    0x45,0xae,0xe2,0xac,0x96,0xce,0x94,0xec,
];

// SHA512 digest of the UTF-8 encoding the word `FALSE`(bytes: 0x46,0x41,0x4c,0x53,0x45)
const FALSE : &'static [u8] = &[
    0xc4,0x24,0xd8,0xc6,0x5e,0x21,0xdf,0x09,
    0xd0,0xca,0x85,0x1c,0xf5,0x79,0xc7,0x53,
    0x63,0x3b,0x2f,0x76,0xd3,0x89,0x60,0xce,
    0xb2,0x0d,0x5c,0x1f,0x2a,0xde,0x13,0xd7,
    0xa5,0x90,0x98,0x00,0xa1,0x1f,0x5f,0xad,
    0x3c,0x87,0x15,0x40,0x70,0x14,0x85,0x9e,
    0xde,0x58,0xe9,0x44,0xfb,0x53,0x10,0x18,
    0x64,0x26,0x68,0x82,0x47,0x28,0x66,0xdb,
];

pub fn json_digest <'a> (acc: &'a mut [u8;64], val: &Value) {
    match val {
        Value::Null => {
            for (l, r) in acc.iter_mut().zip(NULL.iter()) { *l ^= *r }
        },
        Value::Bool(true) => {
            for (l, r) in acc.iter_mut().zip(TRUE.iter()) { *l ^= *r }
        },
        Value::Bool(false) => {
            for (l, r) in acc.iter_mut().zip(FALSE.iter()) { *l ^= *r }
        },
        Value::Number(n) => {
            let as_f64 =
                if n.is_i64() {
                    n.as_i64().unwrap() as f64
                }
                else if n.is_u64() {
                    n.as_u64().unwrap() as f64
                }
                else {
                    n.as_f64().unwrap()
                };

            let mut bytes = [0u8;8];
            NetworkEndian::write_f64(&mut bytes, as_f64);
            let digest = sha512::hash(&bytes).0;
            for (l, r) in acc.iter_mut().zip(digest.iter()) { *l ^= *r }
        },
        Value::String(s) => {
            let bytes = s.as_bytes();
            let digest = sha512::hash(&bytes).0;
            for (l, r) in acc.iter_mut().zip(digest.iter()) { *l ^= *r }
        },
        Value::Array(a) => {
            for (i, v) in a.iter().enumerate() {
                let mut index_bytes = [0u8;8];
                NetworkEndian::write_f64(&mut index_bytes, i as f64);
                let index_digest = sha512::hash(&index_bytes).0;
                let mut value_digest = [0u8;64];
                json_digest (&mut value_digest, v);
                // fuse the index digest into the value digest via bitwise AND
                for (l, r) in value_digest.iter_mut().zip(index_digest.iter()) { *l &= *r }
                // fuse the results in value_digest into our accumulator via bitwise XOR
                for (l, r) in acc.iter_mut().zip(value_digest.iter()) { *l ^= *r }
            }
        },
        Value::Object(o) => {
            for (k, v) in o.iter() {
                let key_bytes = k.as_bytes();
                let key_digest = sha512::hash(&key_bytes).0;
                let mut value_digest = [0u8;64];
                json_digest (&mut value_digest, v);
                // fuse the key digest into the value digest via bitwise AND
                for (l, r) in value_digest.iter_mut().zip(key_digest.iter()) { *l &= *r }
                // fuse the results in value_digest into our accumulator via bitwise XOR
                for (l, r) in acc.iter_mut().zip(value_digest.iter()) { *l ^= *r }
            }
        },
    }
}


#[cfg(test)]
mod tests {

    use serde_json::{Value};

    const TEST_VECTOR_1:&'static str = r###"
{
    "a": [1,2,"3"],
    "b": false
}
"###;


    const TEST_VECTOR_2:&'static str = r###"
{
    "b": false,
    "a": [1,2,"3"]
}
"###;

    const TEST_VECTOR_3:&'static str = r###"
{
    "a": [1,2,"3"]
}
"###;

    const TEST_VECTOR_4:&'static str = r###"
{
    "a": ["3",1,2]
}
"###;


    #[test]
    fn arrays_with_same_elements_should_have_different_digests() {
        let v3 = serde_json::from_str::<Value>(TEST_VECTOR_3).unwrap();
        let mut buf3 = [0u8;64];
        super::json_digest(&mut buf3, &v3);

        let v4 = serde_json::from_str::<Value>(TEST_VECTOR_4).unwrap();
        let mut buf4 = [0u8;64];
        super::json_digest(&mut buf4, &v4);

        let mut acc = 0;
        for (b3,b4) in buf3.iter().zip(buf4.iter()) {
            acc ^= *b3 ^ *b4;
        }
        assert!(acc != 0);
    }


    #[test]
    fn the_same_digest_is_produced_regardless_of_object_order() {
        let v1 = serde_json::from_str::<Value>(TEST_VECTOR_1).unwrap();
        let mut buf1 = [0u8;64];
        super::json_digest(&mut buf1, &v1);

        let v2 = serde_json::from_str::<Value>(TEST_VECTOR_2).unwrap();
        let mut buf2 = [0u8;64];
        super::json_digest(&mut buf2, &v2);

        for (b1,b2) in buf1.iter().zip(buf2.iter()) {
            assert_eq!(*b1, *b2);
        }

    }
}
