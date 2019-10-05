use byteorder::{ByteOrder, NetworkEndian};
use sodiumoxide::crypto::hash::sha256;
use serde_json::Value;


// SHA256 digest of the UTF-8 encoding the word `NULL`(bytes: 0x4e,0x55,0x4c,0x4c)
const NULL  : &'static [u8] = &[
    0xfb,0x32,0x90,0x00,0x22,0x8c,0xc5,0xa2,
    0x4c,0x26,0x4c,0x57,0x13,0x9d,0xe8,0xbf,
    0x85,0x4f,0xc8,0x6f,0xc1,0x8b,0xf1,0xc0,
    0x4a,0xb6,0x1a,0x2b,0x5c,0xb4,0xb9,0x21,
];
// SHA256 digest of the UTF-8 encoding the word `TRUE`(bytes: 0x54,0x52,0x55,0x45)
const TRUE  : &'static [u8] = &[
    0xdf,0xe8,0x80,0x90,0xc5,0xed,0x7a,0xc2,
    0xf3,0x25,0x71,0xf0,0xfc,0x82,0x2f,0xda,
    0x4d,0x8c,0xd2,0x81,0xfc,0x71,0x38,0xc7,
    0xcd,0x6d,0xb6,0x56,0xf6,0xe2,0xd0,0x81,
];
// SHA256 digest of the UTF-8 encoding the word `FALSE`(bytes: 0x46,0x41,0x4c,0x53,0x45)
const FALSE : &'static [u8] = &[
    0x4e,0x52,0x3a,0x5a,0xe5,0xb4,0x63,0x6c,
    0x75,0x90,0x1b,0x79,0xfa,0xfb,0xd3,0x91,
    0x2e,0x41,0xdc,0x79,0x87,0x41,0x4e,0x68,
    0x8b,0x09,0xd4,0xb4,0x36,0xff,0x22,0xb3,
];

pub fn json_digest <'a> (acc: &'a mut [u8;32], val: &Value) {
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
            let digest = sha256::hash(&bytes).0;
            for (l, r) in acc.iter_mut().zip(digest.iter()) { *l ^= *r }
        },
        Value::String(s) => {
            let bytes = s.as_bytes();
            let digest = sha256::hash(&bytes).0;
            for (l, r) in acc.iter_mut().zip(digest.iter()) { *l ^= *r }
        },
        Value::Array(a) => {
            for (i, v) in a.iter().enumerate() {
                let mut index_bytes = [0u8;8];
                NetworkEndian::write_f64(&mut index_bytes, i as f64);
                let index_digest = sha256::hash(&index_bytes).0;
                let mut value_digest = [0u8;32];
                json_digest (&mut value_digest, v);
                // fuse the index digest into the value digest via bitwise AND
                for (l, r) in value_digest.iter_mut().zip(index_digest.iter()) { *l &= *r }
                // fuse the results in value_digest into our accumulator
                for (l, r) in acc.iter_mut().zip(value_digest.iter()) { *l ^= *r }
            }
        },
        Value::Object(o) => {
            for (k, v) in o.iter() {
                let key_bytes = k.as_bytes();
                let key_digest = sha256::hash(&key_bytes).0;
                let mut value_digest = [0u8;32];
                json_digest (&mut value_digest, v);
                // fuse the key digest into the value digest via bitwise AND
                for (l, r) in value_digest.iter_mut().zip(key_digest.iter()) { *l &= *r }
                // fuse the results in value_digest into our accumulator
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
        let mut buf3 = [0u8;32];
        super::json_digest(&mut buf3, &v3);

        let v4 = serde_json::from_str::<Value>(TEST_VECTOR_4).unwrap();
        let mut buf4 = [0u8;32];
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
        let mut buf1 = [0u8;32];
        super::json_digest(&mut buf1, &v1);

        let v2 = serde_json::from_str::<Value>(TEST_VECTOR_2).unwrap();
        let mut buf2 = [0u8;32];
        super::json_digest(&mut buf2, &v2);

        for (b1,b2) in buf1.iter().zip(buf2.iter()) {
            assert_eq!(*b1, *b2);
        }

    }
}
