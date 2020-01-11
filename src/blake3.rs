use byteorder::{ByteOrder, NetworkEndian};
use blake3;
use serde_json::Value;


// SHA256 digest of the UTF-8 encoding the word `NULL`(bytes: 0x4e,0x55,0x4c,0x4c)
const NULL  : &'static [u8] = &[
    0x22,0x3e,0x36,0x4f,0xf2,0x2a,0xb5,0xdc,
    0xa1,0x2f,0x48,0xea,0x1d,0x6a,0xf1,0xd1,
    0x9d,0x1f,0xc7,0x29,0x06,0xca,0xbd,0x8d,
    0x15,0x34,0x8f,0x55,0xfe,0xdd,0x2d,0x92,
];
// SHA256 digest of the UTF-8 encoding the word `TRUE`(bytes: 0x54,0x52,0x55,0x45)
const TRUE  : &'static [u8] = &[
    0x95,0xab,0xc5,0x06,0x6f,0x98,0x84,0x5d,
    0x95,0xd5,0xaa,0xbb,0xbb,0x9e,0xdf,0x98,
    0x3e,0xb4,0x32,0x44,0xe2,0x1d,0x35,0xf6,
    0xcb,0xc5,0xc0,0xce,0xbc,0x25,0xa1,0xe7,
];
// SHA256 digest of the UTF-8 encoding the word `FALSE`(bytes: 0x46,0x41,0x4c,0x53,0x45)
const FALSE : &'static [u8] = &[
    0x0f,0x2f,0xfe,0xa4,0xa5,0xb0,0xc2,0x5c,
    0xa1,0x01,0x00,0x9d,0xe4,0xab,0x4f,0x76,
    0x8c,0x5c,0x63,0x6f,0x50,0xc0,0xda,0xe8,
    0x2a,0x94,0x5b,0xe4,0x5a,0xb1,0xe8,0x26,
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
            let digest = blake3::hash(&bytes);
            for (l, r) in acc.iter_mut().zip(digest.as_bytes().iter()) { *l ^= *r }
        },
        Value::String(s) => {
            let bytes = s.as_bytes();
            let digest = blake3::hash(&bytes);
            for (l, r) in acc.iter_mut().zip(digest.as_bytes().iter()) { *l ^= *r }
        },
        Value::Array(a) => {
            for (i, v) in a.iter().enumerate() {
                let mut index_bytes = [0u8;8];
                NetworkEndian::write_f64(&mut index_bytes, i as f64);
                let index_digest = blake3::hash(&index_bytes);
                let mut value_digest = [0u8;32];
                json_digest (&mut value_digest, v);
                // fuse the index digest into the value digest via bitwise AND
                for (l, r) in value_digest.iter_mut().zip(index_digest.as_bytes().iter()) { *l &= *r }
                // fuse the results in value_digest into our accumulator
                for (l, r) in acc.iter_mut().zip(value_digest.iter()) { *l ^= *r }
            }
        },
        Value::Object(o) => {
            for (k, v) in o.iter() {
                let key_bytes = k.as_bytes();
                let key_digest = blake3::hash(&key_bytes);
                let mut value_digest = [0u8;32];
                json_digest (&mut value_digest, v);
                // fuse the key digest into the value digest via bitwise AND
                for (l, r) in value_digest.iter_mut().zip(key_digest.as_bytes().iter()) { *l &= *r }
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
    fn arrays_with_same_elements_in_diffent_orders_should_have_different_digests() {
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
    fn objects_with_the_same_properties_in_different_orders_should_have_the_same_digest() {
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
