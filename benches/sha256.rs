#![feature(test)]
//#![deny(warnings, rust_2018_idioms)]

extern crate test;

use test::Bencher;
use json_digest::sha256::json_digest;
use serde_json::Value;

use serde::Deserialize;

use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

const TEST_VECTOR:&'static str = r###"
{
    "a": ["3",1,2]
}
"###;


#[bench]
fn sha256_calculation_small(b: &mut Bencher) {
    let v = serde_json::from_str::<Value>(TEST_VECTOR).unwrap();
    let mut digest = [0u8;32];
    b.iter(|| {
        json_digest(&mut digest, &v)
    })
}

#[bench]
fn sha256_calculation_large(b: &mut Bencher) {
    // Open the file in read-only mode with buffer.
    let file = File::open("./benches/sf-city-lots-json/citylots.json").unwrap();
    let reader = BufReader::new(file);

    // Read the JSON contents of the file as an instance of `User`.
    let v:Value = serde_json::from_reader(reader).unwrap();

    let mut digest = [0u8;32];
    b.iter(|| {
        json_digest(&mut digest, &v)
    })
}
