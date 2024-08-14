use std::fs::File;
use std::io::BufReader;

use idb_rs::TILSection;

fn main() {
    let file = "/tmp/lasterror.til";
    let file = BufReader::new(File::open(file).unwrap());
    let til = TILSection::parse(file).unwrap();
    println!("TIL: {til:#?}");
}
