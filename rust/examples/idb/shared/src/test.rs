use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufReader, BufWriter, Seek};
use std::path::{Path, PathBuf};

use anyhow::ensure;

use crate::{IDBParser, IDBSectionCompression, TILSection};

#[test]
fn parse_idbs() {
    let files = find_all("resources/idbs".as_ref(), &["idb".as_ref(), "i64".as_ref()]).unwrap();
    for filename in files {
        println!("{}", filename.to_str().unwrap());
        let file = BufReader::new(File::open(&filename).unwrap());
        let mut parser = IDBParser::new(file).unwrap();
        let til = parser.read_til_section(parser.til_section().unwrap());

        // if success, parse next file
        let error = match til {
            Ok(_til) => continue,
            Err(e) => e,
        };

        //otherwise create a decompress version of the file for more testing
        let mut output = BufWriter::new(std::fs::File::create("/tmp/lasterror.til").unwrap());
        parser
            .decompress_til_section(parser.til_section().unwrap(), &mut output)
            .unwrap();
        panic!("{error:?}")
    }
}

#[test]
fn parse_tils() {
    let files = find_all("resources/tils".as_ref(), &["til".as_ref()]).unwrap();
    let results = files
        .into_iter()
        .map(|x| parse_til_file(&x).map_err(|e| (x, e)))
        .collect::<Result<(), _>>();
    let Err((file, error)) = results else {
        // if success, finish the test
        return;
    };
    println!("Unable to parse {}", file.to_str().unwrap());
    //otherwise create a decompress version of the file for more testing
    let mut input = BufReader::new(std::fs::File::open(&file).unwrap());
    let mut output = BufWriter::new(std::fs::File::create("/tmp/lasterror.til").unwrap());
    TILSection::decompress_inner(&mut input, &mut output).unwrap();
    panic!(
        "Unable to parse file `{}`: {error:?}",
        file.to_str().unwrap()
    );
}

fn parse_til_file(file: &Path) -> anyhow::Result<()> {
    println!("TIL file: {}", file.to_str().unwrap());
    // makes sure it don't read out-of-bounds
    let mut input = BufReader::new(std::fs::File::open(file).unwrap());
    // TODO make a SmartReader
    match TILSection::read(&mut input, IDBSectionCompression::None) {
        Ok(_til) => {
            let current = input.seek(std::io::SeekFrom::Current(0))?;
            let end = input.seek(std::io::SeekFrom::End(0))?;
            ensure!(
                current == end,
                "unable to consume the entire TIL file, {current} != {end}"
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn find_all(path: &Path, exts: &[&OsStr]) -> anyhow::Result<Vec<PathBuf>> {
    fn inner_find_all(path: &Path, exts: &[&OsStr], buf: &mut Vec<PathBuf>) -> anyhow::Result<()> {
        for entry in std::fs::read_dir(path).unwrap().map(Result::unwrap) {
            let entry_type = entry.metadata().unwrap().file_type();
            if entry_type.is_dir() {
                inner_find_all(&entry.path(), exts, buf)?;
                continue;
            }

            if !entry_type.is_file() {
                continue;
            }

            let filename = entry.file_name();
            let Some(ext) = Path::new(&filename).extension() else {
                continue;
            };

            if exts.contains(&ext) {
                buf.push(entry.path())
            }
        }
        Ok(())
    }
    let mut result = vec![];
    inner_find_all(path, exts, &mut result)?;
    Ok(result)
}
