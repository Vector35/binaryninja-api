`pdb`
===

[![](https://img.shields.io/crates/v/pdb.svg)](https://crates.io/crates/pdb) [![](https://docs.rs/pdb/badge.svg)](https://docs.rs/pdb/) ![Build Status](https://github.com/willglynn/pdb/actions/workflows/ci.yml/badge.svg)

This is a Rust library that parses Microsoft PDB (Program Database) files.
These files contain debugging information produced by most compilers that
target Windows, including information about symbols, types, modules, and so on.

The PDB format is not documented per sé, but Microsoft has [published
information](https://github.com/Microsoft/microsoft-pdb) in the form of C++
code relating to its use. The PDB format is full of... history, including
support for debugging 16-bit executables, COBOL user-defined types, and myriad
other features. `pdb` does not understand everything about the PDB format,
but it does cover enough to be useful for typical programs compiled today.

[Documentation on docs.rs](https://docs.rs/pdb/).

Design
---

`pdb`'s design objectives are similar to
[`gimli`](https://github.com/gimli-rs/gimli):

* `pdb` works with the original data as it's formatted on-disk as long as
  possible.

* `pdb` parses only what you ask.

* `pdb` can read PDBs anywhere. There's no dependency on Windows, on the
  [DIA SDK](https://msdn.microsoft.com/en-us/library/x93ctkx8.aspx), or on
  the target's native byte ordering.

Usage Example
---

```rust
use pdb::FallibleIterator;
use std::fs::File;

fn main() -> pdb::Result<()> {
    let file = File::open("fixtures/self/foo.pdb")?;
    let mut pdb = pdb::PDB::open(file)?;

    let symbol_table = pdb.global_symbols()?;
    let address_map = pdb.address_map()?;

    let mut symbols = symbol_table.iter();
    while let Some(symbol) = symbols.next()? {
        match symbol.parse() {
            Ok(pdb::SymbolData::Public(data)) if data.function => {
                // we found the location of a function!
                let rva = data.offset.to_rva(&address_map).unwrap_or_default
                println!("{} is {}", rva, data.name);
            }
            _ => {}
        }
    }

    Ok(())
}
```

Example Programs
---

Run with `cargo run --release --example <name>`:

* [`pdb_symbols`](examples/pdb_symbols.rs) is a toy program that prints the name and location of every function and
  data value defined in the symbol table.

* [`pdb2hpp`](examples/pdb2hpp.rs) is a somewhat larger program that prints an approximation of a C++ header file for
  a requested type given only a PDB.

* [`pdb_lines`](examples/pdb_lines.rs) outputs line number information for every symbol in every module contained in
  a PDB.

Real-world examples:

* [`mstange/pdb-addr2line`](https://github.com/mstange/pdb-addr2line) resolves addresses to function names, and to file name and line number information, with the help of a PDB file. Inline stacks are supported.

* [`getsentry/symbolic`](https://github.com/getsentry/symbolic) is a high-level symbolication library supporting most common debug file formats, demangling, and more.

License
---

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Contribution
---

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
