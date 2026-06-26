// Copyright 2017 pdb Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The `pdb` create parses Microsoft PDB (Program Database) files. PDB files contain debugging
//! information produced by most compilers that target Windows, including information about symbols,
//! types, modules, and so on.
//!
//! # Usage
//!
//! PDB files are accessed via the [`pdb::PDB`] object.
//!
//! # Example
//!
//! ```
//! # use pdb::FallibleIterator;
//! #
//! # fn test() -> pdb::Result<usize> {
//! let file = std::fs::File::open("fixtures/self/foo.pdb")?;
//! let mut pdb = pdb::PDB::open(file)?;
//!
//! let symbol_table = pdb.global_symbols()?;
//! let address_map = pdb.address_map()?;
//!
//! # let mut count: usize = 0;
//! let mut symbols = symbol_table.iter();
//! while let Some(symbol) = symbols.next()? {
//!     match symbol.parse() {
//!         Ok(pdb::SymbolData::Public(data)) if data.function => {
//!             // we found the location of a function!
//!             let rva = data.offset.to_rva(&address_map).unwrap_or_default();
//!             println!("{} is {}", rva, data.name);
//!             # count += 1;
//!         }
//!         _ => {}
//!     }
//! }
//!
//! # Ok(count)
//! # }
//! # assert!(test().expect("test") > 2000);
//! ```

#![allow(non_upper_case_globals)]

// modules
mod common;
mod dbi;
mod framedata;
mod modi;
mod msf;
mod omap;
mod pdb;
mod pdbi;
mod pe;
pub mod register;
mod source;
mod strings;
mod symbol;
mod tpi;

// exports
pub use crate::common::*;
pub use crate::dbi::*;
pub use crate::framedata::*;
pub use crate::modi::*;
pub use crate::omap::*;
pub use crate::pdb::*;
pub use crate::pdbi::*;
pub use crate::pe::*;
pub use crate::source::*;
pub use crate::strings::*;
pub use crate::symbol::*;
pub use crate::tpi::*;

// re-export FallibleIterator for convenience
#[doc(no_inline)]
pub use fallible_iterator::FallibleIterator;
