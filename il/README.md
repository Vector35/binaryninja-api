# IL schema

These files describe every LLIL, MLIL and HLIL operation once. The C++,
Python and Rust APIs' operand tables, accessors, builders and classes are
generated from them.

- `llil.xml`, `mlil.xml`, `hlil.xml` describe each level's operations.
- `common.xml` holds definitions shared by more than one level.
- `kinds.xml` says how each kind of operand value is spelled in each binding.
- `names.xml` gives the roles and binding spellings of operand names.
- `il.xsd` validates all of the above.
- `ilgen/` is the generator.

Generated code lives between `BEGIN GENERATED` and `END GENERATED`
comments. Edit the schema rather than the generated code.
