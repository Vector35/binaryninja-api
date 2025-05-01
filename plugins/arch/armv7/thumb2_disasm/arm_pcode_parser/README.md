# goal
translate the pseudocode for arm instructions (given in the docs) to target languages

once the pcode is extracted, automatic generation of ultra-accurate disassemblers should become possible

# how
use Grako parser generator, describe the language (pcode.ebnf) and write code generator (codegen.py)

# example
input statement:
```
if n == 15 || BitCount(registers) < 2 || (P == '1' && M == '1') then UNPREDICTABLE
```

output parse tree:
```
[
  "if",
  [
    "n",
    [],
    [
      "==",
      [
        "15",
        []
      ],
      "||",
      [
        "BitCount(",
        [
          "registers",
          []
        ],
        ")"
      ],
      "<",
      [
        "2",
        []
      ],
      "||",
      [
        "(",
        "P",
        [],
        [
          "==",
          [
            "'1'",
            []
          ],
          "&&",
          [
            "M",
            []
          ],
          "==",
          [
            "'1'",
            []
          ]
        ],
        [],
        ")"
      ]
    ]
  ],
  "then",
  "UNPREDICTABLE"
]
```



