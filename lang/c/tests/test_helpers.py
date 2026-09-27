#!/usr/bin/env python3
"""Compile and execute the standalone header; no Binary Ninja installation needed.

CC/CXX may select compilers. Examples:
    python3 test_helpers.py
    CC=gcc CXX=g++ python3 test_helpers.py --standard c11 --sanitize
"""

import argparse
import json
import os
import random
import shlex
import shutil
import subprocess
import tempfile
from contextlib import nullcontext
from pathlib import Path

HEADER_DIR = Path(__file__).resolve().parents[1]
WIDTHS = [(8, 'B'), (16, 'W'), (32, 'D'), (64, 'Q'), (128, 'O')]


def literal(value, bits):
    if bits == 128:
        return f'(((bn_pseudoc_uint128)UINT64_C(0x{value >> 64:x}) << 64) | UINT64_C(0x{value & ((1 << 64) - 1):x}))'
    return f'UINT{max(32, bits)}_C(0x{value:x})'


def ctype(bits):
    return 'bn_pseudoc_uint128' if bits == 128 else f'uint{bits}_t'


def rotate(value, bits, count, right=False, carry=None):
    # Reference model: move individual bits around a list, including carry.
    ring = list(f'{value:0{bits}b}')
    if carry is not None:
        ring.insert(0, str(carry))
    count %= len(ring)
    for _ in range(count):
        ring = ring[-1:] + ring[:-1] if right else ring[1:] + ring[:1]
    return int(''.join(ring[-bits:]), 2)


def integer_checks():
    rng = random.Random(0x424e)
    source = []
    for bits, suffix in WIDTHS:
        mask = (1 << bits) - 1
        values = [0, 1, mask, mask - 1, 1 << (bits - 1), (1 << (bits - 1)) - 1,
                  mask // 3, mask // 3 * 2] + [rng.getrandbits(bits) for _ in range(12)]
        counts = sorted({0, 1, 2, bits - 1, bits, bits + 1, bits + 2, 2 * bits,
                         2 * bits + 1, 255, 256, 257, (1 << 64) - 1})
        if bits == 128:
            source.append('#if BN_PSEUDOC_HAS_INT128')
        source.append('{')
        source.append(f'static const struct {{ {ctype(bits)} value; uint64_t count; '
                      f'{ctype(bits)} expected[6]; }} rotations[] = {{')
        for value in values:
            for count in counts:
                expected = [rotate(value, bits, count, right) for right in [False, True]]
                expected += [rotate(value, bits, count, right, carry)
                             for right in [False, True] for carry in [0, 1]]
                source.append('{' + literal(value, bits) + f', UINT64_C({count}), {{'
                              + ', '.join(literal(v, bits) for v in expected) + '}},')
        source.append('};\nfor (size_t i = 0; i < sizeof(rotations)/sizeof(rotations[0]); ++i) {')
        for index, (operation, extra) in enumerate([('ROL', ''), ('ROR', ''), ('RLC', ', false'),
                                                  ('RLC', ', true'), ('RRC', ', false'), ('RRC', ', true')]):
            source.append(f'CHECK({operation}{suffix}(rotations[i].value, rotations[i].count{extra}) '
                          f'== rotations[i].expected[{index}]);')
        source.append('}')
        # All one-bit inputs, plus random and signed boundaries. Reverse and CLS
        # expectations come from strings rather than the implementation's loops.
        bit_values = values + [1 << index for index in range(bits)]
        source.append(f'static const struct {{ {ctype(bits)} value, reversed; unsigned cls; }} bit_cases[] = {{')
        for value in bit_values:
            text = f'{value:0{bits}b}'
            leading = len(text) - len(text.lstrip(text[0])) - 1
            source.append('{' + literal(value, bits) + ', ' + literal(int(text[::-1], 2), bits)
                          + f', {leading}' + '},')
        source.append('};\nfor (size_t i = 0; i < sizeof(bit_cases)/sizeof(bit_cases[0]); ++i) {')
        source.append(f'CHECK(__rbit(bit_cases[i].value) == bit_cases[i].reversed);\n'
                      f'CHECK(__cls(bit_cases[i].value) == bit_cases[i].cls);\n'
                      f'for (unsigned j = 0; j < {bits}; ++j) '
                      f'CHECK(TEST_BIT{suffix}(bit_cases[i].value, j) == ((bit_cases[i].value >> j) & 1));\n'
                      f'CHECK(!TEST_BIT{suffix}(bit_cases[i].value, {bits}));\n'
                      f'CHECK(!TEST_BIT{suffix}(bit_cases[i].value, UINT64_MAX));\n}}')
        source.append('}')
        if bits == 128:
            source.append('#endif')
    for bits, suffix in WIDTHS[:-1]:
        if bits == 64:
            source.append('#if BN_PSEUDOC_HAS_INT128')
        source.append('{')
        source.append(f'CHECK(sizeof(COMBINE(({ctype(bits)})0, ({ctype(bits)})0)) == {bits // 4});')
        for high in [0, 1, (1 << bits) - 1, 1 << (bits - 1)]:
            for low in [0, 1, (1 << bits) - 1, 1 << (bits - 1)]:
                joined = literal((high << bits) | low, bits * 2)
                source.append(f'CHECK(COMBINE((int{bits}_t){literal(high, bits)}, '
                              f'(int{bits}_t){literal(low, bits)}) == {joined});\n'
                              f'CHECK(HIGH{suffix}({joined}) == {literal(high, bits)});\n'
                              f'CHECK(LOW{suffix}({joined}) == {literal(low, bits)});')
        source.append('}')
        if bits == 64:
            source.append('#endif')
    # Dispatch must support different native types that happen to share a width.
    for signed in ['signed char', 'short', 'int', 'long', 'long long']:
        source.append(f'CHECK(__cls(({signed})-1) == sizeof({signed}) * CHAR_BIT - 1);\n'
                      f'CHECK(__rbit(({signed})1) == (UINT64_C(1) << (sizeof({signed}) * CHAR_BIT - 1)));')
    source.append('enum Choice { chosen = 1 };\nCHECK(__cls(chosen) == sizeof(chosen) * CHAR_BIT - 2);')
    return '\n'.join(source)


def representation_checks():
    source = []
    for bits, floating, exponent, quiet in [(16, 'float16_t', 0x7c00, 0x200),
                                          (32, 'float', 0x7f800000, 0x400000),
                                          (64, 'double', 0x7ff0000000000000, 0x8000000000000)]:
        if bits == 16:
            source.append('#if BN_PSEUDOC_HAS_FLOAT16')
        source.append('{')
        values = [0, 1, 1 << (bits - 1), exponent - 1, exponent, exponent | 1,
                  exponent | quiet, exponent | quiet | 0x123, (1 << bits) - 1]
        for value in values:
            source.append(f'{{ {ctype(bits)} expected = {literal(value, bits)}; '
                          f'{floating} value = BIT_CAST({floating}, expected); {ctype(bits)} actual;\n'
                          'memcpy(&actual, &value, sizeof(actual)); CHECK(actual == expected);\n'
                          f'CHECK(BIT_CAST({ctype(bits)}, value) == expected);\n'
                          f'{floating} partial = READ_PART({floating}, expected, 0);\n'
                          'memcpy(&actual, &partial, sizeof(actual)); CHECK(actual == expected);\n'
                          f'actual = 0; WRITE_PART({floating}, actual, 0, partial); CHECK(actual == expected); }}')
        source.append('}')
        if bits == 16:
            source.append('#endif')
    # Byte-based reference checks every valid offset, including unaligned fields.
    for size, floating in [(4, 'float'), (8, 'double')]:
        for part in [1, 2, 4]:
            for offset in range(size - part + 1):
                source.append(f'{{ unsigned char original[{size}], expected[{size}]; '
                              f'{floating} value; uint{part * 8}_t replacement = (uint{part * 8}_t)0xa5b6c7d8;\n'
                              f'for (unsigned i = 0; i < {size}; ++i) original[i] = (unsigned char)(0x19 * i + 3);\n'
                              'memcpy(&value, original, sizeof(value)); memcpy(expected, original, sizeof(expected));\n'
                              f'uint{part * 8}_t read = READ_PART(uint{part * 8}_t, value, {offset});\n'
                              f'CHECK(memcmp(&read, original + {offset}, sizeof(read)) == 0);\n'
                              f'WRITE_PART(uint{part * 8}_t, value, {offset}, replacement);\n'
                              f'memcpy(expected + {offset}, &replacement, sizeof(replacement));\n'
                              'CHECK(memcmp(&value, expected, sizeof(value)) == 0); }')
    source.append('''
    int evaluations = 0;
    uint32_t bits = UINT32_C(0x7f812345);
    float value = BIT_CAST(float, (++evaluations, bits));
    CHECK(evaluations == 1);
    uint32_t read = READ_PART(uint32_t, (++evaluations, value), 0);
    CHECK(evaluations == 2 && read == bits);
    uint64_t destination[2] = {0, 0};
    int index = 0;
    WRITE_PART(uint32_t, destination[index++], 0, (uint32_t)(index == 1 ? 7 : 9));
    CHECK(index == 1);
    uint32_t written;
    memcpy(&written, destination, sizeof(written));
    CHECK(written == 7 && destination[1] == 0);
    int high_count = 0, low_count = 0;
    CHECK(COMBINE((uint8_t)(++high_count), (uint8_t)(++low_count)) == 257);
    CHECK(high_count == 1 && low_count == 1);
    int a = 1, b = 2;
    CHECK(min(a++, b++) == 1 && a == 2 && b == 3);
    CHECK(max(a++, b++) == 3 && a == 3 && b == 4);
    unsigned calls = 0;
    CHECK(__rbit((uint8_t)(++calls)) == 128 && calls == 1);
    CHECK(__cls((uint8_t)(++calls)) == 5 && calls == 2);
    CHECK(LOWB(++calls) == 3 && calls == 3);
    CHECK(FCMP_UO(NAN, 0.0) && FCMP_UO(0.0, NAN));
    CHECK(!FCMP_O(NAN, NAN) && FCMP_O(-0.0, 0.0));
    CHECK(isinf(INFINITY) && isnan(NAN));
    CHECK(sizeof(BIT_CAST(const uint32_t, value)) == sizeof(value));
    CHECK(READ_PART(const uint32_t, value, 0) == bits);
    CHECK(READ_PART(volatile uint32_t, value, 0) == bits);
    ''')
    return '\n'.join(source)


INVALID = {
    'bit-cast-size': 'uint64_t a = BIT_CAST(uint64_t, (uint32_t)0); (void)a;',
    'read-bounds': 'uint32_t a = READ_PART(uint32_t, (uint32_t)0, 1); (void)a;',
    'read-negative': 'uint32_t a = READ_PART(uint32_t, (uint64_t)0, -1); (void)a;',
    'read-dynamic': 'uint32_t a = READ_PART(uint32_t, (uint64_t)0, argc); (void)a;',
    'write-size': 'uint64_t a = 0; WRITE_PART(uint16_t, a, 0, (uint32_t)0);',
    'write-bounds': 'uint64_t a = 0; WRITE_PART(uint32_t, a, 5, (uint32_t)0);',
    'write-negative': 'uint64_t a = 0; WRITE_PART(uint32_t, a, -1, (uint32_t)0);',
    'write-dynamic': 'uint64_t a = 0; WRITE_PART(uint32_t, a, argc, (uint32_t)0);',
    'write-const': 'const uint64_t a = 0; WRITE_PART(uint32_t, a, 0, (uint32_t)0);',
    'write-volatile': 'volatile uint64_t a = 0; WRITE_PART(uint32_t, a, 0, (uint32_t)0);',
    'combine-size': '(void)COMBINE((uint8_t)0, (uint16_t)0);',
    'combine-float': '(void)COMBINE(1.0f, (uint32_t)0);',
    'rbit-float': '(void)__rbit(1.0f);',
    'cls-float': '(void)__cls(1.0f);',
}


def compiler_command(standard, compiler=None):
    if compiler:
        return [compiler]
    variable, defaults = ('CXX', ['clang++', 'g++']) if standard.startswith('c++') else ('CC', ['clang', 'gcc'])
    if variable in os.environ:
        return shlex.split(os.environ[variable])
    for name in defaults:
        compiler = shutil.which(name)
        if compiler:
            return [compiler]
    raise RuntimeError(f'No compiler found; set {variable}')


def driver_for(compiler, driver):
    if driver != 'auto':
        return driver
    return 'clang-cl' if Path(compiler[0]).stem.lower() == 'clang-cl' or '--driver-mode=cl' in compiler else 'gnu'


def run(standard, optimization, sanitize=False, compiler=None, driver='auto', no_run=False,
        compile_only=False, output_dir=None):
    compiler = compiler_command(standard, compiler)
    driver = driver_for(compiler, driver)
    print(f'Testing {shlex.join(compiler)} {standard} {optimization} ({driver}, UBSan={sanitize})', flush=True)
    if driver == 'clang-cl':
        if standard == 'c++11':
            raise ValueError('Use c++14 or c++17 with the Clang-CL driver and Microsoft C++ library')
        if sanitize:
            raise ValueError('The --sanitize checks require a GNU-style compiler driver')
        flags = ['/nologo', '/W4', '/WX', '/fp:strict', '/MT', '/I' + str(HEADER_DIR),
                 '/Od' if optimization == '-O0' else '/O2', '/std:' + standard]
        flags += ['/TP', '/EHsc'] if standard.startswith('c++') else ['/TC']
    else:
        flags = [f'-std={standard}', optimization, '-Wall', '-Wextra', '-Werror', '-fno-fast-math',
                 '-I', str(HEADER_DIR)]
    if sanitize:
        flags.extend(['-fsanitize=undefined', '-fno-sanitize-recover=all'])
    flags += shlex.split(os.environ.get('CXXFLAGS' if standard.startswith('c++') else 'CFLAGS', ''))
    link_flags = shlex.split(os.environ.get('LDFLAGS', ''))
    context = nullcontext(output_dir) if output_dir else tempfile.TemporaryDirectory(prefix='pseudoc-helpers-')
    with context as directory:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        report = {'compiler': compiler, 'driver': driver, 'standard': standard, 'optimization': optimization,
                  'compile_only': compile_only, 'execution_requested': not (no_run or compile_only), 'cases': []}

        def compile_source(name, program, valid=True):
            source = root / (name + ('.cpp' if standard.startswith('c++') else '.c'))
            object_file = root / (name + ('.obj' if driver == 'clang-cl' else '.o'))
            executable = root / (name + ('.exe' if driver == 'clang-cl' or os.name == 'nt' else ''))
            source.write_text(program)
            # Invalid cases must fail compilation, not merely fail to link.
            object_only = compile_only or not valid
            if driver == 'clang-cl':
                command = compiler + flags + [str(source), '/Fo' + str(object_file)]
                command += ['/c'] if object_only else ['/Fe' + str(executable)] + link_flags
            else:
                command = compiler + flags + [str(source)]
                command += ['-c', '-o', str(object_file)] if object_only else ['-o', str(executable), '-lm'] + link_flags
            result = subprocess.run(command, capture_output=True, text=True, timeout=90)
            (root / (name + '.compiler.log')).write_text(result.stdout + result.stderr)
            record = {'name': name, 'command': command, 'compile_exit': result.returncode,
                      'expected_valid': valid, 'executed': False}
            report['cases'].append(record)
            (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
            if not valid:
                assert result.returncode != 0, f'Invalid input compiled successfully:\n{program}'
                return
            assert result.returncode == 0, result.stderr
            if not (no_run or compile_only):
                result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30)
                record.update(executed=True, run_exit=result.returncode)
                (root / (name + '.run.log')).write_text(result.stdout + result.stderr)
                (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
                assert result.returncode == 0, result.stdout + result.stderr

        preamble = '''#include "pseudoc_helpers.h"
#include "pseudoc_helpers.h"
#include <stdio.h>
#ifdef __cplusplus
#include <algorithm>
#include <vector>
#endif
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "line %d: %s\\n", __LINE__, #expr); return 1; } } while (0)
'''
        compile_source('semantics', preamble + 'int main(void) {\n' + integer_checks() + '\n' + representation_checks()
                       + '\nreturn 0; }\n')
        # Users may opt out when native SDKs or their own definitions supply names.
        compile_source('overrides', '''#define BN_PSEUDOC_NO_MINMAX
#define BN_PSEUDOC_NO_EXTENDED_TYPES
#define BN_PSEUDOC_NO_BIT_INTRINSICS
typedef struct { char payload[3]; } float16_t;
#define __rbit(value) (value)
#define __cls(value) (value)
#define BIT_CAST(type, value) ((type)(value))
#define min(a, b) 71
#define max(a, b) 72
#include "pseudoc_helpers.h"
int main(void) { return sizeof(float16_t) != 3 || min(0, 0) != 71
    || max(0, 0) != 72
    || __rbit(7) != 7 || __cls(9) != 9 || BIT_CAST(int, 11) != 11; }
''')
        compile_source('minmax', '''#define min(a, b) 71
#define max(a, b) 72
#include "pseudoc_helpers.h"
#ifndef min
#error "The caller's min macro was removed"
#endif
#ifndef max
#error "The caller's max macro was removed"
#endif
int main(void) { return min(0, 0) != 71 || max(0, 0) != 72; }
''')
        for name, statement in INVALID.items():
            try:
                compile_source(name, '#include "pseudoc_helpers.h"\nint main(int argc, char** argv) {\n'
                               '(void)argc; (void)argv;\n' + statement + '\nreturn 0; }', valid=False)
            except AssertionError as error:
                raise AssertionError(f'{name}: {error}') from error
        if standard.startswith('c++'):
            compile_source('nontrivial', '#include "pseudoc_helpers.h"\n'
                           'struct Nontrivial { int value; ~Nontrivial() {} };\n'
                           'int main() { (void)BIT_CAST(int, Nontrivial()); }', valid=False)
        print('Valid programs compiled' + ('' if compile_only else ' and linked')
              + '; invalid-input compilation rejected'
              + ('; execution skipped.' if no_run or compile_only else '; execution checks passed.'), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--standard', choices=['c11', 'c++11', 'c++14', 'c++17'])
    parser.add_argument('--optimization', choices=['O0', 'O2'], default='O2')
    parser.add_argument('--sanitize', action='store_true', help='Requires a compiler with UBSan')
    parser.add_argument('--compiler', help='Compiler executable; defaults to CC/CXX or compiler discovery')
    parser.add_argument('--driver', choices=['auto', 'gnu', 'clang-cl'], default='auto')
    parser.add_argument('--no-run', action='store_true', help='Compile and link without executing (cross compilation)')
    parser.add_argument('--compile-only', action='store_true', help='Compile objects without linking or executing')
    parser.add_argument('--output-dir', type=Path, help='Keep sources, commands, diagnostics, and programs here')
    arguments = parser.parse_args()
    modes = [arguments.standard] if arguments.standard else ['c11', 'c++11', 'c++17']
    if not arguments.standard and driver_for(compiler_command('c++17', arguments.compiler), arguments.driver) == 'clang-cl':
        modes = ['c11', 'c++14', 'c++17']
    for mode in modes:
        output = arguments.output_dir / mode if arguments.output_dir else None
        run(mode, '-' + arguments.optimization, arguments.sanitize, arguments.compiler, arguments.driver,
            arguments.no_run, arguments.compile_only, output)
