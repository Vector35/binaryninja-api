#!/usr/bin/env python
# This is an auto generated unit test file do not edit directly
import os
import unittest
import pickle
import zipfile
import testcommon
import binaryninja
import api_test
import difflib


class TestBinaryNinjaAPI(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.builder = testcommon.TestBuilder("suite/binaries/test_corpus")
        try:
            #Python 2 does not have the encodings option
            self.oracle_test_data = pickle.load(open(os.path.join("suite", "oracle.pkl"), "rUb"), errors="ignore")
        except TypeError:
            self.oracle_test_data = pickle.load(open(os.path.join("suite", "oracle.pkl"), "rU"))
        self.verifybuilder = testcommon.VerifyBuilder("suite/binaries/test_corpus")

    def run_binary_test(self, testfile):
        testname = None
        with zipfile.ZipFile(testfile, "r") as zf:
            testname = zf.namelist()[0]
            zf.extractall()

        self.assertTrue(os.path.exists(testname + ".pkl"), "Test pickle doesn't exist")
        try:
            #Python 2 does not have the encodings option
            binary_oracle = pickle.load(open(testname + ".pkl", "rUb"), errors="ignore")
        except TypeError:
            binary_oracle = pickle.load(open(testname + ".pkl", "rU"))

        test_builder = testcommon.BinaryViewTestBuilder(testname, "suite/binaries/test_corpus")
        for method in test_builder.methods():
            test = getattr(test_builder, method)()
            oracle = binary_oracle[method]
            if test == oracle:
                continue

            result = getattr(test_builder, method).__doc__
            result += ":\n"
            d = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
            skipped_lines = 0
            for delta in d.compare(test, oracle):
                if delta[0] == ' ':
                    skipped_lines += 1
                    continue
                if skipped_lines > 0:
                    result += "<---" + str(skipped_lines) + ' same lines--->\n'
                    skipped_lines = 0
                delta = delta.replace('\n', '')
                result += delta + '\n'
            self.assertTrue(False, result)
        os.unlink(testname)

    def test_Architecture(self):
        oracle = self.oracle_test_data['test_Architecture']
        test = self.builder.test_Architecture()
        result = ""
        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        skipped_lines = 0
        for delta in differ.compare(test, oracle):
            if delta[0] == ' ':
                skipped_lines += 1
                continue
            if skipped_lines > 0:
                result += "<---" + str(skipped_lines) + ' same lines--->\n'
                skipped_lines = 0
            delta = delta.replace('\n', '')
            result += delta + '\n'

        self.assertTrue(oracle == test, result)

    def test_Architecture_list(self):
        oracle = self.oracle_test_data['test_Architecture_list']
        test = self.builder.test_Architecture_list()
        result = ""
        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        skipped_lines = 0
        for delta in differ.compare(test, oracle):
            if delta[0] == ' ':
                skipped_lines += 1
                continue
            if skipped_lines > 0:
                result += "<---" + str(skipped_lines) + ' same lines--->\n'
                skipped_lines = 0
            delta = delta.replace('\n', '')
            result += delta + '\n'

        self.assertTrue(oracle == test, result)

    def test_Assemble(self):
        oracle = self.oracle_test_data['test_Assemble']
        test = self.builder.test_Assemble()
        result = ""
        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        skipped_lines = 0
        for delta in differ.compare(test, oracle):
            if delta[0] == ' ':
                skipped_lines += 1
                continue
            if skipped_lines > 0:
                result += "<---" + str(skipped_lines) + ' same lines--->\n'
                skipped_lines = 0
            delta = delta.replace('\n', '')
            result += delta + '\n'

        self.assertTrue(oracle == test, result)

    def test_BinaryViewType_list(self):
        oracle = self.oracle_test_data['test_BinaryViewType_list']
        test = self.builder.test_BinaryViewType_list()
        result = ""
        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        skipped_lines = 0
        for delta in differ.compare(test, oracle):
            if delta[0] == ' ':
                skipped_lines += 1
                continue
            if skipped_lines > 0:
                result += "<---" + str(skipped_lines) + ' same lines--->\n'
                skipped_lines = 0
            delta = delta.replace('\n', '')
            result += delta + '\n'

        self.assertTrue(oracle == test, result)

    def test_Enumeration(self):
        oracle = self.oracle_test_data['test_Enumeration']
        test = self.builder.test_Enumeration()
        result = ""
        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        skipped_lines = 0
        for delta in differ.compare(test, oracle):
            if delta[0] == ' ':
                skipped_lines += 1
                continue
            if skipped_lines > 0:
                result += "<---" + str(skipped_lines) + ' same lines--->\n'
                skipped_lines = 0
            delta = delta.replace('\n', '')
            result += delta + '\n'

        self.assertTrue(oracle == test, result)

    def test_Function(self):
        oracle = self.oracle_test_data['test_Function']
        test = self.builder.test_Function()
        result = ""
        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        skipped_lines = 0
        for delta in differ.compare(test, oracle):
            if delta[0] == ' ':
                skipped_lines += 1
                continue
            if skipped_lines > 0:
                result += "<---" + str(skipped_lines) + ' same lines--->\n'
                skipped_lines = 0
            delta = delta.replace('\n', '')
            result += delta + '\n'

        self.assertTrue(oracle == test, result)

    def test_Plugin_bin_info(self):
        oracle = self.oracle_test_data['test_Plugin_bin_info']
        test = self.builder.test_Plugin_bin_info()
        result = ""
        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        skipped_lines = 0
        for delta in differ.compare(test, oracle):
            if delta[0] == ' ':
                skipped_lines += 1
                continue
            if skipped_lines > 0:
                result += "<---" + str(skipped_lines) + ' same lines--->\n'
                skipped_lines = 0
            delta = delta.replace('\n', '')
            result += delta + '\n'

        self.assertTrue(oracle == test, result)

    def test_Struct(self):
        oracle = self.oracle_test_data['test_Struct']
        test = self.builder.test_Struct()
        result = ""
        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        skipped_lines = 0
        for delta in differ.compare(test, oracle):
            if delta[0] == ' ':
                skipped_lines += 1
                continue
            if skipped_lines > 0:
                result += "<---" + str(skipped_lines) + ' same lines--->\n'
                skipped_lines = 0
            delta = delta.replace('\n', '')
            result += delta + '\n'

        self.assertTrue(oracle == test, result)

    def test_Types(self):
        oracle = self.oracle_test_data['test_Types']
        test = self.builder.test_Types()
        result = ""
        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        skipped_lines = 0
        for delta in differ.compare(test, oracle):
            if delta[0] == ' ':
                skipped_lines += 1
                continue
            if skipped_lines > 0:
                result += "<---" + str(skipped_lines) + ' same lines--->\n'
                skipped_lines = 0
            delta = delta.replace('\n', '')
            result += delta + '\n'

        self.assertTrue(oracle == test, result)

    def test_events(self):
        oracle = self.oracle_test_data['test_events']
        test = self.builder.test_events()
        result = ""
        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        skipped_lines = 0
        for delta in differ.compare(test, oracle):
            if delta[0] == ' ':
                skipped_lines += 1
                continue
            if skipped_lines > 0:
                result += "<---" + str(skipped_lines) + ' same lines--->\n'
                skipped_lines = 0
            delta = delta.replace('\n', '')
            result += delta + '\n'

        self.assertTrue(oracle == test, result)

    def test_linear_disassembly(self):
        oracle = self.oracle_test_data['test_linear_disassembly']
        test = self.builder.test_linear_disassembly()
        result = ""
        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        skipped_lines = 0
        for delta in differ.compare(test, oracle):
            if delta[0] == ' ':
                skipped_lines += 1
                continue
            if skipped_lines > 0:
                result += "<---" + str(skipped_lines) + ' same lines--->\n'
                skipped_lines = 0
            delta = delta.replace('\n', '')
            result += delta + '\n'

        self.assertTrue(oracle == test, result)

    def test_low_il_stack(self):
        oracle = self.oracle_test_data['test_low_il_stack']
        test = self.builder.test_low_il_stack()
        result = ""
        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        skipped_lines = 0
        for delta in differ.compare(test, oracle):
            if delta[0] == ' ':
                skipped_lines += 1
                continue
            if skipped_lines > 0:
                result += "<---" + str(skipped_lines) + ' same lines--->\n'
                skipped_lines = 0
            delta = delta.replace('\n', '')
            result += delta + '\n'

        self.assertTrue(oracle == test, result)

    def test_med_il_stack(self):
        oracle = self.oracle_test_data['test_med_il_stack']
        test = self.builder.test_med_il_stack()
        result = ""
        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        skipped_lines = 0
        for delta in differ.compare(test, oracle):
            if delta[0] == ' ':
                skipped_lines += 1
                continue
            if skipped_lines > 0:
                result += "<---" + str(skipped_lines) + ' same lines--->\n'
                skipped_lines = 0
            delta = delta.replace('\n', '')
            result += delta + '\n'

        self.assertTrue(oracle == test, result)

    def test_partial_register_dataflow(self):
        oracle = self.oracle_test_data['test_partial_register_dataflow']
        test = self.builder.test_partial_register_dataflow()
        result = ""
        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        skipped_lines = 0
        for delta in differ.compare(test, oracle):
            if delta[0] == ' ':
                skipped_lines += 1
                continue
            if skipped_lines > 0:
                result += "<---" + str(skipped_lines) + ' same lines--->\n'
                skipped_lines = 0
            delta = delta.replace('\n', '')
            result += delta + '\n'

        self.assertTrue(oracle == test, result)

    def test_verify_BNDB_round_trip(self):
        self.assertTrue(self.verifybuilder.test_verify_BNDB_round_trip(), self.test_verify_BNDB_round_trip.__doc__)

    def test_binary___aliased_jumptable(self):
        self.run_binary_test('suite/binaries/test_corpus/aliased_jumptable.zip')

    def test_binary___byte_jump_table(self):
        self.run_binary_test('suite/binaries/test_corpus/byte_jump_table.zip')

    def test_binary___duff(self):
        self.run_binary_test('suite/binaries/test_corpus/duff.zip')

    def test_binary___helloworld(self):
        self.run_binary_test('suite/binaries/test_corpus/helloworld.zip')

    def test_binary___helloworld_armeb(self):
        self.run_binary_test('suite/binaries/test_corpus/helloworld_armeb.zip')

    def test_binary___integer_test(self):
        self.run_binary_test('suite/binaries/test_corpus/integer_test.zip')

    def test_binary___interprocedural_alias(self):
        self.run_binary_test('suite/binaries/test_corpus/interprocedural_alias.zip')

    def test_binary___jump_loop(self):
        self.run_binary_test('suite/binaries/test_corpus/jump_loop.zip')

    def test_binary___jumptable_aarch64(self):
        self.run_binary_test('suite/binaries/test_corpus/jumptable_aarch64.zip')

    def test_binary___jumptable_mips32(self):
        self.run_binary_test('suite/binaries/test_corpus/jumptable_mips32.zip')

    def test_binary___jumptable_multiple_indirect(self):
        self.run_binary_test('suite/binaries/test_corpus/jumptable_multiple_indirect.zip')

    def test_binary___jumptable_no_range_check(self):
        self.run_binary_test('suite/binaries/test_corpus/jumptable_no_range_check.zip')

    def test_binary___jumptable_reordered(self):
        self.run_binary_test('suite/binaries/test_corpus/jumptable_reordered.zip')

    def test_binary___jumptable_x86(self):
        self.run_binary_test('suite/binaries/test_corpus/jumptable_x86.zip')

    def test_binary___jumptable_x86_64(self):
        self.run_binary_test('suite/binaries/test_corpus/jumptable_x86_64.zip')

    def test_binary___loop_constant_propagate(self):
        self.run_binary_test('suite/binaries/test_corpus/loop_constant_propagate.zip')

    def test_binary___ls(self):
        self.run_binary_test('suite/binaries/test_corpus/ls.zip')

    def test_binary___md5(self):
        self.run_binary_test('suite/binaries/test_corpus/md5.zip')

    def test_binary___partial_register_dataflow(self):
        self.run_binary_test('suite/binaries/test_corpus/partial_register_dataflow.zip')

    def test_binary___pe_thumb(self):
        self.run_binary_test('suite/binaries/test_corpus/pe_thumb.zip')

    def test_binary___quick3dcoreplugin_dll(self):
        self.run_binary_test('suite/binaries/test_corpus/quick3dcoreplugin.dll.zip')

    def test_binary___rangecheck(self):
        self.run_binary_test('suite/binaries/test_corpus/rangecheck.zip')

    def test_binary___switch_linux_ppc_le_32(self):
        self.run_binary_test('suite/binaries/test_corpus/switch_linux_ppc_le_32.zip')

    def test_binary___x87(self):
        self.run_binary_test('suite/binaries/test_corpus/x87.zip')


if __name__ == "__main__":
    test_suite = unittest.defaultTestLoader.loadTestsFromModule(api_test)
    test_suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestBinaryNinjaAPI))
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(test_suite)
