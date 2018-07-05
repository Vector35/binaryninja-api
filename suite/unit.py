#!/usr/bin/env python
# This is an auto generated unit test file do not edit directly
import os
import sys
import unittest
import pickle
import zipfile
import testcommon
import api_test
import difflib
from collections import Counter

global verbose
verbose = False


class TestBinaryNinjaAPI(unittest.TestCase):
    # Returns a tuple of:
    #   bool   : Two lists are equal
    #   string : The string diff
    # Args:
    #   list
    #   list   : (compare list one vs list two)
    #   string : anything additional wanted to be printed before the string diff
    #   bool   : the ordering of the items in the two lists must be the same
    def report(self, oracle, test, firstText='', strictOrdering = False):
        stringDiff = ""

        equality = False
        if not strictOrdering:
            equality = (Counter(oracle) == Counter(test))
        else:
            equality = (oracle == test)

        if equality:
            return (True, '')
        elif not strictOrdering:
            try:
                for elem in oracle:
                    test.remove(elem)
                    oracle.remove(elem)  # If it's not in the test, it won't get here!
            except ValueError:
                pass

        differ = difflib.Differ(charjunk=difflib.IS_CHARACTER_JUNK)
        skipped_lines = 0
        for delta in differ.compare(oracle, test):
            if delta[0] == ' ':
                skipped_lines += 1
                continue
            if skipped_lines > 0:
                stringDiff += "<---" + str(skipped_lines) + ' same lines--->\n'
                skipped_lines = 0
            delta = delta.replace('\n', '')
            stringDiff += delta + '\n'

        stringDiffList = stringDiff.split('\n')

        if len(stringDiffList) > 10:
            if not verbose:
                stringDiff = '\n'.join(line if len(line) <= 100 else line[:100] + "...and " + str(len(line) - 100) + " more characters" for line in stringDiffList[:10])
                stringDiff += '\n\n### And ' + str(len(stringDiffList)) + " more lines, use '-v' to show ###"
        elif not verbose:
            stringDiff = '\n'.join(line if len(line) <= 100 else line[:100] + "...and " + str(len(line) - 100) + " more characters" for line in stringDiffList)
        stringDiff = '\n\n' + firstText + stringDiff
        return (equality, stringDiff)

    @classmethod
    def setUpClass(self):
        self.builder = testcommon.TestBuilder("suite/binaries/test_corpus")
        try:
            # Python 2 does not have the encodings option
            self.oracle_test_data = pickle.load(open(os.path.join("suite", "oracle.pkl"), "rb"), encoding='charmap')
        except TypeError:
            self.oracle_test_data = pickle.load(open(os.path.join("suite", "oracle.pkl"), "rb"))
        self.verifybuilder = testcommon.VerifyBuilder("suite/binaries/test_corpus")

    def run_binary_test(self, testfile):
        testname = None
        with zipfile.ZipFile(testfile, "r") as zf:
            testname = zf.namelist()[0]
            zf.extractall()

        self.assertTrue(os.path.exists(testname + ".pkl"), "Test pickle doesn't exist")
        try:
            # Python 2 does not have the encodings option
            binary_oracle = pickle.load(open(testname + ".pkl", "rb"), encoding='charmap')
        except TypeError:
            binary_oracle = pickle.load(open(testname + ".pkl", "rb"))

        test_builder = testcommon.BinaryViewTestBuilder(testname, "suite/binaries/test_corpus")
        for method in test_builder.methods():
            test = getattr(test_builder, method)()
            oracle = binary_oracle[method]
            if test == oracle:
                continue

            result = getattr(test_builder, method).__doc__
            result += ":\n"
            report = self.report(oracle, test, result)
            self.assertTrue(report[0], report[1])  # Test does not agree with oracle
        os.unlink(testname)

    def test_Architecture(self):
        oracle = self.oracle_test_data['test_Architecture']
        test = self.builder.test_Architecture()
        report = self.report(oracle, test)
        self.assertTrue(report[0], report[1])  # Test does not agree with oracle

    def test_Architecture_list(self):
        oracle = self.oracle_test_data['test_Architecture_list']
        test = self.builder.test_Architecture_list()
        report = self.report(oracle, test)
        self.assertTrue(report[0], report[1])  # Test does not agree with oracle

    def test_Assemble(self):
        oracle = self.oracle_test_data['test_Assemble']
        test = self.builder.test_Assemble()
        report = self.report(oracle, test)
        self.assertTrue(report[0], report[1])  # Test does not agree with oracle

    def test_BinaryViewType_list(self):
        oracle = self.oracle_test_data['test_BinaryViewType_list']
        test = self.builder.test_BinaryViewType_list()
        report = self.report(oracle, test)
        self.assertTrue(report[0], report[1])  # Test does not agree with oracle

    def test_Enumeration(self):
        oracle = self.oracle_test_data['test_Enumeration']
        test = self.builder.test_Enumeration()
        report = self.report(oracle, test)
        self.assertTrue(report[0], report[1])  # Test does not agree with oracle

    def test_Function(self):
        oracle = self.oracle_test_data['test_Function']
        test = self.builder.test_Function()
        report = self.report(oracle, test)
        self.assertTrue(report[0], report[1])  # Test does not agree with oracle

    def test_Plugin_bin_info(self):
        oracle = self.oracle_test_data['test_Plugin_bin_info']
        test = self.builder.test_Plugin_bin_info()
        report = self.report(oracle, test)
        self.assertTrue(report[0], report[1])  # Test does not agree with oracle

    def test_Struct(self):
        oracle = self.oracle_test_data['test_Struct']
        test = self.builder.test_Struct()
        report = self.report(oracle, test)
        self.assertTrue(report[0], report[1])  # Test does not agree with oracle

    def test_Types(self):
        oracle = self.oracle_test_data['test_Types']
        test = self.builder.test_Types()
        report = self.report(oracle, test)
        self.assertTrue(report[0], report[1])  # Test does not agree with oracle

    def test_events(self):
        oracle = self.oracle_test_data['test_events']
        test = self.builder.test_events()
        report = self.report(oracle, test)
        self.assertTrue(report[0], report[1])  # Test does not agree with oracle

    def test_linear_disassembly(self):
        oracle = self.oracle_test_data['test_linear_disassembly']
        test = self.builder.test_linear_disassembly()
        report = self.report(oracle, test)
        self.assertTrue(report[0], report[1])  # Test does not agree with oracle

    def test_low_il_stack(self):
        oracle = self.oracle_test_data['test_low_il_stack']
        test = self.builder.test_low_il_stack()
        report = self.report(oracle, test)
        self.assertTrue(report[0], report[1])  # Test does not agree with oracle

    def test_med_il_stack(self):
        oracle = self.oracle_test_data['test_med_il_stack']
        test = self.builder.test_med_il_stack()
        report = self.report(oracle, test)
        self.assertTrue(report[0], report[1])  # Test does not agree with oracle

    def test_partial_register_dataflow(self):
        oracle = self.oracle_test_data['test_partial_register_dataflow']
        test = self.builder.test_partial_register_dataflow()
        report = self.report(oracle, test)
        self.assertTrue(report[0], report[1])  # Test does not agree with oracle

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
    if len(sys.argv) > 1:
        if sys.argv[1] == '-v' or sys.argv[1] == '-V' or sys.argv[1] == '--verbose':
            verbose = True

    test_suite = unittest.defaultTestLoader.loadTestsFromModule(api_test)
    test_suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestBinaryNinjaAPI))
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(test_suite)
