#!/usr/bin/env python3
import pickle
import sys
import os
import zipfile
from optparse import OptionParser
import testcommon
import time

if sys.version_info.major == 2:
    print("Generate unit tests on Python 3. Python 2 is not compatible.")
    sys.exit(1)

unit_test_template = """#!/usr/bin/env python3
# This is an auto generated unit test file do not edit directly
import os
import sys
import unittest
import pickle
import zipfile
import difflib
from collections import Counter

api_suite_path = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), {4}))
sys.path.append(api_suite_path)
import config
import testcommon
import api_test
import rebasing_test


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
                stringDiff += "<---" + str(skipped_lines) + ' same lines--->\\n'
                skipped_lines = 0
            delta = delta.replace(\'\\n\', '')
            stringDiff += delta + \'\\n\'

        stringDiffList = stringDiff.split(\'\\n\')

        if len(stringDiffList) > 10:
            if not config.verbose:
                stringDiff = \'\\n\'.join(line if len(line) <= 100 else line[:100] + "...and " + str(len(line) - 100) + " more characters" for line in stringDiffList[:10])
                stringDiff += \'\\n\\n### And ' + str(len(stringDiffList)) + " more lines, use '-v' to show ###"
        elif not config.verbose:
            stringDiff = \'\\n\'.join(line if len(line) <= 100 else line[:100] + "...and " + str(len(line) - 100) + " more characters" for line in stringDiffList)
        stringDiff = \'\\n\\n\' + firstText + stringDiff
        return (equality, stringDiff)

    @classmethod
    def setUpClass(self):
        self.builder = testcommon.TestBuilder("{3}")
        pickle_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "oracle.pkl")
        try:
            # Python 2 does not have the encodings option
            self.oracle_test_data = pickle.load(open(pickle_path, "rb"), encoding='utf8')
        except TypeError:
            self.oracle_test_data = pickle.load(open(pickle_path, "rb"))
        self.verifybuilder = testcommon.VerifyBuilder("{3}")

    def run_binary_test(self, testfile, options=None):
        testname = None
        with zipfile.ZipFile(os.path.join(api_suite_path, testfile), "r") as zf:
            testname = zf.namelist()[0]
            zf.extractall(path=api_suite_path)

        pickle_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), testname + ".pkl")
        self.assertTrue(pickle_path, "Test pickle doesn't exist")
        try:
            # Python 2 does not have the encodings option
            binary_oracle = pickle.load(open(pickle_path, "rb"), encoding='utf8')
        except TypeError:
            binary_oracle = pickle.load(open(pickle_path, "rb"))

        test_builder = testcommon.BinaryViewTestBuilder(testname, options)
        for method in test_builder.methods():
            test = getattr(test_builder, method)()
            oracle = binary_oracle[method]
            if test == oracle:
                continue

            result = getattr(test_builder, method).__doc__
            result += ":\\n"
            report = self.report(oracle, test, result)
            self.assertTrue(report[0], report[1])  # Test does not agree with oracle
        os.unlink(os.path.join(api_suite_path, testname))
{1}{2}

if __name__ == "__main__":
    api_only = False
    if len(sys.argv) > 1:
        for i in range(1, len(sys.argv)):
            if sys.argv[i] == '-v' or sys.argv[i] == '-V' or sys.argv[i] == '--verbose':
                config.verbose = True
            elif sys.argv[i] == '--api-only':
                config.api_only = True

    test_suite = unittest.defaultTestLoader.loadTestsFromModule(api_test)
    test_suite = unittest.defaultTestLoader.loadTestsFromModule(rebasing_test)
    if not config.api_only:
        test_suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestBinaryNinjaAPI))
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(test_suite)
"""


binary_test_string = """
    def test_binary__{0}(self):
        self.run_binary_test('{1}', options={2})
"""

test_string = """
    def {0}(self):
        oracle = self.oracle_test_data['{0}']
        test = self.builder.{0}()
        report = self.report(oracle, test)
        self.assertTrue(report[0], report[1])  # Test does not agree with oracle
"""

verify_string = """
    def {0}(self):
        self.assertTrue(self.verifybuilder.{0}(), self.{0}.__doc__)
"""


class OracleTestFile:
    def __init__(self, filename):
        self.f = open(filename + ".pkl", "wb")
        self.pkl = pickle.Pickler(self.f, protocol=2)
        self.filename = filename
        self.oracle_test_data = {}

    def add_entry(self, builder, test_name):
        self.oracle_test_data[test_name] = getattr(builder, test_name)()

    def close(self):
        self.pkl.dump(self.oracle_test_data)
        self.f.close()


class UnitTestFile:
    binary_test_options = {}
    binary_test_options['binaries/test_corpus/pe_thumb'] = {'analysis.experimental.alternateTypePropagation' : True}

    def __init__(self, filename, outdir, test_store):
        self.filename = filename
        self.test_store = test_store
        self.outdir = outdir
        self.f = open(filename, "wb")
        self.template = unit_test_template
        self.tests = ""
        self.binary_tests = ""

    def close(self):
        api_path = os.path.relpath(os.path.dirname(os.path.realpath(__file__)), start=self.outdir)
        api_path = os.path.normpath(api_path)
        api_path = map(lambda x: '"{0}"'.format(x), api_path.split(os.sep))
        api_path = '{0}'.format(', '.join(api_path))
        test_store = self.test_store.replace(os.sep, '/') if os.name == 'nt' else self.test_store
        self.f.write(self.template.format(self.outdir, self.tests, self.binary_tests, test_store, api_path).encode('utf8'))
        self.f.close()

    def add_verify(self, test_name):
        self.tests += verify_string.format(test_name)

    def add_test(self, test_name):
        self.tests += test_string.format(test_name)

    def add_binary_test(self, test_store, binary):
        name = binary[len(test_store):].replace(os.path.sep, "_").replace(".", "_")
        if os.name == 'nt':
            binary = binary.replace(os.sep, '/')
        self.binary_tests += binary_test_string.format(name, binary + ".zip", UnitTestFile.binary_test_options.get(binary, None))


quiet = False
def myprint(stuff):
    if not quiet:
        print(stuff)


def update_progress(complete, total, description, done=False):
    n = 20
    maxdesc = 50
    if total == 0:
        total, complete = 10, 10
    if len(description) > maxdesc:
        description = description[:maxdesc]
    elif len(description) < maxdesc:
        description += ' ' * (maxdesc - len(description))

    if not quiet:
        sys.stdout.write('\r[{0}{1}] {2:10.0f}% - {3}'.format('#' * int(n * (float(complete) / total)), ' ' * (n - int(n * (float(complete) / total))), 100 * float(complete) / total, description))
        if done:
            sys.stdout.write("\n")


class TestStoreError(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


def generate(test_store, outdir, exclude_binaries):
    if not os.path.isdir(os.path.join(os.path.dirname(__file__), test_store)):
        raise TestStoreError("Specified test store is not a directory")

    unittest = UnitTestFile(os.path.join(outdir, "unit.py"), outdir, test_store)
    oracle = OracleTestFile(os.path.join(outdir, "oracle"))

    # Generate the tests that don't involve binaries but do involve oracles
    builder = testcommon.TestBuilder(test_store)
    tests = builder.methods()
    for progress, test_name in enumerate(tests):
        update_progress(progress, len(tests), "Generating test data")
        oracle.add_entry(builder, test_name)
        unittest.add_test(test_name)
    update_progress(len(tests), len(tests), "Generating test data", True)

    # Generate the tests that just verify things work as expected
    verify = testcommon.VerifyBuilder(test_store)
    tests = verify.methods()
    for progress, test_name in enumerate(tests):
        update_progress(progress, len(tests), "Generating verify data")
        unittest.add_verify(test_name)
    update_progress(len(tests), len(tests), "Generating verify data", True)

    # Now generate test that involve binaries
    allfiles = sorted(testcommon.get_file_list(test_store))
    for progress, testfile in enumerate(allfiles):
        oraclefile = None
        zip_only = False
        if testfile.endswith(".gitignore"):
            continue
        if testfile.endswith(".pkl"):
            continue
        elif testfile.endswith(".DS_Store"):
            continue
        elif testfile.endswith(".bndb"):
            # For databases, we do not wish to create oracle data for them
            # However, we do wish them to be zipped
            zip_only = True
            oraclefile = testfile
        elif testfile.endswith(".bndb.zip"):
            continue
        elif testfile.endswith(".zip"):
            # We have a zipped binary unzip it so we can rebaseline
            with zipfile.ZipFile(testfile, "r") as zf:
                zf.extractall(path = os.path.dirname(__file__))
            if not os.path.exists(testfile[:-4]):
                print("Error extracting testfile %s from zip: %s" % (testfile[:-4], testfile))
                continue
            oraclefile = testfile[:-4]
        else:
            if os.path.exists(testfile + ".zip"):
                # We've got a binary and zip for that binary just skip it
                continue
            # We have a binary that isn't zipped use it as a new test case
            oraclefile = testfile

        # create the zip archive for the file
        if not os.path.exists(oraclefile + ".zip"):
            with zipfile.ZipFile(oraclefile + ".zip", "w") as zf:
                zf.write(oraclefile, os.path.relpath(oraclefile, start=os.path.dirname(__file__)))

        if zip_only:
            os.unlink(oraclefile)
            continue

        oraclefile_rel = os.path.relpath(oraclefile, start=os.path.dirname(__file__))

        # Now generate the oracle data
        update_progress(progress, len(allfiles), oraclefile_rel)
        unittest.add_binary_test(test_store, oraclefile_rel)
        binary_start_time = time.time()
        if exclude_binaries:
            continue
        test_data = testcommon.BinaryViewTestBuilder(oraclefile_rel, UnitTestFile.binary_test_options.get(oraclefile_rel, None))
        binary_oracle = OracleTestFile(os.path.join(outdir, oraclefile_rel))
        for method in test_data.methods():
            binary_oracle.add_entry(test_data, method)
        binary_oracle.close()
        print("{0:.2f}".format(time.time() - binary_start_time))

        # Generate oracle data for rebasing tests
        name = oraclefile_rel[len(test_store):].replace(os.path.sep, "_").replace(".", "_")[1:]
        if name in ["helloworld", "duff", "partial_register_dataflow", "raw"]:
            test_data = testcommon.BinaryViewTestBuilder(oraclefile_rel, options={'loader.imageBase' : 0xf00000})
            binary_oracle = OracleTestFile(os.path.join(outdir, oraclefile_rel) + "_rebasing")
            for method in test_data.methods():
                binary_oracle.add_entry(test_data, method)
            binary_oracle.close()

        os.unlink(oraclefile)

    update_progress(len(allfiles), len(allfiles), "Generating binary unit tests complete", True)
    unittest.close()
    oracle.close()


def main():
    usage = "usage: %prog [-q] [-x] [-o <dir>] [-i <dir>]"
    parser = OptionParser(usage=usage)
    default_output = os.path.relpath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "suite"))
    parser.add_option("-q", "--quiet",
                      dest="quiet", action="store_true",
                      default=False, help="Don't print anything")
    parser.add_option("-x", "--exclude",
                      dest="exclude_binary", action="store_true",
                      default=False, help="Exclude regeneration of binaries")
    parser.add_option("-o", "--outputdir", default=default_output,
                      dest="outputdir", action="store", type="string",
                      help="output directory where the unit.py and oracle.py files will be stored (relative to cwd)")
    parser.add_option("-i", "--inputdir", default=os.path.join("binaries", "test_corpus"),
                      dest="test_store", action="store", type="string",
                      help="input directory containing the binaries you which to generate unit tests from (relative to this file)")

    options, args = parser.parse_args()
    print("OUTPUT: %s" % options.outputdir)

    myprint("[+] INFO: Using test store: %s" % options.test_store)
    if len(testcommon.get_file_list(options.test_store)) == 0:
        myprint("ERROR: No files in the test store %s" % testcommon.get_file_list(options.test_store))
        sys.exit(1)

    myprint("[+] INFO: Generating test store")
    try:
        generate(options.test_store, options.outputdir, options.exclude_binary)
    except TestStoreError as te:
        myprint("[-] ERROR: Failed to generate test store: %s" % te.message)
        sys.exit(1)
    myprint("[+] SUCCESS: Generating test store")
    sys.exit(0)


if __name__ == "__main__":
    main()
