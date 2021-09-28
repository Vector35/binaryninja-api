#!/usr/bin/env python3
import pickle
import sys
import os
import zipfile
from optparse import OptionParser
import testcommon
import time

#Prevent user settings or plugins from impacting unit tests
os.environ["BN_DISABLE_USER_PLUGINS"] = "True"
os.environ["BN_DISABLE_USER_SETTINGS"] = "True"
os.environ["BN_DISABLE_REPOSITORY_PLUGINS"] = "True"
os.environ["BN_EXPERIMENTAL_DEBUGGER"] = "True"

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

#Prevent user settings or plugins from impacting unit tests
os.environ["BN_DISABLE_USER_PLUGINS"] = "True"
os.environ["BN_DISABLE_USER_SETTINGS"] = "True"
os.environ["BN_DISABLE_REPOSITORY_PLUGINS"] = "True"
os.environ["BN_EXPERIMENTAL_DEBUGGER"] = "True"

api_suite_path = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), {4}))
sys.path.append(api_suite_path)
# support direct invocation of configuration unit.py
commondir = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", ".."))
sys.path.append(commondir)

debugger_suite_path = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..",
                                                    "public", "debugger", "test"))
sys.path.append(debugger_suite_path)

import config
import testcommon
import api_test
import debugger_test


class TestBinaryNinja(unittest.TestCase):
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

    def run_binary_test(self, testfile, oracle_suffix="", config_settings=None):
        testname = None
        with zipfile.ZipFile(os.path.join(api_suite_path, testfile), "r") as zf:
            testname = zf.namelist()[0]
            zf.extractall(path=api_suite_path)

        pickle_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), testname + oracle_suffix + ".pkl")
        self.assertTrue(pickle_path, "Test pickle doesn't exist")
        try:
            # Python 2 does not have the encodings option
            binary_oracle = pickle.load(open(pickle_path, "rb"), encoding='utf8')
        except TypeError:
            binary_oracle = pickle.load(open(pickle_path, "rb"))

        test_builder = testcommon.BinaryViewTestBuilder(testname, config_settings)
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

def filter_test_suite(suite, keyword):
    result = unittest.TestSuite()
    for child in suite._tests:
        if type(child) == unittest.suite.TestSuite:
            result.addTest(filter_test_suite(child, keyword))
        elif keyword.lower() in child._testMethodName.lower():
            result.addTest(child)
    return result

def main():
    test_keyword = None
    if len(sys.argv) > 1:
        for i in range(1, len(sys.argv)):
            if sys.argv[i] == '-v' or sys.argv[i] == '-V' or sys.argv[i] == '--verbose':
                config.verbose = True
            elif sys.argv[i] == '--api-only':
                config.api_only = True
            elif sys.argv[i] == '--debugger-only':
                config.debugger_only = True
            else:
                # otherwise the argument is taken as a test case search keyword
                test_keyword = sys.argv[i]

    if config.api_only:
        runner = unittest.TextTestRunner(verbosity=2)
        test_suite = unittest.defaultTestLoader.loadTestsFromModule(api_test)
    elif config.debugger_only:
        runner = unittest.TextTestRunner(verbosity=2)
        test_suite = unittest.defaultTestLoader.loadTestsFromModule(debugger_test)
    else:
        runner = unittest.TextTestRunner(verbosity=2)
        test_suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestBinaryNinja)
        test_suite.addTest(unittest.defaultTestLoader.loadTestsFromModule(api_test))

    # if test keyword supplied, filter
    if test_keyword:
        test_suite = filter_test_suite(test_suite, test_keyword)

    runner.run(test_suite)

if __name__ == "__main__":
    main()
"""


binary_test_string = """
    def test_binary__{0}(self):
        self.run_binary_test('{1}', oracle_suffix='{2}', config_settings={3})
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

    def add_binary_test(self, test_store, binary, oracle_suffix="", config_settings=None):
        name = binary[len(test_store):].replace(os.path.sep, "_").replace(".", "_")
        if os.name == 'nt':
            binary = binary.replace(os.sep, '/')
        name += oracle_suffix
        self.binary_tests += binary_test_string.format(name, binary + ".zip", oracle_suffix, config_settings)


quiet = False
def myprint(stuff):
    if not quiet:
        print(stuff)


def update_progress(complete, total, description, done=False):
    n = 20
    maxdesc = 70
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


def generate(test_store, outdir, exclude_binaries, config_settings=None):
    if not os.path.isdir(os.path.join(os.path.dirname(__file__), test_store)):
        raise TestStoreError("Specified test store is not a directory")

    if not os.path.exists(outdir):
        os.makedirs(outdir)

    unittest = UnitTestFile(os.path.join(outdir, "unit.py"), outdir, test_store)
    oracle = OracleTestFile(os.path.join(outdir, "oracle"))

    # check all files to see if there is any newly added ones.
    # If so, create a zip archive for it and delete the original file
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
        elif testfile.endswith(".zip"):
            continue
        else:
            if os.path.exists(testfile + ".zip"):
                # We've got a zip file for it, skip
                continue

            # create the zip archive for the file
            if not os.path.exists(testfile + ".zip"):
                with zipfile.ZipFile(testfile + ".zip", "w") as zf:
                    zf.write(testfile, os.path.relpath(testfile, start=os.path.dirname(__file__)))

            os.unlink(testfile)

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
    total_progress = len(allfiles)
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

        testfile_basename = os.path.basename(oraclefile)
        testfile_rel = os.path.relpath(oraclefile, start=os.path.dirname(__file__))
        oraclefile_basepath = testfile_rel[:-len(testfile_basename)]
        oraclefile_rel = os.path.join(oraclefile_basepath, testfile_basename)

        # Create directory for pickle oracle results
        if not os.path.exists(os.path.join(outdir, oraclefile_basepath)):
            os.makedirs(os.path.join(outdir, oraclefile_basepath))

        # Now generate the oracle data
        update_progress(progress, len(allfiles), oraclefile_rel)
        unittest.add_binary_test(test_store, testfile_rel, config_settings=config_settings)
        binary_start_time = time.time()
        if exclude_binaries:
            continue
        test_data = testcommon.BinaryViewTestBuilder(testfile_rel, config_settings)
        binary_oracle = OracleTestFile(os.path.join(outdir, oraclefile_rel))
        for method in test_data.methods():
            binary_oracle.add_entry(test_data, method)
        binary_oracle.close()
        print("{0:.2f}".format(time.time() - binary_start_time))

        # Generate oracle data for rebasing tests
        if testfile_basename in ["helloworld", "duff", "partial_register_dataflow", "raw"]:
            oracle_suffix = "_rebasing"
            rebasing_options = {**config_settings, **{'loader.imageBase' : 0xf00000}}
            unittest.add_binary_test(test_store, testfile_rel, oracle_suffix, rebasing_options)
            test_data = testcommon.BinaryViewTestBuilder(testfile_rel, rebasing_options)
            binary_oracle = OracleTestFile(os.path.join(outdir, oraclefile_rel) + oracle_suffix)
            for method in test_data.methods():
                binary_oracle.add_entry(test_data, method)
            binary_oracle.close()

        os.unlink(oraclefile)

    update_progress(total_progress, total_progress, "Generating binary unit tests complete", True)
    unittest.close()
    oracle.close()


def main():
    usage = "usage: %prog [-q] [-x] [-o <dir>] [-i <dir>]"
    parser = OptionParser(usage=usage)
    default_output = os.path.relpath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "suite", "generated"))
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
    parser.add_option("-a", "--analysismodes",
                      dest="analysis_modes", action="store_true",
                      default=False, help="Generate additional oracle files to support analysis mode testing")

    options, args = parser.parse_args()

    test_store_location = os.path.relpath(os.path.join(testcommon.BinaryViewTestBuilder.get_root_directory(), options.test_store))
    myprint(f"[+] INFO: Input Test Corpus: {test_store_location}")
    if len(testcommon.get_file_list(options.test_store)) == 0:
        myprint(f"ERROR: Test Corpus is empty: {testcommon.get_file_list(options.test_store)}")
        sys.exit(1)

    configurations = {}
    configurations['default'] = {}
    if options.analysis_modes:
        configurations['mode_controlflow'] = {'analysis.mode' : 'controlFlow'}
        configurations['mode_basic'] = {'analysis.mode' : 'basic'}
        configurations['mode_intermediate'] = {'analysis.mode' : 'intermediate'}

    myprint("[+] INFO: Generating Automated Unit Tests and Oracle Results")
    for (name, config_settings) in configurations.items():
        oracle_target = os.path.join(options.outputdir, name)
        myprint(f"[+] INFO: Oracle Target Directory: {oracle_target}")
        try:
            generate(options.test_store, oracle_target, options.exclude_binary, config_settings)
            myprint(f"[+] SUCCESS: Generated Results for the '{name}' Configuration")
        except TestStoreError as te:
            myprint(f"[-] ERROR: Failed to Generate Results for the '{name}' Configuration: {te.message}")
            sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
