#!/usr/bin/env python
# This test file is maintained for API unit test distribution.
import os
import sys
import unittest
import pickle
import zipfile
import difflib
from collections import Counter

api_suite_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "api", "suite")
sys.path.append(api_suite_path)
import testcommon
import api_test

global verbose
verbose = False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        for i in range(1, len(sys.argv)):
            if sys.argv[i] == '-v' or sys.argv[i] == '-V' or sys.argv[i] == '--verbose':
                verbose = True

    test_suite = unittest.defaultTestLoader.loadTestsFromModule(api_test)
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(test_suite)
