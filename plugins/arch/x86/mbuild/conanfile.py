#BEGIN_LEGAL
#
#Copyright (c) 2022 Intel Corporation
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#END_LEGAL

import os

from conans import ConanFile


class MBuildConan(ConanFile):
    name = "mbuild"
    description = "A simple portable dependence-based build-system written in Python."
    url = "https://github.com/intelxed/mbuild.git"
    homepage = "https://intelxed.github.io/"
    license = "Apache License 2.0"
    topics = ("intel", "mbuild", "build")

    exports_sources = (
        "LICENSE",
        "mbuild/*",
    )
    no_copy_source = True

    def build(self):
        pass

    def package(self):
        self.copy("mbuild/*", src=self.source_folder, dst="lib")
        self.copy("LICENSE", src=self.source_folder, dst="licenses")

    def package_info(self):
        lib_dir = os.path.join(self.package_folder, "lib")
        self.output.info(f"Appending PYTHONPATH environment var: {lib_dir}")
        self.env_info.PYTHONPATH.append(lib_dir)

    def package_id(self):
        self.info.header_only()
