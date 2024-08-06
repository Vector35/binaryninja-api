# coding=utf-8
# Copyright (c) 2015-2024 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
import random
from typing import Dict, Optional

from binaryninja.collaboration.merge import ConflictSplitter, MergeConflict
from binaryninja.database import KeyValueStore


class RNGConflictSplitter(ConflictSplitter):
	def get_name(self) -> str:
		return "RNG Conflict Splitter"

	def can_split(self, key: str, conflict: MergeConflict):
		# Only handle metadata entries
		return conflict.type == "value_store_entry"

	def split(self, key: str, conflict: MergeConflict, result: KeyValueStore) -> Optional[Dict[str, MergeConflict]]:
		# Choose a random side to win
		conflict.success(random.choice([conflict.first, conflict.second]))
		return {}

splitter = RNGConflictSplitter()
splitter.register()
