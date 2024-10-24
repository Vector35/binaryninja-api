import os

from binaryninja._binaryninjacore import BNGetUserPluginDirectory
user_plugin_dir = os.path.realpath(BNGetUserPluginDirectory())
current_path = os.path.realpath(__file__)

from .sharedcache import *

