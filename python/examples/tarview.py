from binaryninja import *
from io import BytesIO
import tarfile


# TODO: Gross use of the api
# Who is responsible for create_child? The BV or the BVT?
"""
bvt = BinaryViewType['Tar']
tbv = bvt.create(BinaryView.new(fread("/Users/glennsmith/Documents/binaries/random downloads/mods.tar")))
child1 = bvt.create_child(tbv, "mod_setenv.so")
child2 = bvt.create_child(tbv, "mod_wstunnel.so")
"""


# TODO: Better impl of this (C++ ??)
class AdapterView(BinaryView):
    name = "Adapter"
    long_name = "Adapter View"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)

    @staticmethod
    def is_valid_for_data(data):
        return False

    def init(self):
        # TODO: Need to be per-child
        name = self.get_load_settings("Adapter").get_string("loader.adapter.childName")
        md = BinaryViewType[self.parent_view.view_type].get_metadata_for_child(self.parent_view, name)
        offset = md["start"]
        size = md["size"]
        self.add_auto_segment(0, size, offset, size, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        return True

    def perform_get_entry_point(self):
        return 0

    def perform_is_executable(self):
        return False

    def perform_is_relocatable(self):
        return False

    def perform_get_address_size(self):
        return 1


class TarView(BinaryView):
    name = "Tar"
    long_name = "Tar Archive"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)

    @staticmethod
    def is_valid_for_data(data):
        try:
            with tarfile.open(fileobj=BytesIO(data[:]), mode='r') as f:
                return True
        except:
            return False

    @classmethod
    def has_children_for_data(cls, data):
        return True

    @classmethod
    def get_children_for_data(cls, data):
        with tarfile.open(fileobj=BytesIO(data[:]), mode='r') as tf:
            result = []
            for member in tf.getmembers():
                result.append(member.name)
            return result

    @classmethod
    def get_metadata_for_child(cls, data, child):
        with tarfile.open(fileobj=BytesIO(data[:]), mode='r') as tf:
            result = []
            for member in tf.getmembers():
                if member.name == child:
                    # TODO: Standardize this
                    md = {}
                    md["start"] = member.offset_data
                    md["size"] = member.size
                    return Metadata(md)
        return None

    @classmethod
    def create_child_for_data(cls, data, child):
        # TODO: Better way of doing this
        load_settings = data.get_load_settings("Adapter")
        load_settings.set_string("loader.adapter.childName", child)
        data.set_load_settings("Adapter", load_settings)

        # TODO: Is this a good way of doing adapter views?
        view = BinaryViewType["Adapter"].create(data)
        result = binaryninja.load(view)
        return result

    def init(self):
        self.add_auto_segment(0, self.parent_view.length, 0, self.parent_view.length, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)

        # TODO: Need this per-child
        load_settings = self.get_load_settings("Adapter")
        if load_settings is None:
            load_settings = Settings(get_unique_identifier())
        load_settings.register_setting("loader.adapter.childName", """
            {        
                "title": "Child Name",
                "type": "string",
                "description": ""
            }
        """)
        self.set_load_settings("Adapter", load_settings)

        return True

    def perform_get_entry_point(self):
        return 0

    def perform_is_executable(self):
        return False

    def perform_is_relocatable(self):
        return False

    def perform_get_address_size(self):
        return 1


TarView.register()
AdapterView.register()
