# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class WindowsMinidump(KaitaiStruct):
    """Windows MiniDump (MDMP) file provides a concise way to store process
    core dumps, which is useful for debugging. Given its small size,
    modularity, some cross-platform features and native support in some
    debuggers, it is particularly useful for crash reporting, and is
    used for that purpose in Windows and Google Chrome projects.
    
    The file itself is a container, which contains a number of typed
    "streams", which contain some data according to its type attribute.
    
    .. seealso::
       Source - https://msdn.microsoft.com/en-us/library/ms680378(VS.85).aspx
    """

    class StreamTypes(Enum):
        unused = 0
        reserved_0 = 1
        reserved_1 = 2
        thread_list = 3
        module_list = 4
        memory_list = 5
        exception = 6
        system_info = 7
        thread_ex_list = 8
        memory_64_list = 9
        comment_a = 10
        comment_w = 11
        handle_data = 12
        function_table = 13
        unloaded_module_list = 14
        misc_info = 15
        memory_info_list = 16
        thread_info_list = 17
        handle_operation_list = 18
    SEQ_FIELDS = ["magic1", "magic2", "version", "num_streams", "ofs_streams", "checksum", "timestamp", "flags"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['magic1']['start'] = self._io.pos()
        self.magic1 = self._io.ensure_fixed_contents(b"\x4D\x44\x4D\x50")
        self._debug['magic1']['end'] = self._io.pos()
        self._debug['magic2']['start'] = self._io.pos()
        self.magic2 = self._io.ensure_fixed_contents(b"\x93\xA7")
        self._debug['magic2']['end'] = self._io.pos()
        self._debug['version']['start'] = self._io.pos()
        self.version = self._io.read_u2le()
        self._debug['version']['end'] = self._io.pos()
        self._debug['num_streams']['start'] = self._io.pos()
        self.num_streams = self._io.read_u4le()
        self._debug['num_streams']['end'] = self._io.pos()
        self._debug['ofs_streams']['start'] = self._io.pos()
        self.ofs_streams = self._io.read_u4le()
        self._debug['ofs_streams']['end'] = self._io.pos()
        self._debug['checksum']['start'] = self._io.pos()
        self.checksum = self._io.read_u4le()
        self._debug['checksum']['end'] = self._io.pos()
        self._debug['timestamp']['start'] = self._io.pos()
        self.timestamp = self._io.read_u4le()
        self._debug['timestamp']['end'] = self._io.pos()
        self._debug['flags']['start'] = self._io.pos()
        self.flags = self._io.read_u8le()
        self._debug['flags']['end'] = self._io.pos()

    class ThreadList(KaitaiStruct):
        """
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/ms680515(v=vs.85).aspx
        """
        SEQ_FIELDS = ["num_threads", "threads"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['num_threads']['start'] = self._io.pos()
            self.num_threads = self._io.read_u4le()
            self._debug['num_threads']['end'] = self._io.pos()
            self._debug['threads']['start'] = self._io.pos()
            self.threads = [None] * (self.num_threads)
            for i in range(self.num_threads):
                if not 'arr' in self._debug['threads']:
                    self._debug['threads']['arr'] = []
                self._debug['threads']['arr'].append({'start': self._io.pos()})
                _t_threads = self._root.Thread(self._io, self, self._root)
                _t_threads._read()
                self.threads[i] = _t_threads
                self._debug['threads']['arr'][i]['end'] = self._io.pos()

            self._debug['threads']['end'] = self._io.pos()


    class LocationDescriptor(KaitaiStruct):
        """
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/ms680383(v=vs.85).aspx
        """
        SEQ_FIELDS = ["len_data", "ofs_data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_data']['start'] = self._io.pos()
            self.len_data = self._io.read_u4le()
            self._debug['len_data']['end'] = self._io.pos()
            self._debug['ofs_data']['start'] = self._io.pos()
            self.ofs_data = self._io.read_u4le()
            self._debug['ofs_data']['end'] = self._io.pos()

        @property
        def data(self):
            if hasattr(self, '_m_data'):
                return self._m_data if hasattr(self, '_m_data') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.ofs_data)
            self._debug['_m_data']['start'] = io.pos()
            self._m_data = io.read_bytes(self.len_data)
            self._debug['_m_data']['end'] = io.pos()
            io.seek(_pos)
            return self._m_data if hasattr(self, '_m_data') else None


    class MinidumpString(KaitaiStruct):
        """Specific string serialization scheme used in MiniDump format is
        actually a simple 32-bit length-prefixed UTF-16 string.
        
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/ms680395(v=vs.85).aspx
        """
        SEQ_FIELDS = ["len_str", "str"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_str']['start'] = self._io.pos()
            self.len_str = self._io.read_u4le()
            self._debug['len_str']['end'] = self._io.pos()
            self._debug['str']['start'] = self._io.pos()
            self.str = (self._io.read_bytes(self.len_str)).decode(u"UTF-16LE")
            self._debug['str']['end'] = self._io.pos()


    class SystemInfo(KaitaiStruct):
        """"System info" stream provides basic information about the
        hardware and operating system which produces this dump.
        
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/ms680396(v=vs.85).aspx
        """

        class CpuArchs(Enum):
            intel = 0
            arm = 5
            ia64 = 6
            amd64 = 9
            unknown = 65535
        SEQ_FIELDS = ["cpu_arch", "cpu_level", "cpu_revision", "num_cpus", "os_type", "os_ver_major", "os_ver_minor", "os_build", "os_platform", "ofs_service_pack", "os_suite_mask", "reserved2"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['cpu_arch']['start'] = self._io.pos()
            self.cpu_arch = KaitaiStream.resolve_enum(self._root.SystemInfo.CpuArchs, self._io.read_u2le())
            self._debug['cpu_arch']['end'] = self._io.pos()
            self._debug['cpu_level']['start'] = self._io.pos()
            self.cpu_level = self._io.read_u2le()
            self._debug['cpu_level']['end'] = self._io.pos()
            self._debug['cpu_revision']['start'] = self._io.pos()
            self.cpu_revision = self._io.read_u2le()
            self._debug['cpu_revision']['end'] = self._io.pos()
            self._debug['num_cpus']['start'] = self._io.pos()
            self.num_cpus = self._io.read_u1()
            self._debug['num_cpus']['end'] = self._io.pos()
            self._debug['os_type']['start'] = self._io.pos()
            self.os_type = self._io.read_u1()
            self._debug['os_type']['end'] = self._io.pos()
            self._debug['os_ver_major']['start'] = self._io.pos()
            self.os_ver_major = self._io.read_u4le()
            self._debug['os_ver_major']['end'] = self._io.pos()
            self._debug['os_ver_minor']['start'] = self._io.pos()
            self.os_ver_minor = self._io.read_u4le()
            self._debug['os_ver_minor']['end'] = self._io.pos()
            self._debug['os_build']['start'] = self._io.pos()
            self.os_build = self._io.read_u4le()
            self._debug['os_build']['end'] = self._io.pos()
            self._debug['os_platform']['start'] = self._io.pos()
            self.os_platform = self._io.read_u4le()
            self._debug['os_platform']['end'] = self._io.pos()
            self._debug['ofs_service_pack']['start'] = self._io.pos()
            self.ofs_service_pack = self._io.read_u4le()
            self._debug['ofs_service_pack']['end'] = self._io.pos()
            self._debug['os_suite_mask']['start'] = self._io.pos()
            self.os_suite_mask = self._io.read_u2le()
            self._debug['os_suite_mask']['end'] = self._io.pos()
            self._debug['reserved2']['start'] = self._io.pos()
            self.reserved2 = self._io.read_u2le()
            self._debug['reserved2']['end'] = self._io.pos()

        @property
        def service_pack(self):
            if hasattr(self, '_m_service_pack'):
                return self._m_service_pack if hasattr(self, '_m_service_pack') else None

            if self.ofs_service_pack > 0:
                io = self._root._io
                _pos = io.pos()
                io.seek(self.ofs_service_pack)
                self._debug['_m_service_pack']['start'] = io.pos()
                self._m_service_pack = self._root.MinidumpString(io, self, self._root)
                self._m_service_pack._read()
                self._debug['_m_service_pack']['end'] = io.pos()
                io.seek(_pos)

            return self._m_service_pack if hasattr(self, '_m_service_pack') else None


    class ExceptionRecord(KaitaiStruct):
        """
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/ms680367(v=vs.85).aspx
        """
        SEQ_FIELDS = ["code", "flags", "inner_exception", "addr", "num_params", "reserved", "params"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['code']['start'] = self._io.pos()
            self.code = self._io.read_u4le()
            self._debug['code']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = self._io.read_u4le()
            self._debug['flags']['end'] = self._io.pos()
            self._debug['inner_exception']['start'] = self._io.pos()
            self.inner_exception = self._io.read_u8le()
            self._debug['inner_exception']['end'] = self._io.pos()
            self._debug['addr']['start'] = self._io.pos()
            self.addr = self._io.read_u8le()
            self._debug['addr']['end'] = self._io.pos()
            self._debug['num_params']['start'] = self._io.pos()
            self.num_params = self._io.read_u4le()
            self._debug['num_params']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.read_u4le()
            self._debug['reserved']['end'] = self._io.pos()
            self._debug['params']['start'] = self._io.pos()
            self.params = [None] * (15)
            for i in range(15):
                if not 'arr' in self._debug['params']:
                    self._debug['params']['arr'] = []
                self._debug['params']['arr'].append({'start': self._io.pos()})
                self.params[i] = self._io.read_u8le()
                self._debug['params']['arr'][i]['end'] = self._io.pos()

            self._debug['params']['end'] = self._io.pos()


    class MiscInfo(KaitaiStruct):
        """
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/ms680389(v=vs.85).aspx
        """
        SEQ_FIELDS = ["len_info", "flags1", "process_id", "process_create_time", "process_user_time", "process_kernel_time", "cpu_max_mhz", "cpu_cur_mhz", "cpu_limit_mhz", "cpu_max_idle_state", "cpu_cur_idle_state"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['len_info']['start'] = self._io.pos()
            self.len_info = self._io.read_u4le()
            self._debug['len_info']['end'] = self._io.pos()
            self._debug['flags1']['start'] = self._io.pos()
            self.flags1 = self._io.read_u4le()
            self._debug['flags1']['end'] = self._io.pos()
            self._debug['process_id']['start'] = self._io.pos()
            self.process_id = self._io.read_u4le()
            self._debug['process_id']['end'] = self._io.pos()
            self._debug['process_create_time']['start'] = self._io.pos()
            self.process_create_time = self._io.read_u4le()
            self._debug['process_create_time']['end'] = self._io.pos()
            self._debug['process_user_time']['start'] = self._io.pos()
            self.process_user_time = self._io.read_u4le()
            self._debug['process_user_time']['end'] = self._io.pos()
            self._debug['process_kernel_time']['start'] = self._io.pos()
            self.process_kernel_time = self._io.read_u4le()
            self._debug['process_kernel_time']['end'] = self._io.pos()
            self._debug['cpu_max_mhz']['start'] = self._io.pos()
            self.cpu_max_mhz = self._io.read_u4le()
            self._debug['cpu_max_mhz']['end'] = self._io.pos()
            self._debug['cpu_cur_mhz']['start'] = self._io.pos()
            self.cpu_cur_mhz = self._io.read_u4le()
            self._debug['cpu_cur_mhz']['end'] = self._io.pos()
            self._debug['cpu_limit_mhz']['start'] = self._io.pos()
            self.cpu_limit_mhz = self._io.read_u4le()
            self._debug['cpu_limit_mhz']['end'] = self._io.pos()
            self._debug['cpu_max_idle_state']['start'] = self._io.pos()
            self.cpu_max_idle_state = self._io.read_u4le()
            self._debug['cpu_max_idle_state']['end'] = self._io.pos()
            self._debug['cpu_cur_idle_state']['start'] = self._io.pos()
            self.cpu_cur_idle_state = self._io.read_u4le()
            self._debug['cpu_cur_idle_state']['end'] = self._io.pos()


    class Dir(KaitaiStruct):
        """
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/ms680365(v=vs.85).aspx
        """
        SEQ_FIELDS = ["stream_type", "len_data", "ofs_data"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['stream_type']['start'] = self._io.pos()
            self.stream_type = KaitaiStream.resolve_enum(self._root.StreamTypes, self._io.read_u4le())
            self._debug['stream_type']['end'] = self._io.pos()
            self._debug['len_data']['start'] = self._io.pos()
            self.len_data = self._io.read_u4le()
            self._debug['len_data']['end'] = self._io.pos()
            self._debug['ofs_data']['start'] = self._io.pos()
            self.ofs_data = self._io.read_u4le()
            self._debug['ofs_data']['end'] = self._io.pos()

        @property
        def data(self):
            if hasattr(self, '_m_data'):
                return self._m_data if hasattr(self, '_m_data') else None

            _pos = self._io.pos()
            self._io.seek(self.ofs_data)
            self._debug['_m_data']['start'] = self._io.pos()
            _on = self.stream_type
            if _on == self._root.StreamTypes.memory_list:
                self._raw__m_data = self._io.read_bytes(self.len_data)
                io = KaitaiStream(BytesIO(self._raw__m_data))
                self._m_data = self._root.MemoryList(io, self, self._root)
                self._m_data._read()
            elif _on == self._root.StreamTypes.misc_info:
                self._raw__m_data = self._io.read_bytes(self.len_data)
                io = KaitaiStream(BytesIO(self._raw__m_data))
                self._m_data = self._root.MiscInfo(io, self, self._root)
                self._m_data._read()
            elif _on == self._root.StreamTypes.thread_list:
                self._raw__m_data = self._io.read_bytes(self.len_data)
                io = KaitaiStream(BytesIO(self._raw__m_data))
                self._m_data = self._root.ThreadList(io, self, self._root)
                self._m_data._read()
            elif _on == self._root.StreamTypes.exception:
                self._raw__m_data = self._io.read_bytes(self.len_data)
                io = KaitaiStream(BytesIO(self._raw__m_data))
                self._m_data = self._root.ExceptionStream(io, self, self._root)
                self._m_data._read()
            elif _on == self._root.StreamTypes.system_info:
                self._raw__m_data = self._io.read_bytes(self.len_data)
                io = KaitaiStream(BytesIO(self._raw__m_data))
                self._m_data = self._root.SystemInfo(io, self, self._root)
                self._m_data._read()
            else:
                self._m_data = self._io.read_bytes(self.len_data)
            self._debug['_m_data']['end'] = self._io.pos()
            self._io.seek(_pos)
            return self._m_data if hasattr(self, '_m_data') else None


    class Thread(KaitaiStruct):
        """
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/ms680517(v=vs.85).aspx
        """
        SEQ_FIELDS = ["thread_id", "suspend_count", "priority_class", "priority", "teb", "stack", "thread_context"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['thread_id']['start'] = self._io.pos()
            self.thread_id = self._io.read_u4le()
            self._debug['thread_id']['end'] = self._io.pos()
            self._debug['suspend_count']['start'] = self._io.pos()
            self.suspend_count = self._io.read_u4le()
            self._debug['suspend_count']['end'] = self._io.pos()
            self._debug['priority_class']['start'] = self._io.pos()
            self.priority_class = self._io.read_u4le()
            self._debug['priority_class']['end'] = self._io.pos()
            self._debug['priority']['start'] = self._io.pos()
            self.priority = self._io.read_u4le()
            self._debug['priority']['end'] = self._io.pos()
            self._debug['teb']['start'] = self._io.pos()
            self.teb = self._io.read_u8le()
            self._debug['teb']['end'] = self._io.pos()
            self._debug['stack']['start'] = self._io.pos()
            self.stack = self._root.MemoryDescriptor(self._io, self, self._root)
            self.stack._read()
            self._debug['stack']['end'] = self._io.pos()
            self._debug['thread_context']['start'] = self._io.pos()
            self.thread_context = self._root.LocationDescriptor(self._io, self, self._root)
            self.thread_context._read()
            self._debug['thread_context']['end'] = self._io.pos()


    class MemoryList(KaitaiStruct):
        """
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/ms680387(v=vs.85).aspx
        """
        SEQ_FIELDS = ["num_mem_ranges", "mem_ranges"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['num_mem_ranges']['start'] = self._io.pos()
            self.num_mem_ranges = self._io.read_u4le()
            self._debug['num_mem_ranges']['end'] = self._io.pos()
            self._debug['mem_ranges']['start'] = self._io.pos()
            self.mem_ranges = [None] * (self.num_mem_ranges)
            for i in range(self.num_mem_ranges):
                if not 'arr' in self._debug['mem_ranges']:
                    self._debug['mem_ranges']['arr'] = []
                self._debug['mem_ranges']['arr'].append({'start': self._io.pos()})
                _t_mem_ranges = self._root.MemoryDescriptor(self._io, self, self._root)
                _t_mem_ranges._read()
                self.mem_ranges[i] = _t_mem_ranges
                self._debug['mem_ranges']['arr'][i]['end'] = self._io.pos()

            self._debug['mem_ranges']['end'] = self._io.pos()


    class MemoryDescriptor(KaitaiStruct):
        """
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/ms680384(v=vs.85).aspx
        """
        SEQ_FIELDS = ["addr_memory_range", "memory"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['addr_memory_range']['start'] = self._io.pos()
            self.addr_memory_range = self._io.read_u8le()
            self._debug['addr_memory_range']['end'] = self._io.pos()
            self._debug['memory']['start'] = self._io.pos()
            self.memory = self._root.LocationDescriptor(self._io, self, self._root)
            self.memory._read()
            self._debug['memory']['end'] = self._io.pos()


    class ExceptionStream(KaitaiStruct):
        """
        .. seealso::
           Source - https://msdn.microsoft.com/en-us/library/ms680368(v=vs.85).aspx
        """
        SEQ_FIELDS = ["thread_id", "reserved", "exception_rec", "thread_context"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['thread_id']['start'] = self._io.pos()
            self.thread_id = self._io.read_u4le()
            self._debug['thread_id']['end'] = self._io.pos()
            self._debug['reserved']['start'] = self._io.pos()
            self.reserved = self._io.read_u4le()
            self._debug['reserved']['end'] = self._io.pos()
            self._debug['exception_rec']['start'] = self._io.pos()
            self.exception_rec = self._root.ExceptionRecord(self._io, self, self._root)
            self.exception_rec._read()
            self._debug['exception_rec']['end'] = self._io.pos()
            self._debug['thread_context']['start'] = self._io.pos()
            self.thread_context = self._root.LocationDescriptor(self._io, self, self._root)
            self.thread_context._read()
            self._debug['thread_context']['end'] = self._io.pos()


    @property
    def streams(self):
        if hasattr(self, '_m_streams'):
            return self._m_streams if hasattr(self, '_m_streams') else None

        _pos = self._io.pos()
        self._io.seek(self.ofs_streams)
        self._debug['_m_streams']['start'] = self._io.pos()
        self._m_streams = [None] * (self.num_streams)
        for i in range(self.num_streams):
            if not 'arr' in self._debug['_m_streams']:
                self._debug['_m_streams']['arr'] = []
            self._debug['_m_streams']['arr'].append({'start': self._io.pos()})
            _t__m_streams = self._root.Dir(self._io, self, self._root)
            _t__m_streams._read()
            self._m_streams[i] = _t__m_streams
            self._debug['_m_streams']['arr'][i]['end'] = self._io.pos()

        self._debug['_m_streams']['end'] = self._io.pos()
        self._io.seek(_pos)
        return self._m_streams if hasattr(self, '_m_streams') else None


