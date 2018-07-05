import unittest
import platform
import os
from binaryninja.setting import Setting
from binaryninja.metadata import Metadata
from binaryninja.demangle import demangle_gnu3, get_qualified_name
from binaryninja.architecture import Architecture


class SettingsAPI(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		pass

	@classmethod
	def tearDownClass(cls):
		setting = Setting("test")
		setting.remove_setting_group("test")

	def test_bool_settings(self):
		setting = Setting("test")
		setting.set("bool_test_true", True)
		setting.set("bool_test_false", False)
		assert not setting.get_bool("bool_test_false"), "bool_test_false failed"
		assert setting.get_bool("bool_test_true"), "bool_test_true failed"
		assert setting.get_bool("bool_test_default_True", True), "bool_test_default_True failed"
		assert not setting.get_bool("bool_test_default_False", False), "bool_test_default_False failed"

	def test_int_settings(self):
		setting = Setting("test")
		setting.set("int_test1", 0x100)
		setting.set("int_test2", 0)
		setting.set("int_test3", -1)
		assert setting.get_integer("int_test1") == 0x100, "int_test1 failed"
		assert setting.get_integer("int_test2") == 0, "int_test2 failed"
		assert setting.get_integer("int_test3") == -1, "int_test3 failed"
		assert setting.get_integer("int_test_default_1", 1) == 1, "int_test_default_1 failed"

	def test_float_settings(self):
		setting = Setting("test")
		setting.set("float_test1", 10.5)
		setting.set("float_test2", -0.5)
		assert setting.get_double("float_test1") == 10.5, "float_test1 failed"
		assert setting.get_double("float_test2") == -0.5, "float_test1 failed"
		assert setting.get_double("float_test_default", -5.5), "float_test_default failed"

	def test_str_settings(self):
		setting = Setting("test")
		setting.set("str_test1", "hi")
		setting.set("str_test2", "")
		setting.set("str_test3", "A" * 1000)
		assert setting.get_string("str_test1") == "hi", "str_test1 failed"
		assert setting.get_string("str_test2") == "", "str_test2 failed"
		assert setting.get_string("str_test3") == "A" * 1000, "str_test3 failed"
		assert setting.get_string("str_test_default", "hi") == "hi", "str_test_default failed"

	def test_int_list_settings(self):
		setting = Setting("test")
		setting.set("int_list_test1", [0x100])
		setting.set("int_list_test2", [1, 2])
		setting.set("int_list_test3", [])
		assert setting.get_integer_list("int_list_test1") == [0x100], "int_list_test1 failed"
		assert setting.get_integer_list("int_list_test2") == [1, 2], "int_list_test2 failed"
		assert setting.get_integer_list("int_list_test3") == [], "int_list_test3 failed"
		assert setting.get_integer_list("int_list_test_default", [2, 3]), "int_list_test_default failed"

	def test_str_list_settings(self):
		setting = Setting("test")
		setting.set("str_list_test1", ["hi"])
		setting.set("str_list_test2", ["hello", "world"])
		setting.set("str_list_test3", [])
		assert setting.get_string_list("str_list_test1") == ["hi"], "str_list_test1 failed"
		assert setting.get_string_list("str_list_test2") == ["hello", "world"], "str_list_test2 failed"
		assert setting.get_string_list("str_list_test3") == [], "str_list_test3 failed"
		assert setting.get_string_list("str_list_test_default", ["hi", "there"]), "str_list_test_default failed"


class MetaddataAPI(unittest.TestCase):
	def test_metadata_basic_types(self):
		# Core is tested thoroughly through the C++ unit tests here we focus on the python api side
		md = Metadata(1)
		assert md.is_integer
		assert int(md) == 1
		assert md.value == 1

		md = Metadata(-1, signed=True)
		assert md.is_signed_integer
		assert int(md) == -1
		assert md.value == -1
		md = Metadata(1, signed=False)
		assert md.is_unsigned_integer
		assert int(md) == 1
		md = Metadata(3.14)
		assert md.is_float
		assert float(md) == 3.14
		assert md.value == 3.14

		md = Metadata("asdf")
		assert md.is_string
		assert str(md) == "asdf"
		assert len(md) == 4
		assert md.value == "asdf"

		md = Metadata("\x00\x00\x41\x00", raw=True)
		assert md.is_raw
		assert len(md) == 4
		assert str(md) == "\x00\x00\x41\x00"
		assert md.value == "\x00\x00\x41\x00"

	def test_metadata_compound_types(self):
		md = Metadata([1, 2, 3])
		assert md.is_array
		assert md.value == [1, 2, 3]
		assert len(md) == 3
		assert md[0] == 1
		assert md[1] == 2
		assert md[2] == 3
		assert isinstance(list(md), list)
		md.remove(0)
		assert len(md) == 2
		assert md == [2, 3]

		md = Metadata({"a": 1, "b": 2})
		assert md.is_dict
		assert len(md) == 2
		assert md.value == {"a": 1, "b": 2}
		assert md["a"] == 1
		assert md["b"] == 2
		md.remove("a")
		assert len(md) == 1
		assert md == {"b": 2}

	def test_metadata_equality(self):
		assert Metadata(1) == 1
		assert Metadata(1) != 0
		assert Metadata(1) == Metadata(1)
		assert Metadata(1) != Metadata(0)

		assert Metadata(3.14) == 3.14
		assert Metadata(3.14) == Metadata(3.14)
		assert Metadata(3.14) != 3.1
		assert Metadata(3.14) != Metadata(3.1)

		assert Metadata("asdf") == "asdf"
		assert Metadata("asdf") == Metadata("asdf")
		assert Metadata("asdf") != "qwer"
		assert Metadata("asdf") != Metadata("qwer")

		assert Metadata("as\x00df", raw=True) == "as\x00df"
		assert Metadata("as\x00df", raw=True) == Metadata("as\x00df", raw=True)
		assert Metadata("as\x00df", raw=True) != "qw\x00er"
		assert Metadata("as\x00df", raw=True) != Metadata("qw\x00er", raw=True)

		assert Metadata([1, 2, 3]) == [1, 2, 3]
		assert Metadata([1, 2, 3]) == Metadata([1, 2, 3])
		assert Metadata([1, 2, 3]) != [1, 2]
		assert Metadata([1, 2, 3]) != Metadata([1, 2])

		assert Metadata({"a": 1, "b": 2}) == {"a": 1, "b": 2}
		assert Metadata({"a": 1, "b": 2}) == Metadata({"a": 1, "b": 2})
		assert Metadata({"a": 1, "b": 2}) != {"a": 1}
		assert Metadata({"a": 1, "b": 2}) != Metadata({"a": 1})


class DemanglerTest(unittest.TestCase):
	def get_type_string(self, t, n):
		out = ""
		if t is not None:
			out = str(t.get_string_before_name())
			if len(out) > 1 and out[-1] != ' ':
				out += " "
			out += get_qualified_name(n)
			out += str(t.get_string_after_name())
		return out

	def test_demangle_gnu3(self):
		tests = ("__ZN15BinaryNinjaCore12BinaryReader5Read8Ev",
			"__ZN5QListIP18QAbstractAnimationE18detach_helper_growEii",
			"__ZN13QStatePrivate22emitPropertiesAssignedEv",
			"__ZN17QtMetaTypePrivate23QMetaTypeFunctionHelperI14QItemSelectionLb1EE9ConstructEPvPKv",
			"__ZN18QSharedDataPointerI16QFileInfoPrivateE4dataEv",
			"__ZN26QAbstractNativeEventFilterD2Ev",
			"__ZN5QListIP14QAbstractStateE3endEv",
			"__ZNK15BinaryNinjaCore19ArchitectureWrapper22GetOpcodeDisplayLengthEv",
			"__ZN15BinaryNinjaCore17ScriptingInstance19SetCurrentSelectionEyy",
			"__ZL32qt_meta_stringdata_QHistoryState",
			"__ZN12_GLOBAL__N_114TypeDestructor14DestructorImplI11QStringListLb1EE8DestructEiPv",
			"__ZN13QGb18030Codec5_nameEv",
			"__ZN5QListIP7QObjectE6detachEv",
			"__ZN19QBasicAtomicPointerI9QFreeListI13QMutexPrivateN12_GLOBAL__N_117FreeListConstantsEEE17testAndSetReleaseEPS4_S6_",
			"__ZN12QJsonPrivate6Parser12reserveSpaceEi",
			"__ZN20QStateMachinePrivate12endMacrostepEb",
			"__ZN14QScopedPointerI20QTemporaryDirPrivate21QScopedPointerDeleterIS0_EED2Ev",
			"__ZN14QVariantIsNullIN12_GLOBAL__N_115CoreTypesFilterEE8delegateI10QMatrix4x4EEbPKT_",
			"__ZN26QAbstractProxyModelPrivateC2Ev",
			"__ZNSt3__110__function6__funcIZ26BNWorkerInteractiveEnqueueE4$_16NS_9allocatorIS2_EEFvvEEclEv")

		results = ("int32_t BinaryNinjaCore::BinaryReader::Read8()",
			"int32_t QList<QAbstractAnimation*>::detach_helper_grow(int32_t, int32_t)",
			"int32_t QStatePrivate::emitPropertiesAssigned()",
			"int32_t QtMetaTypePrivate::QMetaTypeFunctionHelper<QItemSelection, true>::Construct(void*, void const*)",
			"int32_t QSharedDataPointer<QFileInfoPrivate>::data()",
			"void QAbstractNativeEventFilter::~QAbstractNativeEventFilter()",
			"int32_t QList<QAbstractState*>::end()",
			"int32_t BinaryNinjaCore::ArchitectureWrapper::GetOpcodeDisplayLength() const",
			"int32_t BinaryNinjaCore::ScriptingInstance::SetCurrentSelection(uint64_t, uint64_t)",
			"qt_meta_stringdata_QHistoryState",
			"int32_t (anonymous namespace)::TypeDestructor::DestructorImpl<QStringList, true>::Destruct(int32_t, void*)",
			"int32_t QGb18030Codec::_name()",
			"int32_t QList<QObject*>::detach()",
			"int32_t QBasicAtomicPointer<QFreeList<QMutexPrivate, (anonymous namespace)::FreeListConstants> >::testAndSetRelease(QFreeList<QMutexPrivate, (anonymous namespace)::FreeListConstants>*, QFreeList<QMutexPrivate, (anonymous namespace)::FreeListConstants>*)",
			"int32_t QJsonPrivate::Parser::reserveSpace(int32_t)",
			"int32_t QStateMachinePrivate::endMacrostep(bool)",
			"void QScopedPointer<QTemporaryDirPrivate, QScopedPointerDeleter<QTemporaryDirPrivate> >::~QScopedPointer()",
			"bool QVariantIsNull<(anonymous namespace)::CoreTypesFilter>::delegate<QMatrix4x4>(QMatrix4x4 const*)",
			"void QAbstractProxyModelPrivate::QAbstractProxyModelPrivate()",
			"int32_t std::__1::__function::__func<BNWorkerInteractiveEnqueue::$_16, std::__1::allocator<BNWorkerInteractiveEnqueue::$_16>, void ()>::operator()()")

		for i, test in enumerate(tests):
			t, n = demangle_gnu3(Architecture['x86'], test)
			assert self.get_type_string(t, n) == results[i]
