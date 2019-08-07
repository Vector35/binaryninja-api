import unittest
import platform
import os
from binaryninja.binaryview import BinaryView, BinaryViewType
from binaryninja.settings import Settings, SettingsScope
from binaryninja.metadata import Metadata
from binaryninja.demangle import demangle_gnu3, get_qualified_name
from binaryninja.architecture import Architecture


class SettingsAPI(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		pass

	@classmethod
	def tearDownClass(cls):
		pass

	def test_settings_create(self):
		s1 = Settings()
		s2 = Settings(None)
		s3 = Settings("default")
		s4 = Settings("test")
		assert s1 == s2, "test_settings_create failed"
		assert s1 == s3, "test_settings_create failed"
		assert s1 != s4, "test_settings_create failed"

	def test_settings_defaults(self):
		settings = Settings()
		assert settings.contains("analysis.linearSweep.autorun"), "test_settings_defaults failed"
		assert settings.contains("analysis.unicode.blocks"), "test_settings_defaults failed"
		assert settings.contains("downloadClient.providerName"), "test_settings_defaults failed"
		assert settings.get_bool_with_scope("analysis.linearSweep.autorun", scope=SettingsScope.SettingsDefaultScope)[0], "test_settings_defaults failed"
		assert settings.get_bool_with_scope("analysis.linearSweep.autorun", scope=SettingsScope.SettingsDefaultScope)[1] == SettingsScope.SettingsDefaultScope, "test_settings_defaults failed"

	def test_settings_registration(self):
		settings = Settings("test")
		assert not settings.contains("testGroup.testSetting"), "test_settings_registration failed"
		assert settings.register_group("testGroup", "Title"), "test_settings_registration failed"
		assert settings.register_setting("testGroup.testSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : true, "type" : "boolean", "id" : "testSetting"}'), "test_settings_registration failed"
		assert settings.contains("testGroup.testSetting"), "test_settings_registration failed"

	def test_settings_usage(self):
		settings = Settings("test")
		assert not settings.contains("testGroup.testSetting"), "test_settings_types failed"
		assert settings.register_group("testGroup", "Title"), "test_settings_types failed"
		assert not settings.register_setting("testGroup.boolSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : 500, "type" : "boolean", "id" : "boolSetting"}'), "test_settings_types failed"
		assert settings.register_setting("testGroup.boolSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : true, "type" : "boolean", "id" : "boolSetting"}'), "test_settings_types failed"
		assert not settings.register_setting("testGroup.doubleSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : true, "type" : "number", "id" : "doubleSetting"}'), "test_settings_types failed"
		assert settings.register_setting("testGroup.doubleSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : 500, "type" : "number", "id" : "doubleSetting"}'), "test_settings_types failed"
		assert settings.register_setting("testGroup.integerSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : 500, "type" : "number", "id" : "integerSetting"}'), "test_settings_types failed"
		assert not settings.register_setting("testGroup.stringSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : 500, "type" : "string", "id" : "stringSetting"}'), "test_settings_types failed"
		assert settings.register_setting("testGroup.stringSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : "value", "type" : "string", "id" : "stringSetting"}'), "test_settings_types failed"
		assert not settings.register_setting("testGroup.stringListSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : true, "type" : "array", "id" : "stringListSetting"}'), "test_settings_types failed"
		assert settings.register_setting("testGroup.stringListSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : ["value1", "value2"], "type" : "array", "id" : "stringListSetting"}'), "test_settings_types failed"
		assert settings.register_setting("testGroup.ignoreContextBoolSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : true, "type" : "boolean", "id" : "boolSetting", "ignore" : ["Context"]}'), "test_settings_types failed"
		assert settings.register_setting("testGroup.ignoreUserBoolSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : true, "type" : "boolean", "id" : "boolSetting", "ignore" : ["User"]}'), "test_settings_types failed"
		assert settings.register_setting("testGroup.readOnlyBoolSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : true, "type" : "boolean", "id" : "boolSetting", "ignore" : ["Context", "User"]}'), "test_settings_types failed"

		assert settings.contains("testGroup.boolSetting"), "test_settings_types failed"
		assert settings.contains("testGroup.doubleSetting"), "test_settings_types failed"
		assert settings.contains("testGroup.integerSetting"), "test_settings_types failed"
		assert settings.contains("testGroup.stringSetting"), "test_settings_types failed"
		assert settings.contains("testGroup.stringListSetting"), "test_settings_types failed"

		assert settings.get_bool("testGroup.boolSetting") == True, "test_settings_types failed"
		assert settings.get_double("testGroup.doubleSetting") == 500, "test_settings_types failed"
		assert settings.get_integer("testGroup.integerSetting") == 500, "test_settings_types failed"
		assert settings.get_string("testGroup.stringSetting") == "value", "test_settings_types failed"
		assert settings.get_string_list("testGroup.stringListSetting") == ["value1", "value2"], "test_settings_types failed"

		assert settings.set_bool("testGroup.boolSetting", False), "test_settings_types failed"
		assert settings.set_double("testGroup.doubleSetting", 700), "test_settings_types failed"
		assert settings.set_integer("testGroup.integerSetting", 700), "test_settings_types failed"
		assert settings.set_string("testGroup.stringSetting", "value_user"), "test_settings_types failed"
		assert settings.set_string_list("testGroup.stringListSetting", ["value3", "value4"]), "test_settings_types failed"

		assert settings.get_bool("testGroup.boolSetting") == False, "test_settings_types failed"
		assert settings.get_double("testGroup.doubleSetting") == 700, "test_settings_types failed"
		assert settings.get_integer("testGroup.integerSetting") == 700, "test_settings_types failed"
		assert settings.get_string("testGroup.stringSetting") == "value_user", "test_settings_types failed"
		assert settings.get_string_list("testGroup.stringListSetting") == ["value3", "value4"], "test_settings_types failed"

		assert settings.get_bool_with_scope("testGroup.boolSetting", scope=SettingsScope.SettingsDefaultScope)[0] == True, "test_settings_types failed"
		assert settings.get_double_with_scope("testGroup.doubleSetting", scope=SettingsScope.SettingsDefaultScope)[0] == 500, "test_settings_types failed"
		assert settings.get_integer_with_scope("testGroup.integerSetting", scope=SettingsScope.SettingsDefaultScope)[0] == 500, "test_settings_types failed"
		assert settings.get_string_with_scope("testGroup.stringSetting", scope=SettingsScope.SettingsDefaultScope)[0] == "value", "test_settings_types failed"
		assert settings.get_string_list_with_scope("testGroup.stringListSetting", scope=SettingsScope.SettingsDefaultScope)[0] == ["value1", "value2"], "test_settings_types failed"

		assert settings.get_bool_with_scope("testGroup.boolSetting", scope=SettingsScope.SettingsUserScope)[0] == False, "test_settings_types failed"
		assert settings.get_double_with_scope("testGroup.doubleSetting", scope=SettingsScope.SettingsUserScope)[0] == 700, "test_settings_types failed"
		assert settings.get_integer_with_scope("testGroup.integerSetting", scope=SettingsScope.SettingsUserScope)[0] == 700, "test_settings_types failed"
		assert settings.get_string_with_scope("testGroup.stringSetting", scope=SettingsScope.SettingsUserScope)[0] == "value_user", "test_settings_types failed"
		assert settings.get_string_list_with_scope("testGroup.stringListSetting", scope=SettingsScope.SettingsUserScope)[0] == ["value3", "value4"], "test_settings_types failed"

		raw_view = BinaryView.new(b'0x55')
		assert not settings.set_bool("testGroup.ignoreContextBoolSetting", False, scope=SettingsScope.SettingsDefaultScope), "test_settings_types failed"
		assert not settings.set_bool("testGroup.ignoreContextBoolSetting", False, scope=SettingsScope.SettingsContextScope), "test_settings_types failed"
		assert not settings.set_bool("testGroup.ignoreContextBoolSetting", False, raw_view, scope=SettingsScope.SettingsContextScope), "test_settings_types failed"
		assert settings.set_bool("testGroup.ignoreContextBoolSetting", False, scope=SettingsScope.SettingsUserScope), "test_settings_types failed"
		assert not settings.set_bool("testGroup.ignoreUserBoolSetting", False), "test_settings_types failed"
		assert settings.set_bool("testGroup.ignoreUserBoolSetting", False, raw_view), "test_settings_types failed"
		assert settings.set_bool("testGroup.ignoreUserBoolSetting", False, raw_view, scope=SettingsScope.SettingsContextScope), "test_settings_types failed"
		assert not settings.set_bool("testGroup.readOnlyBoolSetting", False), "test_settings_types failed"
		assert not settings.set_bool("testGroup.readOnlyBoolSetting", False, scope=SettingsScope.SettingsContextScope), "test_settings_types failed"
		assert not settings.set_bool("testGroup.readOnlyBoolSetting", False, scope=SettingsScope.SettingsUserScope), "test_settings_types failed"

		s2 = Settings("test2")
		assert s2.serialize_schema() is "", "test_settings_types failed"
		test_schema = settings.serialize_schema()
		assert test_schema != "", "test_settings_types failed"
		assert s2.deserialize_schema(test_schema), "test_settings_types failed"

		assert s2.get_bool("testGroup.boolSetting") == True, "test_settings_types failed"
		assert s2.get_double("testGroup.doubleSetting") == 500, "test_settings_types failed"
		assert s2.get_integer("testGroup.integerSetting") == 500, "test_settings_types failed"
		assert s2.get_string("testGroup.stringSetting") == "value", "test_settings_types failed"
		assert s2.get_string_list("testGroup.stringListSetting") == ["value1", "value2"], "test_settings_types failed"

		assert s2.copy_values_from(settings), "test_settings_types failed"
		assert s2.get_bool("testGroup.boolSetting") == False, "test_settings_types failed"
		assert s2.get_double("testGroup.doubleSetting") == 700, "test_settings_types failed"
		assert s2.get_integer("testGroup.integerSetting") == 700, "test_settings_types failed"
		assert s2.get_string("testGroup.stringSetting") == "value_user", "test_settings_types failed"
		assert s2.get_string_list("testGroup.stringListSetting") == ["value3", "value4"], "test_settings_types failed"

		assert s2.reset_all(), "test_settings_types failed"
		assert s2.get_bool("testGroup.boolSetting") == True, "test_settings_types failed"
		assert s2.get_double("testGroup.doubleSetting") == 500, "test_settings_types failed"
		assert s2.get_integer("testGroup.integerSetting") == 500, "test_settings_types failed"
		assert s2.get_string("testGroup.stringSetting") == "value", "test_settings_types failed"
		assert s2.get_string_list("testGroup.stringListSetting") == ["value1", "value2"], "test_settings_types failed"

		s3 = Settings("test3")
		assert s3.deserialize_schema(test_schema, SettingsScope.SettingsContextScope)
		assert not s3.contains("testGroup.ignoreContextBoolSetting"), "test_settings_types failed"
		assert s3.contains("testGroup.ignoreUserBoolSetting"), "test_settings_types failed"
		assert not s3.contains("testGroup.readOnlyBoolSetting"), "test_settings_types failed"

		assert s3.deserialize_schema(test_schema, SettingsScope.SettingsUserScope, False)
		assert s3.contains("testGroup.ignoreContextBoolSetting"), "test_settings_types failed"
		assert not s3.contains("testGroup.ignoreUserBoolSetting"), "test_settings_types failed"
		assert not s3.contains("testGroup.readOnlyBoolSetting"), "test_settings_types failed"

		assert s3.deserialize_schema(test_schema, SettingsScope.SettingsUserScope, False)
		assert s3.deserialize_schema(s3.serialize_schema(), SettingsScope.SettingsContextScope, False)
		assert not s3.contains("testGroup.ignoreContextBoolSetting"), "test_settings_types failed"
		assert not s3.contains("testGroup.ignoreUserBoolSetting"), "test_settings_types failed"
		assert not s3.contains("testGroup.readOnlyBoolSetting"), "test_settings_types failed"

	def test_load_settings(self):
		bvt_name = "Mapped (Python)" if "Mapped (Python)" in map(lambda bvt: bvt.name, list(BinaryViewType)) else "Mapped"
		raw_view = BinaryView.new(b'0x55')
		assert raw_view.view_type == "Raw", "test_load_settings failed"
		mapped_view = BinaryViewType[bvt_name].create(raw_view)
		assert mapped_view.view_type == bvt_name, "test_load_settings failed"
		assert mapped_view.segments[0].start == 0, "test_load_settings failed"
		assert len(mapped_view) == 4, "test_load_settings failed"
		load_settings = BinaryViewType[bvt_name].get_load_settings_for_data(raw_view)
		assert load_settings is not None, "test_load_settings failed"
		assert load_settings.contains("loader.architecture"), "test_load_settings failed"
		assert load_settings.contains("loader.platform"), "test_load_settings failed"
		assert load_settings.contains("loader.imageBase"), "test_load_settings failed"
		assert load_settings.contains("loader.entryPoint"), "test_load_settings failed"
		load_settings.set_string("loader.architecture", 'x86_64')
		load_settings.set_integer("loader.imageBase", 0x500000)
		load_settings.set_integer("loader.entryPoint", 0x500000)
		raw_view.set_load_settings(bvt_name, load_settings)
		mapped_view = BinaryViewType[bvt_name].create(raw_view)
		assert mapped_view.view_type == bvt_name, "test_load_settings failed"
		assert mapped_view.segments[0].start == 0x500000, "test_load_settings failed"
		assert len(mapped_view) == 4, "test_load_settings failed"

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
		assert md.value.decode("charmap") == "\x00\x00\x41\x00"

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
