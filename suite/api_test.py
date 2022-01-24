import unittest
import platform
import os

from binaryninja.binaryview import BinaryView, BinaryViewType
from binaryninja.settings import Settings, SettingsScope
from binaryninja.metadata import Metadata
from binaryninja.demangle import demangle_gnu3, demangle_ms, get_qualified_name
from binaryninja.architecture import Architecture
from binaryninja.pluginmanager import RepositoryManager
from binaryninja.platform import Platform
from binaryninja.function import Function
from binaryninja.types import (Type, TypeBuilder, FunctionParameter, BoolWithConfidence, EnumerationBuilder, NamedTypeReferenceBuilder,
    IntegerBuilder, CharBuilder, FloatBuilder, WideCharBuilder, PointerBuilder, ArrayBuilder, FunctionBuilder, StructureBuilder,
	StructureMember)

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
		assert settings.contains("network.downloadProviderName"), "test_settings_defaults failed"
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
		assert not settings.register_setting("testGroup.stringListSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : true, "type" : "array", "elementType" : "string", "id" : "stringListSetting"}'), "test_settings_types failed"
		assert settings.register_setting("testGroup.stringListSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : ["value1", "value2"], "type" : "array", "elementType" : "string", "id" : "stringListSetting"}'), "test_settings_types failed"
		assert settings.register_setting("testGroup.ignoreResourceBoolSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : true, "type" : "boolean", "id" : "boolSetting", "ignore" : ["SettingsResourceScope"]}'), "test_settings_types failed"
		assert settings.register_setting("testGroup.ignoreUserBoolSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : true, "type" : "boolean", "id" : "boolSetting", "ignore" : ["SettingsUserScope"]}'), "test_settings_types failed"
		assert settings.register_setting("testGroup.readOnlyBoolSetting", '{"description" : "Test description.", "title" : "Test Title", "default" : true, "type" : "boolean", "id" : "boolSetting", "ignore" : ["SettingsResourceScope", "SettingsUserScope"]}'), "test_settings_types failed"

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
		assert not settings.set_bool("testGroup.ignoreResourceBoolSetting", False, scope=SettingsScope.SettingsDefaultScope), "test_settings_types failed"
		assert not settings.set_bool("testGroup.ignoreResourceBoolSetting", False, scope=SettingsScope.SettingsResourceScope), "test_settings_types failed"
		assert not settings.set_bool("testGroup.ignoreResourceBoolSetting", False, raw_view, scope=SettingsScope.SettingsResourceScope), "test_settings_types failed"
		assert settings.set_bool("testGroup.ignoreResourceBoolSetting", False, scope=SettingsScope.SettingsUserScope), "test_settings_types failed"
		assert not settings.set_bool("testGroup.ignoreUserBoolSetting", False), "test_settings_types failed"
		assert settings.set_bool("testGroup.ignoreUserBoolSetting", False, raw_view), "test_settings_types failed"
		assert settings.set_bool("testGroup.ignoreUserBoolSetting", False, raw_view, scope=SettingsScope.SettingsResourceScope), "test_settings_types failed"
		assert not settings.set_bool("testGroup.readOnlyBoolSetting", False), "test_settings_types failed"
		assert not settings.set_bool("testGroup.readOnlyBoolSetting", False, scope=SettingsScope.SettingsResourceScope), "test_settings_types failed"
		assert not settings.set_bool("testGroup.readOnlyBoolSetting", False, scope=SettingsScope.SettingsUserScope), "test_settings_types failed"

		s2 = Settings("test2")
		assert s2.serialize_schema() == "", "test_settings_types failed"
		test_schema = settings.serialize_schema()
		assert test_schema != "", "test_settings_types failed"
		assert s2.deserialize_schema(test_schema), "test_settings_types failed"

		assert s2.get_bool("testGroup.boolSetting") == True, "test_settings_types failed"
		assert s2.get_double("testGroup.doubleSetting") == 500, "test_settings_types failed"
		assert s2.get_integer("testGroup.integerSetting") == 500, "test_settings_types failed"
		assert s2.get_string("testGroup.stringSetting") == "value", "test_settings_types failed"
		assert s2.get_string_list("testGroup.stringListSetting") == ["value1", "value2"], "test_settings_types failed"

		assert s2.deserialize_settings(settings.serialize_settings(scope = SettingsScope.SettingsUserScope), raw_view, SettingsScope.SettingsResourceScope), "test_settings_types failed"
		assert s2.get_bool("testGroup.boolSetting", raw_view) == False, "test_settings_types failed"
		assert s2.get_double("testGroup.doubleSetting", raw_view) == 700, "test_settings_types failed"
		assert s2.get_integer("testGroup.integerSetting", raw_view) == 700, "test_settings_types failed"
		assert s2.get_string("testGroup.stringSetting", raw_view) == "value_user", "test_settings_types failed"
		assert s2.get_string_list("testGroup.stringListSetting", raw_view) == ["value3", "value4"], "test_settings_types failed"

		assert s2.reset_all(), "test_settings_types failed"
		assert s2.get_bool("testGroup.boolSetting") == True, "test_settings_types failed"
		assert s2.get_double("testGroup.doubleSetting") == 500, "test_settings_types failed"
		assert s2.get_integer("testGroup.integerSetting") == 500, "test_settings_types failed"
		assert s2.get_string("testGroup.stringSetting") == "value", "test_settings_types failed"
		assert s2.get_string_list("testGroup.stringListSetting") == ["value1", "value2"], "test_settings_types failed"

		s3 = Settings("test3")
		assert s3.deserialize_schema(test_schema, SettingsScope.SettingsResourceScope)
		assert not s3.contains("testGroup.ignoreResourceBoolSetting"), "test_settings_types failed"
		assert s3.contains("testGroup.ignoreUserBoolSetting"), "test_settings_types failed"
		assert not s3.contains("testGroup.readOnlyBoolSetting"), "test_settings_types failed"

		assert s3.deserialize_schema(test_schema, SettingsScope.SettingsUserScope, False)
		assert s3.contains("testGroup.ignoreResourceBoolSetting"), "test_settings_types failed"
		assert not s3.contains("testGroup.ignoreUserBoolSetting"), "test_settings_types failed"
		assert not s3.contains("testGroup.readOnlyBoolSetting"), "test_settings_types failed"

		assert s3.deserialize_schema(test_schema, SettingsScope.SettingsUserScope, False)
		assert s3.deserialize_schema(s3.serialize_schema(), SettingsScope.SettingsResourceScope, False)
		assert not s3.contains("testGroup.ignoreResourceBoolSetting"), "test_settings_types failed"
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
		assert load_settings.contains("loader.entryPointOffset"), "test_load_settings failed"
		load_settings.set_string("loader.architecture", 'x86_64')
		load_settings.set_integer("loader.imageBase", 0x500000)
		load_settings.set_integer("loader.entryPointOffset", 0)
		raw_view.set_load_settings(bvt_name, load_settings)
		mapped_view = BinaryViewType[bvt_name].create(raw_view)
		assert mapped_view.view_type == bvt_name, "test_load_settings failed"
		assert mapped_view.segments[0].start == 0x500000, "test_load_settings failed"
		assert len(mapped_view) == 4, "test_load_settings failed"
		assert raw_view.get_load_settings(bvt_name) == load_settings
		raw_view.set_load_settings(bvt_name, None)
		assert raw_view.get_load_settings(bvt_name) is None


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

	def test_demangle_ms(self):
		tests = (
			"??_V@YAPAXI@Z",
			"??_U@YAPAXI@Z"
		)

		oracle = (
			"void* __cdecl operator delete[](uint32_t)",
			"void* __cdecl operator new[](uint32_t)"
		)
		for i, test in enumerate(tests):
			t, n = demangle_ms(Architecture['x86'], test)
			result = self.get_type_string(t, n)
			assert result == oracle[i], f"oracle: {oracle[i]}\nresult: {result}"

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

		oracle = ("int32_t BinaryNinjaCore::BinaryReader::Read8()",
			"int32_t QList<QAbstractAnimation*>::detach_helper_grow(int32_t, int32_t)",
			"int32_t QStatePrivate::emitPropertiesAssigned()",
			"int32_t QtMetaTypePrivate::QMetaTypeFunctionHelper<QItemSelection, true>::Construct(void*, void const*)",
			"int32_t QSharedDataPointer<QFileInfoPrivate>::data()",
			"void QAbstractNativeEventFilter::~QAbstractNativeEventFilter()",
			"int32_t QList<QAbstractState*>::end()",
			"int32_t BinaryNinjaCore::ArchitectureWrapper::GetOpcodeDisplayLength() const",
			"int32_t BinaryNinjaCore::ScriptingInstance::SetCurrentSelection(uint64_t, uint64_t)",
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
			result = self.get_type_string(t, n)
			assert result == oracle[i], f"oracle: '{oracle[i]}'\nresult: '{result}'"


class PluginManagerTest(unittest.TestCase):
	def test_install_plugin(self):
		mgr = RepositoryManager()
		assert mgr.check_for_updates()
		assert mgr.default_repository.path == 'community'
		assert 'community' in [r.path for r in mgr.repositories]
		assert 'official' in [r.path for r in mgr.repositories]
		assert 'Vector35_debugger' in [p.path for p in mgr['official'].plugins]
		try:
			dbg = mgr['official']['Vector35_debugger']
			assert dbg.dependencies == 'colorama\n'
			assert dbg.name == 'Debugger'
			assert not dbg.installed
			assert not dbg.running
			assert not dbg.enabled
			assert not dbg.disable_pending
			dbg.install()
			dbg.enable()
			assert dbg.installed
			assert dbg.enabled
		finally:
			dbg.uninstall()


class TypeParserTest(unittest.TestCase):
	def setUp(self):
		self.arch = 'x86_64'
		self.p = Platform[self.arch]

	def test_integers(self):
		integers = [
			("a", "char a;",                   1, True),
			("b", "unsigned char b;",          1, False),
			("c", "signed char c;",            1, True),
			("d", "int8_t d;",                 1, True),
			("e", "uint8_t e;",                1, False),
			("f", "short f;",                  2, True),
			("g", "unsigned short g;",         2, False),
			("h", "signed short h;",           2, True),
			("i", "short int i;",              2, True),
			("j", "unsigned short int j;",     2, False),
			("k", "signed short int k;",       2, True),
			("l", "uint16_t l;",               2, False),
			("m", "int16_t m;",                2, True),
			("n", "int n;",                    4, True),
			("o", "unsigned int o;",           4, False),
			("p", "signed int p;",             4, True),
			("t", "int32_t t;",                4, True),
			("u", "uint32_t u;",               4, False),
			("q", "long int q;",               8, True),
			("r", "unsigned long int r;",      8, False),
			("s", "signed long int s;",        8, True),
			("v", "long long v;",              8, True),
			("w", "long long int w;",          8, True),
			("x", "unsigned long long int x;", 8, False)]

		for name, definition, size, signed in integers:
			with self.subTest():
				result = self.p.parse_types_from_source(definition)
				var = result.variables[name]
				assert len(var) == size, f"Size for type: {definition} != {size} for arch {self.arch}"
				assert signed == var.signed, f"Sign for type: {definition} isn't {'signed' if signed else 'unsigned'}"

	def test_structures(self):
		structures = [
			("a", "struct a { uint32_t x; uint64_t y; };", 16, 8, 2),
			("b", "struct b { uint64_t x; uint64_t y; };", 16, 8, 2),
			("c", "struct c { uint64_t x; uint32_t y; };", 16, 8, 2),
		]
		for name, definition, size, alignment, members in structures:
			with self.subTest():
				result = self.p.parse_types_from_source(definition)
				s = result.types[name]
				assert len(s) == size, f"Structure property: 'size' {size} incorrect for {definition} got {len(s)} instead"
				assert s.alignment == alignment, f"Structure property: 'alignment' {alignment} incorrect for {definition} got {s.alignment} instead"
				assert len(s.members) == members, f"Structure property: 'members' {members} incorrect for {definition} got {len(s.members)} instead"

class TypeBuilderTest(unittest.TestCase):
	def setUp(self) -> None:
		self.arch = Architecture['x86_64']
		self.plat = Platform['x86_64']
		self.cc = self.plat.calling_conventions[0]

	def test_builder_mutability_round_trip(self):
		ib = TypeBuilder.int(4)
		ib.const = True
		ib.volatile = False
		ib.alternate_name = "billy bob"
		ib.signed = True
		assert ib.const
		assert not ib.volatile
		assert ib.alternate_name == "billy bob"
		assert ib.signed
		assert len(ib) == 4
		assert ib == ib.immutable_copy().mutable_copy(), "IntegerBuilder failed to round trip mutability"

		b = TypeBuilder.char("my_char")
		b.const = True
		b.volatile = False
		assert b.alternate_name == "my_char"
		b.alternate_name = "my_char2"
		assert b.const
		assert not b.volatile
		assert b.alternate_name == "my_char2"
		assert b == b.immutable_copy().mutable_copy(), "CharBuilder failed to round trip mutability"


		b = TypeBuilder.float(4, "half")
		b.const = True
		b.volatile = False
		assert b.const
		assert not b.volatile
		assert b.alternate_name == "half"
		assert b == b.immutable_copy().mutable_copy(), "FloatBuilder failed to round trip mutability"

		b = TypeBuilder.wide_char(4, "wchar32_t")
		b.const = True
		b.volatile = False
		assert b.const
		assert not b.volatile
		assert b.alternate_name == "wchar32_t"
		assert b == b.immutable_copy().mutable_copy(), "WideCharBuilder failed to round trip mutability"

		b = TypeBuilder.pointer(self.arch, ib, 4)
		b.const = True
		b.volatile = False
		assert ib.immutable_copy() == b.immutable_target
		assert ib == b.target
		assert ib.immutable_copy() == b.child.immutable_copy()
		assert b == b.immutable_copy().mutable_copy(), "PointerBuilder failed to round trip mutability"
		pb = b

		b = TypeBuilder.void()
		assert b == b.immutable_copy().mutable_copy(), "VoidBuilder failed to round trip mutability"
		vb = b

		b = TypeBuilder.bool()
		assert b == b.immutable_copy().mutable_copy(), "VoidBuilder failed to round trip mutability"
		bb = b

		b = TypeBuilder.function(vb, [FunctionParameter(pb, "arg1")], self.cc)
		assert b.system_call_number is None
		b.system_call_number = 1
		assert b.system_call_number == 1
		b.clear_system_call()
		assert b.system_call_number is None
		b.system_call_number = 1

		assert b == b.immutable_copy().mutable_copy(), "FunctionBuilder failed to round trip mutability"
		assert b.immutable_return_value == vb.immutable_copy()
		assert b.return_value == vb
		b.return_value = b
		b.append(bb)
		b.append(FunctionParameter(pb, "arg3"))
		assert b.calling_convention == self.cc
		assert b.can_return
		b.can_return = False
		assert not b.can_return
		assert b.stack_adjust == 0
		assert len(b.parameters) == 3
		assert b.parameters[0].type == pb.immutable_copy()
		assert b.parameters[0].name == "arg1"
		assert b.parameters[1].type == bb.immutable_copy()
		assert b.parameters[1].name == ""
		assert b.parameters[2].type == pb.immutable_copy()
		assert b.parameters[2].name == "arg3"
		assert b.stack_adjust.value == 0
		assert not b.variable_arguments
		b.parameters = [FunctionParameter(pb, "arg1")]
		assert b.parameters[0].type == pb.immutable_copy()
		assert b.parameters[0].name == "arg1"
		assert len(b.parameters) == 1

		b = TypeBuilder.function(vb)
		assert len(b.parameters) == 0
		assert b.return_value == TypeBuilder.void()
		assert b == b.immutable_copy().mutable_copy(), "FunctionBuilder failed to round trip mutability"

		# b = TypeBuilder.structure([(ib, "name")], False)
		# assert b.alignment == 4
		# assert b.
		# b = TypeBuilder.structure([StructureMember()])

		b = TypeBuilder.array(pb, 4)
		assert len(b) == len(pb) * 4
		assert b.count == 4
		assert b.element_type == pb.immutable_copy()
