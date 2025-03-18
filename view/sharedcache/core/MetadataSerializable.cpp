#include "MetadataSerializable.hpp"

namespace SharedCacheCore {

void Serialize(SerializationContext& context, std::string_view str) {
	context.writer.String(str.data(), str.length());
}

void Serialize(SerializationContext& context, const char* value) {
	Serialize(context, std::string_view(value));
}

void Serialize(SerializationContext& context, bool b)
{
	context.writer.Bool(b);
}

void Serialize(SerializationContext& context, int8_t value) {
	context.writer.Int(value);
}

void Serialize(SerializationContext& context, uint8_t value) {
	context.writer.Uint(value);
}

void Serialize(SerializationContext& context, int16_t value) {
	context.writer.Int(value);
}

void Serialize(SerializationContext& context, uint16_t value) {
	context.writer.Uint(value);
}

void Serialize(SerializationContext& context, int32_t value) {
	context.writer.Int(value);
}

void Serialize(SerializationContext& context, uint32_t value) {
	context.writer.Uint(value);
}

void Serialize(SerializationContext& context, int64_t value) {
	context.writer.Int64(value);
}

void Serialize(SerializationContext& context, uint64_t value) {
	context.writer.Uint64(value);
}

void Deserialize(DeserializationContext& context, std::string_view name, bool& b) {
	b = context.doc[name.data()].GetBool();
}

void Deserialize(DeserializationContext& context, std::string_view name, uint8_t& b)
{
	b = static_cast<uint8_t>(context.doc[name.data()].GetUint64());
}

void Deserialize(DeserializationContext& context, std::string_view name, uint16_t& b)
{
	b = static_cast<uint16_t>(context.doc[name.data()].GetUint64());
}

void Deserialize(DeserializationContext& context, std::string_view name, uint32_t& b)
{
	b = static_cast<uint32_t>(context.doc[name.data()].GetUint64());
}

void Deserialize(DeserializationContext& context, std::string_view name, uint64_t& b)
{
	b = context.doc[name.data()].GetUint64();
}

void Deserialize(DeserializationContext& context, std::string_view name, int8_t& b)
{
	b = context.doc[name.data()].GetInt64();
}

void Deserialize(DeserializationContext& context, std::string_view name, int16_t& b)
{
	b = context.doc[name.data()].GetInt64();
}

void Deserialize(DeserializationContext& context, std::string_view name, int32_t& b)
{
	b = context.doc[name.data()].GetInt();
}

void Deserialize(DeserializationContext& context, std::string_view name, int64_t& b)
{
	b = context.doc[name.data()].GetInt64();
}

void Deserialize(DeserializationContext& context, std::string_view name, std::string& b)
{
	b = context.doc[name.data()].GetString();
}

void Deserialize(DeserializationContext& context, std::string_view name, std::map<uint64_t, std::string>& b)
{
	for (auto& i : context.doc[name.data()].GetArray())
		b[i.GetArray()[0].GetUint64()] = i.GetArray()[1].GetString();
}

void Deserialize(DeserializationContext& context, std::string_view name, std::unordered_map<uint64_t, std::string>& b)
{
	for (auto& i : context.doc[name.data()].GetArray())
		b[i.GetArray()[0].GetUint64()] = i.GetArray()[1].GetString();
}

void Deserialize(DeserializationContext& context, std::string_view name, std::unordered_map<uint64_t, uint64_t>& b)
{
	for (auto& i : context.doc[name.data()].GetArray())
		b[i.GetArray()[0].GetUint64()] = i.GetArray()[1].GetUint64();
}

void Deserialize(DeserializationContext& context, std::string_view name, std::unordered_map<std::string, std::unordered_map<uint64_t, uint64_t>>& b)
{
	for (auto& i : context.doc[name.data()].GetArray())
	{
		std::string key = i.GetArray()[0].GetString();
		std::unordered_map<uint64_t, uint64_t> memArray;
		for (auto& member : i.GetArray()[1].GetArray())
		{
			memArray[member.GetArray()[0].GetUint64()] = member.GetArray()[1].GetUint64();
		}
		b[key] = memArray;
	}
}

void Deserialize(DeserializationContext& context, std::string_view name, std::unordered_map<std::string, std::string>& b)
{
	for (auto& i : context.doc[name.data()].GetArray())
		b[i.GetArray()[0].GetString()] = i.GetArray()[1].GetString();
}

void Deserialize(DeserializationContext& context, std::string_view name, std::vector<std::string>& b)
{
	for (auto& i : context.doc[name.data()].GetArray())
		b.emplace_back(i.GetString());
}

// Note: This flattens the pair into [first, second.first, second.second] with no nested arrays.
void Serialize(SerializationContext& context, const std::pair<uint64_t, std::pair<uint64_t, uint64_t>>& value)
{
	context.writer.StartArray();
	Serialize(context, value.first);
	Serialize(context, value.second.first);
	Serialize(context, value.second.second);
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, std::vector<std::pair<uint64_t, std::pair<uint64_t, uint64_t>>>& b)
{
	for (auto& i : context.doc[name.data()].GetArray())
	{
		std::pair<uint64_t, std::pair<uint64_t, uint64_t>> j;
		j.first = i.GetArray()[0].GetUint64();
		j.second.first = i.GetArray()[1].GetUint64();
		j.second.second = i.GetArray()[2].GetUint64();
		b.push_back(j);
	}
}

void Deserialize(DeserializationContext& context, std::string_view name, std::vector<std::pair<uint64_t, bool>>& b)
{
	for (auto& i : context.doc[name.data()].GetArray())
	{
		std::pair<uint64_t, bool> j;
		j.first = i.GetArray()[0].GetUint64();
		j.second = i.GetArray()[1].GetBool();
		b.push_back(j);
	}
}

void Deserialize(DeserializationContext& context, std::string_view name, std::vector<uint64_t>& b)
{
	for (auto& i : context.doc[name.data()].GetArray())
	{
		b.push_back(i.GetUint64());
	}
}

void Deserialize(DeserializationContext& context, std::string_view name, std::unordered_map<std::string, uint64_t>& b)
{
	for (auto& i : context.doc[name.data()].GetArray())
	{
		b[i.GetArray()[0].GetString()] = i.GetArray()[1].GetUint64();
	}
}

void Deserialize(DeserializationContext& context, std::string_view name, std::vector<std::pair<uint64_t, std::vector<std::pair<uint64_t, std::string>>>>& b)
{
	for (auto& i : context.doc[name.data()].GetArray())
	{
		std::pair<uint64_t, std::vector<std::pair<uint64_t, std::string>>> j;
		j.first = i.GetArray()[0].GetUint64();
		for (auto& k : i.GetArray()[1].GetArray())
		{
			j.second.push_back({k.GetArray()[0].GetUint64(), k.GetArray()[1].GetString()});
		}
		b.push_back(j);
	}
}

void Serialize(SerializationContext& context, const mach_header_64& value) {
	context.writer.StartArray();
	Serialize(context, value.magic);
	// cputype and cpusubtype are signed but were serialized as unsigned in
	// v4.2 (metadata version 2). We continue serializing them as unsigned
	// so we don't need to bump the metadata version.
	Serialize(context, static_cast<uint32_t>(value.cputype));
	Serialize(context, static_cast<uint32_t>(value.cpusubtype));
	Serialize(context, value.filetype);
	Serialize(context, value.ncmds);
	Serialize(context, value.sizeofcmds);
	Serialize(context, value.flags);
	Serialize(context, value.reserved);
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, mach_header_64& b)
{
	auto bArr = context.doc[name.data()].GetArray();
	b.magic = bArr[0].GetUint();
	b.cputype = bArr[1].GetUint();
	b.cpusubtype = bArr[2].GetUint();
	b.filetype = bArr[3].GetUint();
	b.ncmds = bArr[4].GetUint();
	b.sizeofcmds = bArr[5].GetUint();
	b.flags = bArr[6].GetUint();
	b.reserved = bArr[7].GetUint();
}

void Serialize(SerializationContext& context, const symtab_command& value)
{
	context.writer.StartArray();
	Serialize(context, value.cmd);
	Serialize(context, value.cmdsize);
	Serialize(context, value.symoff);
	Serialize(context, value.nsyms);
	Serialize(context, value.stroff);
	Serialize(context, value.strsize);
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, symtab_command& b)
{
	auto bArr = context.doc[name.data()].GetArray();
	b.cmd = bArr[0].GetUint();
	b.cmdsize = bArr[1].GetUint();
	b.symoff = bArr[2].GetUint();
	b.nsyms = bArr[3].GetUint();
	b.stroff = bArr[4].GetUint();
	b.strsize = bArr[5].GetUint();
}

void Serialize(SerializationContext& context, const dysymtab_command& value)
{
	context.writer.StartArray();
	Serialize(context, value.cmd);
	Serialize(context, value.cmdsize);
	Serialize(context, value.ilocalsym);
	Serialize(context, value.nlocalsym);
	Serialize(context, value.iextdefsym);
	Serialize(context, value.nextdefsym);
	Serialize(context, value.iundefsym);
	Serialize(context, value.nundefsym);
	Serialize(context, value.tocoff);
	Serialize(context, value.ntoc);
	Serialize(context, value.modtaboff);
	Serialize(context, value.nmodtab);
	Serialize(context, value.extrefsymoff);
	Serialize(context, value.nextrefsyms);
	Serialize(context, value.indirectsymoff);
	Serialize(context, value.nindirectsyms);
	Serialize(context, value.extreloff);
	Serialize(context, value.nextrel);
	Serialize(context, value.locreloff);
	Serialize(context, value.nlocrel);
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, dysymtab_command& b)
{
	auto bArr = context.doc[name.data()].GetArray();
	b.cmd = bArr[0].GetUint();
	b.cmdsize = bArr[1].GetUint();
	b.ilocalsym = bArr[2].GetUint();
	b.nlocalsym = bArr[3].GetUint();
	b.iextdefsym = bArr[4].GetUint();
	b.nextdefsym = bArr[5].GetUint();
	b.iundefsym = bArr[6].GetUint();
	b.nundefsym = bArr[7].GetUint();
	b.tocoff = bArr[8].GetUint();
	b.ntoc = bArr[9].GetUint();
	b.modtaboff = bArr[10].GetUint();
	b.nmodtab = bArr[11].GetUint();
	b.extrefsymoff = bArr[12].GetUint();
	b.nextrefsyms = bArr[13].GetUint();
	b.indirectsymoff = bArr[14].GetUint();
	b.nindirectsyms = bArr[15].GetUint();
	b.extreloff = bArr[16].GetUint();
	b.nextrel = bArr[17].GetUint();
	b.locreloff = bArr[18].GetUint();
	b.nlocrel = bArr[19].GetUint();
}

void Serialize(SerializationContext& context, const dyld_info_command& value)
{
	context.writer.StartArray();
	Serialize(context, value.cmd);
	Serialize(context, value.cmdsize);
	Serialize(context, value.rebase_off);
	Serialize(context, value.rebase_size);
	Serialize(context, value.bind_off);
	Serialize(context, value.bind_size);
	Serialize(context, value.weak_bind_off);
	Serialize(context, value.weak_bind_size);
	Serialize(context, value.lazy_bind_off);
	Serialize(context, value.lazy_bind_size);
	Serialize(context, value.export_off);
	Serialize(context, value.export_size);
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, dyld_info_command& b)
{
	auto bArr = context.doc[name.data()].GetArray();
	b.cmd = bArr[0].GetUint();
	b.cmdsize = bArr[1].GetUint();
	b.rebase_off = bArr[2].GetUint();
	b.rebase_size = bArr[3].GetUint();
	b.bind_off = bArr[4].GetUint();
	b.bind_size = bArr[5].GetUint();
	b.weak_bind_off = bArr[6].GetUint();
	b.weak_bind_size = bArr[7].GetUint();
	b.lazy_bind_off = bArr[8].GetUint();
	b.lazy_bind_size = bArr[9].GetUint();
	b.export_off = bArr[10].GetUint();
	b.export_size = bArr[11].GetUint();
}

void Serialize(SerializationContext& context, const routines_command_64& value)
{
	context.writer.StartArray();
	Serialize(context, value.cmd);
	Serialize(context, value.cmdsize);
	Serialize(context, value.init_address);
	Serialize(context, value.init_module);
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, routines_command_64& b)
{
	auto bArr = context.doc[name.data()].GetArray();
	// Because we might open databases that had not previously serialized this, we must allow
	// an empty array, otherwise we will crash!
	if (bArr.Size() < 4)
		return;
	b.cmd = bArr[0].GetUint();
	b.cmdsize = bArr[1].GetUint();
	b.init_address = bArr[2].GetUint64();
	b.init_module = bArr[3].GetUint64();
}

void Serialize(SerializationContext& context, const function_starts_command& value)
{
	context.writer.StartArray();
	Serialize(context, value.cmd);
	Serialize(context, value.cmdsize);
	Serialize(context, value.funcoff);
	Serialize(context, value.funcsize);
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, function_starts_command& b)
{
	auto bArr = context.doc[name.data()].GetArray();
	b.cmd = bArr[0].GetUint();
	b.cmdsize = bArr[1].GetUint();
	b.funcoff = bArr[2].GetUint();
	b.funcsize = bArr[3].GetUint();
}

void Serialize(SerializationContext& context, const section_64& value)
{
	context.writer.StartArray();

	std::string_view sectname(value.sectname, 16);
	std::string_view segname(value.segname, 16);

	Serialize(context, sectname.substr(0, sectname.find('\0')));
	Serialize(context, segname.substr(0, segname.find('\0')));
	Serialize(context, value.addr);
	Serialize(context, value.size);
	Serialize(context, value.offset);
	Serialize(context, value.align);
	Serialize(context, value.reloff);
	Serialize(context, value.nreloc);
	Serialize(context, value.flags);
	Serialize(context, value.reserved1);
	Serialize(context, value.reserved2);
	Serialize(context, value.reserved3);
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, std::vector<section_64>& b)
{
	auto bArr = context.doc[name.data()].GetArray();
	for (auto& s : bArr)
	{
		section_64 sec;
		auto s2 = s.GetArray();
		std::string sectNameStr = s2[0].GetString();
		memset(sec.sectname, 0, 16);
		memcpy(sec.sectname, sectNameStr.c_str(), sectNameStr.size());
		std::string segNameStr = s2[1].GetString();
		memset(sec.segname, 0, 16);
		memcpy(sec.segname, segNameStr.c_str(), segNameStr.size());
		sec.addr = s2[2].GetUint64();
		sec.size = s2[3].GetUint64();
		sec.offset = s2[4].GetUint();
		sec.align = s2[5].GetUint();
		sec.reloff = s2[6].GetUint();
		sec.nreloc = s2[7].GetUint();
		sec.flags = s2[8].GetUint();
		sec.reserved1 = s2[9].GetUint();
		sec.reserved2 = s2[10].GetUint();
		sec.reserved3 = s2[11].GetUint();
		b.push_back(std::move(sec));
	}
}

void Serialize(SerializationContext& context, const linkedit_data_command& value)
{
	context.writer.StartArray();
	Serialize(context, value.cmd);
	Serialize(context, value.cmdsize);
	Serialize(context, value.dataoff);
	Serialize(context, value.datasize);
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, linkedit_data_command& b)
{
	auto bArr = context.doc[name.data()].GetArray();
	b.cmd = bArr[0].GetUint();
	b.cmdsize = bArr[1].GetUint();
	b.dataoff = bArr[2].GetUint();
	b.datasize = bArr[3].GetUint();
}

void Serialize(SerializationContext& context, const segment_command_64& value)
{
	context.writer.StartArray();
	std::string_view segname(value.segname, 16);
	Serialize(context, segname.substr(0, segname.find('\0')));
	Serialize(context, value.vmaddr);
	Serialize(context, value.vmsize);
	Serialize(context, value.fileoff);
	Serialize(context, value.filesize);
	Serialize(context, value.maxprot);
	Serialize(context, value.initprot);
	Serialize(context, value.nsects);
	Serialize(context, value.flags);
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, segment_command_64& b)
{
	auto bArr = context.doc[name.data()].GetArray();
	std::string segNameStr = bArr[0].GetString();
	memset(b.segname, 0, 16);
	memcpy(b.segname, segNameStr.c_str(), segNameStr.size());
	b.vmaddr = bArr[1].GetUint64();
	b.vmsize = bArr[2].GetUint64();
	b.fileoff = bArr[3].GetUint64();
	b.filesize = bArr[4].GetUint64();
	b.maxprot = bArr[5].GetUint();
	b.initprot = bArr[6].GetUint();
	b.nsects = bArr[7].GetUint();
	b.flags = bArr[8].GetUint();
}

void Deserialize(DeserializationContext& context, std::string_view name, std::vector<segment_command_64>& b)
{
	auto bArr = context.doc[name.data()].GetArray();
	for (auto& s : bArr)
	{
		segment_command_64 sec;
		auto s2 = s.GetArray();
		std::string segNameStr = s2[0].GetString();
		memset(sec.segname, 0, 16);
		memcpy(sec.segname, segNameStr.c_str(), segNameStr.size());
		sec.vmaddr = s2[1].GetUint64();
		sec.vmsize = s2[2].GetUint64();
		sec.fileoff = s2[3].GetUint64();
		sec.filesize = s2[4].GetUint64();
		sec.maxprot = s2[5].GetUint();
		sec.initprot = s2[6].GetUint();
		sec.nsects = s2[7].GetUint();
		sec.flags = s2[8].GetUint();
		b.push_back(std::move(sec));
	}
}

void Serialize(SerializationContext& context, const build_version_command& value)
{
	context.writer.StartArray();
	Serialize(context, value.cmd);
	Serialize(context, value.cmdsize);
	Serialize(context, value.platform);
	Serialize(context, value.minos);
	Serialize(context, value.sdk);
	Serialize(context, value.ntools);
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, build_version_command& b)
{
	auto bArr = context.doc[name.data()].GetArray();
	b.cmd = bArr[0].GetUint();
	b.cmdsize = bArr[1].GetUint();
	b.platform = bArr[2].GetUint();
	b.minos = bArr[3].GetUint();
	b.sdk = bArr[4].GetUint();
	b.ntools = bArr[5].GetUint();
}

void Serialize(SerializationContext& context, const build_tool_version& value)
{
	context.writer.StartArray();
	Serialize(context, value.tool);
	Serialize(context, value.version);
	context.writer.EndArray();
}

void Deserialize(DeserializationContext& context, std::string_view name, std::vector<build_tool_version>& b)
{
	auto bArr = context.doc[name.data()].GetArray();
	for (auto& s : bArr)
	{
		build_tool_version sec;
		auto s2 = s.GetArray();
		sec.tool = s2[0].GetUint();
		sec.version = s2[1].GetUint();
		b.push_back(sec);
	}
}

} // namespace SharedCacheCore
