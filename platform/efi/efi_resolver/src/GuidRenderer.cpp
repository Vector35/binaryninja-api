#include "GuidRenderer.h"

bool isType(const vector<pair<Type*, size_t>>& context, const string& name)
{
    if (context.empty())
        return false;

    auto [deepestType, size] = context.back();
    if (!deepestType->IsNamedTypeRefer())
        return false;

    return deepestType->GetTypeName().GetString() == name;
}

bool EfiGuidRenderer::IsValidForData(BinaryView* bv, uint64_t address, Type* type,
    vector<pair<Type*, size_t>>& context)
{
    return isType(context, "EFI_GUID");
}

static string formatGuid(uint32_t data1, uint16_t data2, uint16_t data3, uint64_t data4)
{
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0')
        << std::setw(8) << data1 << "-"
        << std::setw(4) << data2 << "-"
        << std::setw(4) << data3 << "-"
        << std::setw(16) << data4;
    return oss.str();
}

vector<DisassemblyTextLine> EfiGuidRenderer::GetLinesForData(
    BinaryView* bv, uint64_t address, Type*, const vector<InstructionTextToken>& prefix,
    size_t, vector<pair<Type*, size_t>>& context)
{
    BinaryReader reader(bv);
    reader.Seek(address);
    auto data1 = reader.Read32();
    auto data2 = reader.Read16();
    auto data3 = reader.Read16();
    auto data4 = reader.ReadBE64();
    string guidStr = formatGuid(data1, data2, data3, data4);

    DisassemblyTextLine line;
    line.addr = address;
    line.tokens = prefix;
    line.tokens.emplace_back(TextToken, "[EFI_GUID(\"");
    line.tokens.emplace_back(StringToken, guidStr);
    line.tokens.emplace_back(TextToken, "\")]");
    return { line };
}

void EfiGuidRenderer::Register()
{
    DataRendererContainer::RegisterTypeSpecificDataRenderer(new EfiGuidRenderer());
}
