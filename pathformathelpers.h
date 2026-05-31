#pragma once

#include <fmt/format.h>
#include <filesystem>
#include <string>

namespace BinaryNinjaPathFormat
{
	inline std::string PathToUtf8String(const std::filesystem::path& path)
	{
		auto value = path.u8string();
		return std::string(reinterpret_cast<const char*>(value.data()), value.size());
	}

	inline std::string PrintablePath(const std::filesystem::path& path)
	{
		// TODO: Make diagnostic formatting tolerant of native paths that cannot be represented as valid UTF-8,
		// such as Windows paths containing unpaired UTF-16 surrogates.
		return PathToUtf8String(path);
	}
}

// fmt/std.h provides its own std::filesystem::path formatter. Keep that disabled in translation units that
// include this header first, so path formatting consistently goes through PrintablePath.
#if !defined(FMT_STD_H_)
#ifndef FMT_CPP_LIB_FILESYSTEM
#define FMT_CPP_LIB_FILESYSTEM 0
#endif
template<> struct fmt::formatter<std::filesystem::path> : fmt::formatter<std::string>
{
	format_context::iterator format(const std::filesystem::path& path, format_context& ctx) const
	{
		return fmt::formatter<std::string>::format(BinaryNinjaPathFormat::PrintablePath(path), ctx);
	}
};
#endif
