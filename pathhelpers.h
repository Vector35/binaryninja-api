#pragma once

#include "binaryninjacore.h"
#include "pathformathelpers.h"

#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace BinaryNinja::Path
{
	using BinaryNinjaPathFormat::PathToUtf8String;

	// Diagnostic-only path formatting. Use PathToUtf8String for data interchange.
	using BinaryNinjaPathFormat::PrintablePath;

	inline std::filesystem::path Utf8ToPath(std::string_view path)
	{
#if defined(WIN32) || defined(_WIN32)
		std::u8string utf8Path;
		utf8Path.reserve(path.size());
		for (char ch : path)
			utf8Path.push_back(static_cast<char8_t>(static_cast<unsigned char>(ch)));
		return std::filesystem::path(utf8Path);
#else
		return std::filesystem::path(std::string(path));
#endif
	}

	inline std::filesystem::path PathFromCoreBorrowed(BNPath* path)
	{
		if (!path)
			return {};

		size_t count = 0;
		const void* data = BNGetPathData(path, &count);
		if (!data)
			return {};

#if defined(WIN32) || defined(_WIN32)
		return std::filesystem::path(
			std::wstring(static_cast<const wchar_t*>(data), static_cast<const wchar_t*>(data) + count));
#else
		return std::filesystem::path(
			std::string(static_cast<const char*>(data), static_cast<const char*>(data) + count));
#endif
	}

	inline std::string PrintablePath(BNPath* path)
	{
		return PrintablePath(PathFromCoreBorrowed(path));
	}

	inline BNPath* PathToCore(const std::filesystem::path& path)
	{
		const auto& native = path.native();
		return BNCreatePath(native.data(), native.size());
	}

	class APIObject
	{
		struct AdoptObject
		{};

		BNPath* m_path;

		APIObject(BNPath* path, AdoptObject): m_path(path) {}

	  public:
		explicit APIObject(const std::filesystem::path& path): m_path(PathToCore(path)) {}
		~APIObject()
		{
			BNFreePath(m_path);
		}
		APIObject(const APIObject&) = delete;
		APIObject& operator=(const APIObject&) = delete;
		APIObject(APIObject&& other) noexcept: m_path(std::exchange(other.m_path, nullptr)) {}
		APIObject& operator=(APIObject&& other) noexcept
		{
			if (this != &other)
			{
				BNFreePath(m_path);
				m_path = std::exchange(other.m_path, nullptr);
			}
			return *this;
		}

		static APIObject Adopt(BNPath* path) { return APIObject(path, AdoptObject {}); }

		operator BNPath*() const { return m_path; }
		BNPath* get() const { return m_path; }
	};

	inline std::filesystem::path PathFromCore(BNPath* path)
	{
		APIObject ownedPath = APIObject::Adopt(path);
		return PathFromCoreBorrowed(ownedPath.get());
	}

	class APIObjectList
	{
		std::vector<APIObject> m_objects;
		std::vector<BNPath*> m_paths;

	  public:
		template <typename Alloc>
		explicit APIObjectList(const std::vector<std::filesystem::path, Alloc>& paths)
		{
			m_objects.reserve(paths.size());
			m_paths.reserve(paths.size());
			for (const auto& path : paths)
			{
				m_objects.emplace_back(path);
				m_paths.push_back(m_objects.back().get());
			}
		}

		BNPath** data() { return m_paths.data(); }
		size_t size() const { return m_paths.size(); }
	};
}
