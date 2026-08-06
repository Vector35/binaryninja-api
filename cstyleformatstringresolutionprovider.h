#pragma once

#include "binaryninjaapi.h"

namespace BinaryNinja
{
	/*! Resolves C-style printf format strings to their consumed argument types.

		\ingroup formatstringresolutionprovider
	*/
	class CStyleFormatStringResolutionProvider : public FormatStringResolutionProvider
	{
	  public:
		CStyleFormatStringResolutionProvider();

		std::optional<std::vector<Confidence<Ref<Type>>>> IsValid(
			const std::string& format, Platform* platform) override;
	};

	/*! Registers the built-in C-style format string provider if it is not already registered. */
	void RegisterCStyleFormatStringResolutionProvider();
}
