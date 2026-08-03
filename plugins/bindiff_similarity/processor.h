#pragma once

#include "binaryninjaapi.h"
#include <functional>
#include <memory>
#include <string>

class BinDiffProcessor
{
public:
	struct Impl;
	std::unique_ptr<Impl> m_impl;

	BinDiffProcessor(BinaryNinja::BinaryView& view);

	~BinDiffProcessor();

	void AddFunction(BinaryNinja::Function& func);

	// Finalizes the graphs and writes the .BinExport protobuf to the specified path.
	// Returns false when the output could not be written.
	bool Process(const std::string& exportFilePath,
		std::function<bool(double)> progress = [](double) { return true; });
};
