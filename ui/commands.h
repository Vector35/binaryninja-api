#pragma once

#include <QtWidgets/QWidget>
#include "binaryninjaapi.h"
#include "render.h"
#include "uicontext.h"

bool BINARYNINJAUIAPI undefineNameForAddress(BinaryViewRef data, uint64_t addr);
bool BINARYNINJAUIAPI undefineNameForLocalVariable(BinaryViewRef data,
	FunctionRef func, const BinaryNinja::Variable& var);
bool BINARYNINJAUIAPI inputNameForAddress(QWidget* parent, BinaryViewRef data, uint64_t addr);
bool BINARYNINJAUIAPI inputNameForLocalVariable(QWidget* parent, BinaryViewRef data,
	FunctionRef function, const BinaryNinja::Variable& var);
bool BINARYNINJAUIAPI inputNameForType(QWidget* parent, std::string& name, const QString& title = "Set Name",
	const QString& msg = "Enter name:");

bool BINARYNINJAUIAPI InferArraySize(TypeRef& type, size_t selectionSize);
bool BINARYNINJAUIAPI askForNewType(QWidget* parent, BinaryViewRef data, FunctionRef func, const std::string& title,
	TypeRef& type, BinaryNinja::QualifiedName& name);
bool BINARYNINJAUIAPI inputNewType(QWidget* parent, BinaryViewRef data, FunctionRef currentFunction,
	uint64_t currentAddr, size_t selectionSize, HighlightTokenState& highlight);
bool BINARYNINJAUIAPI createInferredMember(QWidget* parent, BinaryViewRef data, HighlightTokenState& highlight,
	FunctionRef func, BNFunctionGraphType type);

bool BINARYNINJAUIAPI inputPossibleValueSet(QWidget* parent, BinaryViewRef data, FunctionRef currentFunction,
	HighlightTokenState& highlight, uint64_t defSiteAddress, size_t ilInstructionIndex = BN_INVALID_EXPR);

bool BINARYNINJAUIAPI overwriteCode(BinaryViewRef data, ArchitectureRef arch,
	uint64_t addr, size_t len, const BinaryNinja::DataBuffer& buffer);
bool BINARYNINJAUIAPI overwriteCode(BinaryViewRef data, ArchitectureRef arch,
	uint64_t addr, const BinaryNinja::DataBuffer& buffer);

StructureRef BINARYNINJAUIAPI getInnerMostStructureContaining(BinaryViewRef data, StructureRef structure,
	size_t& memberIndex, const std::vector<std::string>& nameList, size_t nameIndex, TypeRef& type, std::string& typeName);
StructureRef BINARYNINJAUIAPI getInnerMostStructureContainingOffset(BinaryViewRef data, StructureRef structure,
	const std::vector<std::string>& nameList, size_t nameIndex, size_t offset, TypeRef& type, std::string& typeName);
// Get the offset of the inner most structure, ralative to the supplied outer most structure
uint64_t BINARYNINJAUIAPI getInnerMostStructureOffset(BinaryViewRef data, StructureRef structure,
	const std::vector<std::string>& nameList, size_t nameIndex);

// Auto generate a structure name
std::string BINARYNINJAUIAPI createStructureName(BinaryViewRef data);
