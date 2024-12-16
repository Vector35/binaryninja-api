#pragma once

#include <QtWidgets/QWidget>
#include "binaryninjaapi.h"
#include "render.h"
#include "uicontext.h"

/*!
    @addtogroup commands
    \ingroup uiapi
    @{
*/

bool BINARYNINJAUIAPI undefineForAddress(BinaryViewRef data, uint64_t addr);
bool BINARYNINJAUIAPI undefineNameForAddress(BinaryViewRef data, uint64_t addr);
bool BINARYNINJAUIAPI undefineNameForLocalVariable(
    BinaryViewRef data, FunctionRef func, const BinaryNinja::Variable& var);
bool BINARYNINJAUIAPI inputNameForAddress(QWidget* parent, BinaryViewRef data, uint64_t addr);
bool BINARYNINJAUIAPI inputNameForLocalVariable(
    QWidget* parent, BinaryViewRef data, FunctionRef function, const BinaryNinja::Variable& var);
bool BINARYNINJAUIAPI inputNameForType(
    QWidget* parent, std::string& name, const QString& title = "Set Name", const QString& msg = "Enter name:");

bool BINARYNINJAUIAPI InferArraySize(TypeRef& type, size_t selectionSize);
bool BINARYNINJAUIAPI askForNewType(QWidget* parent, std::optional<BinaryNinja::TypeContainer> container, const std::string& title,
    bool allowZeroSize, TypeRef& type, BinaryNinja::QualifiedName& name);
bool BINARYNINJAUIAPI inputNewType(QWidget* parent, BinaryViewRef data, FunctionRef currentFunction,
    uint64_t currentAddr, size_t selectionSize, HighlightTokenState& highlight);
bool BINARYNINJAUIAPI createInferredMember(QWidget* parent, BinaryViewRef data, HighlightTokenState& highlight,
    FunctionRef func, const BinaryNinja::FunctionViewType& ilType, size_t instrIndex);
bool BINARYNINJAUIAPI createStructMembers(
    QWidget* parent, BinaryViewRef data, HighlightTokenState& highlight, FunctionRef func);

bool BINARYNINJAUIAPI inputPossibleValueSet(QWidget* parent, BinaryViewRef data, FunctionRef currentFunction, const BinaryNinja::FunctionViewType& funcType,
    const BinaryNinja::Variable& var, size_t ilInstructionIndex = BN_INVALID_EXPR);

bool BINARYNINJAUIAPI getEnumSelection(QWidget* parent, BinaryViewRef data, FunctionRef func, uint64_t constValue,
	TypeRef& selectedEnum, bool checkValue, bool canTruncate);

bool BINARYNINJAUIAPI overwriteCode(
    BinaryViewRef data, ArchitectureRef arch, uint64_t addr, size_t len, const BinaryNinja::DataBuffer& buffer);
bool BINARYNINJAUIAPI overwriteCode(
    BinaryViewRef data, ArchitectureRef arch, uint64_t addr, const BinaryNinja::DataBuffer& buffer);

StructureRef BINARYNINJAUIAPI getInnerMostStructureContaining(BinaryViewRef data, StructureRef structure,
    size_t& memberIndex, const std::vector<std::string>& nameList, size_t nameIndex, TypeRef& type,
    std::string& typeName);
StructureRef BINARYNINJAUIAPI getInnerMostStructureContainingOffset(BinaryViewRef data, StructureRef structure,
    const std::vector<std::string>& nameList, size_t nameIndex, size_t offset, TypeRef& type, std::string& typeName);
// Get the offset of the inner most structure, ralative to the supplied outer most structure
uint64_t BINARYNINJAUIAPI getInnerMostStructureOffset(
    BinaryViewRef data, StructureRef structure, const std::vector<std::string>& nameList, size_t nameIndex);

// Auto generate a usable type name with the given prefix
std::string BINARYNINJAUIAPI createStructureName(BinaryNinja::TypeContainer types, const std::string& prefix = "struct_");

std::optional<BinaryNinja::Variable> BINARYNINJAUIAPI getSplitVariableForAssignment(
	FunctionRef func, const BinaryNinja::FunctionViewType& ilType, uint64_t location, const BinaryNinja::Variable& var);

std::optional<size_t> getVariableDefinitionInstructionIndex(
    FunctionRef func, const BinaryNinja::FunctionViewType& funcType, const BinaryNinja::Variable& var, size_t ilInstructionIndex);
std::optional<size_t> getVariableDefinitionAddress(
    FunctionRef func, const BinaryNinja::FunctionViewType& funcType, const BinaryNinja::Variable& var, size_t ilInstructionIndex);

bool IsDefaultArgumentOrParameterName(const std::string& name);
std::optional<std::string> GetVariableNameFromExpr(BinaryNinja::Function* func,
	const BinaryNinja::HighLevelILInstruction& instr);

// Return a function type for a given type. The input type can be a function type itself, or a pointer to a function
// type, or a NTR to a pointer to a function type. This is used when the user set the type of function using a
// typedef-ed type
TypeRef GetFunctionType(BinaryViewRef data, TypeRef type);

/*!
	@}
*/
