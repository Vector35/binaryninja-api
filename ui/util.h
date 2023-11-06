#pragma once

#include "uitypes.h"
#include "viewframe.h"
#include "qfileaccessor.h"
#include <QtWidgets/QWidget>
#include <QtCore/QFileInfo>

#include <optional>

/*!
    @addtogroup Util
    \ingroup uiapi
    @{
*/

std::string BINARYNINJAUIAPI getStringForLocalVariable(ArchitectureRef arch, FunctionRef func, BinaryNinja::Variable localVar);
std::string BINARYNINJAUIAPI getStringForRegisterValue(ArchitectureRef arch, BinaryNinja::RegisterValue value);
std::string BINARYNINJAUIAPI getPossibleValueSetStateName(BNRegisterValueType state);
std::string BINARYNINJAUIAPI getStringForIntegerValue(int64_t value);
std::string BINARYNINJAUIAPI getStringForIntegerValue(uint64_t value);
std::string BINARYNINJAUIAPI getStringForPossibleValueSet(ArchitectureRef arch, const BinaryNinja::PossibleValueSet& values);
std::string BINARYNINJAUIAPI getStringForInstructionDataflowDetails(BinaryViewRef data, ArchitectureRef arch, FunctionRef func, uint64_t address);
std::optional<BinaryNinja::PossibleValueSet> BINARYNINJAUIAPI getPossibleValueSetForToken(View* view, BinaryViewRef data, ArchitectureRef arch,
    FunctionRef func, HighlightTokenState token, size_t instrIdx);

void BINARYNINJAUIAPI showHexPreview(QWidget* parent, ViewFrame* frame, const QPoint& previewPos, BinaryViewRef data, uint64_t address);
bool BINARYNINJAUIAPI showDisassemblyPreview(QWidget* parent, ViewFrame* frame, const QPoint& previewPos,BinaryViewRef data, FunctionRef func,
    const ViewLocation& location);
void BINARYNINJAUIAPI showTextTooltip(QWidget* parent, const QPoint& previewPos, const QString& text);

bool BINARYNINJAUIAPI isBinaryNinjaDataBase(QFileInfo& info, QFileAccessor& accessor);

PlatformRef BINARYNINJAUIAPI getOrAskForPlatform(QWidget* parent, BinaryViewRef data);
PlatformRef BINARYNINJAUIAPI getOrAskForPlatform(QWidget* parent, PlatformRef defaultValue);

/*!
	@}
*/
