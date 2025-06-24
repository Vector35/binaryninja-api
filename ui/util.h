#pragma once

#include "uitypes.h"
#include "viewframe.h"
#include "qfileaccessor.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"
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
std::string BINARYNINJAUIAPI getStringForUIntegerValue(uint64_t value);
std::string BINARYNINJAUIAPI getStringForPossibleValueSet(ArchitectureRef arch, const BinaryNinja::PossibleValueSet& values, bool pretty = true);
std::string BINARYNINJAUIAPI getStringForInstructionDataflowDetails(BinaryViewRef data, ArchitectureRef arch, FunctionRef func, uint64_t address);
std::optional<BinaryNinja::PossibleValueSet> BINARYNINJAUIAPI getPossibleValueSetForToken(View* view, BinaryViewRef data, ArchitectureRef arch,
    FunctionRef func, HighlightTokenState token, size_t instrIdx);

std::optional<BinaryNinja::PossibleValueSet> BINARYNINJAUIAPI getPossibleValueSetForILToken(View* view, HighlightTokenState token);
std::optional<uint64_t> BINARYNINJAUIAPI getAddressOfILTokenExpr(View* view, HighlightTokenState token);

template <typename T>
std::optional<T> visitILInstructionForToken(View* view, const HighlightTokenState& token,
		const std::function<std::optional<T>(BinaryNinja::LowLevelILInstruction&)>& llil,
		const std::function<std::optional<T>(BinaryNinja::MediumLevelILInstruction&)>& mlil,
		const std::function<std::optional<T>(BinaryNinja::HighLevelILInstruction&)>& hlil)
{
	if (token.token.exprIndex == BN_INVALID_EXPR)
		return {};

	BNFunctionGraphType type = view->getILViewType().type;
	switch (type)
	{
	case InvalidILViewType:
	case NormalFunctionGraph:
		break;
	case LiftedILFunctionGraph:
	case MappedMediumLevelILFunctionGraph:
	case MappedMediumLevelILSSAFormFunctionGraph:
		// omitted because I don't know how to get to _exactly_ the right mapped mlil
		// function from the View frame -- if we go through the Function object we may
		// not get the same IL function object the token corresponds to due to an update
		break;
	case LowLevelILFunctionGraph:
	case LowLevelILSSAFormFunctionGraph:
	{
		LowLevelILFunctionRef llilFunc = view->getCurrentLowLevelILFunction();

		if (llilFunc && type == LowLevelILSSAFormFunctionGraph)
			llilFunc = llilFunc->GetSSAForm();

		if (!llilFunc)
			break;

		if (token.token.exprIndex >= llilFunc->GetExprCount())
		{
			FunctionRef func = llilFunc->GetFunction();
			uint64_t start = func ? func->GetStart() : 0;

			BinaryNinja::LogErrorF("Invalid LowLevelIL token exprIndex {} in {} of {:x}", token.token.exprIndex, type, start);
			break;
		}

		BinaryNinja::LowLevelILInstruction instr = llilFunc->GetExpr(token.token.exprIndex);

		if (instr.instructionIndex >= llilFunc->GetInstructionCount())
		{
			FunctionRef func = llilFunc->GetFunction();
			uint64_t start = func ? func->GetStart() : 0;

			BinaryNinja::LogErrorF("Invalid LowLevelIL token exprIndex {} in {} of {:x} (reported instrIndex {})", token.token.exprIndex, type, start, instr.instructionIndex);
			break;
		}

		return llil(instr);
	}
	case MediumLevelILFunctionGraph:
	case MediumLevelILSSAFormFunctionGraph:
	{
		MediumLevelILFunctionRef mlilFunc = view->getCurrentMediumLevelILFunction();

		if (mlilFunc && type == MediumLevelILSSAFormFunctionGraph)
			mlilFunc = mlilFunc->GetSSAForm();

		if (!mlilFunc)
			break;

		if (token.token.exprIndex >= mlilFunc->GetExprCount())
		{
			FunctionRef func = mlilFunc->GetFunction();
			uint64_t start = func ? func->GetStart() : 0;

			BinaryNinja::LogErrorF("Invalid MediumLevelIL token exprIndex {} in {} of {:x}", token.token.exprIndex, type, start);
			break;
		}

		BinaryNinja::MediumLevelILInstruction instr = mlilFunc->GetExpr(token.token.exprIndex);

		if (instr.instructionIndex >= mlilFunc->GetInstructionCount())
		{
			FunctionRef func = mlilFunc->GetFunction();
			uint64_t start = func ? func->GetStart() : 0;

			BinaryNinja::LogErrorF("Invalid MediumLevelIL token exprIndex {} in {} of {:x} (reported instrIndex {})", token.token.exprIndex, type, start, instr.instructionIndex);
			break;
		}

		return mlil(instr);
	}
	case HighLevelILFunctionGraph:
	case HighLevelILSSAFormFunctionGraph:
	case HighLevelLanguageRepresentationFunctionGraph:
	{
		HighLevelILFunctionRef hlilFunc = view->getCurrentHighLevelILFunction();

		if (hlilFunc && type == HighLevelILSSAFormFunctionGraph)
			hlilFunc = hlilFunc->GetSSAForm();

		if (!hlilFunc)
			break;

		if (token.token.exprIndex >= hlilFunc->GetExprCount())
		{
			FunctionRef func = hlilFunc->GetFunction();
			uint64_t start = func ? func->GetStart() : 0;

			BinaryNinja::LogErrorF("Invalid HighLevelIL token exprIndex {} in {} of {:x}", token.token.exprIndex, type, start);
			break;
		}

		BinaryNinja::HighLevelILInstruction instr = hlilFunc->GetExpr(token.token.exprIndex);

		if (instr.instructionIndex >= hlilFunc->GetInstructionCount())
		{
			FunctionRef func = hlilFunc->GetFunction();
			uint64_t start = func ? func->GetStart() : 0;

			BinaryNinja::LogErrorF("Invalid HighLevelIL token exprIndex {} in {} of {:x} (reported instrIndex {})", token.token.exprIndex, type, start, instr.instructionIndex);
			break;
		}

		return hlil(instr);
	}
	default:
		break;
	}

	return {};
}

void BINARYNINJAUIAPI showHexPreview(QWidget* parent, ViewFrame* frame, const QPoint& previewPos, BinaryViewRef data, uint64_t address);
bool BINARYNINJAUIAPI showDisassemblyPreview(QWidget* parent, ViewFrame* frame, const QPoint& previewPos,BinaryViewRef data, FunctionRef func,
    const ViewLocation& location);
void BINARYNINJAUIAPI showTextTooltip(QWidget* parent, const QPoint& previewPos, const QString& text);

bool BINARYNINJAUIAPI isBinaryNinjaDatabase(QFileInfo& info, QFileAccessor& accessor);

PlatformRef BINARYNINJAUIAPI getOrAskForPlatform(QWidget* parent, BinaryViewRef data);
PlatformRef BINARYNINJAUIAPI getOrAskForPlatform(QWidget* parent, PlatformRef defaultValue);

std::optional<std::string> BINARYNINJAUIAPI getStringForGraphType(BNFunctionGraphType type);
std::optional<BinaryNinja::FunctionViewType> BINARYNINJAUIAPI getGraphTypeForString(const std::string& type);

namespace fmt
{
	template<typename... T>
	QString qformat(format_string<T...> fmt, T&&... args)
	{
		return QString::fromStdString(vformat(fmt, make_format_args(args...)));
	}
}

template<> struct fmt::formatter<QString>
{
	format_context::iterator format(const QString& obj, format_context& ctx) const
	{
		return fmt::format_to(ctx.out(), "{}", obj.toStdString());
	}
	constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator { return ctx.begin(); }
};

/*!
	@}
*/
