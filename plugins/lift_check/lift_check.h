
#pragma once

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"

class ILVerifier
{
public:
	BNFunctionGraphType m_ilType;

	struct Diagnostic
	{
		BNTypeParserErrorSeverity severity;
		BNFunctionGraphType ilType;
		size_t exprIndex;
		size_t instrIndex;
		std::string message;

		static Diagnostic Diag(
			BNTypeParserErrorSeverity severity,
			const ILVerifier* verifier,
			const std::string& message
		)
		{
			Diagnostic d;
			d.severity = severity;
			d.ilType = verifier->m_ilType;
			d.exprIndex = BN_INVALID_EXPR;
			d.instrIndex = BN_INVALID_EXPR;
			d.message = message;
			return d;
		}
		static Diagnostic Error(
			const ILVerifier* verifier,
			const std::string& message
		)
		{
			Diagnostic d;
			d.severity = ErrorSeverity;
			d.ilType = verifier->m_ilType;
			d.exprIndex = BN_INVALID_EXPR;
			d.instrIndex = BN_INVALID_EXPR;
			d.message = message;
			return d;
		}
		static Diagnostic Diag(
			BNTypeParserErrorSeverity severity,
			const ILVerifier* verifier,
			const BinaryNinja::LowLevelILInstruction& instr,
			const std::string& message
		)
		{
			Diagnostic d;
			d.severity = severity;
			d.ilType = verifier->m_ilType;
			d.exprIndex = instr.exprIndex;
			d.instrIndex = instr.instructionIndex;
			d.message = fmt::format("{:?} {}", instr, message);
			return d;
		}
		static Diagnostic Error(
			const ILVerifier* verifier,
			const BinaryNinja::LowLevelILInstruction& instr,
			const std::string& message
		)
		{
			Diagnostic d;
			d.severity = ErrorSeverity;
			d.ilType = verifier->m_ilType;
			d.exprIndex = instr.exprIndex;
			d.instrIndex = instr.instructionIndex;
			d.message = fmt::format("{:?} {}", instr, message);
			return d;
		}
		static Diagnostic Diag(
			BNTypeParserErrorSeverity severity,
			const ILVerifier* verifier,
			const BinaryNinja::MediumLevelILInstruction& instr,
			const std::string& message
		)
		{
			Diagnostic d;
			d.severity = severity;
			d.ilType = verifier->m_ilType;
			d.exprIndex = instr.exprIndex;
			d.instrIndex = instr.instructionIndex;
			d.message = fmt::format("{:?} {}", instr, message);
			return d;
		}
		static Diagnostic Error(
			const ILVerifier* verifier,
			const BinaryNinja::MediumLevelILInstruction& instr,
			const std::string& message
		)
		{
			Diagnostic d;
			d.severity = ErrorSeverity;
			d.ilType = verifier->m_ilType;
			d.exprIndex = instr.exprIndex;
			d.instrIndex = instr.instructionIndex;
			d.message = fmt::format("{:?} {}", instr, message);
			return d;
		}
		static Diagnostic Diag(
			BNTypeParserErrorSeverity severity,
			const ILVerifier* verifier,
			const BinaryNinja::HighLevelILInstruction& instr,
			const std::string& message
		)
		{
			Diagnostic d;
			d.severity = severity;
			d.ilType = verifier->m_ilType;
			d.exprIndex = instr.exprIndex;
			d.instrIndex = instr.instructionIndex;
			d.message = fmt::format("{:?} {}", instr, message);
			return d;
		}
		static Diagnostic Error(
			const ILVerifier* verifier,
			const BinaryNinja::HighLevelILInstruction& instr,
			const std::string& message
		)
		{
			Diagnostic d;
			d.severity = ErrorSeverity;
			d.ilType = verifier->m_ilType;
			d.exprIndex = instr.exprIndex;
			d.instrIndex = instr.instructionIndex;
			d.message = fmt::format("{:?} {}", instr, message);
			return d;
		}
	};

protected:
	std::vector<Diagnostic> m_diagnostics;

public:
	explicit ILVerifier(BNFunctionGraphType graphType);
	virtual ~ILVerifier() = default;
	virtual void Verify() = 0;

	std::vector<Diagnostic>&& GetDiagnostics() { return std::move(m_diagnostics); }
};
