#include "PeiResolver.h"

bool PeiResolver::resolvePeiIdt()
{
    string archName = m_view->GetDefaultArchitecture()->GetName();
    string intrinsicName;
    if (archName == "x86")
        intrinsicName = "IDTR32";
    else
        intrinsicName = "IDTR64";

    auto refs = m_view->GetCodeReferencesForType(QualifiedName(intrinsicName));
    for (auto ref : refs) {
        if (m_task->IsCancelled())
            return false;

        auto mlil = ref.func->GetMediumLevelIL();
        auto instrIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
        auto instr = mlil->GetInstruction(instrIdx);

        auto hlil = ref.func->GetHighLevelIL();
        auto hlils = HighLevelILExprsAt(ref.func, m_view->GetDefaultArchitecture(), ref.addr);

        for (auto expr : hlils) {
            if (expr.operation != HLIL_INTRINSIC ||
                expr.GetParent().operation != HLIL_ASSIGN ||
                expr.GetParent().GetDestExpr<HLIL_ASSIGN>().operation != HLIL_STRUCT_FIELD ||
                expr.GetParent().GetDestExpr<HLIL_ASSIGN>().GetSourceExpr<HLIL_STRUCT_FIELD>().operation != HLIL_VAR)
                continue;

            auto var = expr.GetParent().GetDestExpr<HLIL_ASSIGN>().GetSourceExpr<HLIL_STRUCT_FIELD>().GetVariable();
            ref.func->CreateUserVariable(var, m_view->GetTypeByName(QualifiedName(intrinsicName)), intrinsicName);
        }

        if (instr.operation == MLIL_INTRINSIC) {
            // binja doesn't do type propagation on intrinsic instructions
            auto output_params = instr.GetOutputVariables<MLIL_INTRINSIC>();
            if (output_params.size() < 1)
                continue;
            ref.func->CreateUserVariable(output_params[0],
                m_view->GetTypeByName(QualifiedName(intrinsicName)),
                intrinsicName);
        }
        m_view->UpdateAnalysisAndWait();
    }

    // TODO There is an issue related to structure's type propagation, binja doesn't propagate indirect structure access properly
    //   here is a temporary fix, should be removed after vector35/binaryninja/#749 got fixed
    refs = m_view->GetCodeReferencesForType(QualifiedName("EFI_PEI_SERVICES"));
    for (auto ref : refs) {
        if (m_task->IsCancelled())
            return false;

        auto mlil = ref.func->GetMediumLevelIL();
        auto instrIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
        auto instr = mlil->GetInstruction(instrIdx);

        if (instr.operation != MLIL_SET_VAR)
            continue;

        if (instr.GetSourceExpr<MLIL_SET_VAR>().operation != MLIL_LOAD_STRUCT)
            continue;

        ref.func->CreateUserVariable(instr.GetDestVariable<MLIL_SET_VAR>(),
            mlil->GetExprType(instr.GetSourceExpr<MLIL_SET_VAR>()).GetValue(),
            nonConflictingLocalName(ref.func, "EfiPeiServices"));
        m_view->UpdateAnalysisAndWait();
    }

    return true;
}

bool PeiResolver::resolvePeiMrc()
{
    auto funcs = m_view->GetAnalysisFunctionList();
    for (auto func : funcs) {
        if (m_task->IsCancelled())
            return false;

        auto mlil = func->GetMediumLevelIL();
        auto blocks = mlil->GetBasicBlocks();
        for (auto block : blocks) {
            for (size_t i = block->GetStart(); i < block->GetEnd(); i++) {
                auto instr = mlil->GetInstruction(i);
                if (instr.operation != MLIL_INTRINSIC)
                    continue;
                uint32_t intrinsicIdx = instr.GetIntrinsic<MLIL_INTRINSIC>();

                if (m_view->GetDefaultArchitecture()->GetIntrinsicName(intrinsicIdx) != "Coproc_GetOneWord")
                    continue;
                auto intrinsicParams = instr.GetParameterExprs<MLIL_INTRINSIC>();
                if (intrinsicParams.size() != 5)
                    continue;

                bool found = true;

                const int value[5] = { 0xf, 0x0, 0xd, 0x0, 0x2 };
                for (int j = 0; j < 5; j++) {
                    auto param = intrinsicParams[j];
                    if (param.operation != MLIL_CONST) {
                        found = false;
                        break;
                    }

                    if (param.GetConstant<MLIL_CONST>() != value[j]) {
                        found = false;
                        break;
                    }
                }

                if (!found)
                    continue;

                // At this point, we can make sure this instruction fetches EFI_PEI_SERVICES
                auto output = instr.GetOutputVariables();
                if (output.size() > 0) {
                    auto pointerType = Type::PointerType(m_view->GetDefaultArchitecture(),
                        Type::PointerType(m_view->GetDefaultArchitecture(),
                            m_view->GetTypeByName(QualifiedName("EFI_PEI_SERVICES"))));
                    func->CreateUserVariable(output[0], pointerType, nonConflictingLocalName(func, "PeiServices"));
                    m_view->UpdateAnalysisAndWait();
                }
            }
        }
    }
    return true;
}

bool PeiResolver::resolvePeiMrs()
{
    // ideally we don't need this function, but since we don't support type propagation on intrinsic instructions
    // we have to manually propagate it
    auto refs = m_view->GetCodeReferencesForType(QualifiedName("EFI_PEI_SERVICES"));
    for (auto ref : refs) {
        if (m_task->IsCancelled())
            return false;

        auto mlil = ref.func->GetMediumLevelIL();
        auto instrIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
        auto instr = mlil->GetInstruction(instrIdx);
        if (instr.operation == MLIL_INTRINSIC) {
            auto params = instr.GetOutputVariables();
            if (params.size() < 1)
                continue;

            auto pointerType = Type::PointerType(m_view->GetDefaultArchitecture(),
                Type::PointerType(m_view->GetDefaultArchitecture(),
                    m_view->GetTypeByName(QualifiedName("EFI_PEI_SERVICES"))));
            ref.func->CreateUserVariable(params[0],
                pointerType,
                nonConflictingLocalName(ref.func, "EfiPeiServices"));
            m_view->UpdateAnalysisAndWait();
        }
    }
    return true;
}

bool PeiResolver::resolvePlatformPointers()
{
    string archName = m_view->GetDefaultArchitecture()->GetName();
    string intrinsicTypeName;

    if (archName == "x86" || archName == "x86-64") {
        return resolvePeiIdt();
    } else if (archName == "arm" || archName == "thumb2") {
        return resolvePeiMrc();
    } else if (archName == "aarch64") {
        return resolvePeiMrs();
    }
    LogError("Not supported arch: %s", archName.c_str());
    return false;
}

bool PeiResolver::resolvePeiDescriptors()
{
    const string descriptorNames[2] = { "EFI_PEI_NOTIFY_DESCRIPTOR", "EFI_PEI_PPI_DESCRIPTOR" };
    for (auto descriptor : descriptorNames) {
        auto refs = m_view->GetCodeReferencesForType(QualifiedName(descriptor));
        for (auto ref : refs) {
            if (m_task->IsCancelled())
                return false;

            auto mlil = ref.func->GetMediumLevelIL();
            auto instrIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
            auto instr = mlil->GetInstruction(instrIdx);

            if (instr.operation != MLIL_CALL && instr.operation != MLIL_TAILCALL)
                continue;

            auto destExpr = instr.GetDestExpr();
            if (destExpr.operation != MLIL_LOAD_STRUCT)
                continue;

            // at this point this instruction is probably a call to LocatPpi, InstallPpi or NotifyPpi
            if (!mlil->GetExprType(destExpr).GetValue()->IsPointer())
                continue;

            auto funcType = mlil->GetExprType(destExpr).GetValue()->GetChildType().GetValue();
            auto params = funcType->GetParameters();
            int targetParamIdx = -1;
            for (int i = 0; i < params.size(); i++) {
                auto param = params[i];
                if (!param.type.GetValue()->IsPointer())
                    continue;
                auto paramTypeName = param.type.GetValue()->GetChildType().GetValue()->GetTypeName().GetString();
                if (paramTypeName.find(descriptor) != paramTypeName.npos) {
                    // this is the param
                    targetParamIdx = i;
                    break;
                }
            }
            if (targetParamIdx < 0)
                continue;

            // Now we are confident that this position is a call that pass Descriptor as a parameter
            defineTypeAtCallsite(ref.func, ref.addr, descriptor, targetParamIdx, true);
        }
    }
    return true;
}

bool PeiResolver::resolvePeiServices()
{
    auto refs = m_view->GetCodeReferencesForType(QualifiedName("EFI_PEI_SERVICES"));

    for (auto ref : refs) {
        if (m_task->IsCancelled())
            return false;

        auto func = ref.func;
        auto mlil = func->GetMediumLevelIL();
        if (!mlil)
            continue;

        auto mlilSsa = mlil->GetSSAForm();
        size_t mlilIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
        auto instr = mlilSsa->GetInstruction(mlil->GetSSAInstructionIndex(mlilIdx));

        if (instr.operation == MLIL_CALL_SSA || instr.operation == MLIL_TAILCALL_SSA) {
            auto dest = instr.GetDestExpr();
            if (dest.operation != MLIL_LOAD_STRUCT_SSA)
                continue;
            auto offset = dest.GetOffset();

            if (offset == 0x18 + m_width * 2) {
                // LocatePpi
                resolveGuidInterface(ref.func, ref.addr, 1, 4);
            } else if (offset == 0x18 || offset == 0x18 + m_width || offset == 0x18 + m_width * 3) {
                // InstallPpi, ReinstallPpi, NotifyPpi
            }
        }
    }
    return true;
}

bool PeiResolver::resolvePei()
{
    if (!setModuleEntry(PEI))
        return false;

    if (!resolvePlatformPointers())
        return false;

    if (!resolvePeiDescriptors())
        return false;

    if (!resolvePeiServices())
        return false;

    return true;
}

PeiResolver::PeiResolver(Ref<BinaryView> view, Ref<BackgroundTask> task)
    : Resolver(view, task)
{
    initProtocolMapping();
    setModuleEntry(PEI);
}
