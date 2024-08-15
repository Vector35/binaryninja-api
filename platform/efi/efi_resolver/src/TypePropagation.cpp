#include "TypePropagation.h"
#include "highlevelilinstruction.h"

TypePropagation::TypePropagation(BinaryView* view)
{
    m_view = view;
    m_queue.clear();
    m_platform = view->GetDefaultPlatform();
}

const std::map<std::string, std::string> defaultName = {
    { "EFI_SYSTEM_TABLE", "gST" },
    { "EFI_BOOT_SERVICES", "gBS" },
    { "EFI_RUNTIME_SERVICES", "gRT" },
    { "EFI_MM_SYSTEM_TABLE", "gMmst" },
    { "EFI_SMM_SYSTEM_TABLE2", "gSmmst" },
    { "EFI_HANDLE", "gHandle" }
};

bool TypePropagation::propagateFuncParamTypes(Function* func)
{
    m_queue.push_back(func->GetStart());

    LogDebug("Start Type propagation from 0x%llx", func->GetStart());

    while (!m_queue.empty()) {
        uint64_t addr = m_queue.front();
        m_queue.pop_front();

        Ref<Function> target_func = m_view->GetAnalysisFunction(m_platform, addr);
        auto params = target_func->GetType()->GetParameters();
        bool update = false;

        auto param_vars = target_func->GetParameterVariables().GetValue();
        for (auto var : param_vars) {
            bool propagate = false;
            auto var_type = target_func->GetVariableType(var).GetValue();

            if (var_type->IsPointer()) {
                Ref<Type> target_type = var_type->GetChildType().GetValue();
                if (target_type->IsPointer() || target_type->IsNamedTypeRefer())
                    propagate = true;
            } else if (var_type->IsNamedTypeRefer()) {
                Ref<Type> target_type = m_view->GetTypeById(var_type->GetNamedTypeReference()->GetTypeId());
                if (target_type->IsPointer())
                    propagate = true;
            }
            if (!propagate)
                continue;

            // Check whether the param is an aliased var. If it's an aliased var, it may not be directly used in the function
            Ref<HighLevelILFunction> hlil_func_ssa = target_func->GetHighLevelIL()->GetSSAForm();
            std::set<Variable> aliased_vars = target_func->GetHighLevelILAliasedVariables();

            auto it = aliased_vars.find(var);
            if (it == aliased_vars.end()) {
                // not an aliaed var, use version 0
                update |= propagateFuncParamTypes(target_func, SSAVariable(var, 0));
            } else {
                // this param is an aliased var, get the ssa_var
                auto uses = target_func->GetHighLevelIL()->GetVariableUses(var);
                for (auto use : uses) {
                    auto hlil_instr = target_func->GetHighLevelIL()->GetExpr(use);
                    hlil_instr = hlil_instr.GetParent();
                    if (hlil_instr.operation != HLIL_VAR_INIT)
                        continue;
                    SSAVariable ssa_var = hlil_instr.GetSSAForm().GetDestSSAVariable();
                    update |= propagateFuncParamTypes(target_func, ssa_var);
                }
            }
        }

        if (update)
            m_view->UpdateAnalysisAndWait();
    }
    return true;
}

bool TypePropagation::propagateFuncParamTypes(Function* func, SSAVariable ssa_var)
{
    bool update = false;
    auto mlil_func_ssa = func->GetMediumLevelIL()->GetSSAForm();
    auto uses = mlil_func_ssa->GetSSAVarUses(ssa_var);
    for (auto use : uses) {
        auto instr = mlil_func_ssa->GetInstruction(use);
        switch (instr.operation) {
        case MLIL_CALL_SSA:
        case MLIL_TAILCALL_SSA: {
            // propagate variable type to sub function
            auto dest = instr.GetDestExpr();
            if (!dest.GetValue().IsConstant())
                continue;
            Ref<Function> subfunc = m_view->GetAnalysisFunction(m_platform, dest.GetValue().value);

            if (!subfunc)
                continue;

            auto subfunc_type = subfunc->GetType();
            auto subfunc_params = subfunc->GetType()->GetParameters();

            auto instr_params = instr.GetParameterExprs();
            for (int i = 0; i < instr_params.size(); i++) {
                if (instr_params[i].operation != MLIL_VAR_SSA)
                    continue;
                if (instr_params[i].GetSourceSSAVariable() != ssa_var)
                    continue;
                if (i >= subfunc_params.size())
                    break;
                auto ssa_var_type = func->GetVariableType(ssa_var.var).GetValue();
                auto typeName = GetOriginalTypeName(ssa_var_type);

                auto changeFuncType = [](BinaryView* bv, Ref<Type> funcType, std::string paramName, Ref<Type> paramType, int paramIdx) {
                    auto newFuncType = TypeBuilder(funcType);
                    auto adjustedParams = newFuncType.GetParameters();
                    adjustedParams.at(paramIdx) = FunctionParameter(paramName, paramType);
                    newFuncType.SetParameters(adjustedParams);
                    return newFuncType.Finalize();
                };

                subfunc->SetUserType(changeFuncType(m_view, subfunc_type, GetVarNameForTypeStr(typeName), ssa_var_type, i));
                m_view->UpdateAnalysisAndWait();

                if (std::find(m_queue.begin(), m_queue.end(), subfunc->GetStart()) == m_queue.end())
                    m_queue.push_back(subfunc->GetStart());
                update = true;
                break;
            }
            break;
        }

        case MLIL_STORE_SSA: {
            auto target = instr.GetDestExpr<MLIL_STORE_SSA>();
            if (!target.GetValue().IsConstant())
                continue;
            auto constant = target.GetValue().value;
            auto ssa_var_type = func->GetVariableType(ssa_var.var).GetValue();
            auto typeName = GetOriginalTypeName(ssa_var_type);

            auto it = defaultName.find(typeName);
            if (it != defaultName.end())
                typeName = it->second;

            m_view->DefineDataVariable(constant, ssa_var_type);
            m_view->DefineUserSymbol(new Symbol(DataSymbol, typeName, constant));

            update = true;
            break;
        }

        case MLIL_SET_VAR_SSA: {
            auto src = instr.GetSourceExpr<MLIL_SET_VAR_SSA>();
            auto dest = instr.GetDestSSAVariable<MLIL_SET_VAR_SSA>();

            auto dest_type = func->GetVariableType(dest.var);
            Confidence<Ref<Type>> src_type;
            switch (src.operation) {
            case MLIL_VAR_SSA:
                src_type = func->GetVariableType(src.GetSourceSSAVariable().var);
                break;

            case MLIL_LOAD_SSA:
            case MLIL_LOAD_STRUCT_SSA:
                src_type = src.GetType();
                break;

            default:
                continue;
            }

            if (src_type.GetValue() && src_type.GetValue() != dest_type.GetValue()) {
                func->CreateUserVariable(dest.var, src_type, func->GetVariableName(dest.var));
                update |= propagateFuncParamTypes(func, SSAVariable(dest.var, dest.version));
            }
            break;
        }

        default:
            LogInfo("Not handled case during type propagation. At %llx: %d", instr.address, instr.operation);
            break;
        }
    }
    return update;
}
