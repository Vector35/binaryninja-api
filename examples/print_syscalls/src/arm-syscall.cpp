/*
 * Outputs the syscall numbers called by a binary.
 */

#include <sys/stat.h>

#include <iostream>
#include <cstdlib>

#include "binaryninjacore.h"
#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;

#ifndef __WIN32__
#include <libgen.h>
#include <dlfcn.h>
string get_plugins_directory()
{
    Dl_info info;
    if (!dladdr((void *)BNGetBundledPluginDirectory, &info))
        return NULL;

    stringstream ss;
    ss << dirname((char *)info.dli_fname) << "/plugins/";
    return ss.str();
}
#else
string get_plugins_directory()
{
    return "C:\\Program Files\\Vector35\\Binary Ninja\\plugins\\";
}
#endif

bool is_file(char *fname)
{
    struct stat buf;
    if (stat(fname, &buf) == 0 && (buf.st_mode & S_IFREG) == S_IFREG)
        return true;

    return false;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        cerr << "USAGE: " << argv[0] << " <file_name>" << endl;
        exit(-1);
    }

    char *fname = argv[1];
    if (!is_file(fname)) {
        cerr << "Error: " << fname << " is not a regular file" << endl;
        exit(-1);
    }

    /* In order to initiate the bundled plugins properly, the location
     * of where bundled plugins directory is must be set. Since
     * libbinaryninjacore is in the path get the path to it and use it to
     * determine the plugins directory */
    SetBundledPluginDirectory(get_plugins_directory());
    InitCorePlugins();
    InitUserPlugins();

    auto bd = BinaryData(new FileMetadata(), fname);
    BinaryView *bv = 0;

    for (auto type : BinaryViewType::GetViewTypesForData(&bd)) {
        if (type->GetName() != "Raw") {
            bv = type->Create(&bd);
            break;
        }
    }

    if (!bv || bv->GetTypeName() == "Raw"){
        cerr << "Error: Unable to get any other view type besides Raw";
        exit(-1);
    }

    bv->UpdateAnalysis();
    while (bv->GetAnalysisProgress().state != IdleState);

    auto arch = bv->GetDefaultArchitecture();
    auto platform = bv->GetDefaultPlatform();

    auto cc = platform->GetSystemCallConvention();
    if (!cc) {
        cerr << "Error: No system call conventions found for "
             << platform->GetName() << endl;
        exit(-1);
    }

    auto reg = cc->GetIntegerArgumentRegisters()[0];

    for (Function *func : bv->GetAnalysisFunctionList()) {
        auto il_func = func->GetLowLevelIL();

        for (size_t i = 0; i < il_func->GetInstructionCount(); i++) {
            auto instr = (*il_func)[il_func->GetIndexForInstruction(i)];

            if (instr.operation == LLIL_SYSCALL) {
                auto reg_value = func->GetRegisterValueAtLowLevelILInstruction(i, reg);

                cout <<  "System call address: 0x"
                     << hex << instr.address
                     << " - "
                     << dec << reg_value.value
                     << endl;
            }
        }
    }

    return 0;
}
