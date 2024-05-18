/*
 * Outputs the syscall numbers called by a binary.
 */

#include <sys/stat.h>

#include <iostream>
#include <cstdlib>

#include "binaryninjacore.h"
#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;


bool is_file(char* fname)
{
	struct stat buf;
	if (stat(fname, &buf) == 0 && (buf.st_mode & S_IFREG) == S_IFREG)
		return true;

	return false;
}

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		cerr << "USAGE: " << argv[0] << " <file_name>" << endl;
		exit(-1);
	}

	char* fname = argv[1];
	if (!is_file(fname))
	{
		cerr << "Error: " << fname << " is not a regular file" << endl;
		exit(-1);
	}

	/* In order to initiate the bundled plugins properly, the location
	 * of where bundled plugins directory is must be set.*/
	SetBundledPluginDirectory(GetBundledPluginDirectory());
	InitPlugins();

	Ref<BinaryView> bv = BinaryNinja::Load(fname);
	if (!bv || bv->GetTypeName() == "Raw")
	{
		fprintf(stderr, "Input file does not appear to be an executable\n");
		return -1;
	}

	auto arch = bv->GetDefaultArchitecture();
	auto platform = bv->GetDefaultPlatform();

	auto cc = platform->GetSystemCallConvention();
	if (!cc)
	{
		cerr << "Error: No system call conventions found for " << platform->GetName() << endl;
		exit(-1);
	}

	auto reg = cc->GetIntegerArgumentRegisters()[0];

	for (Function* func : bv->GetAnalysisFunctionList())
	{
		auto il_func = func->GetLowLevelIL();

		for (size_t i = 0; i < il_func->GetInstructionCount(); i++)
		{
			auto instr = (*il_func)[il_func->GetIndexForInstruction(i)];

			if (instr.operation == LLIL_SYSCALL)
			{
				auto reg_value = il_func->GetRegisterValueAtInstruction(reg, i);

				cout << "System call address: 0x" << hex << instr.address << " - " << dec << reg_value.value << endl;
			}
		}
	}

	// Close the file so that the resources can be freed
	bv->GetFile()->Close();

	// Shutting down is required to allow for clean exit of the core
	BNShutdown();

	return 0;
}
