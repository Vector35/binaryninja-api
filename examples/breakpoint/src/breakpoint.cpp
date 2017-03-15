#include <inttypes.h>
#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;

void write_breakpoint(BinaryNinja::BinaryView *view, uint64_t start, uint64_t length)
{
	// Sample function to show registering a plugin menu item for a range of bytes.
    // Also possible:
    //   register
    //   register_for_address
    //   register_for_function

	Ref<Architecture> arch = view->GetDefaultArchitecture();
	string arch_name = arch->GetName();

	if (arch_name.compare(0, 3, "x86") == 0) {
		string int3s = string(length, '\xcc');
		view->Write(start, int3s.c_str(), length);
    } else {
		LogError("No support for breakpoint on %s", arch_name.c_str());
    }
}

extern "C"
{
	BINARYNINJAPLUGIN bool CorePluginInit()
	{
        // Register the plugin with Binary Ninja
        PluginCommand::RegisterForRange("Convert to breakpoint",
                                        "Fill region with breakpoint instructions.",
                                        &write_breakpoint);
		return true;
	}
}
