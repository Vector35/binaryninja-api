# Settings

## UI

![settings >](./img/settings.png "Settings")

Binary Ninja provides various settings which are available via the `[CMD/CTRL] ,` hotkey. These settings allow a wide variety of customization of the user interface and functional aspects of the analysis environment.

Several search keywords are available in the settings UI. Those include:

- `@default` - Shows settings that are in the default scope
- `@user` - Shows only settings that the user has changed
- `@project` - Shows settings scoped to the current project
- `@resource` - Shows settings scoped to the current resource (for example if you used open-with-options and changed settings)
- `@modified` - Shows settings that are changed from their default values

There are several scopes available for settings:

* **User Settings** - Settings that apply globally and override the defaults. These settings are stored in `settings.json` within the [User Folder](./#user-folder).
* **Project Settings** - Settings which only apply if a project is opened. These settings are stored in `.binaryninja/settings.json` within a Project Folder. Project Folders can exist anywhere except within the User Folder. These settings apply to all files contained in the Project Folder and override the default and user settings. In order to activate this feature, select the Project Settings tab and a clickable "Open Project" link will appear at the top right of the view. Clicking this will create `.binaryninja/settings.json` in the folder of the currently selected binary view. If it already exists, this link will be replaced with the path of the project folder.
* **Resource Settings** - Settings which only apply to a specific BinaryView object within a file. These settings persist in a Binary Ninja Database (.bndb) database or ephemerally in a BinaryView object if a database does not yet exist for a file.

???+ Warning "Tip"
    Both the _Project_ and _Resource_ tabs have a drop down indicator (▾) that can be clicked to select the project or resource whose settings you want to adjust.

All settings are uniquely identified with an identifier string. Identifiers are available in the settings UI via the context menu and are useful for find settings using the search box and for [programmatically](https://api.binary.ninja/binaryninja.settings-module.html) interacting with settings.

**Note**: In order to facilitate reproducible analysis results, when opening a file for the first time, all of the analysis settings are automatically serialized into the _Resource Setting_ scope. This prevents subsequent _User_ and _Project_ setting modifications from unintentionally changing existing analysis results.

## All Settings
|Category|Setting|Description|Type|Default|Scope|Key|
|---|---|---|---|---|---|---|
|analysis|Disallow Branch to String|Enable the ability to halt analysis of branch targets that fall within a string reference. This setting may be useful for malformed binaries.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.conservative.disallowBranchToString'>analysis.conservative.disallowBranchToString</a>|
|analysis|Purge Snapshots|When saving a database, purge old snapshots keeping only the current snapshot.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsUserScope`]|<a id='analysis.database.purgeSnapshots'>analysis.database.purgeSnapshots</a>|
|analysis|Purge Undo History|When saving a database, purge current and existing undo history.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsUserScope`]|<a id='analysis.database.purgeUndoHistory'>analysis.database.purgeUndoHistory</a>|
|analysis|Suppress Reanalysis|Disable function reanalysis on database load when the product version or analysis settings change.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.database.suppressReanalysis'>analysis.database.suppressReanalysis</a>|
|analysis|External Debug Info File|Separate file to attempt to parse and import debug information from.|`string`| |[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.debugInfo.external'>analysis.debugInfo.external</a>|
|analysis|Import Debug Information|Attempt to parse and apply debug information from each file opened.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.debugInfo.internal'>analysis.debugInfo.internal</a>|
|analysis|Alternate Type Propagation|Enable an alternate approach for function type propagation. This setting is experimental and may be useful for some binaries.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.experimental.alternateTypePropagation'>analysis.experimental.alternateTypePropagation</a>|
|analysis|Correlated Memory Value Propagation|Attempt to propagate the value of an expression from a memory definition to a usage. Currently this feature is simplistic and the scope is a single basic block. This setting is experimental and may be useful for some binaries.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.experimental.correlatedMemoryValuePropagation'>analysis.experimental.correlatedMemoryValuePropagation</a>|
|analysis|Gratuitous Function Update|Force the function update cycle to always end with an IncrementalAutoFunctionUpdate type.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.experimental.gratuitousFunctionUpdate'>analysis.experimental.gratuitousFunctionUpdate</a>|
|analysis|Heuristic Value Range Clamping|Use DataVariable state inferencing to help determine the possible size of a lookup table.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.experimental.heuristicRangeClamp'>analysis.experimental.heuristicRangeClamp</a>|
|analysis|Keep Dead Code Branches|Keep unreachable code branches and associated basic blocks in HLIL.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.experimental.keepDeadCodeBranches'>analysis.experimental.keepDeadCodeBranches</a>|
|analysis|Return Value Propagation|Propagate and use constant return values from functions in the caller in order to simplify downstream expressions.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.experimental.returnValuePropagation'>analysis.experimental.returnValuePropagation</a>|
|analysis|Translate Windows CFG Calls|Attempt to identify and translate calls to `_guard_dispatch_icall_nop` to improve analysis of control flow guard binaries.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.experimental.translateWindowsCfgCalls'>analysis.experimental.translateWindowsCfgCalls</a>|
|analysis|Extract Types From Manged Names|Attempt to extract types from mangled names using the demangler. This can lead to recovering inaccurate parameters.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.extractTypesFromMangedNames'>analysis.extractTypesFromMangedNames</a>|
|analysis|Always Analyze Indirect Branches|When using faster analysis modes, perform full analysis of functions containing indirect branches.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.forceIndirectBranches'>analysis.forceIndirectBranches</a>|
|analysis|Aggressive Condition Complexity Removal Threshold|High Level IL tuning parameter.|`number`|`64`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.hlil.aggressiveConditionComplexityRemovalThreshold'>analysis.hlil.aggressiveConditionComplexityRemovalThreshold</a>|
|analysis|Max Condition Complexity|High Level IL tuning parameter.|`number`|`1024`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.hlil.maxConditionComplexity'>analysis.hlil.maxConditionComplexity</a>|
|analysis|Max Condition Reduce Iterations|High Level IL tuning parameter.|`number`|`1024`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.hlil.maxConditionReduceIterations'>analysis.hlil.maxConditionReduceIterations</a>|
|analysis|Max Intermediate Condition Complexity|High Level IL tuning parameter.|`number`|`1048576`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.hlil.maxIntermediateConditionComplexity'>analysis.hlil.maxIntermediateConditionComplexity</a>|
|analysis|Eliminate Pure Calls during HLIL Optimization|Whether or not pure calls (calls to functions with no side-effects) are removed during HLIL optimizations.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.hlil.pureCallElimination'>analysis.hlil.pureCallElimination</a>|
|analysis|Switch Case Node Threshold|High Level IL tuning parameter.|`number`|`4`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.hlil.switchCaseNodeThreshold'>analysis.hlil.switchCaseNodeThreshold</a>|
|analysis|Switch Case Value Count Threshold|High Level IL tuning parameter.|`number`|`6`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.hlil.switchCaseValueCountThreshold'>analysis.hlil.switchCaseValueCountThreshold</a>|
|analysis|Target Max Condition Complexity|High Level IL tuning parameter.|`number`|`16`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.hlil.targetMaxConditionComplexity'>analysis.hlil.targetMaxConditionComplexity</a>|
|analysis|Initial Analysis Hold|Enabling the analysis hold discards all future analysis updates until clearing the hold. This setting only applies to analysis in the InitialState.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.initialAnalysisHold'>analysis.initialAnalysisHold</a>|
|analysis|Advanced Analysis Cache Size|Controls the number of functions for which the most recent generated advanced analysis is cached. Large values may result in very high memory utilization.|`number`|`64`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.limits.cacheSize'>analysis.limits.cacheSize</a>|
|analysis|Max Function Analysis Time|Any functions that exceed this analysis time are deferred. A value of 0 disables this feature. The default value is 20 seconds. Time is specified in milliseconds.|`number`|`20000`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.limits.maxFunctionAnalysisTime'>analysis.limits.maxFunctionAnalysisTime</a>|
|analysis|Max Function Size|Any functions over this size will not be automatically analyzed. A value of 0 disables analysis of functions and suppresses the related log warning. To override see FunctionAnalysisSkipOverride. Size is specified in bytes.|`number`|`65536`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.limits.maxFunctionSize'>analysis.limits.maxFunctionSize</a>|
|analysis|Max Function Update Count|Any functions that exceed this incremental update count are deferred. A value of 0 disables this feature.|`number`|`100`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.limits.maxFunctionUpdateCount'>analysis.limits.maxFunctionUpdateCount</a>|
|analysis|Max Lookup Table Size|Limits the maximum number of entries for a lookup table.|`number`|`4095`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.limits.maxLookupTableSize'>analysis.limits.maxLookupTableSize</a>|
|analysis|Minimum String Length|The minimum length for strings created during auto-analysis|`number`|`4`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.limits.minStringLength'>analysis.limits.minStringLength</a>|
|analysis|Maximum String Search|Maximum number of strings to find before giving up.|`number`|`1048576`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.limits.stringSearch'>analysis.limits.stringSearch</a>|
|analysis|Worker Thread Count|The number of worker threads available for concurrent analysis activities.|`number`|`9`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.limits.workerThreadCount'>analysis.limits.workerThreadCount</a>|
|analysis|Autorun Linear Sweep|Automatically run linear sweep when opening a binary for analysis.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.linearSweep.autorun'>analysis.linearSweep.autorun</a>|
|analysis|Control Flow Graph Analysis|Enable the control flow graph analysis (Analysis Phase 3) portion of linear sweep.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.linearSweep.controlFlowGraph'>analysis.linearSweep.controlFlowGraph</a>|
|analysis|Detailed Linear Sweep Log Information|Linear sweep generates additional log information at the InfoLog level.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.linearSweep.detailedLogInfo'>analysis.linearSweep.detailedLogInfo</a>|
|analysis|Entropy Heuristics for Linear Sweep|Enable the application of entropy based heuristics to the function search space for linear sweep.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.linearSweep.entropyHeuristics'>analysis.linearSweep.entropyHeuristics</a>|
|analysis|High Entropy Threshold for Linear Sweep|Regions in the binary at or above this threshold are not included in the search space for linear sweep.|`number`|`0.82`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.linearSweep.entropyThresholdHigh'>analysis.linearSweep.entropyThresholdHigh</a>|
|analysis|Low Entropy Threshold for Linear Sweep|Regions in the binary at or below this threshold are not included in the search space for linear sweep.|`number`|`0.025`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.linearSweep.entropyThresholdLow'>analysis.linearSweep.entropyThresholdLow</a>|
|analysis|Max Linear Sweep Work Queues|The number of binary regions under concurrent analysis.|`number`|`64`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.linearSweep.maxWorkQueues'>analysis.linearSweep.maxWorkQueues</a>|
|analysis|Permissive Linear Sweep|Permissive linear sweep searches all executable segments regardless of read/write permissions. By default, linear sweep searches sections that are ReadOnlyCodeSectionSemantics, or if no sections are defined, segments that are read/execute.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.linearSweep.permissive'>analysis.linearSweep.permissive</a>|
|analysis|Load/Store Splitting|Controls splitting of oversized variable field accesses into appropriately sized accesses|`string`|`validFieldsOnly`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.mlil.loadStoreSplitting'>analysis.mlil.loadStoreSplitting</a>|
| | |  enum: Do not split oversized accesses to fields|`enum`|`off`| | |
| | |  enum: Split oversized accesses to valid fields and hide accessed gaps/alignment/padding bytes|`enum`|`validFieldsOnly`| | |
| | |  enum: Split oversized accesses to valid fields and include accessed gaps/alignment/padding bytes|`enum`|`allOffsets`| | |
|analysis|Analysis Mode|Controls the amount of analysis performed on functions.|`string`|`full`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.mode'>analysis.mode</a>|
| | |  enum: Only perform control flow analysis on the binary. Cross references are valid only for direct function calls. [Disassembly Only]|`enum`|`controlFlow`| | |
| | |  enum: Perform fast initial analysis of the binary. This mode does not analyze types or data flow through stack variables. [LLIL and Equivalents]|`enum`|`basic`| | |
| | |  enum: Perform analysis which includes type propagation and data flow. [MLIL and Equivalents]|`enum`|`intermediate`| | |
| | |  enum: Perform full analysis of the binary.|`enum`|`full`| | |
|analysis|Autorun Function Signature Matcher|Automatically run the function signature matcher when opening a binary for analysis.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.signatureMatcher.autorun'>analysis.signatureMatcher.autorun</a>|
|analysis|Auto Function Analysis Suppression|Enable suppressing analysis of automatically discovered functions.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.suppressNewAutoFunctionAnalysis'>analysis.suppressNewAutoFunctionAnalysis</a>|
|analysis|Tail Call Heuristics|Attempts to recover function starts that may be obscured by tail call optimization (TCO). Specifically, branch targets within a function are analyzed as potential function starts.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.tailCallHeuristics'>analysis.tailCallHeuristics</a>|
|analysis|Tail Call Translation|Performs tail call translation for jump instructions where the target is an existing function start.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.tailCallTranslation'>analysis.tailCallTranslation</a>|
|analysis|Type Parser|Specify the implementation used for parsing types from text.|`string`|`ClangTypeParser`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.types.parserName'>analysis.types.parserName</a>|
| | | |`enum`|`CoreTypeParser`| | |
| | | |`enum`|`ClangTypeParser`| | |
|analysis|Type Printer|Specify the implementation used for formatting types into text.|`string`|`CoreTypePrinter`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.types.printerName'>analysis.types.printerName</a>|
| | | |`enum`|`CoreTypePrinter`| | |
|analysis|Simplify Templates|Simplify common C++ templates that are expanded with default arguments at compile time (eg. `std::__cxx11::basic_string<wchar, std::char_traits<wchar>, std::allocator<wchar> >` to `std::wstring`).|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.types.templateSimplifier'>analysis.types.templateSimplifier</a>|
|analysis|Unicode Blocks|Defines which unicode blocks to consider when searching for strings.|`array`|[]|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.unicode.blocks'>analysis.unicode.blocks</a>|
|analysis|UTF-16 Encoding|Whether or not to consider UTF-16 code points when searching for strings.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.unicode.utf16'>analysis.unicode.utf16</a>|
|analysis|UTF-32 Encoding|Whether or not to consider UTF-32 code points when searching for strings.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.unicode.utf32'>analysis.unicode.utf32</a>|
|analysis|UTF-8 Encoding|Whether or not to consider UTF-8 code points when searching for strings.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='analysis.unicode.utf8'>analysis.unicode.utf8</a>|
|arch|x86 Disassembly Case|Specify the case for opcodes, operands, and registers.|`boolean`|`True`|[`SettingsUserScope`]|<a id='arch.x86.disassembly.lowercase'>arch.x86.disassembly.lowercase</a>|
|arch|x86 Disassembly Separator|Specify the token separator between operands.|`string`|`, `|[`SettingsUserScope`]|<a id='arch.x86.disassembly.separator'>arch.x86.disassembly.separator</a>|
|arch|x86 Disassembly Syntax|Specify disassembly syntax for the x86/x86_64 architectures.|`string`|`BN_INTEL`|[`SettingsUserScope`]|<a id='arch.x86.disassembly.syntax'>arch.x86.disassembly.syntax</a>|
| | |  enum: Sets the disassembly syntax to a simplified Intel format. (TBD) |`enum`|`BN_INTEL`| | |
| | |  enum: Sets the disassembly syntax to Intel format. (Destination on the left) |`enum`|`INTEL`| | |
| | |  enum: Sets the disassembly syntax to AT&T format. (Destination on the right) |`enum`|`AT&T`| | |
|corePlugins|Aarch64 Architecture|Enable the built-in Aarch64 architecture module.|`boolean`|`True`|[`SettingsUserScope`]|<a id='corePlugins.architectures.aarch64'>corePlugins.architectures.aarch64</a>|
|corePlugins|ARMv7 Architecture|Enable the built-in ARMv7 architecture module.|`boolean`|`True`|[`SettingsUserScope`]|<a id='corePlugins.architectures.armv7'>corePlugins.architectures.armv7</a>|
|corePlugins|MIPS Architecture|Enable the built-in MIPS architecture module.|`boolean`|`True`|[`SettingsUserScope`]|<a id='corePlugins.architectures.mips'>corePlugins.architectures.mips</a>|
|corePlugins|PowerPC Architecture|Enable the built-in PowerPC architecture module.|`boolean`|`True`|[`SettingsUserScope`]|<a id='corePlugins.architectures.powerpc'>corePlugins.architectures.powerpc</a>|
|corePlugins|x86/x86_64 Architecture|Enable the built-in x86/x86_64 architecture module.|`boolean`|`True`|[`SettingsUserScope`]|<a id='corePlugins.architectures.x86'>corePlugins.architectures.x86</a>|
|corePlugins|Crypto Plugin|Enable the built-in crypto plugin.|`boolean`|`True`|[`SettingsUserScope`]|<a id='corePlugins.crypto'>corePlugins.crypto</a>|
|corePlugins|Debugger|Enable the built-in debugger plugin.|`boolean`|`True`|[`SettingsUserScope`]|<a id='corePlugins.debugger'>corePlugins.debugger</a>|
|corePlugins|IDB Import Plugin (Beta)|Enable the built-in IDB import plugin.|`boolean`|`False`|[`SettingsUserScope`]|<a id='corePlugins.idbImport'>corePlugins.idbImport</a>|
|corePlugins|PDB Import Plugin|Enable the built-in PDB import plugin.|`boolean`|`True`|[`SettingsUserScope`]|<a id='corePlugins.pdbImport'>corePlugins.pdbImport</a>|
|corePlugins|DECREE Platform|Enable the built-in DECREE platform module.|`boolean`|`True`|[`SettingsUserScope`]|<a id='corePlugins.platforms.decree'>corePlugins.platforms.decree</a>|
|corePlugins|FreeBSD Platform|Enable the built-in FreeBSD platform module.|`boolean`|`True`|[`SettingsUserScope`]|<a id='corePlugins.platforms.freebsd'>corePlugins.platforms.freebsd</a>|
|corePlugins|Linux Platform|Enable the built-in Linux platform module.|`boolean`|`True`|[`SettingsUserScope`]|<a id='corePlugins.platforms.linux'>corePlugins.platforms.linux</a>|
|corePlugins|macOS Platform|Enable the built-in macOS platform module.|`boolean`|`True`|[`SettingsUserScope`]|<a id='corePlugins.platforms.mac'>corePlugins.platforms.mac</a>|
|corePlugins|Windows Platform|Enable the built-in Windows platform module.|`boolean`|`True`|[`SettingsUserScope`]|<a id='corePlugins.platforms.windows'>corePlugins.platforms.windows</a>|
|corePlugins|Triage Plugin|Enable the built-in triage plugin.|`boolean`|`True`|[`SettingsUserScope`]|<a id='corePlugins.triage'>corePlugins.triage</a>|
|corePlugins|Objective-C|Enable the built-in Objective-C plugin.|`boolean`|`True`|[`SettingsUserScope`]|<a id='corePlugins.workflows.objc'>corePlugins.workflows.objc</a>|
|debugger|Stop At Entry Point|Stop the target at program entry point|`boolean`|`True`|[`SettingsUserScope`]|<a id='debugger.stopAtEntryPoint'>debugger.stopAtEntryPoint</a>|
|debugger|Stop At System Entry Point|Stop the target at system entry point|`boolean`|`False`|[`SettingsUserScope`]|<a id='debugger.stopAtSystemEntryPoint'>debugger.stopAtSystemEntryPoint</a>|
|files|Auto Rebase Load File|When opening a file with options, automatically rebase an image which has a default load address of zero to 4MB for 64-bit binaries, or 64KB for 32-bit binaries.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsUserScope`]|<a id='files.pic.autoRebase'>files.pic.autoRebase</a>|
|files|Universal Mach-O Architecture Preference|Specify an architecture preference for automatic loading of a Mach-O file from a Universal archive. By default, the first object file in the listing is loaded.|`array`|[]|[`SettingsUserScope`]|<a id='files.universal.architecturePreference'>files.universal.architecturePreference</a>|
|network|Download Provider|Specify the registered DownloadProvider which enables resource fetching over HTTPS.|`string`|`CoreDownloadProvider`|[`SettingsUserScope`]|<a id='network.downloadProviderName'>network.downloadProviderName</a>|
| | | |`enum`|`CoreDownloadProvider`| | |
| | | |`enum`|`PythonDownloadProvider`| | |
|network|Enable External Resources|Allow Binary Ninja to download external images and resources when displaying markdown content (e.g. plugin descriptions).|`boolean`|`True`|[`SettingsUserScope`]|<a id='network.enableExternalResources'>network.enableExternalResources</a>|
|network|Enable External URLs|Allow Binary Ninja to download and open external URLs.|`boolean`|`True`|[`SettingsUserScope`]|<a id='network.enableExternalUrls'>network.enableExternalUrls</a>|
|network|Enable Plugin Manager|Allow Binary Ninja to connect to the update server to check for new plugins and plugin updates.|`boolean`|`True`|[`SettingsUserScope`]|<a id='network.enablePluginManager'>network.enablePluginManager</a>|
|network|Enable Release Notes|Allow Binary Ninja to connect to the update server to display release notes on new tabs.|`boolean`|`True`|[`SettingsUserScope`]|<a id='network.enableReleaseNotes'>network.enableReleaseNotes</a>|
|network|Enable Update Channel List|Allow Binary Ninja to connect to the update server to determine which update channels are available.|`boolean`|`True`|[`SettingsUserScope`]|<a id='network.enableUpdateChannelList'>network.enableUpdateChannelList</a>|
|network|Enable Updates|Allow Binary Ninja to connect to the update server to check for updates.|`boolean`|`True`|[`SettingsUserScope`]|<a id='network.enableUpdates'>network.enableUpdates</a>|
|network|HTTPS Proxy|Override default HTTPS proxy settings. By default, HTTPS Proxy settings are detected and used automatically via environment variables (e.g., https_proxy). Alternatively, proxy settings are obtained from the Internet Settings section of the Windows registry, or the Mac OS X System Configuration Framework.|`string`| |[`SettingsUserScope`]|<a id='network.httpsProxy'>network.httpsProxy</a>|
|network|Enable Auto Downloading PDBs|Automatically search for and download pdb files from specified symbol servers.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='network.pdbAutoDownload'>network.pdbAutoDownload</a>|
|network|Websocket Provider|Specify the registered WebsocketProvider which enables communication over HTTPS.|`string`|`CoreWebsocketProvider`|[`SettingsUserScope`]|<a id='network.websocketProviderName'>network.websocketProviderName</a>|
| | | |`enum`|`CoreWebsocketProvider`| | |
|pdb|Allow Unnamed Void Symbol Types|Allow creation of symbols with no name and void types, often used as static local variables. Generally, these are just noisy and not relevant.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='pdb.allowUnnamedVoidSymbols'>pdb.allowUnnamedVoidSymbols</a>|
|pdb|Expand RTTI Structures|Create structures for RTTI symbols with variable-sized names and arrays.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='pdb.expandRTTIStructures'>pdb.expandRTTIStructures</a>|
|pdb|Generate Virtual Table Structures|Create Virtual Table (VTable) structures for C++ classes found when parsing.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='pdb.generateVTables'>pdb.generateVTables</a>|
|pdb|Load Global Module Symbols|Load symbols in the Global module of the PDB. These symbols have generally lower quality types due to relying on the demangler.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='pdb.loadGlobalSymbols'>pdb.loadGlobalSymbols</a>|
|pdb|Absolute PDB Symbol Store Path|Absolute path specifying where the PDB symbol store exists on this machine, overrides relative path.|`string`| |[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='pdb.localStoreAbsolute'>pdb.localStoreAbsolute</a>|
|pdb|Cache Downloaded PDBs in Local Store|Store PDBs downloaded from Symbol Servers in the local Symbol Store Path.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='pdb.localStoreCache'>pdb.localStoreCache</a>|
|pdb|Relative PDB Symbol Store Path|Path *relative* to the binaryninja _user_ directory, specifying the pdb symbol store.|`string`|`symbols`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='pdb.localStoreRelative'>pdb.localStoreRelative</a>|
|pdb|Symbol Server List|List of servers to query for pdb symbols.|`array`|[`https://msdl.microsoft.com/download/symbols`]|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='pdb.symbolServerList'>pdb.symbolServerList</a>|
|pluginManager|Community Plugin Repository|Whether the community plugin repository is enabled|`boolean`|`True`|[`SettingsUserScope`]|<a id='pluginManager.communityRepo'>pluginManager.communityRepo</a>|
|pluginManager|Community Plugin Manager Update Channel|Specify which community update channel the Plugin Manager should update plugins from.|`string`|`master`|[`SettingsUserScope`]|<a id='pluginManager.communityUpdateChannel'>pluginManager.communityUpdateChannel</a>|
| | |  enum: The default channel. This setting should be used unless you are testing the Plugin Manager.|`enum`|`master`| | |
| | |  enum: Plugin Manager test channel.|`enum`|`test`| | |
|pluginManager|Debug Plugin Manager|Enable debug functionality for the Plugin Manager.|`boolean`|`False`|[`SettingsUserScope`]|<a id='pluginManager.debug'>pluginManager.debug</a>|
|pluginManager|Official Plugin Repository|Whether the official plugin repository is enabled|`boolean`|`True`|[`SettingsUserScope`]|<a id='pluginManager.officialRepo'>pluginManager.officialRepo</a>|
|pluginManager|Official Plugin Manager Update Channel|Specify which official update channel the Plugin Manager should update plugins from.|`string`|`master`|[`SettingsUserScope`]|<a id='pluginManager.officialUpdateChannel'>pluginManager.officialUpdateChannel</a>|
| | |  enum: The default channel. This setting should be used unless you are testing the Plugin Manager.|`enum`|`master`| | |
| | |  enum: Plugin Manager test channel.|`enum`|`test`| | |
|pluginManager|Unofficial 3rd Party Plugin Repository Display Name|Specify display name of 3rd party plugin repository.|`string`| |[`SettingsUserScope`]|<a id='pluginManager.unofficialName'>pluginManager.unofficialName</a>|
|pluginManager|Unofficial 3rd Party Plugin Repository URL|Specify URL of 3rd party plugin|`string`| |[`SettingsUserScope`]|<a id='pluginManager.unofficialUrl'>pluginManager.unofficialUrl</a>|
|python|Python Path Override|Python interpreter binary which may be necessary to install plugin dependencies. Should be the same version as the one specified in the 'Python Interpreter' setting|`string`| |[`SettingsUserScope`]|<a id='python.binaryOverride'>python.binaryOverride</a>|
|python|Python Interpreter|Python interpreter library(dylib/dll/so.1) to load if one is not already present when plugins are loaded.|`string`| |[`SettingsUserScope`]|<a id='python.interpreter'>python.interpreter</a>|
|python|Minimum Python Log Level|Set the minimum Python log level which applies in headless operation only. The log is connected to stderr. Additionally, stderr must be associated with a terminal device.|`string`|`WarningLog`|[`SettingsUserScope`]|<a id='python.log.minLevel'>python.log.minLevel</a>|
| | |  enum: Print Debug, Info, Warning, Error, and Alert messages to stderr on the terminal device.|`enum`|`DebugLog`| | |
| | |  enum: Print Info, Warning, Error, and Alert messages to stderr on the terminal device.|`enum`|`InfoLog`| | |
| | |  enum: Print Warning, Error, and Alert messages to stderr on the terminal device.|`enum`|`WarningLog`| | |
| | |  enum: Print Error and Alert messages to stderr on the terminal device.|`enum`|`ErrorLog`| | |
| | |  enum: Print Alert messages to stderr on the terminal device.|`enum`|`AlertLog`| | |
| | |  enum: Disable all logging in headless operation.|`enum`|`Disabled`| | |
|python|Python Virtual Environment Site-Packages|The 'site-packages' directory for your python virtual environment.|`string`| |[`SettingsUserScope`]|<a id='python.virtualenv'>python.virtualenv</a>|
|rendering|Show variable and integer annotations|Show variable and integer  annotations in disassembly i.e. {var_8}|`boolean`|`True`|[`SettingsUserScope`]|<a id='rendering.annotations'>rendering.annotations</a>|
|rendering|Show All Expression Types in Debug Reports|Enables the "Show All Expression Types" option in debug reports.|`boolean`|`False`|[`SettingsUserScope`]|<a id='rendering.debug.types'>rendering.debug.types</a>|
|rendering|HLIL Scoping Style|Controls the display of new scopes in HLIL.|`string`|`default`|[`SettingsUserScope`]|<a id='rendering.hlil.scopingStyle'>rendering.hlil.scopingStyle</a>|
| | |  enum: Default BNIL scoping style.|`enum`|`default`| | |
| | |  enum: Braces around scopes, same line.|`enum`|`braces`| | |
| | |  enum: Braces around scopes, new line.|`enum`|`bracesNewLine`| | |
|rendering|Tab Width|Width (in characters) of a single tab/indent in HLIL.|`number`|`4`|[`SettingsUserScope`]|<a id='rendering.hlil.tabWidth'>rendering.hlil.tabWidth</a>|
|rendering|Maximum String Annotation Length|The maximum substring length that will be shown in string annotations.|`number`|`32`|[`SettingsUserScope`]|<a id='rendering.strings.maxAnnotationLength'>rendering.strings.maxAnnotationLength</a>|
|triage|Triage Analysis Mode|Controls the amount of analysis performed on functions when opening for triage.|`string`|`basic`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='triage.analysisMode'>triage.analysisMode</a>|
| | |  enum: Only perform control flow analysis on the binary. Cross references are valid only for direct function calls.|`enum`|`controlFlow`| | |
| | |  enum: Perform fast initial analysis of the binary. This mode does not analyze types or data flow through stack variables.|`enum`|`basic`| | |
| | |  enum: Perform full analysis of the binary.|`enum`|`full`| | |
|triage|Triage Shows Hidden Files|Whether the Triage file picker shows hidden files.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='triage.hiddenFiles'>triage.hiddenFiles</a>|
|triage|Triage Linear Sweep Mode|Controls the level of linear sweep performed when opening for triage.|`string`|`partial`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='triage.linearSweep'>triage.linearSweep</a>|
| | |  enum: Do not perform linear sweep of the binary.|`enum`|`none`| | |
| | |  enum: Perform linear sweep on the binary, but skip the control flow graph analysis phase.|`enum`|`partial`| | |
| | |  enum: Perform full linear sweep on the binary.|`enum`|`full`| | |
|triage|Always Prefer Triage Summary View|Always prefer opening binaries in Triage Summary view, even when performing full analysis.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='triage.preferSummaryView'>triage.preferSummaryView</a>|
|triage|Prefer Triage Summary View for Raw Files|Prefer opening raw files in Triage Summary view.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='triage.preferSummaryViewForRaw'>triage.preferSummaryViewForRaw</a>|
|ui|Allow Welcome Popup|By default, the welcome window will only show up when it has changed and this install has not seen it. However, disabling this setting will prevent even that.|`boolean`|`True`|[`SettingsUserScope`]|<a id='ui.allowWelcome'>ui.allowWelcome</a>|
|ui|Developer Mode|Enable developer preferences.|`boolean`|`False`|[`SettingsUserScope`]|<a id='ui.developerMode'>ui.developerMode</a>|
|ui|Dock Window Title Bars|Enable to display title bars for dockable windows attached to a main window.|`boolean`|`True`|[`SettingsUserScope`]|<a id='ui.docks.titleBars'>ui.docks.titleBars</a>|
|ui|Feature Map|Enable the feature map which displays a visual overview of the BinaryView.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='ui.featureMap.enable'>ui.featureMap.enable</a>|
|ui|Feature Map File-Backed Only Mode|Exclude mapped regions that are not backed by a load file.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='ui.featureMap.fileBackedOnly'>ui.featureMap.fileBackedOnly</a>|
|ui|Feature Map Location|Location of the feature map.|`string`|`right`|[`SettingsUserScope`]|<a id='ui.featureMap.location'>ui.featureMap.location</a>|
| | |  enum: Feature map appears on the right side of the window.|`enum`|`right`| | |
| | |  enum: Feature map appears at the top of the window.|`enum`|`top`| | |
|ui|File Contents Lock|Lock the file contents to prevent accidental edits from the UI. File modification via API and menu based patching is explicitly allowed while the lock is enabled.|`boolean`|`True`|[`SettingsUserScope`]|<a id='ui.fileContentsLock'>ui.fileContentsLock</a>|
|ui|Existing Database Detection|When opening a file in the UI, detect if a database exists and offer to open the database.|`string`|`prompt`|[`SettingsUserScope`]|<a id='ui.files.detection.database'>ui.files.detection.database</a>|
| | |  enum: Enable detection and generate prompt.|`enum`|`prompt`| | |
| | |  enum: Enable detection and automatically open the file or database, if found.|`enum`|`always`| | |
| | |  enum: Disable detection.|`enum`|`disable`| | |
|ui|Existing Downloaded URL View Detection|When opening a database from an external URL in the UI, detect if an unsaved database from the same URL is already open and offer to navigate in that open view.|`string`|`prompt`|[`SettingsUserScope`]|<a id='ui.files.detection.openExistingViewFromUrl'>ui.files.detection.openExistingViewFromUrl</a>|
| | |  enum: Enable detection and generate prompt.|`enum`|`prompt`| | |
| | |  enum: Enable detection and automatically switch to the open view, if found.|`enum`|`always`| | |
| | |  enum: Disable detection.|`enum`|`disable`| | |
|ui|Auto Open with Options|Specify the file types which automatically open using the 'Open with Options' dialog.|`array`|[`Mapped`, `Universal`]|[`SettingsUserScope`]|<a id='ui.files.detection.openWithOptions'>ui.files.detection.openWithOptions</a>|
| | | |`enum`|`Mapped`| | |
| | | |`enum`|`ELF`| | |
| | | |`enum`|`Mach-O`| | |
| | | |`enum`|`COFF`| | |
| | | |`enum`|`PE`| | |
| | | |`enum`|`Universal`| | |
|ui|Programmer's Main Symbol List|A list of common 'main' symbols to search for when 'Navigate to Programmer's Main' is enabled.|`array`|[`main`, `_main`, `WinMain`]|[`SettingsUserScope`]|<a id='ui.files.navigation.mainSymbols'>ui.files.navigation.mainSymbols</a>|
|ui|Navigate to Programmer's Main|Detect and navigate to the 'main' function, rather than the entry point, after opening a binary.|`boolean`|`True`|[`SettingsUserScope`]|<a id='ui.files.navigation.preferMain'>ui.files.navigation.preferMain</a>|
|ui|Restore Recent Open with Options|Restores previously modified settings in the 'Open with Options' dialog when opening or reopening files (databases excluded). Load options are only included when reopening the same file.|`string`|`disable`|[`SettingsUserScope`]|<a id='ui.files.restore.viewOptions'>ui.files.restore.viewOptions</a>|
| | |  enum: Only restore settings for files with existing history.|`enum`|`strict`| | |
| | |  enum: Restore settings for files with existing history and propagate most recently used settings for new files.|`enum`|`flexible`| | |
| | |  enum: Disable the settings history for 'Open with Options'.|`enum`|`disable`| | |
|ui|Restore View State for File|Restores the last view state when reopening a file. The view state includes the layout and location.|`boolean`|`True`|[`SettingsUserScope`]|<a id='ui.files.restore.viewState'>ui.files.restore.viewState</a>|
|ui|Font Antialiasing Style|Which antialiasing style should be used when drawing fonts.|`string`|`subpixel`|[`SettingsUserScope`]|<a id='ui.font.antialiasing'>ui.font.antialiasing</a>|
| | |  enum: Perform subpixel antialiasing on fonts.|`enum`|`subpixel`| | |
| | |  enum: Avoid subpixel antialiasing on fonts if possible.|`enum`|`grayscale`| | |
| | |  enum: No subpixel antialiasing at High DPI.|`enum`|`hidpi`| | |
| | |  enum: No font antialiasing.|`enum`|`none`| | |
|ui|Application Font Name|The font to be used in UI elements, e.g. buttons, text fields, etc.|`string`|`Inter`|[`SettingsUserScope`]|<a id='ui.font.app.name'>ui.font.app.name</a>|
|ui|Application Font Size|The desired font size (in points) for interface elements.|`number`|`11`|[`SettingsUserScope`]|<a id='ui.font.app.size'>ui.font.app.size</a>|
|ui|Emoji Font Name|The font to be used in for rendering emoji.|`string`|`Apple Color Emoji`|[`SettingsUserScope`]|<a id='ui.font.emoji.name'>ui.font.emoji.name</a>|
|ui|Emoji Font Style|The subfamily of the emoji font that should be used.|`string`| |[`SettingsUserScope`]|<a id='ui.font.emoji.style'>ui.font.emoji.style</a>|
|ui|Allow Bold View Fonts|Should bold view fonts be allowed?|`boolean`|`True`|[`SettingsUserScope`]|<a id='ui.font.view.bold'>ui.font.view.bold</a>|
|ui|View Font Name|The font to be used in disassembly views, the hex editor, and anywhere a monospaced font is appropriate.|`string`|`Roboto Mono`|[`SettingsUserScope`]|<a id='ui.font.view.name'>ui.font.view.name</a>|
|ui|View Font Size|The desired font size (in points) for the view font.|`number`|`12`|[`SettingsUserScope`]|<a id='ui.font.view.size'>ui.font.view.size</a>|
|ui|View Line Spacing|How much additional spacing should be inserted between baselines in views.|`number`|`1`|[`SettingsUserScope`]|<a id='ui.font.view.spacing'>ui.font.view.spacing</a>|
|ui|View Font Style|The subfamily (e.g. Regular, Medium) of the view font that should be used.|`string`| |[`SettingsUserScope`]|<a id='ui.font.view.style'>ui.font.view.style</a>|
|ui|Input Field History Limit|Controls the number of history entries to store for input dialogs.|`number`|`50`|[`SettingsUserScope`]|<a id='ui.inputHistoryCount'>ui.inputHistoryCount</a>|
|ui|Maximum UI Log Size|Set the maximum number of lines for the UI log.|`number`|`10000`|[`SettingsUserScope`]|<a id='ui.log.maxSize'>ui.log.maxSize</a>|
|ui|Minimum UI Log Level|Set the minimum log level for the UI log.|`string`|`InfoLog`|[`SettingsUserScope`]|<a id='ui.log.minLevel'>ui.log.minLevel</a>|
| | |  enum: Display Debug, Info, Warning, Error, and Alert messages to log console.|`enum`|`DebugLog`| | |
| | |  enum: Display Info, Warning, Error, and Alert messages to log console.|`enum`|`InfoLog`| | |
| | |  enum: Display Warning, Error, and Alert messages to log console.|`enum`|`WarningLog`| | |
| | |  enum: Display Error and Alert messages to log console.|`enum`|`ErrorLog`| | |
| | |  enum: Display Alert messages to log console.|`enum`|`AlertLog`| | |
|ui|Manual Tooltip|Enable to prevent tooltips from showing without &lt;ctrl&gt; being held.|`boolean`|`False`|[`SettingsUserScope`]|<a id='ui.manualTooltip'>ui.manualTooltip</a>|
|ui|Maximum Number of Cross-reference Items|The number of cross-reference items to show in the cross-reference widget. Value 0 means no limit.|`number`|`1000`|[`SettingsUserScope`]|<a id='ui.maxXrefItems'>ui.maxXrefItems</a>|
|ui|Middle Click Navigation Action|Customize action on middle click (scroll wheel click) |`string`|`NewPane`|[`SettingsUserScope`]|<a id='ui.middleClickNavigationAction'>ui.middleClickNavigationAction</a>|
| | |  enum: Split to new pane and navigate|`enum`|`NewPane`| | |
| | |  enum: Split to new tab and navigate|`enum`|`NewTab`| | |
| | |  enum: Split to new window and navigate|`enum`|`NewWindow`| | |
|ui|Shift + Middle Click Navigation Action|Customize action on shift + middle click (scroll wheel click) |`string`|`NewTab`|[`SettingsUserScope`]|<a id='ui.middleClickShiftNavigationAction'>ui.middleClickShiftNavigationAction</a>|
| | |  enum: Split to new pane and navigate|`enum`|`NewPane`| | |
| | |  enum: Split to new tab and navigate|`enum`|`NewTab`| | |
| | |  enum: Split to new window and navigate|`enum`|`NewWindow`| | |
|ui|Desired Maximum Columns for Split Panes|Number of horizontal splits (columns) before defaulting to a vertical split.|`number`|`2`|[`SettingsUserScope`]|<a id='ui.panes.columnCount'>ui.panes.columnCount</a>|
|ui|Show Pane Headers|Enable to display headers containing the current view and options at the top of every pane. When headers are disabled, use the Command Palette or keyboard shortcuts to manage panes.|`boolean`|`True`|[`SettingsUserScope`]|<a id='ui.panes.headers'>ui.panes.headers</a>|
|ui|Preferred Location for New Panes|Default corner for placement of new panes. Split will occur horizontally up to the maximum column setting, then vertically in the corner specified by this setting.|`string`|`bottomRight`|[`SettingsUserScope`]|<a id='ui.panes.newPaneLocation'>ui.panes.newPaneLocation</a>|
| | |  enum: Left side for horizontal split, top side for vertical split.|`enum`|`topLeft`| | |
| | |  enum: Right side for horizontal split, top side for vertical split.|`enum`|`topRight`| | |
| | |  enum: Left side for horizontal split, bottom side for vertical split.|`enum`|`bottomLeft`| | |
| | |  enum: Right side for horizontal split, bottom side for vertical split.|`enum`|`bottomRight`| | |
|ui|Default Split Direction|Default direction for splitting panes.|`string`|`horizontal`|[`SettingsUserScope`]|<a id='ui.panes.splitDirection'>ui.panes.splitDirection</a>|
| | |  enum: Horizontal split (columns).|`enum`|`horizontal`| | |
| | |  enum: Vertical split (rows).|`enum`|`vertical`| | |
|ui|Always Show Pane Options in Status Bar|Enable to always show options for the active pane in the status bar.|`boolean`|`False`|[`SettingsUserScope`]|<a id='ui.panes.statusBarOptions'>ui.panes.statusBarOptions</a>|
|ui|Sync Panes by Default|Sync current location between panes by default.|`boolean`|`True`|[`SettingsUserScope`]|<a id='ui.panes.sync'>ui.panes.sync</a>|
|ui|Recent Command Limit|Specify a limit for the recent command palette history.|`number`|`5`|[`SettingsUserScope`]|<a id='ui.recentCommandLimit'>ui.recentCommandLimit</a>|
|ui|Recent File Limit|Specify a limit for the recent file history in the new tab window.|`number`|`10`|[`SettingsUserScope`]|<a id='ui.recentFileLimit'>ui.recentFileLimit</a>|
|ui|Show Indentation Guides|Show indentation markers in linear high-level IL|`boolean`|`True`|[`SettingsUserScope`]|<a id='ui.renderIndentGuides'>ui.renderIndentGuides</a>|
|ui|Default Scripting Provider|Specify the registered ScriptingProvider for the default scripting console in the UI.|`string`|`Python`|[`SettingsUserScope`]|<a id='ui.scripting.defaultProvider'>ui.scripting.defaultProvider</a>|
| | | |`enum`|`Python`| | |
| | | |`enum`|`Debugger`| | |
| | | |`enum`|`Target`| | |
|ui|Scripting Provider History Size|Specify the maximum number of lines contained in the scripting history.|`number`|`1000`|[`SettingsUserScope`]|<a id='ui.scripting.historySize'>ui.scripting.historySize</a>|
|ui|Display Settings Identifiers|Display setting identifiers in the UI settings view.|`boolean`|`False`|[`SettingsUserScope`]|<a id='ui.settings.displayIdentifiers'>ui.settings.displayIdentifiers</a>|
|ui|Default Sidebar Content on Open|Specify a sidebar widget to automatically activate in the content area when opening a file.|`string`|`Symbols`|[`SettingsUserScope`]|<a id='ui.sidebar.defaultContentWidget'>ui.sidebar.defaultContentWidget</a>|
| | | |`enum`|`None`| | |
| | | |`enum`|`Symbols`| | |
| | | |`enum`|`Types`| | |
| | | |`enum`|`Variables`| | |
| | | |`enum`|`Stack`| | |
| | | |`enum`|`Strings`| | |
| | | |`enum`|`Tags`| | |
| | | |`enum`|`Memory Map`| | |
| | | |`enum`|`Debugger`| | |
|ui|Default Sidebar Reference on Open|Specify a sidebar widget to automatically activate in the reference area when opening a file.|`string`|`Cross References`|[`SettingsUserScope`]|<a id='ui.sidebar.defaultReferenceWidget'>ui.sidebar.defaultReferenceWidget</a>|
| | | |`enum`|`None`| | |
| | | |`enum`|`Mini Graph`| | |
| | | |`enum`|`Cross References`| | |
|ui|Sidebar Mode|Select how the sidebar should react to tab changes.|`string`|`perTab`|[`SettingsUserScope`]|<a id='ui.sidebar.mode'>ui.sidebar.mode</a>|
| | |  enum: Sidebar layout and size is per tab and is remembered when moving between tabs.|`enum`|`perTab`| | |
| | |  enum: Sidebar widgets are per tab but the size of the sidebar is static and does not change.|`enum`|`staticSize`| | |
| | |  enum: Sidebar layout is fully static and stays in the current layout when moving between tabs.|`enum`|`static`| | |
|ui|Open Sidebar on Startup|Open sidebar to default widgets when Binary Ninja is initially launched.|`boolean`|`False`|[`SettingsUserScope`]|<a id='ui.sidebar.openOnStartup'>ui.sidebar.openOnStartup</a>|
|ui|Show Exported Data Variables|Show exported data variables in the symbol list.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsUserScope`]|<a id='ui.symbolList.showExportedDataVars'>ui.symbolList.showExportedDataVars</a>|
|ui|Show Exported Functions|Show exported functions in the symbol list.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsUserScope`]|<a id='ui.symbolList.showExportedFunctions'>ui.symbolList.showExportedFunctions</a>|
|ui|Show Imports|Show imports in the symbol list.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsUserScope`]|<a id='ui.symbolList.showImports'>ui.symbolList.showImports</a>|
|ui|Show Local Data Variables|Show local data variables in the symbol list.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsUserScope`]|<a id='ui.symbolList.showLocalDataVars'>ui.symbolList.showLocalDataVars</a>|
|ui|Show Local Functions|Show local functions in the symbol list.|`boolean`|`True`|[`SettingsProjectScope`, `SettingsUserScope`]|<a id='ui.symbolList.showLocalFunctions'>ui.symbolList.showLocalFunctions</a>|
|ui|Max Tab Filename Length|Truncate filenames longer than this in tab titles.|`number`|`25`|[`SettingsUserScope`]|<a id='ui.tabs.maxFileLength'>ui.tabs.maxFileLength</a>|
|ui|Color Blind Mode|Choose colors that are visible to those with red/green color blindness.|`boolean`|`False`|[`SettingsUserScope`]|<a id='ui.theme.colorBlind'>ui.theme.colorBlind</a>|
|ui|Theme|Customize the appearance and style of Binary Ninja.|`string`|`Dark`|[`SettingsUserScope`]|<a id='ui.theme.name'>ui.theme.name</a>|
|ui|Random Theme on Startup|Randomize the theme on application startup.|`boolean`|`False`|[`SettingsUserScope`]|<a id='ui.theme.randomize'>ui.theme.randomize</a>|
|ui|Disassembly Width|Maximum width of disassembly output, in characters. Not used in cases where disassembly width is automatically calculated, e.g. Linear View.|`number`|`80`|[`SettingsUserScope`]|<a id='ui.view.common.disassemblyWidth'>ui.view.common.disassemblyWidth</a>|
|ui|Maximum Symbol Name Length|Maximum allowed length of symbol names (in characters) before truncation is used.|`number`|`64`|[`SettingsUserScope`]|<a id='ui.view.common.maxSymbolWidth'>ui.view.common.maxSymbolWidth</a>|
|ui|Graph View IL Carousel|Specify the IL view types and order for use with the 'Cycle IL' actions in Graph view.|`array`|[`Disassembly`, `LowLevelIL`, `MediumLevelIL`, `HighLevelIL`]|[`SettingsUserScope`]|<a id='ui.view.graph.carousel'>ui.view.graph.carousel</a>|
| | | |`enum`|`Disassembly`| | |
| | | |`enum`|`LowLevelIL`| | |
| | | |`enum`|`LiftedIL`| | |
| | | |`enum`|`LowLevelILSSAForm`| | |
| | | |`enum`|`MediumLevelIL`| | |
| | | |`enum`|`MediumLevelILSSAForm`| | |
| | | |`enum`|`MappedMediumLevelIL`| | |
| | | |`enum`|`MappedMediumLevelILSSAForm`| | |
| | | |`enum`|`HighLevelIL`| | |
| | | |`enum`|`HighLevelILSSAForm`| | |
| | | |`enum`|`PseudoC`| | |
|ui|Default IL for Graph View|Default IL for graph view. Other settings (e.g. 'ui.files.restore.viewState') have precedence over the default behavior.|`string`|`Disassembly`|[`SettingsUserScope`]|<a id='ui.view.graph.il'>ui.view.graph.il</a>|
| | | |`enum`|`Disassembly`| | |
| | | |`enum`|`LowLevelIL`| | |
| | | |`enum`|`LiftedIL`| | |
| | | |`enum`|`LowLevelILSSAForm`| | |
| | | |`enum`|`MediumLevelIL`| | |
| | | |`enum`|`MediumLevelILSSAForm`| | |
| | | |`enum`|`MappedMediumLevelIL`| | |
| | | |`enum`|`MappedMediumLevelILSSAForm`| | |
| | | |`enum`|`HighLevelIL`| | |
| | | |`enum`|`HighLevelILSSAForm`| | |
| | | |`enum`|`PseudoC`| | |
|ui|Graph View Padding|Add extra space around graphs, proportional to the view's size.|`number`|`0.0`|[`SettingsProjectScope`, `SettingsUserScope`]|<a id='ui.view.graph.padding'>ui.view.graph.padding</a>|
|ui|Prefer Graph View|Default view preference between graph and linear view. User navigation to either view implicitly sets a run-time preference, and takes precedence over the default.|`boolean`|`False`|[`SettingsUserScope`]|<a id='ui.view.graph.preferred'>ui.view.graph.preferred</a>|
|ui|Linear View IL Carousel|Specify the IL view types and order for use with the 'Cycle IL' actions in Linear view.|`array`|[`Disassembly`, `LowLevelIL`, `MediumLevelIL`, `HighLevelIL`]|[`SettingsUserScope`]|<a id='ui.view.linear.carousel'>ui.view.linear.carousel</a>|
| | | |`enum`|`Disassembly`| | |
| | | |`enum`|`LowLevelIL`| | |
| | | |`enum`|`LiftedIL`| | |
| | | |`enum`|`LowLevelILSSAForm`| | |
| | | |`enum`|`MediumLevelIL`| | |
| | | |`enum`|`MediumLevelILSSAForm`| | |
| | | |`enum`|`MappedMediumLevelIL`| | |
| | | |`enum`|`MappedMediumLevelILSSAForm`| | |
| | | |`enum`|`HighLevelIL`| | |
| | | |`enum`|`HighLevelILSSAForm`| | |
| | | |`enum`|`PseudoC`| | |
|ui|Linear View Gutter Width|Linear view gutter and tags width, in characters.|`number`|`5`|[`SettingsUserScope`]|<a id='ui.view.linear.gutterWidth'>ui.view.linear.gutterWidth</a>|
|ui|Default IL for Linear View|Default IL for linear view. Other settings (e.g. 'ui.files.restore.viewState') have precedence over the default behavior.|`string`|`HighLevelIL`|[`SettingsUserScope`]|<a id='ui.view.linear.il'>ui.view.linear.il</a>|
| | | |`enum`|`Disassembly`| | |
| | | |`enum`|`LowLevelIL`| | |
| | | |`enum`|`LiftedIL`| | |
| | | |`enum`|`LowLevelILSSAForm`| | |
| | | |`enum`|`MediumLevelIL`| | |
| | | |`enum`|`MediumLevelILSSAForm`| | |
| | | |`enum`|`MappedMediumLevelIL`| | |
| | | |`enum`|`MappedMediumLevelILSSAForm`| | |
| | | |`enum`|`HighLevelIL`| | |
| | | |`enum`|`HighLevelILSSAForm`| | |
| | | |`enum`|`PseudoC`| | |
|ui|Default filter for types view|Default type filter to use in types view.|`string`|`user`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='ui.view.types.defaultTypeFilter'>ui.view.types.defaultTypeFilter</a>|
| | | |`enum`|`all`| | |
| | | |`enum`|`user`| | |
|ui|TypeView Line Numbers|Controls the display of line numbers in the types view.|`boolean`|`True`|[`SettingsUserScope`]|<a id='ui.view.types.lineNumbers'>ui.view.types.lineNumbers</a>|
|ui|Possible Value Set Function Complexity Limit|Function complexity limit for showing possible value set information. Complexity is calculated as the total number of outgoing edges in the function's MLIL SSA form.|`number`|`25`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='ui.view.variables.pvsComplexityLimit'>ui.view.variables.pvsComplexityLimit</a>|
|ui|File Path in Window Title|Controls whether the window title includes the full file path for the current file.|`boolean`|`False`|[`SettingsUserScope`]|<a id='ui.window.title.showPath'>ui.window.title.showPath</a>|
|updates|Update Channel Preferences|Select update channel and version.|`string`|`None`|[]|<a id='updates.channelPreferences'>updates.channelPreferences</a>|
|updates|Show All Versions|Show all versions that are available for the current update channel in the UI.|`boolean`|`False`|[`SettingsUserScope`]|<a id='updates.showAllVersions'>updates.showAllVersions</a>|
|user|Email|The email that will be shown when collaborating with other users.|`string`| |[`SettingsUserScope`]|<a id='user.email'>user.email</a>|
|user|Name|The name that will be shown when collaborating with other users.|`string`| |[`SettingsUserScope`]|<a id='user.name'>user.name</a>|
|workflows|Workflows Analysis Orchestration Framework|Enable the analysis orchestration framework. This feature is currently under active development.|`boolean`|`False`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='workflows.enable'>workflows.enable</a>|
|workflows|Workflows Example Plugins|Enable the built-in example plugins.|`boolean`|`False`|[`SettingsUserScope`]|<a id='workflows.examples'>workflows.examples</a>|
|workflows|Function Workflow|Workflow selection for function-based analysis.|`string`|`core.function.defaultAnalysis`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='workflows.functionWorkflow'>workflows.functionWorkflow</a>|
| | | |`enum`|`core.function.defaultAnalysis`| | |
| | | |`enum`|`core.function.objectiveC`| | |
| | | |`enum`|`core.module.defaultAnalysis`| | |
|workflows|Module Workflow|Workflow selection for module-based analysis. Note: Module-based workflows incomplete.|`string`|`core.module.defaultAnalysis`|[`SettingsProjectScope`, `SettingsResourceScope`, `SettingsUserScope`]|<a id='workflows.moduleWorkflow'>workflows.moduleWorkflow</a>|
| | | |`enum`|`core.module.defaultAnalysis`| | |
