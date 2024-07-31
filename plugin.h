#pragma once

#include "binaryninjacore.h"
#include "refcount.h"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace BinaryNinja
{
	class BinaryView;
	class Function;
	class LowLevelILFunction;
	struct LowLevelILInstruction;
	class MediumLevelILFunction;
	struct MediumLevelILInstruction;
	class HighLevelILFunction;
	struct HighLevelILInstruction;

	/*!
		\ingroup plugin
	*/
	struct PluginCommandContext
	{
		Ref<BinaryView> binaryView;
		uint64_t address, length;
		size_t instrIndex;
		Ref<Function> function;
		Ref<LowLevelILFunction> lowLevelILFunction;
		Ref<MediumLevelILFunction> mediumLevelILFunction;
		Ref<HighLevelILFunction> highLevelILFunction;

		PluginCommandContext();
	};

	/*!
		The PluginCommand class is used for registering "commands" for Plugins, corresponding to code in those plugins
	 	to be executed.

	 	\ingroup plugin

	 	The proper way to use this class is via one of the \c "Register*" static methods.
	*/
	class PluginCommand
	{
		BNPluginCommand m_command;

		struct RegisteredDefaultCommand
		{
			std::function<void(BinaryView*)> action;
			std::function<bool(BinaryView*)> isValid;
		};

		struct RegisteredAddressCommand
		{
			std::function<void(BinaryView*, uint64_t)> action;
			std::function<bool(BinaryView*, uint64_t)> isValid;
		};

		struct RegisteredRangeCommand
		{
			std::function<void(BinaryView*, uint64_t, uint64_t)> action;
			std::function<bool(BinaryView*, uint64_t, uint64_t)> isValid;
		};

		struct RegisteredFunctionCommand
		{
			std::function<void(BinaryView*, Function*)> action;
			std::function<bool(BinaryView*, Function*)> isValid;
		};

		struct RegisteredLowLevelILFunctionCommand
		{
			std::function<void(BinaryView*, LowLevelILFunction*)> action;
			std::function<bool(BinaryView*, LowLevelILFunction*)> isValid;
		};

		struct RegisteredLowLevelILInstructionCommand
		{
			std::function<void(BinaryView*, const LowLevelILInstruction&)> action;
			std::function<bool(BinaryView*, const LowLevelILInstruction&)> isValid;
		};

		struct RegisteredMediumLevelILFunctionCommand
		{
			std::function<void(BinaryView*, MediumLevelILFunction*)> action;
			std::function<bool(BinaryView*, MediumLevelILFunction*)> isValid;
		};

		struct RegisteredMediumLevelILInstructionCommand
		{
			std::function<void(BinaryView*, const MediumLevelILInstruction&)> action;
			std::function<bool(BinaryView*, const MediumLevelILInstruction&)> isValid;
		};

		struct RegisteredHighLevelILFunctionCommand
		{
			std::function<void(BinaryView*, HighLevelILFunction*)> action;
			std::function<bool(BinaryView*, HighLevelILFunction*)> isValid;
		};

		struct RegisteredHighLevelILInstructionCommand
		{
			std::function<void(BinaryView*, const HighLevelILInstruction&)> action;
			std::function<bool(BinaryView*, const HighLevelILInstruction&)> isValid;
		};

		static void DefaultPluginCommandActionCallback(void* ctxt, BNBinaryView* view);
		static void AddressPluginCommandActionCallback(void* ctxt, BNBinaryView* view, uint64_t addr);
		static void RangePluginCommandActionCallback(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		static void FunctionPluginCommandActionCallback(void* ctxt, BNBinaryView* view, BNFunction* func);
		static void LowLevelILFunctionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func);
		static void LowLevelILInstructionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr);
		static void MediumLevelILFunctionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func);
		static void MediumLevelILInstructionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr);
		static void HighLevelILFunctionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func);
		static void HighLevelILInstructionPluginCommandActionCallback(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr);

		static bool DefaultPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view);
		static bool AddressPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, uint64_t addr);
		static bool RangePluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len);
		static bool FunctionPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, BNFunction* func);
		static bool LowLevelILFunctionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func);
		static bool LowLevelILInstructionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNLowLevelILFunction* func, size_t instr);
		static bool MediumLevelILFunctionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func);
		static bool MediumLevelILInstructionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNMediumLevelILFunction* func, size_t instr);
		static bool HighLevelILFunctionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func);
		static bool HighLevelILInstructionPluginCommandIsValidCallback(
		    void* ctxt, BNBinaryView* view, BNHighLevelILFunction* func, size_t instr);

	  public:
		PluginCommand(const BNPluginCommand& cmd);
		PluginCommand(const PluginCommand& cmd);
		~PluginCommand();

		PluginCommand& operator=(const PluginCommand& cmd);

		/*! Register a command for a given BinaryView.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::Register("MyPlugin\\MyAction", "Perform an action",
				   [](BinaryView* view)
				   {
					   // Perform an action on a view
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::Register("MyPlugin\\MySecondAction", "Perform an action", MyPlugin::MyCommand);
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void Register(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view)>& action);

		/*! Register a command for a given BinaryView, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::Register("MyPlugin\\MyAction", "Perform an action",
					[](BinaryView* view)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::Register("MyPlugin\\MySecondAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Function that returns whether the command is allowed to be performed.
		*/
		static void Register(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view)>& action, const std::function<bool(BinaryView* view)>& isValid);

		/*! Register a command for a given BinaryView, when an address is selected.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForAddress("MyPlugin\\MyAddressAction", "Perform an action on an address",
				   [](BinaryView* view, uint64_t addr)
				   {
					   // Perform an action on a view and address
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view, uint64_t addr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForAddress("MyPlugin\\MySecondAddressAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForAddress(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr)>& action);

		/*! Register a command for a given BinaryView and an address, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForAddress("MyPlugin\\MyAddressAction", "Perform an action",
					[](BinaryView* view, uint64_t addr)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, uint64_t addr)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view, uint64_t addr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForAddress("MyPlugin\\MySecondAddressAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, uint64_t addr){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForAddress(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr)>& action,
		    const std::function<bool(BinaryView* view, uint64_t addr)>& isValid);

		/*! Register a command for a given BinaryView, when a range of address is selected.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForRange("MyPlugin\\MyRangeAction", "Perform an action on a range",
				   [](BinaryView* view, uint64_t addr, uint64_t len)
				   {
					   // Perform an action on a view and address
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view, uint64_t addr, uint64_t len)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForRange("MyPlugin\\MySecondRangeAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForRange(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr, uint64_t len)>& action);

		/*! Register a command for a given BinaryView and a range, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForRange("MyPlugin\\MyRangeAction", "Perform an action",
					[](BinaryView* view, uint64_t addr, uint64_t len)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, uint64_t addr, uint64_t len)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace, e.g. "void myCommand(BinaryView* view)"
			void MyPlugin::MyCommand(BinaryView* view, uint64_t addr, uint64_t len)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForRange("MyPlugin\\MySecondRangeAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, uint64_t addr, uint64_t len){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForRange(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, uint64_t addr, uint64_t len)>& action,
		    const std::function<bool(BinaryView* view, uint64_t addr, uint64_t len)>& isValid);

		/*! Register a command for a given BinaryView within a function.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForFunction("MyPlugin\\MyFunctionAction", "Perform an action on a function",
				   [](BinaryView* view, Function* func)
				   {
					   // Perform an action on a view and function
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, Function* func)"
			void MyPlugin::MyCommand(BinaryView* view, Function* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForFunction("MyPlugin\\MySecondFunctionAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, Function* func)>& action);

		/*! Register a command for a given BinaryView and a function, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForFunction("MyPlugin\\MyFunctionAction", "Perform an action",
					[](BinaryView* view, Function* func)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, Function* func)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, Function* func)"
			void MyPlugin::MyCommand(BinaryView* view, Function* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForFunction("MyPlugin\\MySecondFunctionAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, Function* func){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, Function* func)>& action,
		    const std::function<bool(BinaryView* view, Function* func)>& isValid);

		/*! Register a command for a given BinaryView within a LowLevelILFunction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForLowLevelILFunction("MyPlugin\\MyLLILFunctionAction", "Perform an action on a llil function",
				   [](BinaryView* view, LowLevelILFunction* func)
				   {
					   // Perform an action on a view and function
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, LowLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, LowLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForLowLevelILFunction("MyPlugin\\MySecondLLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForLowLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, LowLevelILFunction* func)>& action);

		/*! Register a command for a given BinaryView and a Low Level IL function, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForLowLevelILFunction("MyPlugin\\MyLLILFunctionAction", "Perform an action",
					[](BinaryView* view, LowLevelILFunction* func)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, LowLevelILFunction* func)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, LowLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, LowLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForLowLevelILFunction("MyPlugin\\MySecondLLILAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, LowLevelILFunction* func){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForLowLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, LowLevelILFunction* func)>& action,
		    const std::function<bool(BinaryView* view, LowLevelILFunction* func)>& isValid);

		/*! Register a command for a given BinaryView with a given LowLevelILInstruction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForRegisterForLowLevelILInstruction("MyPlugin\\MyLLILInstructionAction",
		    		"Perform an action on an instruction",
				   [](BinaryView* view, LowLevelILInstruction* instr)
				   {
					   // Perform an action on a view and a LowLevelILInstruction
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, LowLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, LowLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForLowLevelILInstruction("MyPlugin\\MySecondLLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForLowLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const LowLevelILInstruction& instr)>& action);

		/*! Register a command for a given BinaryView and a LowLevelILInstruction, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForLowLevelILInstruction("MyPlugin\\MyLLILInstructionAction", "Perform an action",
					[](BinaryView* view, LowLevelILInstruction* instr)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, LowLevelILInstruction* instr)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, LowLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, LowLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForLowLevelILInstruction("MyPlugin\\MySecondLLILAction",
		    		"Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, LowLevelILInstruction* instr){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForLowLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const LowLevelILInstruction& instr)>& action,
		    const std::function<bool(BinaryView* view, const LowLevelILInstruction& instr)>& isValid);

		/*! Register a command for a given BinaryView within a MediumLevelILFunction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForMediumLevelILFunction("MyPlugin\\MyMLILFunctionAction", "Perform an action on a mlil function",
				   [](BinaryView* view, MediumLevelILFunction* func)
				   {
					   // Perform an action on a view and function
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, MediumLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, MediumLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForMediumLevelILFunction("MyPlugin\\MySecondMLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForMediumLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, MediumLevelILFunction* func)>& action);

		/*! Register a command for a given BinaryView and a Medium Level IL function, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForMediumLevelILFunction("MyPlugin\\MyMLILFunctionAction", "Perform an action",
					[](BinaryView* view, MediumLevelILFunction* func)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, MediumLevelILFunction* func)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, MediumLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, MediumLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForMediumLevelILFunction("MyPlugin\\MySecondMLILAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, MediumLevelILFunction* func){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForMediumLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, MediumLevelILFunction* func)>& action,
		    const std::function<bool(BinaryView* view, MediumLevelILFunction* func)>& isValid);

		/*! Register a command for a given BinaryView with a given MediumLevelILInstruction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForRegisterForMediumLevelILInstruction("MyPlugin\\MyMLILInstructionAction",
		    		"Perform an action on an instruction",
				   [](BinaryView* view, MediumLevelILInstruction* instr)
				   {
					   // Perform an action on a view and a MediumLevelILInstruction
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, MediumLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, MediumLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForMediumLevelILInstruction("MyPlugin\\MySecondMLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForMediumLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const MediumLevelILInstruction& instr)>& action);

		/*! Register a command for a given BinaryView and a MediumLevelILInstruction, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForMediumLevelILInstruction("MyPlugin\\MyMLILInstructionAction", "Perform an action",
					[](BinaryView* view, MediumLevelILInstruction* instr)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, MediumLevelILInstruction* instr)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, MediumLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, MediumLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForMediumLevelILInstruction("MyPlugin\\MySecondMLILAction",
		    		"Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, MediumLevelILInstruction* instr){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForMediumLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const MediumLevelILInstruction& instr)>& action,
		    const std::function<bool(BinaryView* view, const MediumLevelILInstruction& instr)>& isValid);

		/*! Register a command for a given BinaryView within a HighLevelILFunction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForHighLevelILFunction("MyPlugin\\MyHLILFunctionAction", "Perform an action on a hlil function",
				   [](BinaryView* view, HighLevelILFunction* func)
				   {
					   // Perform an action on a view and function
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, HighLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, HighLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForMediumLevelILFunction("MyPlugin\\MySecondHLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForHighLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, HighLevelILFunction* func)>& action);

		/*! Register a command for a given BinaryView and a High Level IL function, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForHighLevelILFunction("MyPlugin\\MyHLILFunctionAction", "Perform an action",
					[](BinaryView* view, HighLevelILFunction* func)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, HighLevelILFunction* func)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, HighLevelILFunction* func)"
			void MyPlugin::MyCommand(BinaryView* view, HighLevelILFunction* func)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForHighLevelILFunction("MyPlugin\\MySecondHLILAction", "Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, HighLevelILFunction* func){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForHighLevelILFunction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, HighLevelILFunction* func)>& action,
		    const std::function<bool(BinaryView* view, HighLevelILFunction* func)>& isValid);

		/*! Register a command for a given BinaryView with a given HighLevelILInstruction.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using a lambda expression
		    PluginCommand::RegisterForRegisterForHighLevelILInstruction("MyPlugin\\MyHLILInstructionAction",
		    		"Perform an action on an instruction",
				   [](BinaryView* view, HighLevelILInstruction* instr)
				   {
					   // Perform an action on a view and a HighLevelILInstruction
				   });

			// Registering a command using a standard static function
		 	// This also works with functions in the global namespace, e.g.
		 	// "void myCommand(BinaryView* view, HighLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, HighLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForHighLevelILInstruction("MyPlugin\\MySecondHLILAction", "Perform an action", MyPlugin::MyCommand);

			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		*/
		static void RegisterForHighLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const HighLevelILInstruction& instr)>& action);

		/*! Register a command for a given BinaryView and a HighLevelILInstruction, with a validity check.

			This will appear in the top menu and the right-click context menu.

			\code{.cpp}

		 	// Registering a command using lambda expressions
		    PluginCommand::RegisterForHighLevelILInstruction("MyPlugin\\MyHLILInstructionAction", "Perform an action",
					[](BinaryView* view, HighLevelILInstruction* instr)
					{
					   // Perform an action on a view that requires it having symbols
					},
		        	[](BinaryView* view, HighLevelILInstruction* instr)
					{
						return view->HasSymbols();
					});

			// Registering a command using a standard static function, and a lambda for the isValid check
		 	// This also works with functions in the global namespace,
		 	// 	e.g. "void myCommand(BinaryView* view, HighLevelILInstruction* instr)"
			void MyPlugin::MyCommand(BinaryView* view, HighLevelILInstruction* instr)
		 	{
		 		// Perform an action on a view
		 	}

		    PluginCommand::RegisterForHighLevelILInstruction("MyPlugin\\MySecondHLILAction",
		    		"Perform an action", MyPlugin::MyCommand,
				   [](BinaryView *view, HighLevelILInstruction* instr){ return view->HasSymbols(); });
			\endcode

			\param name
		 	\parblock
		 	Name of the command to register. This will appear in the top menu and the context menu.

		 	You can register submenus to an item by separating names with a \c "\\". The base (farthest right) name will
		 	be the item which upon being clicked will perform the action.
		 	\endparblock
			\param description Description of the command
			\param action Action to perform
		 	\param isValid Expression that returns whether the command is allowed to be performed.
		*/
		static void RegisterForHighLevelILInstruction(const std::string& name, const std::string& description,
		    const std::function<void(BinaryView* view, const HighLevelILInstruction& instr)>& action,
		    const std::function<bool(BinaryView* view, const HighLevelILInstruction& instr)>& isValid);

		/*! Get the list of registered PluginCommands

			\return The list of registered PluginCommands
		*/
		static std::vector<PluginCommand> GetList();

		/*! Get the list of valid PluginCommands for a given context

			\param ctxt The context to be used for the checks
			\return The list of valid plugin commands.
		*/
		static std::vector<PluginCommand> GetValidList(const PluginCommandContext& ctxt);

		/*! Get the name for the registered PluginCommand

			\return The name for the registered PluginCommand
		*/
		std::string GetName() const { return m_command.name; }

		/*! Get the description for the registered PluginCommand

			\return The description for the registered PluginCommand
		*/
		std::string GetDescription() const { return m_command.description; }

		/*! Get the type of the registered PluginCommand

			\return The type of the registered PluginCommand
		*/
		BNPluginCommandType GetType() const { return m_command.type; }
		const BNPluginCommand* GetObject() const { return &m_command; }

		bool IsValid(const PluginCommandContext& ctxt) const;
		void Execute(const PluginCommandContext& ctxt) const;
	};


	/*!
		\ingroup plugin
	*/
	class MainThreadAction :
	    public CoreRefCountObject<BNMainThreadAction, BNNewMainThreadActionReference, BNFreeMainThreadAction>
	{
	  public:
		MainThreadAction(BNMainThreadAction* action);
		void Execute();
		bool IsDone() const;
		void Wait();
	};

	/*!
		\ingroup plugin
	*/
	class MainThreadActionHandler
	{
	  public:
		virtual void AddMainThreadAction(MainThreadAction* action) = 0;
	};

	/*!
		\ingroup plugin
	*/
	class BackgroundTask :
	    public CoreRefCountObject<BNBackgroundTask, BNNewBackgroundTaskReference, BNFreeBackgroundTask>
	{
	  public:
		BackgroundTask(BNBackgroundTask *task);

		/*!
			Provides a mechanism for reporting progress of
			an optionally cancelable task to the user via the status bar in the UI.
			If canCancel is is `True`, then the task can be cancelled either
			programmatically or by the user via the UI.

			\note This API does not provide a means to execute a task. The caller is responsible to execute (and possibly cancel) the task.

			\param initialText Text description of the progress of the background task (displayed in status bar of the UI)
			\param canCancel Whether the task can be cancelled
		*/
		BackgroundTask(const std::string &initialText, bool canCancel);

		bool CanCancel() const;
		bool IsCancelled() const;
		bool IsFinished() const;
		std::string GetProgressText() const;
		uint64_t GetRuntimeSeconds() const;

		void Cancel();
		void Finish();
		void SetProgressText(const std::string& text);

		static std::vector<Ref<BackgroundTask>> GetRunningTasks();
	};


}
