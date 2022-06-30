#pragma once

extern "C" {
	class BNType;
	struct BNDataVariable
	{
		uint64_t address;
		BNType* type;
		bool autoDiscovered;
		uint8_t typeConfidence;
	};

	struct BNDataVariableAndName
	{
		uint64_t address;
		BNType* type;
		char* name;
		bool autoDiscovered;
		uint8_t typeConfidence;
	};
}