/* this is intended for use by BINJA */
int assemble_multiline(const std::string& code, std::vector<uint8_t>& result, std::string& err);

/* this is lower level API intended to be use by benchmarking tools (eg: test_asm.cpp) */
int assemble_single(std::string src, uint32_t addr, uint8_t *result, std::string& err, int& failures);
int disasm_capstone(uint8_t *data, uint32_t addr, std::string& result, std::string& err);
