from binaryninja.architecture import Architecture, ArchitectureHook

class X86ReturnHook(ArchitectureHook):
    def get_instruction_text(self, data, addr):
        # Call the original implementation's method by calling the superclass
        result, length = super(X86ReturnHook, self).get_instruction_text(data, addr)

        # Patch the name of the 'retn' instruction to 'ret'
        if len(result) > 0 and result[0].text == 'retn':
            result[0].text = 'ret'

        return result, length

# Install the hook by constructing it with the desired architecture to hook, then registering it
X86ReturnHook(Architecture['x86']).register()

