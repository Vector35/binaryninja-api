This README explains the process of generating the input and output type information for x86 intrinsics. 

It takes two major steps:

1. Tweak the xed build process and generate the information for each iform. 
    - Apply the `patch.diff` to `$XED_SOURCE/pysrc/generator.py`
    - Build xed and harvest the `iform-type-dump.txt`
    - Copy the `iform-type-dump.txt` to the current folder

2. run the `parse-iform-types.py` 
    - It will generate `../x86_intrinsic_input_type.cpp` and `../x86_intrinsic_output_type.cpp`. 