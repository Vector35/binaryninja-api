cd arm_pcode_parser
make clean
make
cd ..
make -f Makefile-linux clean
make -f Makefile-linux
cp libthumb.so ../../ui/plugins/libarch_thumb2.so
cd ../../
make -j4
cd arch/thumb2
../../suite/thumb2_test.py
