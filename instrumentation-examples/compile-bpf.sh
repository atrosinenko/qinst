file=afl/afl-bpf.c
vim $file
clang -O3 -emit-llvm -c $file -o - | llc -march=bpf -filetype=obj -o $file.o
llvm-objdump -d -t -r $file.o
