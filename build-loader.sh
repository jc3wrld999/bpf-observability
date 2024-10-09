KERNEL_SRCTREE=$(pwd)
clang -o loader-bin -I$(pwd)/lib/ \
  $(pwd)/lib/bpf_load.c \
  loader.c -lelf -lbpf
