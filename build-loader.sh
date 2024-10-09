KERNEL_SRCTREE=$(pwd)
clang -o loader-bin -I$(pwd)/include/ \
  $(pwd)/include/bpf_load.c \
  loader.c -lelf -lbpf
