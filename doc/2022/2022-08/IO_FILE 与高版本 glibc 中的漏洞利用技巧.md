#  IO_FILE 与高版本 glibc 中的漏洞利用技巧   
原创 evilpan  有价值炮灰   2022-07-31 20:10  
  
Hacking glibc for fun and profit!  
# 前言  
  
在日常的二进制漏洞利用过程中，最终在获取到任意地址读写之都会面临一个问题: 要从哪里读，写到哪里去。对于信息泄露有很多方法，比如寻找一些数据结构在内存中残留的地址，可以是内部结构，也可以是用户定义的结构；相比而言，内存写原语的使用场景就相对有限了。因为在当今的系统安全纵深防护之下，代码和数据已经呈现了严格分离的趋势，可读可写可执行的历史遗留问题会逐渐退出历史舞台。更多的利用方法是关注代码重用(ROP)、可修改的函数指针、面向对象引入的多态调用等等。  
  
具体的利用技巧和目标对象有直接联系，本文介绍的是基于 Glibc 的运行场景，也是当前很多 CTF 赛题所面临的场景。犹记得上古年代堆漏洞利用是那么单纯，先泄露 libc、然后 free_hook 写 system，然后 getshell。但随着 glibc 版本的更新，也逐渐引入了一些新的缓释措施，因此大家的目光就转向了其他的后利用链。其中 FILE 结构体虽然不是唯一的，但却是使用最多的，因此本文就来学习一下。  
> 下文涉及源代码部分如无特殊说明均来自   
glibc-2.35[1]  
  
# FILE 101  
  
我们平时往输入输出读写数据的时候，也许是直接使用 glibc 对系统调用的浅封装 open、read、write，但更多时候也使用 fopen、fread、printf 等，而后者大多是 POSIX 标准的 IO 函数。这些函数主要围绕 FILE 结构体而操作，由 fopen 返回，也就是常说的 _IO_FILE:  
```
typedef struct _IO_FILE FILE;
```  
## 数据结构  
  
该结构体的定义如下所示:  
```
struct _IO_FILE
{
  int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;   /* Current read pointer */
  char *_IO_read_end;   /* End of get area. */
  char *_IO_read_base;  /* Start of putback+get area. */
  char *_IO_write_base; /* Start of put area. */
  char *_IO_write_ptr;  /* Current put pointer. */
  char *_IO_write_end;  /* End of put area. */
  char *_IO_buf_base;   /* Start of reserve area. */
  char *_IO_buf_end;    /* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  // ...
};
```  
  
作为一个管理 IO 流缓冲的数据结构，需要保存当前用户写入的内存，包括已经读出和写入的大小和剩余数量等，这些位置使用指针表示；当然也包括系统调用所需的文件句柄 _fileno；另外 _flags 用于指定当前文件流的属性，比如是否可读可写等。  
  
虽然我们平时也会使用 fopen 打开并读写文件，但更多的情况下并没有显式操作 FILE，而是使用了标准库中定义的 stdin、stdout 和 stderr 宏去进行读写标准输入输出。这些值其实也是 FILE 指针:  
```
extern struct _IO_FILE_plus _IO_2_1_stdin_;

FILE *stdin = (FILE *) &_IO_2_1_stdin_;
FILE *stdout = (FILE *) &_IO_2_1_stdout_;
//...
```  
  
以 stdin 为例，虽然其类型是 FILE *，但实际类型却是 _IO_2_1_stdin_ 的类型，即 _IO_FILE_plus:  
```
struct _IO_FILE_plus
{
  FILE file;
  const struct _IO_jump_t *vtable;
};
```  
  
该结构第一个元素包含的也是 FILE，因此可以进行强制类型转换。但末尾还多了个指针，一般这种模式常用于在 C 语言中实现面向对象(多态)调用，这个指针就作为虚函数表。该虚表的定义如下:  
```
#define JUMP_FIELD(TYPE, NAME) TYPE NAME
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
```  
  
包含了针对文件 read、write、close、sync 等操作的函数指针，列举其中两个函数原型:  
```
typedef ssize_t (*_IO_read_t) (FILE *, void *, ssize_t);
typedef ssize_t (*_IO_write_t) (FILE *, const void *, ssize_t);
```  
## 标准 I/O  
  
上面介绍了 _IO_FILE 中的相关基础结构，接着看围绕这些结构所展开的一些常见攻击手法。不过在此之前还需重点介绍一下关于标准输入输出的定义，如下所示:  
```
# define DEF_STDFILE(NAME, FD, CHAIN, FLAGS) \  static _IO_lock_t _IO_stdfile_##FD##_lock = _IO_lock_initializer; \  static struct _IO_wide_data _IO_wide_data_##FD \    = { ._wide_vtable = &_IO_wfile_jumps }; \  struct _IO_FILE_plus NAME \    = {FILEBUF_LITERAL(CHAIN, FLAGS, FD, &_IO_wide_data_##FD), \       &_IO_file_jumps};

DEF_STDFILE(_IO_2_1_stdin_, 0, 0, _IO_NO_WRITES);
DEF_STDFILE(_IO_2_1_stdout_, 1, &_IO_2_1_stdin_, _IO_NO_READS);
DEF_STDFILE(_IO_2_1_stderr_, 2, &_IO_2_1_stdout_, _IO_NO_READS+_IO_UNBUFFERED);
```  
  
_IO_wide_data 是针对宽字符的虚函数表，这里先不关心，重点关注的是对 _IO_FILE_plus 结构体末尾虚函数表的定义，可以看到三者都被定义为了全局的 _IO_file_jumps:  
```
#define libio_vtable __attribute__ ((section ("__libc_IO_vtables")))
#define JUMP_INIT(NAME, VALUE) VALUE
#define JUMP_INIT_DUMMY JUMP_INIT(dummy, 0), JUMP_INIT (dummy2, 0)

const struct _IO_jump_t _IO_file_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_default_pbackfail),
  JUMP_INIT(xsputn, _IO_file_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn),
  JUMP_INIT(seekoff, _IO_new_file_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_new_file_setbuf),
  JUMP_INIT(sync, _IO_new_file_sync),
  JUMP_INIT(doallocate, _IO_file_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close),
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
libc_hidden_data_def (_IO_file_jumps)
```  
  
并且，该全局虚函数表在 ELF 中使用单独的段 __libc_IO_vtables 进行标识:  
```
root@pwnlab:/pwn$ rabin2 -S /usr/lib/x86_64-linux-gnu/libc.so.6 | grep __libc
16  0x001baac0    0x1a01 0x001baac0    0x1a01 -r-x __libc_freeres_fn
27  0x00214910      0xe8 0x00215910      0xe8 -rw- __libc_subfreeres
28  0x002149f8       0x8 0x002159f8       0x8 -rw- __libc_atexit
29  0x00214a00     0xd68 0x00215a00     0xd68 -rw- __libc_IO_vtables
```  
## 文件链表  
  
开头介绍 FILE 数据结构的时候，有一个字段还没介绍，即 struct _IO_FILE *_chain。从名字上也可以猜测这个字段用于实现链表结构。在上节介绍 stdin/out/err 定义的时候看到:  
- • stdin->chain = 0  
  
- • stdout->chain = &stdin  
  
- • stderr->chain = &stdout  
  
最后还定义了一个全局的头部 _IO_list_all:  
```
struct _IO_FILE_plus *_IO_list_all = &_IO_2_1_stderr_;
```  
  
从链表顺序可见，stdin 在链表尾部，stderr 在头部。实际在使用 fopen 打开新的文件流时，会经过一系列调用:  
- • **fopen/fopen64**  
  
- • _IO_new_fopen  
  
- • __fopen_internal  
  
- • _IO_new_file_init_internal  
  
- • _IO_link_in  
  
最终将新创建的 FILE 结构体插入上述链表的**头部**:  
```
void _IO_link_in (struct _IO_FILE_plus *fp) {
    if ((fp->file._flags & _IO_LINKED) == 0) {
        fp->file._flags |= _IO_LINKED;
        fp->file._chain = (FILE *) _IO_list_all;
        _IO_list_all = fp;
    }
}
```  
  
所以说全局的 _IO_list_all 维护了当前 IO 库所打开的所有文件流。这是为了方便所有文件流进行迭代，比如在程序退出前需要清空缓冲区并执行关闭文件等操作，这在后文漏洞利用的过程中也会提到。  
## 文件读写  
  
上面其实简要介绍了 fopen 的流程，文件读写的过程其实也类似，先看读文件的 **fread**，其调用链路为:  
- • fread  
  
- • _IO_fread  
  
- • _IO_sgetn  
  
- • _IO_XSGETN  
  
其中 _IO_XSGETN 是一个宏，其定义如下:  
```
#define _IO_XSGETN(FP, DATA, N) JUMP2 (__xsgetn, FP, DATA, N)

#define JUMP0(FUNC, THIS) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS)
#define JUMP1(FUNC, THIS, X1) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)
#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)
#define JUMP3(FUNC, THIS, X1,X2,X3) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1,X2, X3)
```  
  
JUMPn 主要是跳转到 vtable 对应的字段获取动态函数地址，不同点主要在于参数个数。因此实际的文件读取流程都在 _IO_file_xsgetn 函数中，getn 表示从 fp 中读取 n 字节。具体实现代码太长就不复制了，可以简要概括如下:  
- • 读取并不是直接读到给定的地址，而是先读到内部的缓存，由 _IO_buf_base 表示；  
  
- • 如果内部缓存还没分配，使用 _IO_doallocbuf 进行分配，会从相同的虚表中查找对应的 __doallocate 方法并执行；  
  
- • _IO_file_doallocate 内部会使用 malloc 分配缓存，默认大小是 8192；  
  
- • _IO_buf_base 指向缓存头部，_IO_buf_end 指向尾部(=p+size)；  
  
- • _IO_read_ptr 是缓存中有效数据的头部，_IO_read_end 是有效数据的尾部；  
  
- • 如果循环读取的某一刻缓存中的有效数据为空，会触发虚表中的 _IO_file_underflow 调用，判断文件是否已经关闭，如果关闭了就退出读取返回 EOF 给用户，否则继续等待数据；  
  
- • 最底层使用 vtable->read 即系统调用进行读取；  
  
文件写入的流程也大同小异，使用虚表中的 xsputn 即 _IO_file_xsputn 方法进行写入。在新版本 glibc 中使用了新的实现 _IO_new_file_xsputn。和 fread 的差异主要在于内存分配的过程，实际是在触发 **overflow** 调用的时候进行内存分配的，下面是一个实际的栈回溯示例:  
```
[#0] __GI___libc_malloc
[#1] __GI__IO_file_doallocate
[#2] __GI__IO_doallocbuf
[#3] _IO_new_file_overflow
[#4] _IO_new_file_xsputn
[#5] __GI__IO_fwrite
[#6] main
```  
  
触发 overflow 表示内部缓存空间不足，此时会有几种不同的情况:  
1. 1. 缓存还未申请(_IO_write_base == 0)，此时直接申请；  
  
1. 2. 当前已经有缓存，并且正在读取(flags & _IO_CURRENTLY_PUTTING == 0)，此时需要调整对应的读写指针以腾出空间；  
  
1. 3. 否则使用系统调用将数据写入到内核中，释放缓存空间压力；  
  
还有一个值得一提的是 fclose，其大致操作如下:  
- • 将 FILE 指针从全局单链表中删除(_IO_un_link)；  
  
- • vtable->finish:  
  
- • 清空内部缓存(vtable->flush)；  
  
- • 关闭文件句柄(vtable->close)；  
  
- • 释放内部缓存(free)；  
  
- • 释放 FILE 结构体(free)；  
  
至此，完成了对 stdio 生命周期的简单分析。  
# 常见攻击  
  
从前面的介绍可以看出，FILE 结构体之所以是一个常用的攻击目标，是因为其中虚函数表中存在大量的函数指针，并且在程序正常执行的生命周期会触发其中许多方法的查找和执行。加上 stdin、stdout、stderr 这些全局指针的存在，使得一旦可以劫持虚函数查找中的任意一级流程，就可以实现控制流劫持，从而进一步实现任意代码执行。  
  
具体而言又有不同的细分，笔者只根据自己的经验去总结了一些常见攻击方法，若有疏漏可以在文末评论指出。  
> 下文中会将 _IO_FILE_plus 和 FILE 统称为 FILE 结构。  
  
## 虚表劫持  
  
通过前面的代码可知，内存中的 stdin 等全局变量存放着 _IO_2_1_stdin_ 等 FILE 结构体的**地址**，而且这个变量本身并不是 const 的，因此可以在运行中修改。攻击者一旦获取到内存任意读写的原语，就可以修改该变量，令其指向攻击者可控的内存中，并在内存里伪造一个 FILE 结构，从而让其中的 vtable 指向我们伪造的地址。最后在执行对应的 IO 操作时触发虚函数调用即可劫持 PC。  
  
有一些细节需要注意，由于我们伪造了整个 FILE 结构，因此其中的每个字段都要保证不会影响正常运行。例如其中的最后一个字段 _IO_lock_t *_lock，需要是一个合法的指针，计数为 0 (表示未被占用)且可以修改，例如:  
```
gef➤  p *stdin._lock
$1 = {
  lock = 0x0,
  cnt = 0x0,
  owner = 0x0
}
```  
## FSOP  
  
上节说到所有打开的 FILE 结构都会被存放到全局的 _IO_list_all 链表里，并通过 _chain 字段作为链表的 next 指针。在 libc 中有个函数 _IO_flush_all_lockp，主要作用是遍历上述链表，并对其中的每个文件执行刷新缓存的操作:  
```
int _IO_flush_all_lockp (int do_lock) {
  int result = 0;
  FILE *fp;

  for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)
    {
      run_fp = fp;
      if (do_lock)
    _IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
       || (_IO_vtable_offset (fp) == 0
           && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                    > fp->_wide_data->_IO_write_base))
       )
      && _IO_OVERFLOW (fp, EOF) == EOF)
    result = EOF;

      if (do_lock)
    _IO_funlockfile (fp);
      run_fp = NULL;
    }

  return result;
}
```  
  
也就是说会调用 vtable->overflow 方法。这个特性的好处是我们可以通过伪造链表的方式进行多次任意调用，从而实现类似 ROP 的调用链构造。当然根据 && 的短路性质，所构造的 FILE 结构需要满足一些前置条件，一般是选择满足前者，即:  
- • fp->_mode <= 0，且  
  
- • fp->_IO_write_ptr > fp->_IO_write_base  
  
因为后者相对复杂且可能会有一些副作用。  
  
_IO_flush_all_lockp 在很多场景下都会被触发，比如:  
- • glibc abort 调用时(malloc_printerr)  
  
- • main 函数返回时  
  
- • 调用 exit 函数时  
  
- • ……  
  
因此可以在很多交互受限的场景下强行触发漏洞。下面是一个 main 函数退出时调用的栈回溯示例:  
```
[#0] → _IO_flush_all_lockp(do_lock=0x0)
[#1] → _IO_cleanup()
[#2] → __run_exit_handlers(status=0x0, listp=<optimized out>, run_list_atexit=0x1, run_dtors=0x1)
[#3] → __GI_exit(status=0)
[#4] → __libc_start_call_main
[#5] → __libc_start_main_impl
[#6] → _start()
```  
## IO_validate_vtable  
  
不管是虚表劫持还是 FSOP，在 glibc-2.24 之后都会遇到一个问题，即引入了针对虚表地址的额外判断:  
```
# define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  uintptr_t ptr = (uintptr_t) vtable;
  uintptr_t offset = ptr - (uintptr_t) __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
```  
  
这是每次在查找虚表函数，即调用 JUMPn 时都会进行的检查，如果虚表地址不在对应段的范围，会额外进行一次 _IO_vtable_check 检查操作，如果不通过的话会直接 __libc_fatal 退出。  
  
额外检查的目的是判断对应的 FILE 结构体是否在动态库的范围内，因为可能用户会跨动态库去调用外部方法。检查的实现主要如下:  
```
void attribute_hidden
_IO_vtable_check (void)
{
  void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
  PTR_DEMANGLE (flag);
  if (flag == &_IO_vtable_check)
    return;

  {
    Dl_info di;
    struct link_map *l;
    if (!rtld_active ()
        || (_dl_addr (_IO_vtable_check, &di, &l, NULL) != 0
            && l->l_ns != LM_ID_BASE))
      return;
  }

  __libc_fatal ("Fatal error: glibc detected an invalid stdio handle\n");
}
```  
  
其中   
PTR_DEMANGLE[2] 是 glibc 中引入的指针加密特性，目的就是为了提高攻击者修改指针劫持控制流的难度。  
  
这个检查有效防止了修改虚函数表进行攻击的手法，因此业内又开始发掘其绕过方式或者其他的漏洞利用路径。  
### 修改数据指针  
  
其中一种方法是不修改虚表，而是通过修改 FILE 结构体中的其他字段实现任意代码读写。其主要思路是通过这些字段扰乱 I/O 函数则正常执行流程。  
  
对于 fwrite 而言，我们可以先将 fileno 改为 1(标准输出)，这样就可以在触发系统调用时将数据返回给我们，关键是如何设置系统调用的参数。在前面我们说过了，触发系统调用是通过虚表的 vtable->write 去实现的，所以我们主要看调用前的代码:  
```
int
_IO_new_file_overflow (FILE *f, int ch) {
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL) {
    // ...
  }
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
             f->_IO_write_ptr - f->_IO_write_base);
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
      return EOF;
  // ...
}
```  
  
_io_do_write/flush 都会将 write_base 至 write_ptr 之间的数据写入到 fp 中，因此只要将其设置为目标地址区间，就可以实现对应地址的信息泄露。不过需要注意的是前面的两个判断需要绕过，以减少调整内部缓存区域引起的副作用。  
  
简单来说，通过修改以下字段即可实现任意内存地址泄露:  
- • _fileno 设为 1；  
  
- • _flag &= ~_IO_NO_WRITES，清除掉读字段，只需要往目标文件写内容；  
  
- • _flag |= _IO_CURRENTLY_PUTTING；添加该字段，绕过 overflow 的条件判断；  
  
- • 设置 _IO_write_base 为想要泄露的起始地址，_IO_write_ptr 为结束地址；  
  
- • 设置 _IO_read_end = _IO_write_base；  
  
最后一项是为了在 do_write 的时候防止 seek 扰乱内存:  
```
static size_t
new_do_write (FILE *fp, const char *data, size_t to_do) {
      size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base) {
        // seek
  }
  count = _IO_SYSWRITE (fp, data, to_do);
  // ...
}
```  
  
同样的思路也可以用在 fread 中实现任意地址写:  
```
size_t _IO_file_xsgetn (FILE *fp, void *data, size_t n) {
    // while (want > 0)
    have = fp->_IO_read_end - fp->_IO_read_ptr;
    if (want <= have) {
        // 直接拷贝缓存到目标地址
    } else {
        // ...
        if (fp->_IO_buf_base
          && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
        {
          if (__underflow (fp) == EOF)
        break;

          continue;
        }
    }
}

int _IO_new_file_underflow (FILE *fp) {
    // ...
    if (fp->_flags & _IO_EOF_SEEN) return EOF;
    if (fp->_flags & _IO_NO_READS) return EOF;
    if (fp->_IO_read_ptr < fp->_IO_read_end)
        return *(unsigned char *) fp->_IO_read_ptr;
    // ...
    count = _IO_SYSREAD (fp, fp->_IO_buf_base,
            fp->_IO_buf_end - fp->_IO_buf_base);
}
```  
  
如果我们想要从标准输入中写入，那么也只需要满足以下条件:  
- • 设置 _fileno 为 0(标准输入)；  
  
- • 设置 _flag &= ~_IO_NO_READS，绕过 underflow 中的判断；  
  
- • 设置 buf_base 和 buf_end 分别为要写入的目标起始和结束地址，即手动指定缓存。注意写入的大小要小于该缓存大小，否则缓存会被刷到 data 中导致写入数据混乱；  
  
- • 设置 read_base = read_ptr = NULL，这也是初次申请完缓存后 _IO_default_setbuf 设置的默认值；  
  
其本质上是手动对缓存进行”创建“，这样在写入伪造缓存的时候也就写到了手动指定的缓存地址，实现任意地址写入。  
### 虚表类型混淆  
  
除了修改数据指针，还有另外一种绕过 vtable check 的方法。既然 vtable 的作用是多态调用，那么肯定不会只有一种实现，事实上也如此。  
  
例如，在 glibc 的代码中，除了 _IO_file_jumps 这个虚表，还有 _IO_str_jumps，属于另外一种 IO 类型 _IO_streambuf，包含在 _IO_strfile_ 结构中:  
```
struct _IO_str_fields
{
  /* These members are preserved for ABI compatibility.  The glibc     implementation always calls malloc/free for user buffers if     _IO_USER_BUF or _IO_FLAGS2_USER_WBUF are not set.  */
  _IO_alloc_type _allocate_buffer_unused;
  _IO_free_type _free_buffer_unused;
};

struct _IO_streambuf
{
  FILE _f;
  const struct _IO_jump_t *vtable;
};

typedef struct _IO_strfile_
{
  struct _IO_streambuf _sbf;
  struct _IO_str_fields _s;
} _IO_strfile;
```  
  
由于 _IO_str_jumps 这个虚表本来就在 glibc 中，因此是可以满足检查的:  
```
const struct _IO_jump_t _IO_str_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_str_finish),
  JUMP_INIT(overflow, _IO_str_overflow),
  JUMP_INIT(underflow, _IO_str_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_str_pbackfail),
  JUMP_INIT(xsputn, _IO_default_xsputn),
  JUMP_INIT(xsgetn, _IO_default_xsgetn),
  JUMP_INIT(seekoff, _IO_str_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_default_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```  
  
如果我们可以修改 stdin/stdout 虚表的值为该虚表地址，那么就可以利用不同的实现方法去构造后续的任意地址读写原语，这对于使用 file_jumps 虚表条件难以满足时可以作为一种迂回的实现方案。这里细节就不展开了，可以参考网上其他的相关文章:  
- •   
FILE Structure Exploitation ('vtable' check bypass)[3]  
  
- •   
glibc 2.24 下 IO_FILE 的利用[4]  
  
除了 str_jumps，其实在 glibc 中存在大量可选的虚表，在 GDB 中列举如下:  
```
gef➤  info variables -t 'struct _IO_jump_t'
All defined variables with type matching regular expression "struct _IO_jump_t" :

File ./libio/fileops.c:
1481:   const struct _IO_jump_t _IO_file_jumps_maybe_mmap;
1457:   const struct _IO_jump_t _IO_file_jumps_mmap;
1432:   const struct _IO_jump_t __GI__IO_file_jumps;

File ./libio/iofopncook.c:
111:    static const struct _IO_jump_t _IO_cookie_jumps;

File ./libio/iopopen.c:
48:     static const struct _IO_jump_t _IO_proc_jumps;

File ./libio/iovsprintf.c:
38:     static const struct _IO_jump_t _IO_str_chk_jumps;

File ./libio/memstream.c:
36:     static const struct _IO_jump_t _IO_mem_jumps;

File ./libio/obprintf.c:
93:     const struct _IO_jump_t _IO_obstack_jumps;

File ./libio/strops.c:
353:    const struct _IO_jump_t _IO_str_jumps;

File ./libio/vsnprintf.c:
67:     const struct _IO_jump_t _IO_strn_jumps;

File ./libio/vswprintf.c:
66:     const struct _IO_jump_t _IO_wstrn_jumps;

File ./libio/wfileops.c:
1071:   const struct _IO_jump_t _IO_wfile_jumps_maybe_mmap;
1047:   const struct _IO_jump_t _IO_wfile_jumps_mmap;
1021:   const struct _IO_jump_t __GI__IO_wfile_jumps;

File ./libio/wmemstream.c:
37:     static const struct _IO_jump_t _IO_wmem_jumps;

File ./libio/wstrops.c:
362:    const struct _IO_jump_t _IO_wstr_jumps;

File ./stdio-common/vfprintf-internal.c:
2203:   static const struct _IO_jump_t _IO_helper_jumps;
```  
  
比如在   
HITCON 2017 : Ghost in The Heap Writeup[5] 中基于 _IO_wstr_jumps 虚表中的 _IO_wstr_finish 方法实现利用。它们原理都是大同小异的，只有一些细节上的差异。  
# 案例分析  
  
本节来介绍几种比较常见的的后利用技巧，虽然大部分都是在堆漏洞的场景下提出的，但其中的一些思路同样也可以适用于其他的漏洞。  
## House of Pig  
  
这是一种针对分配受限情况下堆漏洞的利用方法，源于 **XCTF 2021 final**，因为是 rekapig 战队出的题所以交了这个名字。主要限制是程序使用 calloc 分配内存，不走 tcache 从而无法使用 **tcache stashing unlink attack** 将布局好的 fake chunk 申请出来。  
  
在这种情况下要想继续成功攻击，可以利用 FILE 结构体中的 I/O 缓存特性，在第一次读/写的时候如果缓存没有初始化，会使用 malloc 进行申请。在对虚表的选择上，该利用方法使用了 _IO_str_jumps 作为伪造 FILE 结构的虚表地址，因为 IO_str_overflow 函数内会连续调用 malloc 、memcpy、free，并且这三个函数的参数都可以由 FILE 结构内的数据来控制。  
  
因此只要先在堆上布局好合适的数据，就可以在触发 overflow 调用 malloc、memcpy、free 三连时触发 __free_hook 劫持并触发任意代码劫持。原始题目中因为使用的是 largebin，因此最初是通过 largebin 攻击将堆地址写入到 _IO_list_all 中，最后通过 _IO_flush_all_lockp 去触发 IO_str_overflow 的调用。  
  
具体堆风水细节这里就不展开了，感兴趣的同学可以参考文末的链接。  
## House of Kiwi  
  
虽然现在大多数堆漏洞还是通过修改 __malloc_hook 或者 __free_hook 去实现代码执行，但在新版本的 glibc 中已经去除掉了(这两个符号依然存在，但是相应的 hook 不会被执行)。而且很多程序中还加上了 seccomp 的沙盒，要求只能执行 read/write/open，这又进一步限制了 ROP 执行 shellcode 的能力。  
  
在这种天然或者认为的限制下也就出现了这种漏洞利用方法，出处懒得考究了，也许是出自一位名为 Kiwi 的大佬。总而言之，这种利用方法的主要思路是通过 __malloc_assert 触发 fflush(stderr)，从而调用 _IO_file_jumps.sync 方法。  
  
虽然原文章中所说的将 sync 地址修改为指定地址实现控制流劫持的方法我感觉似乎不可行(定义 const)，但这个通过断言去触发 I/O 刷新的操作还是值得借鉴的。因为我们可以通过堆风水修改 top chunk 大小去主动触发这个断言，配合上其他的操作可以进一步提升内存布局的能力。  
## House of Emma  
  
该漏洞利用方法同样是为了解决在 glibc-2.34 之后取消 malloc/free hook 导致无法劫持控制流的问题。前面说过 FILE 的 vtable 需要在合法范围，也给出了一系列已有的虚函数表定义，但并没说虚函数表就一定要是其中某一个，实际上只要在对应 section 区间内就可以。  
  
因此，该作者提出了**微偏移**的概念，在原有的虚函数表前后进行微小偏移，这样就可以在触发虚函数调用的时候执行该范围内的任意函数。为此选择了 _IO_cookie_jumps 这个虚函数表，并以及其中的 _IO_cookie_read、_IO_cookie_write 等函数为目标，因为其中存在函数指针的使用:  
```
static ssize_t
_IO_cookie_read (FILE *fp, void *buf, ssize_t size)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
  cookie_read_function_t *read_cb = cfile->__io_functions.read;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (read_cb);
#endif

  if (read_cb == NULL)
    return -1;

  return read_cb (cfile->__cookie, buf, size);
}
```  
  
由于 FILE 结构是我们伪造的，因此大部分内容可控，关键是如何绕过 PTR_DEMANGLE 的指针加密保护，这在前面的章节中也说过。但世上没有绝对安全的系统，只不过是投入成本的问题罢了。通过查看对应代码的回报可以发现，PTR_DEMANGEL 主要是将某个 TLS 段的值 ROR 移位后与原指针异或实现的加密。  
```
gef➤  disassemble _IO_cookie_read
   0x00007ffff7e0d7b0 <+0>:     endbr64
   0x00007ffff7e0d7b4 <+4>:     mov    rax,QWORD PTR [rdi+0xe8]
   0x00007ffff7e0d7bb <+11>:    ror    rax,0x11
   0x00007ffff7e0d7bf <+15>:    xor    rax,QWORD PTR fs:0x30
   0x00007ffff7e0d7c8 <+24>:    test   rax,rax
   0x00007ffff7e0d7cb <+27>:    je     0x7ffff7e0d7d6 <_IO_cookie_read+38>
   0x00007ffff7e0d7cd <+29>:    mov    rdi,QWORD PTR [rdi+0xe0]
   0x00007ffff7e0d7d4 <+36>:    jmp    rax
   0x00007ffff7e0d7d6 <+38>:    mov    rax,0xffffffffffffffff
   0x00007ffff7e0d7dd <+45>:    ret
```  
  
因此只要我们可以将这个值泄露出来或者修改为已知值，同样也能绕过指针加密。这样一来就可以伪造 read_cb 函数指针的值，从而实现任意代码执行的目的。  
## House of Bnana  
  
最后一种技巧和 FILE 结构没什么关系，但我觉得很有趣，所以也介绍一下，让大家感受一下世界的参差。这种技巧依赖于 Largebin attack 可以往任一地址写堆地址的能力，主的目标是伪造 ld.so 中的 rtld_global 结构体。我们知道 ELF 中有也有 ctor 和 dtor，主要是可以让动态链接的程序在加载初期和结束前运行指定代码，这种攻击方法就是瞄准了程序结束后执行的 .finit_array 数组，相关代码片段如下:  
```
if (l->l_info[DT_FINI_ARRAY] != NULL)
{
    ElfW(Addr) *array =
    (ElfW(Addr) *) (l->l_addr
            + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
    unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
            / sizeof (ElfW(Addr)));
    while (i-- > 0)
    ((fini_t) array[i]) ();
}
```  
  
如果能够伪造对应的 FINIT_ARRAY，同样也能实现任意代码执行。当然实现上要解决 ld.so 与 libc.so 之间的 ASLR 偏移问题，据说可以通过爆破第二低字节解决，不过笔者只是出于叶公好龙的口嗨状态，还没有实际尝试过，等测试后再回来补充吧。  
# 小结  
  
由于 glibc 中的代码较多，也就给攻击者提供了许多藏污纳垢之地，仅仅是 I/O 这块就包含了各种不同的漏洞利用姿势。但回头来看，IO_FILE 的战场最初是围绕函数指针(虚表)展开的，且随着不断加固，为了绕过又不得不引入复杂的内存布局。放眼未来的话其实可以打开思路，不仅局限于某个特定结构，甚至不必局限于 libc，文末的 Bnana 就是一个很好的示例。相信随着网络安全行业的发展，会涌现出更多的新人才和新思路，当然 CTF 比赛也会更卷一些了 :)  
# 参考文章  
- •   
Play with FILE Structure - Yet Another Binary Exploit Technique[6]  
  
- •   
利用 _IO_FILE 结构 - CTF-All-In-One[7]  
  
- •   
house of pig 一个新的堆利用详解[8]  
  
- •   
House OF Kiwi[9]  
  
- •   
第七届“湖湘杯” House _OF _Emma | 设计思路与解析[10]  
  
- •   
House of Bnana[11]  
  
> **版权声明**: 自由转载-非商用-非衍生-保持署名 (  
CC 4.0 BY-SA[12])**原文地址**: https://evilpan.com/2022/07/30/glibc-exp-tricks/**微信订阅**: **『有价值炮灰[13]』**--   
TO BE CONTINUED.  
  
#### 引用链接  
  
[1] glibc-2.35: https://github.com/bminor/glibc[2] PTR_DEMANGLE: https://sourceware.org/glibc/wiki/PointerEncryption[3] FILE Structure Exploitation ('vtable' check bypass): https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/[4] glibc 2.24 下 IO_FILE 的利用: https://ctf-wiki.org/pwn/linux/user-mode/io-file/exploit-in-libc2.24/#_io_str_jumps-overflow[5] HITCON 2017 : Ghost in The Heap Writeup: https://tradahacking.vn/hitcon-2017-ghost-in-the-heap-writeup-ee6384cd0b7?gi=17a7cf25c698[6] Play with FILE Structure - Yet Another Binary Exploit Technique: https://gsec.hitb.org/materials/sg2018/D1%20-%20FILE%20Structures%20-%20Another%20Binary%20Exploitation%20Technique%20-%20An-Jie%20Yang.pdf[7] 利用 _IO_FILE 结构 - CTF-All-In-One: https://firmianay.gitbooks.io/ctf-all-in-one/content/doc/4.13_io_file.html[8] house of pig 一个新的堆利用详解: https://www.anquanke.com/post/id/242640[9] House OF Kiwi: https://www.anquanke.com/post/id/235598[10] 第七届“湖湘杯” House _OF _Emma | 设计思路与解析: https://www.cnhackhy.com/109829.htm[11] House of Bnana: https://www.anquanke.com/post/id/222948[12] CC 4.0 BY-SA: https://creativecommons.org/licenses/by-nc/4.0/[13] 有价值炮灰: http://t.evilpan.com/qrcode.jpg  
  
