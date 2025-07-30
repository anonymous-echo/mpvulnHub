#  难以想象的芯片UAF漏洞，Zenbleed漏洞分析   
原创 张一白  华为安全应急响应中心   2023-11-24 18:10  
  
**1**  
  
简介  
  
  
  
Zenbleed  
是一个在  
AMD Zen2  
架构上的指令集漏洞，这个漏洞也是由预测执行产生的。但相对于  
Spectre  
漏洞，  
Zenbleed  
并不需要时间侧信道，攻击方法也远比  
Spectre  
简单。这个漏洞更类似于常规程序中由  
malloc/free  
导致的  
UAF  
问题。  
  
  
  
**2**  
  
了解  
x86 simd  
指令  
  
  
随着对  
CPU  
计算性能需求的增长，  
x86  
处理器引入了  
 MMX,SSE,AVX   
等  
SIMD  
指令，也加入了用于这些指令的专用寄存器  
 MM  
，  
XMM  
，  
YMM  
，  
ZMM  
。在  
Zen2  
架构中，对这类指令最高支持到  
AVX2  
，寄存器最大是  
256bit  
的  
YMM  
系列寄存器。  
  
这里要注意，  
MM  
，  
XMM  
，  
YMM  
的关系就像  
 ax  
，  
eax  
，  
rax  
一样，  
MM0  
是  
XMM0  
和  
YMM0  
的  
64bit  
低位，  
XMM0  
是  
YMM0  
的  
128bit  
低位，它们并不是独立的寄存器。  
  
在程序中，这些寄存器不仅是用来进行数据计算，也用于加速诸如  
strcmp, memcpy, strlen  
等标准库函数。  
  
比如在  
glibc  
中，就有如下使用  
AVX2  
指令优化的  
strcmp  
：  
```
(gdb) x/20i __strlen_avx2...   <__strlen_avx2+9>:   vpxor  xmm0,xmm0,xmm0...   <__strlen_avx2+29>:  vpcmpeqb ymm1,ymm0,YMMWORD PTR [rdi]   <__strlen_avx2+33>:  vpmovmskb eax,ymm1...   <__strlen_avx2+41>:  tzcnt  eax,eax   <__strlen_avx2+45>:  vzeroupper   <__strlen_avx2+48>:  ret
```  
  
  
  
第一段vpxor xmm0,xmm0,xmm0  
将清空整个  
ymm0  
寄存器  
(  
写入  
XMM  
寄存器将自动清空  
YMM  
的高位  
)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9eicDVDMxEQQicK7EEt1I5JIicvOMct6RrwqSs8hCuD1366SX4arqAqgLgtwAdmHmMAyebC7sIeqw9hqHIPJsNQ/640?wx_fmt=png&from=appmsg "")  
  
图片来源：  
https://lock.cmpxchg8b.com/zenbleed.html  
  
第二段vpcmpeqb ymm1, ymm0, [rdi]  
将  
rdi  
指向的内存  
32  
字节与  
YMM0  
比较，比较的结果存入  
YMM1  
中。相同的字节会被设置成  
0xFF  
，不同的字节会被设置成  
0x00  
。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9eicDVDMxEQQicK7EEt1I5JIicvOMct6RAh8iaooHmL9cXb9Rh8Tc9MvXNLGVMqXOibw81jLvBYMCjWiaPSTjSXeCQ/640?wx_fmt=png&from=appmsg "")  
  
图片来源：  
https://lock.cmpxchg8b.com/zenbleed.html  
  
  
随后vpmovmskb eax, ymm1  
将  
ymm1  
中保存的结果转存到  
eax  
中，  
ymm1  
中每一个不为  
0x0  
的字节将设置  
eax  
对应的比特位为  
1  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9eicDVDMxEQQicK7EEt1I5JIicvOMct6RvicicUZYULDaROcuicaevmmSdTGzMIYYibGiaOWOnBI4WToWatQ4t7rT4qg/640?wx_fmt=png&from=appmsg "")  
  
图片来源：  
https://lock.cmpxchg8b.com/zenbleed.html  
  
最后判断字符串的长度，我们就只需要数出来  
eax  
中有多少个前导为  
0  
的  
bit  
。tzcnt eax, eax  
就正好是做这个的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9eicDVDMxEQQicK7EEt1I5JIicvOMct6RIcnl0DOdxVwx9chzEefkSW5ldaThCjGjVdL7vBYdfphAVaguDUnofQ/640?wx_fmt=png&from=appmsg "")  
  
图片来源：  
https://lock.cmpxchg8b.com/zenbleed.html  
  
这段代码还执行了vzeroupper  
，用于清空所有  
YMM  
寄存器的高  
128bit  
，同时也可以避免在从  
VEX  
模式切换到  
non-VEX  
模式带来的性能损失。因此，他出现在了这段代码的末尾。  
  
  
  
**3**  
  
问题所在  
  
我们看到上面有多个清空  
YMM  
高  
128  
位的操作，但  
CPU  
是怎么完成这个操作的呢？  
  
在  
CPU  
中，每个寄存器并非一个独立的存储空间，而是利用  
 **寄存器分配表（****Register Allocation Table****）**  
   
和  
 **寄存器文件（****Register File****）**  
。寄存器文件类似于一个数组，每一个元素存储着一个寄存器的值，而寄存器分配表会存储寄存器名称和寄存器文件数组下标的关系。  
  
当我们清空某个寄存器时，  
CPU  
并不会去清空寄存器文件中实际存储的值，而是设置寄存器分配表中的  
z-bit,   
或者说将寄存器分配表标记为未分配。这个  
flag  
可以独立地被设置于  
YMM  
的高  
128  
位和低  
128  
位（也就是  
XMM  
）。所以在vzeroupper  
执行时，  
CPU  
会释放寄存器文件中对应的表项，并将寄存器分配表对应项设置为  
0  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9eicDVDMxEQQicK7EEt1I5JIicvOMct6RSWYsnDQ2bqw65Hc9e2cCpRP7nIiciabr933uFtjlFPz0EShDFtOmPQEA/640?wx_fmt=png&from=appmsg "")  
  
图片来源：  
https://lock.cmpxchg8b.com/zenbleed.html  
###   
###   
  
但是，为了充分利用流水线，我们的  
CPU  
现在都有一个叫  
 **投机（预测）执行**  
   
的功能。如果  
CPU  
投机执行了vzeroupper  
，但是后续发现预测错误，这时候该怎么办呢？最简单的办法就是直接将设置的  
z-bit  
去掉，让寄存器分配表表项重新映射到原来的寄存器文件表项上。  
  
But wait  
…如果这时候另一个  
CPU  
核已经占用了这个表项  
那会怎么样呢？  
?  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/Pf9eicDVDMxEQQicK7EEt1I5JIicvOMct6RChGlCyCvoT8OYOuVSgVJOFLXuGSJicesDhARG6DnNsUBuicbvbN1BzrQ/640?wx_fmt=gif&from=appmsg "")  
  
图片来源：  
https://lock.cmpxchg8b.com/zenbleed.html  
  
UAF triggered！  
  
  
**4**  
  
漏洞  
  
  
部分  
AMD Zen2 CPU  
在从错误投机的vzeroupper  
指令回滚状态时，可能会出现上述的错误。受影响的至少包括以下产品  
:  
-       
AMD
Ryzen 3000 Series Processors  
  
-     AM  
D
Ryzen PRO 3000 Series Processors  
  
-       
AMD
Ryzen Threadripper 3000 Series Processors  
  
-       
AMD
Ryzen 4000 Series Processors with Radeon Graphics  
  
-       
AMD
Ryzen PRO 4000 Series Processors  
  
-       
AMD
Ryzen 5000 Series Processors with Radeon Graphics  
  
-       
AMD
Ryzen 7020 Series Processors with Radeon Graphics  
  
-     AMD
EPYC   
“  
Rome  
”  
 Processors  
  
首先我们需要触发  
 **XMM****寄存器合并优化（****XMM Register Merge Optimization****）**  
   
然后再来个寄存器重命名，最后再整个错误预测的vzeroupper  
。只要精细的控制时间窗就能触发这个漏洞。  
  
由于一些基础的操作，比如  
strlen  
，  
memcpy  
，  
strcpy  
都使用了这类  
simd  
寄存器进行性能优化，所以我们可以利用这个漏洞有效的监控系统中发生的这些行为，而且无论是发生在虚拟机、沙箱、容器、进程中。  
  
因为同一个寄存器文件是被同一个物理核中的所有寄存器共享的，甚至两个超线程核都是共享的同一个寄存器文件。  
  
  
**5**  
  
复现  
  
  
复现这个问题的方式有很多，我们可以看一个很简单的例子  
:  
```
    vcvtsi2s{s,d}   xmm, xmm, r64
    vmovdqa         ymm, ymm
    jcc             overzero
    vzeroupper
overzero:
    nop
```  
  
  
cvtsi2sd   
是用来触发寄存器合并优化的，它实际做了啥并不重要，任何可以触发寄存器合并优化指令都可以。然后我们用  
vmovdq  
触发寄存器重命名，然后用一个条件跳转让  
cpu  
预测错误，投机执行vzeroupper  
但随后回滚操作，就可以触发这个问题了。  
  
触发后，我们就能直接从  
ymm  
寄存器中，读出别的程序可能正在处理的数据。  
  
实际的  
复现  
比这个复杂一些，可以后台索要附件查看。最终，原作者实现了可以泄露  
30kb  
每核每秒的能力，这个速度足以监控一些密钥和密码信息。  
  
  
**6**  
  
修复  
  
  
AMD  
已经提交了最新的微码，  
linux  
用户更新  
linux-firmware  
即可。你的主板厂家也应该会放出含有最新微码的  
BIOS/UEFI  
，请及时更新。  
  
如果暂时无法更新，可以修改DE_CFG[9]  
来规避，在  
linux  
上，使用以下命令即可。  
```
# wrmsr -a 0xc0011029 $(($(rdmsr -c 0xc0011029) | (1<<9)))
```  
  
  
但这个会带来性能损失。  
  
  
**7**  
  
检测  
  
  
没有什么好的办法检测和识别此类攻击的存在，因为它不需要任何的权限或特殊系统调用。当然我们也绝对不能通过检查vzeroupper  
的调用来判断，它的使用实在是太广泛了。  
  
  
**8**  
  
结论  
  
  
内存管理在哪儿都很难，即使是在芯片中。  
  
  
**9**  
  
参考阅读  
  
  
寄存器文件：  
https://zh.wikipedia.org/wiki/  
寄存器堆  
  
寄存器重命名：  
https://zh.wikipedia.org/wiki/  
寄存器重命名  
  
XMM  
寄存器合并优化：  
https://www.amd.com/en/server-docs/software-optimization-guide-for-amd-epyc-7003-processors-zip-format ,
section 2.11.5  
  
  
**备注：**  
  
**本文绝大多数内容翻译自漏洞发现者的博客原文，本人翻译能力有限，读者感兴趣的话阅读原文可获得更清晰的理解。https://lock.cmpxchg8b.com/zenbleed.html**  
  
****  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI0MTY5NDQyMw==&mid=2247489220&idx=1&sn=aceaf6ab392674653be3a310c1bbb18c&chksm=e906f57cde717c6a639d2e82dd5a0d306dd34aaf9fb2874ddacfcf3468e04eb950c8fa846392&scene=21#wechat_redirect)  
  
[华为终端安全奖励计划|漏洞奖金翻倍活动强势回归--更高奖金，更多守护](http://mp.weixin.qq.com/s?__biz=MzI0MTY5NDQyMw==&mid=2247497222&idx=1&sn=966f8b52c5a6613b13fe5f26a3c99740&chksm=e90515bede729ca8d3d031e9d7be5d951f42835ef78e18577e5266d8302c5fc07a9896c537a5&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzI0MTY5NDQyMw==&mid=2247489220&idx=1&sn=aceaf6ab392674653be3a310c1bbb18c&chksm=e906f57cde717c6a639d2e82dd5a0d306dd34aaf9fb2874ddacfcf3468e04eb950c8fa846392&scene=21#wechat_redirect)  
  
  
["最新奖励计划"正式发布！！](http://mp.weixin.qq.com/s?__biz=MzI0MTY5NDQyMw==&mid=2247496664&idx=1&sn=9419efe55cff61c1f02e3e858ea65ea5&chksm=e9051060de729976e7e769a41c22785a9cd9f1e285d29223a6d195e6f296bb759cdf06986308&scene=21#wechat_redirect)  
  
  
[关于CVSS V4.0，你想知道的都在这了！](http://mp.weixin.qq.com/s?__biz=MzI0MTY5NDQyMw==&mid=2247502286&idx=1&sn=445e9142ca70af759be30d4f8671e2a9&chksm=e9052a76de72a360ff0db518e5e91aff618a06bef5e9d337935a4d79c4954014f74ec199dc89&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzI0MTY5NDQyMw==&mid=2247484735&idx=1&sn=4b003a3c5c8d711511b40d5f45437d22&chksm=e906e687de716f91b41b97daf76519d78cd81c19b4b4c330bbddf9105e4e5e3f0f74ebfeaffa&scene=21#wechat_redirect)  
  
  
  
点这里![](https://mmbiz.qpic.cn/mmbiz_gif/MfTd6rd9CyvNRMW8I9cvI1CK5gKiaYqg2veTn9t9dAe1GxYic7pAvgvRIKNFickConFyX8AvW2reAq8GchJI6aBpA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
关注我们，一键三连～  
  
  
