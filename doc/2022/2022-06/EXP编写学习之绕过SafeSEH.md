#  EXP编写学习之绕过SafeSEH   
yumoqaq  看雪学苑   2022-06-21 18:20  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EXiaaJdNyYhHcc0b2FGBewUKDEDqY6iczGm7CcdwIOmxiaJZ0ibKPKzhqScOHWZr0MDLbQKibqaCPXQFQ/640?wx_fmt=jpeg "")  
  
本文为看雪论坛优秀文章看雪论坛作者ID：yumoqaq  
  
  
  
1  
  
  
**亡羊补牢 ：SafeSEH**  
##   
## SafeSEH对异常处理的保护原理：  
##   
## 编译选项/SafeSEH启动，VS2003以后默认启用。  
##   
## 生成SafeSEH表，放在PE文件中，调用异常处理函数的时候，将地址与SafeSEH表中的地址比较。  
##   
## 检查异常处理链是否位于当前程序的栈中，如果不在栈中，则程序终止异常处理函数的调用。  
##   
## 检查异常处理函数指针是否在程序的栈中，如果指向当前栈中，则终止异常处理函数的调用。  
##   
## 前面两项检查都通过后，程序调用一个全新的函数 RtlIsValidHandler ，对异常处理函数的有效性进行验证。  
##   
## RtlIsValidHandler检测原理：  
  
  
首先，该函数判断异常处理函数地址是不是在加载模块的内存空间，如果属于加载模块的内存空间，校验函数将依次进行如下校验：  
  
   
  
（1）判断程序是否设置了IMAGE_DLLCHARACTERISTICS_NO_SEH 标识。如果设置了这个标识，这个程序内的异常会被忽略。所以当这个标志被设置时，函数直接返回校验失败。  
  
（2）检测程序是否包含安全S.E.H 表。如果程序包含安全S.E.H 表，则将当前的异常处理函数地址与该表进行匹配，匹配成功则返回校验成功，匹配失败则返回校验失败。  
  
（3）判断程序是否设置ILonly 标识。如果设置了这个标识，说明该程序只包含.NET 编译人中间语言，函数直接返回校验失败。  
  
（4）判断异常处理函数地址是否位于不可执行页（non-executable page）上。当异常处理函数地址位于不可执行页上时，校验函数将检测DEP 是否开启，如果系统未开启DEP 则返回校验成功，否则程序抛出访问违例的异常。  
  
   
  
如果异常处理函数的地址没有包含在加载模块的内存空间，校验函数将直接进行DEP 相关检测，函数依次进行如下校验：  
  
   
  
（1）判断异常处理函数地址是否位于不可执行页（non-executable page）上。当异常处理函数地址位于不可执行页上时，校验函数将检测DEP 是否开启，如果系统未开启DEP 则返回校验成功，否则程序抛出访问违例的异常。  
  
（2）判断系统是否允许跳转到加载模块的内存空间外执行，如果允许则返回校验成功，否则返回校验失败。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HoL8rWLfqC4l5ibczH6C2H45YBj24PsdwR1JlO0CqopIZqTicLgicqRVjNNZMRWPXSI2PZ6TENSibHmw/640?wx_fmt=png "")  
##   
## RtlIsValidHandler允许异常函数执行的情况  
  
  
1）异常处理函数位于加载模块内存范围之外，DEP 关闭。  
  
2）异常处理函数位于加载模块内存范围之内，相应模块未启用SafeSEH（安全S.E.H 表为空），同时相应模块不是纯IL。  
  
3）异常处理函数位于加载模块内存范围之内，相应模块启用SafeSEH（安全S.E.H 表不为空），异常处理函数地址包含在安全SEH表中。  
  
   
  
分析一下这三种情况的可行性。  
  
（1）现在我们只考虑SafeSEH，不考虑DEP。排除DEP 干扰后，我们只需在加载模块内存范围之外找到一个跳板指令就可以转入shellcode 执行，这点还是比较容易实现的。  
  
   
  
（2）在第二种情况中，我们可以利用未启用SafeSEH 模块中的指令作为跳板，转入shellcode执行，这也是为什么我们说SafeSEH 需要操作系统与编译器的双重支持。在加载模块中找到一个未启用的SafeSEH 模块也不是一件很困难的事情。  
  
   
  
（3）这种情况下我们有两种思路可以考虑，一是清空安全S.E.H 表，造成该模块未启用SafeSEH 的假象；二是将我们的指令注册到安全S.E.H 表中。由于安全S.E.H 表的信息在内存中是加密存放的，所以突破它的可能性也不大，这条路我们就先放弃吧。  
  
## 利用SafeSEH的缺陷  
  
  
利用S.E.H 的终极特权！这种安全校验存在一个严重的缺陷——如果S.E.H 中的异常函数指针指向堆区，即使安全校验发现了S.E.H 已经不可信，仍然会调用其已被修改过的异常处理函数，因此只要将shellcode 布置到堆区就可以直接跳转执行！  
  
## 绕过SafeSEH  
  
  
1.攻击返回地址绕过  
  
   
  
2.虚函数绕过  
  
   
  
3.从堆中绕过 ：shellcode布置在堆中 ，SEH处理函数指向这个地址即可  
  
   
  
4.利用未启用SafeSEH模块绕过 ：可以把这个模块的指令作为跳板，去执行shellcode  
  
   
  
5.加载模块之外的地址绕过 ：内存中有一些Map类型的映射文件，在这些文件中找到跳板指令覆盖SEH处理函数地址即可绕过  
  
   
  
6.利用未启用SafeSEH的控件，且控件包含溢出漏洞可以被触发（IE浏览器控件）  
  
  
  
2  
  
  
**实践利用加载模块之外的地址**  
  
  
1.我们使用上一篇中的代码，稍微修改来测试，关闭GS DEP ASLR， 开启 SafeSEH ，如果你有VC6 ，最好使用它来编译。  
```
#include <stdio.h>
#include <Windows.h>
 
int zero = 0;
 
int MyException()
{
    printf("Error OverFlow %d\n", zero);
    return 1;
}
 
void __stdcall test(char* str, char* out)
{
    char buf[0x500] = { 0 };
 
    __try
    {
        strcpy(buf, str);
        zero  = 1 / zero;
 
    }
    __except (MyException())
    {
 
    }
}
 
 
int main(int arc, char** argv)
{
    char buf1[200];
    test(argv[1], buf1);
    return 0;
}
```  
  
  
2.先用IDA查看一下代码，因为我用VS2019编译， 编译器会扩展SEH。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HoL8rWLfqC4l5ibczH6C2H4GEAykPBkErhygmX4vib185qk1pyKmYCxehq1sX2VEiaNOpOLPyiafro5w/640?wx_fmt=png "")  
  
可以看到， 这里使用了第3代的异常处理模型 ，往栈中放入了不少东西，会影响我们的偏移。  
  
   
  
用od插件搜索一下，都开启了SafeSEH保护。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HoL8rWLfqC4l5ibczH6C2H4rQOrJ9nEuEnWmvHZ7UJaLpLIHCOGCoJZcKbh9qkD9kribv7ejXo5A8w/640?wx_fmt=png "")  
  
   
  
3.调试一下看看，可以看到，输入0x500个字节的A后， 还差12个字节才可以覆盖到Handler。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HoL8rWLfqC4l5ibczH6C2H4DTFXfV7YxxhVQd3ic2EpSicFoFlvOiauQBNlunG3RYc8TGI6ibGiaH8MpIA/640?wx_fmt=png "")  
  
修改参数 ，再次调试查看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HoL8rWLfqC4l5ibczH6C2H4jDibc9cc1jykEGsoVExwWJZ3J51guI5cQyUmb7UI6enAj9liblia1kyWg/640?wx_fmt=png "")  
  
好的，现在可以看到，Handler已经被覆盖为 C ， 那么现在需要找到跳板地址来跳到shellcode。  
  
   
  
之前已经看过，所有模块都启用了SafeSEH，那么我们需要找到加载模块之外的跳板地址，内存映射查看 MAP类型的地址。  
  
   
  
那么我们需要什么样的跳板指令呢？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HoL8rWLfqC4l5ibczH6C2H4ib45bgUwXSseD1dbAy0S1JibdJfHSEjDUOkmFKeoaTPDmZPM7doibjflQ/640?wx_fmt=png "")  
  
   
  
观察寄存器，发现eax指向我们溢出的缓冲区，那么是否可以利用 jmp eax ， call eax，来跳转到shellcode执行（答案是不行，eax是一个易失寄存器，在转到异常处理函数的过程中会被修改）。  
  
   
  
好的， Next先不管，Handler需要什么样的跳板指令呢，按照之前利用SEH的总结， 我们需要 pop pop ret指令。  
  
   
  
随便填写一个地址测试是否成功转到该地址 ，我们在MAP类型内存映射中，找到了 0x7FFA5BE8地址，7FFA2017 它的指令是 jmp eax。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HoL8rWLfqC4l5ibczH6C2H4zUOStqEv8fZbRsVXUPdLypBhmhZGfleQwNBX72KjMMU1xNIM2B0s4A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HoL8rWLfqC4l5ibczH6C2H4iaA9K05G5rohPhQTrwsks0PySCgEQYZYYXsKy4hkn5pNX3My8paq6ibQ/640?wx_fmt=png "")  
  
好的，修改Handler为这个地址， 看一下是否可以转到这个地址执行 ，答案是可以，但是无法下断跟踪（且提示访问0地址）。  
  
   
  
之后我又选择了一个 pop ret指令的地址， 没办法，只能找到这个指令了，推算一下， 也就是 jmp [esp+4]。  
  
   
  
根据微软的解释 EstablisherFrame 是此函数的固定堆栈分配的基地址 ，也就是我们得到的地址是 系统设置的异常处理函数的ebp（好吧，日后详细研究一下）。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HoL8rWLfqC4l5ibczH6C2H4OIH6ojiaRibTichaDACIbzQXEOAxc3bzey6ibDWjbxYlDdYu5HyQOqV1ZQ/640?wx_fmt=png "")  
  
   
  
好的好的，可以看到程序已经转到栈上执行，如果有合适的跳板指令可以利用（没办法了，我使用win10进行测试）。  
  
  
  
3  
  
  
**结语**  
  
  
1.可以看到限制我们进行漏洞利用的因素有很多，我们不得不研究新的手段来对抗微软的保护机制。  
  
   
  
2.经过测试，如果你不是使用加载模块地址之外的地址，确实会与safeSEH表来进行对比，会提示异常 无效的异常处理程序。  
  
   
  
3.经过这次实践，碰到了各种各样的问题，此时才能理解前人的智慧，不得不佩服。  
#   
#   
# 参考资料  
  
  
0day2  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HoL8rWLfqC4l5ibczH6C2H4zeGib366QJZluyic2QeW1dPpXyvoEQC9VxYbdg8f972zQOCRv2NWaHIA/640?wx_fmt=png "")  
  
  
**看雪ID：yumoqaq**  
  
https://bbs.pediy.com/user-home-930159.htm  
  
*本文由看雪论坛 yumoqaq 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458447393&idx=5&sn=6d82ff01f82a6dda33188cdc22938983&chksm=b18fdeab86f857bd3804504bd2add426b5a0a678624e2f06f04d2e5b4d7df7216e5831e5e8cd&scene=21#wechat_redirect)  
  
  
  
**#****往期推荐**  
  
1.[CVE-2016-0165提权漏洞学习笔记](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458453618&idx=2&sn=dba42df66438701cda904d463e51e760&chksm=b18e36f886f9bfeefd2de981ac20b75516801e14ee248a182751e0b64855fe6df533fe2c4a41&scene=21#wechat_redirect)  
  
  
2.[Fuzzm: 针对WebAssembly内存错误的模糊测试](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458451152&idx=2&sn=4abbf7a643b93027529e12442608aca2&chksm=b18fcc5a86f8454cb6051aab6a45751ad736285e3f46e92436edb2b963b46bee27da5e0c9922&scene=21#wechat_redirect)  
  
  
3.[0rays战队2021圣诞校内招新赛题解](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458449944&idx=2&sn=1c51b842fd748e55cbe2cbf80f8371f2&chksm=b18fc89286f84184d536aaa1cad66bce9fb3799ef344b743ab5b3b02e89f2336ab6977cfbe2c&scene=21#wechat_redirect)  
  
  
4.[2022腾讯游戏安全初赛一题解析](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458449720&idx=1&sn=d3e33c568fee745ef1ad6334443c2eac&chksm=b18fc7b286f84ea479599f079963ab9b9e199717629c8d0636cd87341b552823a01f995a18c3&scene=21#wechat_redirect)  
  
  
5.[一文读懂PE文件签名并手工验证签名有效性](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458449573&idx=1&sn=cfab5d8030041ed7d6d4ed0eb84619fc&chksm=b18fc62f86f84f3901d3bfa087c6b0ceb1882ad1682d155e01107cc4b0d09c8359445c624a84&scene=21#wechat_redirect)  
  
  
6.[CNVD-2018-01084 漏洞复现报告（service.cgi 远程命令执行漏洞）](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458446970&idx=1&sn=fe5fd9a5dd5b284114eec6b391c0ac1a&chksm=b18fdcf086f855e6357dc286aabe7a97b9cb48214018c7f316f59e2a95c2ce982efe6167c773&scene=21#wechat_redirect)  
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
