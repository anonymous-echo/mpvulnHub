#  VCTF apple 复现(apple的通用模板)   
ElegyYuan0x1  看雪学苑   2024-05-28 17:59  
  
本文参考的是Arahat0师傅（https://passport.kanxue.com/user-center-964693.htm）的脚本，这里主要介绍一下vctf apple的house of apple部分的思路。与常规的house of apple不同，这里将_wide_data指向劫持的FILE结构体加减偏移，来让脚本更加可以移植，最后实现栈迁移打ROP链的操作。  
  
  
前情提要：要结合上一篇文章：vctf apples leak libc操作复现（https://bbs.kanxue.com/thread-281083.htm）来观看。在上一篇文章中我们通过较为复杂的overlapping实现了heap和libc的泄露，接下来我们通过劫持结构体来实现一次House of apple2的变形。  
  
## 条件  
  
◆泄露libc地址和堆地址  
  
◆能劫持stdout  
结构体实现对stdout  
结构体的覆写  
  
◆能触发puts函数  
  
## 属性的偏移  
  
  
```
```  
  
##   
## 各大结构体  
> 建议和上面的偏移结合起来看 还是比较详细的  
  
  
```
```  
  
##   
## exp中伪造  
> 先这里给出exp中伪造的stdout  
结构体 方便我们后面分析  
  
  
```
```  
  
##   
## 动调  
  
  
目的：通过puts函数触发_IO_wfile_overflow  
函数来调用_IO_wdoallocbuf  
函数。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKOFClNXBEWWNG7FIMh2EPGlZbZGEia5ygb6pEVlXB5VGtDDApOTaZr1icicPnb14nA8ojicxxib5eVQ/640?wx_fmt=png&from=appmsg "")  
###   
### 正常的调用链  
> 为了搞清楚劫持原理 这里我们分析puts函数的源码  
  
  
  
◆puts中调用_IO_file_xsputn  
（stdout->vatble(0xd8)->_IO_file_xsputn(0x38)）  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8Fm3n45HQMibjRgibGmXT4C1sVH2l5ib3GAVRcOOHQaZuIBklkA3AbalNED3e9UlejbUatM3FmRXRUAQ/640?wx_fmt=jpeg&from=appmsg "")  
- r14此时为 也就是_IO_file_jumps+0x38的位置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Fm3n45HQMibjRgibGmXT4C1sShgvMc6xDeeE2mTrLiaGtic3EyfWicZWhuVEz34wOqUJ62ZYQ8F7Hicm5Q/640?wx_fmt=png&from=appmsg "")  
  
- 而r14是通过mov r14, [rdi+0D8h]取出来的 rdi为_IO_2_1_stdout_ 根据0xd8偏移可以知道是vatble属性  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Fm3n45HQMibjRgibGmXT4C1sLd7TVMwpgW1nqguv3ibwzSvNk5TosRMXU9iam0poABOJsR2TM7uEYduw/640?wx_fmt=png&from=appmsg "")  
  
◆然后调用_IO_file_overflow  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Fm3n45HQMibjRgibGmXT4C1siaXMDIAzTrafF5qeyxcTlslQFdVVVrV9mzJaDkS5Wf7unpQL8f9wq2w/640?wx_fmt=png&from=appmsg "")  
  
  
◆然后走向_IO_do_write  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Fm3n45HQMibjRgibGmXT4C1sVJU3ag0yFu2UQvDrCeaxjqCmcOSGkMCkvWM3MutPIpAgEf0j8vdvCw/640?wx_fmt=png&from=appmsg "")  
  
### _IO_wfile_jumps结构体  
> 所以要调用_IO_wfile_overflow  
则需要vatble+0x38位置为_IO_wfile_jumps  
+24 所以这里控制vtable为_IO_wfile_jumps  
-0x20  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EsKOFClNXBEWWNG7FIMh2EH1km9sBuicrHx8UbI1iaKldj1y1Tc4YWAYtxRQh257KP71cMJntFOrUw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
```
```  
  
###   
### _IO_wfile_overflow函数  
> 我们最终是想要调用_IO_wdoallocbuf  
函数  
  
  
```
```  
  
  
  
◆所以我们需要满足条件:  
- f->_flags & _IO_NO_WRITES为0  
  
- (f->_flags & _IO_CURRENTLY_PUTTING) == 0  
  
- 也就是_flags位置为0  
  
- f->_wide_data(0xa0)->_IO_write_base(0x20) == 0  
  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8Fm3n45HQMibjRgibGmXT4C1slzQ58Ede5QCAD0ZpRLFibef2sfSAHxxyYnsnJGmzFR2AHa9TgtMvUcg/640?wx_fmt=jpeg&from=appmsg "")  
  
### _IO_wdoallocbuf函数  
  
  
```
```  
  
  
  
◆这里我们要执行_IO_WDOALLOCATE  
从而调用我们伪造的函数 所以我们这里需要过掉保护fp->_wide_data->_IO_buf_base  
和!(fp->_flags & _IO_UNBUFFERED)  
  
  
也就是_wide_data(0xa0)的_IO_buf_base(0x38)偏移位置要为0。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Fm3n45HQMibjRgibGmXT4C1sbPznLtP4d5HXia63rMvVnDXOB6fy3HEwUF2OD3pS29to4G71zj9eHwg/640?wx_fmt=png&from=appmsg "")  
  
### 触发_IO_WDOALLOCATE(fp)  
> 这里等效为: *(fp->_wide_data(0xa0)->_wide_vtable(0xe0) + 0x68)(fp)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EsKOFClNXBEWWNG7FIMh2ESlic8sNfvHCiaJsQp9wVtNxrobPR05YUaeqngiafoqrQrXxtTAIbrMI2Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
◆所以最终就成功调用leave retn指令  
  
### 栈迁移  
  
  
◆我们先看汇编代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Fm3n45HQMibjRgibGmXT4C1sf7Msezx64MgYSKJA7fXCyicE0fHRBmLvsfkI0yzNtTdSiaufrQkTKQNA/640?wx_fmt=png&from=appmsg "")  
  
  
◆可以看见这里把rdi  
赋值给了rbx  
而根据前面代码可以知道rdi是_io_wdoallocbuf  
的参数 也就是fp也就是_IO_2_1_stdout_。  
  
  
◆那么回顾我们前面的payload：  
```
FILE.flags = 0
FILE._IO_read_ptr = pop_rbp
FILE._IO_read_end = heap_addr + 0x470 - 8
FILE._IO_read_base = leave_ret
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Fm3n45HQMibjRgibGmXT4C1sWJ5vrazyOlfiauOI8zxDyPsbxr6m7velq116ejdXwDicBiakdMqAFGtcQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
◆然后我们pop_rbp  
让rbp  
变成我们存放payload的chunk内容然后再通过leave ret让rsp也移动到我们的chunk上 实现栈迁移 然后我们就可以愉快打rop链了  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKOFClNXBEWWNG7FIMh2EG7uCwlZEnia3YtAsDD8VHuLHrzz5miaEtk88ibrPk9LgB1eQyGyuj017g/640?wx_fmt=png&from=appmsg "")  
  
  
**看雪ID：ElegyYuan0x1**  
  
https://bbs.kanxue.com/user-home-994584.htm  
  
*本文为看雪论坛优秀文章，由 ElegyYuan0x1 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458555478&idx=4&sn=38146de9a7a584161a06f014190cb022&chksm=b18da4dc86fa2dca63448e856d2ed80df466d8d89a05a7b600b5a6c5ff87fdd71398f0881a6f&scene=21#wechat_redirect)  
  
  
  
**# 往期推荐**  
  
1、[unidbg入门笔记](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458555584&idx=1&sn=56b29f4ca00b49d9a5241b81aec13464&chksm=b18da44a86fa2d5c5312d8cd993dc765670b71c09e4523c3e79ba6baa32ff5e07b75d168a327&scene=21#wechat_redirect)  
  
  
2、[Frida 过检测通用思路之一](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458555503&idx=1&sn=78655315206fbf7f6c3765a7dcf21f3e&chksm=b18da4e586fa2df384619515298ebb8f31153e5dcee07c20f28fa499498ec63269ce32af9600&scene=21#wechat_redirect)  
  
  
3、[CVE-2017-11882分析和白象样本分析](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458555501&idx=1&sn=99d873c7182ecf50f6f4ad61c5f952d6&chksm=b18da4e786fa2df12fc2fe09361c04bf702deacb01323b49385ac6a4fc742944cef028f67a69&scene=21#wechat_redirect)  
  
  
4、[记录一次鹅厂反作弊绕过之利用回调完成异常派遣的提前接收](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458555478&idx=1&sn=307530f8457e936017e693aeec6fbd54&chksm=b18da4dc86fa2dca62fda424eba125a4275a2093e83ed8d169220a4a83a1b246e1f96eb18b44&scene=21#wechat_redirect)  
  
  
5、[H&NCTF RE 部分题解](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458555351&idx=1&sn=9007d8bad102e4aa338c6d7104bd1ffd&chksm=b18da35d86fa2a4b4e4a1e5605da8f45a837c1e2f7ba3edc676af5f841e5ebe0a667e3a2111c&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GJubmq65v9uBFmEJuoJD78321RiaLpp3FAylJv0nbibloCFmXdVe4wvW4ibgnCc6srNI8sGBkX14MpQ/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GJubmq65v9uBFmEJuoJD78321RiaLpp3FAylJv0nbibloCFmXdVe4wvW4ibgnCc6srNI8sGBkX14MpQ/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GJubmq65v9uBFmEJuoJD78321RiaLpp3FAylJv0nbibloCFmXdVe4wvW4ibgnCc6srNI8sGBkX14MpQ/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GJubmq65v9uBFmEJuoJD78txPhfvI9WpuGSCawCN8NJCgzD16Y0IwdUkaI33Qr3DpwRRuvibgRQOg/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
