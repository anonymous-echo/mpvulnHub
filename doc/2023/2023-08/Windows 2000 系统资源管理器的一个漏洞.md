#  Windows 2000 系统资源管理器的一个漏洞   
Qfwfq-  看雪学苑   2023-08-15 17:59  
  
这似乎又是一个0 day漏洞，  
这个漏洞与pif文件有关，是我在研究pif文件的时候发现的。  
  
  
  
**实验环境**  
  
  
Microsoft Windows 2000 5.00.2195 Service Pack 4  
  
  
**用到的软件工具**  
  
  
010Editor  
  
ollydbg  
  
IDA pro  
  
  
```
```  
  
  
首先，win 2000系统里存在一个文件_default.pif，它的结构如下：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz9XKqWhrWYg3z2iaQjf1my4lyRDNmTOL8UVuEy4jibItEh4ibjWdN4U74vA/640?wx_fmt=png "")  
  
  
我在这个文件的基础上添加了一个名为WINDOWS VMM 4.0的块，如下图：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz9gVHqTlQ3EyLz8j6KAZ5WlzcUko1vhr8KxKMStQqibaliboVc4PKQl0LQ/640?wx_fmt=png "")  
  
  
把这个文件放在U盘根目录下，插入win 2000系统后，浏览U盘时，资源管理器崩溃闪退。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz9tlyPcDAeV3GTyjTfFIMpcoybmnA0AIibkS8vF5eXX4KicicibOUYeauyfw/640?wx_fmt=gif "")  
  
  
```
```  
  
  
我们可以确定的是，崩溃的出现是由于我们构造的pif文件里新的内容，而且应该出现在对文件内容的处理的过程中。  
  
  
而根据pif文件的格式：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz93icIsUpxSwIvbewias1Guz34eTvgEf8YeSDADeZyibsYKUic9eQJ86f5Ag/640?wx_fmt=png "")  
  
  
可以看到每个数据块都有一个名字，猜测在对这些数据块处理的代码里可能包含这些名字的字符串常量，也许可以由此定位到数据块处理相关代码。  
  
  
于是在explorer.exe和其调用的动态链接库中搜索这些字符串，最终发现只有系统shell32.dll中存在这些字符串：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz9lI0N90ha6pKdUicicBMOTFmjElyompqbBkjg5FSQ0cFq9ia82zCiaHE7Sg/640?wx_fmt=png "")  
  
  
然后在ollydbg里追踪崩溃。  
  
  
由于windows系统只允许存在一个explorer.exe进程实例，我们用ollydbg打开新的explorer.exe进程进行动态调试时，系统会自动关闭该进程，从而阻止了调试的继续进行。所以需要通过File ->Attach菜单项将系统当前的explorer.exe进程附加ollydbg中的方式进行调试。  
  
  
在调用这些字符串常量的函数里下大量断点，通过函数执行后崩溃是否发生判断溢出点的大致位置：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz9RGwNPGO34x5l8XHbDQHYvaIL32MjkloVZQsFpwwlswQMIhdB8tEGSA/640?wx_fmt=png "")  
  
  
最后跟踪到这个函数：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz9uEYwymVmRd0ewEbUzbv2MBkFwSDTdicGvybib1mErWHXYibHYBKibZwOUA/640?wx_fmt=png "")  
  
  
也就是函数sub_7909062B  
  
整个跟踪过程如下：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz9icB7IAXJCn6ibFYduiaV6aNGXgsTbFLF9JaRA7SJE7O4OmPwEvYqydzJw/640?wx_fmt=png "")  
  
  
动态分析函数sub_7909062B（上图中蓝色笔的部分），观察堆栈，发现在某次执行lstrcpyA后，堆栈里的返回地址和其它数据被覆盖。  
  
  
执行lstrcpyA前后堆栈里的变化：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz9v8Qx6Vr8uSxf8WXqc90HRgcAxBxMtHsLkDLAJicnKUdkr1aGG2ntbZQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz9wN6vAUfQBhiakTB0qdic4yic6qbhreIO7LaKojXO6mPibBMvqVyKgzuemw/640?wx_fmt=png "")  
  
  
```
```  
  
  
函数的返回地址被覆盖，在Windows 2000系统上的漏洞利用应该是毫无难度的简单劳动，但是这回的不太一样。  
  
  
在sub_79057E1D函数开始的地方将this指针保存在堆栈里：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz9PvYc3Lpa6urakZgpibuYWa9ANKQbCFMjjGxH9JF6VjDjJ9mMNBWiaCTQ/640?wx_fmt=png "")  
  
  
在堆栈被覆盖后的代码里又使用到this指针。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz9BSAw3rzgKDCE13jIhMw2DPVoT1IR64XLPO7ZqKQsRnAcK8JKmM9GKg/640?wx_fmt=png "")  
  
  
造成程序没有执行到函数返回指令的机会，所以按照常规方法通过返回地址得到程序执行权的方法在这里不适用。  
  
  
但是this指针被覆盖也为我们提供了获得执行的机会，我们在溢出this指针的数据处设置为堆栈地址硬编码，在溢出数据中构造出索引虚函数地址的数据，可以**概率性**的实现计算器的启动。下面是我构造的pif文件：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz936ibIj9hYHeuumlKJ3Y0S5CUKmE2ZBoiaibZmwmRza9Yf213fjpNhLs1Q/640?wx_fmt=png "")  
  
  
程序执行到this指针索引到的虚函数调用时，数据区里包含了我们的shellcode，启动的程序路径，和用来索引虚函数的链表结构。如下图：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz9iaZeIR5R4zqls3c37MJGRbFXLPaZQj4HibGhFc4Ok6Iwcos7CEZOvg2w/640?wx_fmt=png "")  
  
  
其中包含了我写的shellcode：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz9ib9Z88ibpricR2kTEBlRSbcWvH5EvYMLVW6mCrzjbOibQPOib4WbV6IVJEg/640?wx_fmt=png "")  
  
  
最终效果如下：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz9tlyPcDAeV3GTyjTfFIMpcoybmnA0AIibkS8vF5eXX4KicicibOUYeauyfw/640?wx_fmt=gif "")  
  
  
**概率性**成功的原因是，exploere.exe进程每次启动的其栈地址都是动态变化的，溢出发生时真实的堆栈可能没在我们提前设定的地址处。我这里测试平均每5次会有一次成功启动计算器，最终的频次体验应该和电脑有关。  
  
  
进一步研究，发现程序运行到调用虚函数地址时的寄存器EAX，EBX，ESI的值是溢出数据的某个位置的地址，所以理想的做法应该是寻找一个与JMP EAX,JMP EBX,JMP ESI类似的指令，假如这个指令的地址为A，设this的值为x，[ ]表示在进程地址空间里寻址后取值；我们可以将被覆盖的this指针设定为满足下面的公式的值：  
  
  
[[(x+4)]+0x1c] = A  
  
  
显然，找到满足上式的x是不容易的，我做了尝试，但失败了。不知道有没有更好的技巧来利用这种漏洞。  
  
  
```
```  
  
  
进一步的，我对Windows XP的shell32.dll进行了逆向分析，发现同样的位置与windows 2000的代码极为相似，但是它用安全的_StringCopyWorker函数代替了lstrcpy，如下图：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz9NE5Lia2YOW1aWzTutjRqcgob0t99WwjZxOkLLJiaoK2cibxRIgvpdDqQA/640?wx_fmt=png "")  
  
  
所以有理由相信，在后续的windows系统中微软已经发现了这个漏洞，并修补了它。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKKuuJmn5tL0fdUVEibiaz9l0ibia3T7rUvv210uzuevm7iaoT0VicticD4dMlxQjbXSGfPFYKQAZy5z7g/640?wx_fmt=png "")  
  
  
**看雪ID：Qfwfq-**  
  
https://bbs.kanxue.com/user-home-968912.htm  
  
*本文为看雪论坛精华文章，由 Qfwfq- 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458499288&idx=1&sn=b2b9cd6ff7388a8658d254e13c72f9ad&chksm=b18e885286f9014436a590f2531fda167be67e1e227ea395812968e828932bd44eade34b0dbf&scene=21#wechat_redirect)  
  
  
**#****往期推荐**  
  
1、[在 Windows下搭建LLVM 使用环境](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500602&idx=1&sn=4bcc2af3c62e79403737ce6eb197effc&chksm=b18e8d7086f9046631a74245c89d5029c542976f21a98982b34dd59c0bda4624d49d1d0d246b&scene=21#wechat_redirect)  
  
  
2、[深入学习smali语法](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500599&idx=1&sn=8afbdf12634cbf147b7ca67986002161&chksm=b18e8d7d86f9046b55ff3f6868bd6e1133092b7b4ec7a0d5e115e1ad0a4bd0cb5004a6bb06d1&scene=21#wechat_redirect)  
  
  
3、[安卓加固脱壳分享](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500598&idx=1&sn=d783cb03dc6a3c1a9f9465c5053bbbee&chksm=b18e8d7c86f9046a67659f598242acb74c822aaf04529433c5ec2ccff14adeafa4f45abc2b33&scene=21#wechat_redirect)  
  
  
4、[Flutter 逆向初探](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500574&idx=1&sn=06344a7d18a72530077fbc8f93a40d8f&chksm=b18e8d5486f904424874d7308e840523ebfb2db20811d99e4b0249d42fa8e38c4e80c3f622c6&scene=21#wechat_redirect)  
  
  
5、[一个简单实践理解栈空间转移](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500315&idx=1&sn=19b12ab150dd49325f93ae9d73aef0c4&chksm=b18e8c5186f90547f3b615b160d803a320c103d9d892c7253253db41124ac6993d83d13c5789&scene=21#wechat_redirect)  
  
  
6、[记一次某盾手游加固的脱壳与修复](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500165&idx=1&sn=b16710232d3c2799c4177710f0ea6d41&chksm=b18e8ccf86f905d9a0b6c2c40997e9b859241a4d7f798c4aeab21352b0a72b6135afce349262&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球在看**  
  
