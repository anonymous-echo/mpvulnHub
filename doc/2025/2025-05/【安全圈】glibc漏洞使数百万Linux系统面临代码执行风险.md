#  【安全圈】glibc漏洞使数百万Linux系统面临代码执行风险   
 安全圈   2025-05-19 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![glibc 漏洞 Linux 安全](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgjTHg6iauauslabZ9dIknC28UZqpJHgJfOh1BI0jWgy6dibwMEjt3LKLZdEic9lFJK2NgdHiafFibYZGQ/640?wx_fmt=png&from=appmsg "")  
GNU C 库(glibc)中新报告的漏洞,是无数 Linux 应用程序的基本组成部分,它详细介绍了静态 setuid 二进制文件的共享库加载机制中可能可利用的弱点。  
  
跟踪为 CVE-2025-4802,environment该漏洞源于静态 setuid 二进制文件在通过 dlopen() 进行动态库调用时不正确使用 LD_LIBRARY_PATH 环境变量。  
  
GNU C 库或 glibc 是 GNU 工程和几乎所有主要 Linux 发行版所使用的标准 C 库。它充当操作系统内核和用户空间程序之间的桥梁,实现输入/输出处理、内存分配和网络通信等基本功能。  
  
虽然glibc主要用于动态链接的二进制文件,但它也支持静态链接的可执行文件 – 自包含的程序,包括编译时所有必要的库。  
  
缺陷在于静态 setuid 二进制文件与动态加载器之间的相互作用。advisory根据咨询:  
  
调用 dlopen(包括 setlocale 后的内部 dlopen 调用或调用 NSS 函数(如 getaddrinfo)的静态链接 setuid 二进制文件可能会错误地搜索 LD_LIBRARY_PATH 以确定要加载的库,从而导致执行由攻击者控制的库代码。  
  
通常,像LD_LIBRARY_PATH这样的环境变量被特权二进制文件(即那些有setuid的二进制文件)忽略,以避免引入安全风险。然而,CVE-2025-4802打破了这一假设,允许恶意用户在存在易受攻击的setuid二进制文件并直接或通过常见的libc依赖函数调用dlopen()时注入任意代码。  
  
风险被归类为局部和情境,因为它需要:  
  
系统上的静态链接 setuid 二进制文件。  
  
二进制文件必须调用 dlopen()()——手动或通过间接 libc/NSS 调用。  
  
environment环境必须允许用户设置 LD_LIBRARY_PATH。  
  
该咨询机构承认:“在发布此咨询时没有发现此类计划,但定制setuid程序的存在,尽管作为安全实践受到强烈劝阻,但不能打折扣。  
  
这使得该漏洞成为低概率但高影响力的漏洞,特别是在具有遗留或自定义静态二进制文件的环境中。  
  
系统管理员和 Linux 发行商应:  
  
将 glibc 更新到 2.39 版本,或者如果维护自定义构建,请手动应用修复程序。  
  
审核静态 setuid 二进制文件,并在可能的情况下删除或重新编译它们与动态链接。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】黑客勾结员工窃取数据 上市加密货币交易所预估最高损失4亿美元](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069693&idx=1&sn=d05dc42906f24561a17d256d72f9250d&scene=21#wechat_redirect)  
  
  
  
[【安全圈】离职泄愤售卖客户信息？ 千元获利换来刑事处罚！](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069693&idx=2&sn=45c3952db6058ba101c18f3d5d2dcafe&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Linux 漏洞数量一年激增 967%](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069693&idx=3&sn=79db367c018e907ae1f542e9117a3227&scene=21#wechat_redirect)  
  
  
  
[【安全圈】无视任何杀毒软件！世界上第一个 CPU 级勒索病毒：可直接攻击处理器 控制 BIOS](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069677&idx=1&sn=ef828b3cc2aae263db66d78f23a37ea8&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
