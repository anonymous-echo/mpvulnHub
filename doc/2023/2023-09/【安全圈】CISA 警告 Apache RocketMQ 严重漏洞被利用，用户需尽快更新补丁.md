#  【安全圈】CISA 警告 Apache RocketMQ 严重漏洞被利用，用户需尽快更新补丁   
 安全圈   2023-09-11 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgKPaicOxW94xorwzm2NadXIIJ42j3tuFxiccoU5suStY1aEZGIGk0EVasWO3l4ly0zgHJ3FA28lmFw/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
     
  
美国网络安全和基础设施安全局 (CISA) 已在其已知被利用漏洞 (KEV) 目录中添加了一个严重程度为 CVE-2023-33246 的漏洞，该漏洞影响 Apache 的 RocketMQ 分布式消息传递和流媒体平台。  
  
目前，多个攻击者可能正在利用该漏洞在受影响的系统（RocketMQ 版本 5.1.0 及更低版本）上安装各种有效负载。  
无需身份验证即可利用该漏洞，并且至少从 6 月份起，  DreamBus 僵尸网络的运营商就已在利用该漏洞来部署门罗币加密货币挖矿程序。  
  
设计缺陷  
  
CISA 警告联邦机构 ，应在 9 月 27 日之前修补其系统上安装的 Apache RocketMQ 的 CVE-2023-33246 漏洞。  
如果无法将应用程序更新到安全版本或通过其他方式降低风险，CISA 建议停止使用该产品。  
  
该网络安全机构还指出，攻击者可以“通过使用更新配置功能以 RocketMQ 运行的系统用户身份执行命令”来利用该漏洞。  
  
美国国家标准与技术研究院（NIST）补充说 ，如果攻击者伪造 RocketMQ 协议内容，结果也是一样的。  
  
CISA 针对 CVE-2023-33246 漏洞在发出警告之前 ，漏洞情报平台 VulnCheck 的研究员 Jacob Baines 发布了解释该安全问题的技术细节。  
利用该漏洞是可能的，因为包括 NameServer、Broker 和 Controller 在内的多个 RocketMQ 组件暴露在公共互联网上，使它们成为黑客的攻击目标。  
  
来自多个攻击者的有效负载  
  
为了找出有多少潜在的 RocketMQ 目标暴露在网上，研究人员查找了  
名称为 RocketMQ 服务器使用的 TCP 端口 9876 的主机，发现了大约 4,500 个系统。  
  
Baines 指出 ，大多数系统都集中在一个国家，这可能意味着其中许多系统都是研究人员设置的蜜罐。  
在扫描潜在易受攻击的系统时，研究人员还发现了“各种恶意负载”，这表明多个攻击者正在利用该漏洞。  
  
尽管它们表现出可疑行为，但利用 RocketMQ 漏洞后丢弃的一些可执行文件， 目前并未被病毒扫描平台上的防病毒引擎检测为恶意文件。  
  
样本在系统上的可疑行为包括删除自身、运行命令修改权限、枚举进程、转储凭据、读取 SSH 私钥和 “known_hosts”文件、编码和加密数据以及读取 bash 历史记录。  
  
Baines 表示，尽管 CVE-2023-33246 已知与一名研究对手相关，但至少还有其它 5 个攻击者正在利用它。  
  
当前已提供解决该问题的补丁更新，建议用户更新到该应用程序的最新版本。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhicBvTzibYsTOicOcJLl4lybWxypxkFUorusk894ZR2e22j3uP1xdfjVsbeYuDC8JMXmzG4xGScvNmw/640?wx_fmt=png "")  
[【安全圈】狂妄黑客，集中被捕！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652044017&idx=1&sn=5e223ccc4836e7282f466e627fbf5fa7&chksm=f36fd6b1c4185fa7d2a4d71ba81f62423944271d98687c4faa02f90e21ad850ba0829fff779c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliapu0nzzdMcZwujCSpEqPQ8ib269uCLNtFH0xLDSc1FAkwYxpdRZyAL7Gpfp27egicJ01xP5C2QLUibA/640?wx_fmt=png "")  
[【安全圈】出售逝者及家属个人信息，两名医院护工获刑](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652044017&idx=2&sn=f35b9421b4aea6afceee9d929184f848&chksm=f36fd6b1c4185fa79168087ed6087ba8d2ff1fd0b353279d455dfc4a3a87b5682c02df4c49a4&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg3iaKeQ4jhF97DXRxPLlxeGe8Tyz2piabicE7m9hql6qgyeicLHfcHK6bRn5ujwh5vvBib1Jfv8VNiawog/640?wx_fmt=jpeg "")  
[【安全圈】英特尔承认微代码更新导致 Win10/11 蓝屏，并非都是“微软和微星的锅”](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652044017&idx=3&sn=a0c0240bf6bc4ccf5fb840a64755a641&chksm=f36fd6b1c4185fa711bafa50ff1b1a8fe536e4672af8110dde9e9887e0389af9e62f9fdabca9&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj2zibPojEBBw56RMtEQwiaiaJDy1kkYbSica5A0vTr2sHiathIczBxWfZO4HOeCsic83hZrYAJLgNv5IiaA/640?wx_fmt=png "")  
[【安全圈】X（推特）更新服务条款：禁止第三方抓取数据来培训 AI 模型](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652044017&idx=4&sn=00f10e8677d03477a65dac5a7c4799c6&chksm=f36fd6b1c4185fa702f9243c6f23eb5489f8266e250e7e3e46ffeb955e2a9c428d70a504e00f&scene=21#wechat_redirect)  
  
  
  
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
  
  
