#  【安全圈】Tinyproxy 曝出严重漏洞，影响全球52000 台主机   
 安全圈   2024-05-07 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
系统漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaDbbntRsEBEhQDSJ2Ptfu2fRicedLiaNyLqLJ8ibEoKrTN4jfzbuc3pDKhicy7ddhm3jnsk3jkibTeFkA/640?wx_fmt=jpeg&from=appmsg "")  
  
近日，攻击面管理公司 Censys 分享了一组数据：截至 2024 年 5 月 3 日，在90310台主机中，有 52000 台（约占 57%）运行着有漏洞的 Tinyproxy 版本。  
  
这些可能受到漏洞影响的主机分布于美国（32846 台）、韩国（18358 台）、中国（7808 台）、法国（5208 台）和德国（3680 台）。  
  
该漏洞是HTTP/HTTPS代理工具中一个未修补的重要安全漏洞，被追踪为 CVE-2023-49606，CVSS 得分为 9.8，Cisco Talos 将其描述为一个影响 1.10.0 和 1.11.1 版本（即最新版本）的免用漏洞。  
  
Talos在上周的一份报告中提到：攻击者可通过精心构造的HTTP头触发先前释放内存的重复使用，导致内存破坏且可能导致远程代码执行。攻击者需要发送未经身份验证的HTTP请求以触发此漏洞。  
  
换句话说，未经身份验证的威胁行为者可以发送特制的 HTTP 连接头，从而引发内存破坏，导致远程代码执行。  
  
Tinyproxy 是一个轻量级的开源 HTTP 代理守护程序，专注于简单性和效率。根据 HTTP 规范，客户端提供的标头表示代理在最终 HTTP 请求中必须删除的 HTTP 标头列表。代理从请求中删除这些 HTTP 标头，向远程服务器执行请求，并将响应发送回客户端。Tinyproxy 在函数中正是这样做的：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaDbbntRsEBEhQDSJ2Ptfu2ufzjSibFKYQjcxckXIvEm7pHCRmnKJJ8lKlUHUTu3ib15fn8ia5UZ27Dg/640?wx_fmt=jpeg&from=appmsg "")  
  
首先，我们应该注意到客户端发送的 HTTP 标头驻留在键值存储中。该代码搜索 和 标头，并在 （1） 处获取它们的值，如前所述，这是一系列要删除的 HTTP 标头。客户端列出的每个 HTTP 标头在 （3） 处被删除。从本质上讲，和 标头值中的每个 HTTP 标头都用作从 中删除的键。最后，在 （4） 处，HTTP 标头本身被删除。  
  
在函数中，我们看到：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaDbbntRsEBEhQDSJ2Ptfu2OYZ8HWAQpU3oLao3edBjajuuRMWH2cqibVcJXPntJC3Slts4tZ0s0tw/640?wx_fmt=jpeg&from=appmsg "")  
  
对于具体提供的，其哈希值计算为 （5）。使用哈希值，在 （6） 处检索并释放键值的指针。最后，键本身从（7）的哈希图中删除。  
  
现在考虑一下当客户端发送 HTTP 标头时会发生什么。出于演示目的，我们将它们区分为。在 （1） 处检索标头的值，这当然是 。在 （3） 处，该值用作 处的变量。在（5）处计算字符串的哈希值，与完全相同。请注意，哈希值也不区分大小写。在 （6） 处，哈希用于检索和释放 HTTP 标头值的指针，即 。因此，此时代码已释放了 的内存。在 （7） 处，现在包含过时指针的变量被重用，从而导致释放后使用方案。  
  
很明显，此漏洞可用于执行内存损坏并获得代码执行权限。  
  
去年 12 月 22 日，塔洛斯公司报告了这一漏洞，并发布了该漏洞的概念验证（PoC），描述了如何利用解析 HTTP 连接的问题来触发崩溃，并在某些情况下执行代码。  
  
Tinyproxy 的维护者在上周末提交的一组文件中，指责 Talos 将报告发送到了一个已经不再使用的电子邮件地址，并补充说他们是在 2024 年 5 月 5 日被 Debian Tinyproxy 软件包维护者发现的。  
  
rofl0r 提到：没有人在 GitHub 上提交问题，也没有人在提及的 IRC 聊天中提到漏洞。如果在 Github 或 IRC 上报告了该问题，该漏洞会在一天内得到修复。该公司建议用户在最新版本发布后及时更新。  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaueiafsTWJlE4F3oJeY3vaW8ickOJ3JDraL3YRrZciaoruIXcgcoc0ukx4BN6RPrGic1dMNicacMuePLg/640?wx_fmt=webp&from=appmsg "")  
[【安全圈】抢先中美韩，日本宣布造出全球首款6G手机，速度是5G手机500倍](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059337&idx=1&sn=8b12aef95732fd851b526672b3d7c679&chksm=f36e1a89c419939f38f8564c723bcebc0e5b221cae74f7cf35dc28c439910410bb619c6e93c9&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaDbbntRsEBEhQDSJ2Ptfu2KibN2tyZps6LQTjeRUuqQReTWpP2nlWicwvnq4fhPS5D4AQwFTD0DUOA/640?wx_fmt=jpeg "")  
[【安全圈】窃取 3 万人医疗记录后勒索患者加“撕票”，芬兰黑客 Julius Kivimäki 被判服刑 6 年](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059337&idx=2&sn=53e48250f5af3dc07b506c82b5f8b6ca&chksm=f36e1a89c419939fd2ac016458fc56936471ddf1f1bed7628daafd451622f85201c05ac30ee2&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaDbbntRsEBEhQDSJ2Ptfu2sv0iabLw9UQs7IhGWqESXAFRdNV0lUBIPX0dZlFNpX8dTW3kl0WtmPA/640?wx_fmt=jpeg "")  
[【安全圈】消息称 Docker Hub 平台遭黑客滥用，20% 存储库被散布恶意软件](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059337&idx=3&sn=73d12f936f9ceccebbb1ebd79367c755&chksm=f36e1a89c419939f1851e31d50d7b04fc26af6b7af1da2cee3b0fb046606d9be4e9359115ccb&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaDbbntRsEBEhQDSJ2Ptfu2deH0ZjCLT2ZrsMetL1k0pRwK7iaOPpqEZwgERR6drMHw09JNibZo2ysQ/640?wx_fmt=jpeg "")  
[【安全圈】威胁预警！黑客正在滥用微软 Graph API 与C&C“隐蔽通信”](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059337&idx=4&sn=622ff5428061d342545b8a982b5aba2f&chksm=f36e1a89c419939fe3d29b46a1061a3822aaa43238e0a1d811c746d4a5d120de63b66d2e3061&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
