#  【安全圈】微软披露严重安全漏洞，受影响App安装量超40亿   
 安全圈   2024-05-07 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
近日，研究人员披露了一个名为“Dirty Stream”的严重安全漏洞，该漏洞可能影响几款下载总量数十亿的 Android 应用程序。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaDbbntRsEBEhQDSJ2Ptfu2C6gywyfuWkCzQiaYIAh0NuqJGoUTxULkmVib5Ql83AvODeHqEicMctx5Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
微软威胁情报团队成员 Dimitrios Valsamaras 在一份报告中声明，威胁攻击者可以利用该安全漏洞，执行任意代码以及盗取令牌。一旦成功利用漏洞，威胁攻击者就可以完全控制应用程序的“行为”，并利用窃取的令牌在未经授权的情况下访问受害者的在线账户和其他数据。  
  
这一安全漏洞可能会给大量设备带来威胁风险， Google Play 商店中目前已经发现了几个易受攻击的应用程序，这些应用程序的总安装量超过了 40 亿，其中受该安全漏洞影响程度最大的两个应用程序如下：  
> 小米文件管理器 (com.mi. Android.globalFileexplorer) -，安装量超过 10 亿次WPS Office (cn.wps.moffice_eng) -，安装量超过 5 亿次  
  
  
安卓系统通过为每个应用程序分配专用的数据和内存空间来实现隔离，并以安全的方式促进应用程序之间的数据和文件共享。但实施过程中的疏忽可能会导致绕过应用程序主目录内的读/写限制。  
  
Valsamaras 表示，这种基于内容提供商的模式提供了一种定义明确的文件共享机制，使服务应用程序能够以安全的方式与其他应用程序共享文件，并进行细粒度控制。  
  
然而，在执行的过程中，经常遇到消费应用程序并不验证其接收到的文件内容，而且最令人担忧的是，它使用服务应用程序提供的文件名将接收到的文件缓存在消费应用程序的内部数据目录中。当服务应用程序为了实现应用程序之间的文件共享而声明恶意版本的 FileProvider 类时，这一“陷阱”可能会造成严重后果，最终导致消费应用程序覆盖其私有数据空间中的关键文件。  
  
换句话说，该机制利用了消费应用程序盲目信任输入这一事实，通过自定义、明确的意图，在用户不知情或未经用户同意的情况下发送带有特定文件名的任意有效载荷，从而导致代码执行。  
  
这时候，威胁攻击者就可以覆盖目标应用程序的共享首选项文件，使其与受其控制的服务器通信，从而外泄敏感信息。另一种情况是应用程序从自己的数据目录（而不是"/data/app-lib"）加载本地库，在这种情况下，恶意应用程序可以利用上述漏洞，在加载本地库时用恶意代码覆盖该库并执行。  
  
值得一提的是，在接到安全漏洞披露通知后，小米和 WPS Office 均已于 2024 年 2 月对该安全漏洞问题进行了整改。与此同时，谷歌也就此发布了详细的指导意见，敦促开发者正确处理服务器应用程序提供的文件名。  
  
谷歌方面强调，当客户端应用程序将接收到的文件写入存储时，应该忽略服务器应用程序提供的文件名，而使用自己内部生成的唯一标识符作为文件名，如果生成唯一的文件名不能轻易实现，客户端应用程序就应该对提供的文件名进行核验、清查。  
  
最后，微软方面指出，该安全漏洞问题非常普遍，相关开发者应当采取措施，仔细检查自身应用程序是否存在类似问题。  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaueiafsTWJlE4F3oJeY3vaW8ickOJ3JDraL3YRrZciaoruIXcgcoc0ukx4BN6RPrGic1dMNicacMuePLg/640?wx_fmt=jpeg&from=appmsg "")  
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
  
