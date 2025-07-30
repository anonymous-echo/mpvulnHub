#  【安全圈】警告！ConnectWise 漏洞正被广泛利用，数千台服务器面临危险   
 安全圈   2024-02-25 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
ConnectWise 周二表示，一个严重的 ConnectWise ScreenConnect 漏洞正在被广泛利用，该漏洞使数千台服务器面临被接管的风险。  
  
ConnectWise周一发布了 ScreenConnect 23.9.7 的安全修复程序，披露了两个漏洞，其中包括一个 CVSS 最高得分为 10 的严重错误。该安全公告后来更新为已知针对该漏洞的三个 IP 地址。  
  
Huntress 的研究人员表示，这个被追踪为CVE-2024-1709 的严重缺陷使得绕过身份验证并获得 ScreenConnect 实例的管理访问权限变得“微不足道且极其容易” 。  
  
第二个错误（编号为CVE-2024-1708）是一个路径遍历漏洞，可能允许恶意 ScreenConnect 扩展在其预期子目录之外实现远程代码执行 (RCE)。  
  
然而，Huntress 研究人员指出，仅利用 CVE-2024-1709 就足以实现 RCE。  
  
本地 ConnectWise ScreenConnect 实例的管理员应立即升级到版本 23.9.8，以防止服务器受到损害。据 ConnectWise 称，云实例已经被修补。  
  
ScreenConnect 漏洞威胁无数下游端点ConnectWise ScreenConnect 通常被托管服务提供商 (MSP) 用于远程访问客户端点以获取 IT 支持等服务。  
  
截至周三上午，Shadowserver 检测到约 3,800 个易受最新漏洞影响的 ScreenConnect 实例——估计占所有检测到实例的 93%。该组织在 X 上发布消息称，Shadowserver 周三也开始收到对其蜜罐的攻击请求。  
  
由于每个 ScreenConnect 实例可能为数百或数千个端点提供服务，CVE-2024-1709 可能会为重大供应链攻击奠定基础，这与 Cl0p 勒索软件组织实施的MOVEit 黑客攻击不同，该攻击自2023 年 5 月以来已影响了 2,500 多个组织。  
  
“我不能粉饰它——这太糟糕了，”Huntress 首席执行官凯尔·汉斯洛万 (Kyle Hanslovan) 在一份声明中告诉 SC Media。“该软件的广泛流行以及该漏洞提供的访问权限表明我们正处于勒索软件肆虐的风口浪尖。”  
  
Huntress 也参与了 MOVEit 黑客攻击后的事件响应，并指出由于概念验证 (POC) 漏洞的存在而增加了危险，只有在其他供应商发布自己的 POC 后才决定发布自己的 POC。  
  
Huntress 发言人表示，该公司与 ConnectWise 密切合作，研究该漏洞及其潜在影响。  
  
“双用途软件会带来清算；就像今年夏天通过 MOVEit 发现的 Huntress 一样，它为 IT 团队提供的无缝功能也为黑客提供了同样的功能，”Hanslovan 说道。“利用远程访问软件，坏人可以像好人推送补丁一样轻松地推送勒索软件。一旦他们开始推广他们的数据加密器，我敢打赌 90% 的预防性软件不会捕获它，因为它来自可信的来源。”  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgzq4v8wHXYrCpHtfsu3MOopDIp4p4VjS3nsHl5mSHyLUU7NdQ2ccv5K8WdZSNAEhuvcNzqufI5FQ/640?wx_fmt=png&from=appmsg "")  
[【安全圈】勒索之王LockBit 被11国联合执法覆灭？将发布4.0版本](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054423&idx=1&sn=0fd9e495bfd9ae385b67bd63fa7141e9&chksm=f36e0fd7c41986c19a5bc7cb7a3dff20333c3fb76e469ca3970489388da58caa81fb098ef9f1&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgzq4v8wHXYrCpHtfsu3MOokaj8eicrpicNkib4ibGFT5sDMspNVUGYlVQ0FhunaAvXF9AdberF9eLLgQ/640?wx_fmt=png&from=appmsg "")  
[【安全圈】.LIVE勒索病毒正在大规模传播，请及时修复（附勒索解密代码）](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054423&idx=2&sn=38593acc52ec42e5adb175d90d8f1fd5&chksm=f36e0fd7c41986c1f1777a060c2f88ec28d5548d3b38269ac0fc41667ed057c2c95525772048&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgzq4v8wHXYrCpHtfsu3MOol6Ra43rjNFliaicQ7d7ubksI19RfvMwHxNdibhyWD9NvQyauHb8rjicdYQ/640?wx_fmt=jpeg "")  
[【安全圈】Joomla 发现5个漏洞可执行任意代码](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054423&idx=3&sn=59f460185f705e3183b470edb4249bcd&chksm=f36e0fd7c41986c10b314833c6de089751f4fb2da21a1e3b4b4350ce570727c1ea1d2685c128&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgzq4v8wHXYrCpHtfsu3MOoh0piaWYHsly6x0fhLYfwz57UalbxDI4EA1nkYqWABGkzAUdzj9plN4A/640?wx_fmt=jpeg "")  
[【安全圈】美国医疗支付关键供应商被黑瘫痪，全国众多药店无法处理处方](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054423&idx=4&sn=c1a8c63f40a575499c7fa15947c3ef69&chksm=f36e0fd7c41986c14c36ecaad29f4b36ab30101111509b1eda88a1aa7a94c1c634757e0c98ba&scene=21#wechat_redirect)  
  
  
  
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
  
  
