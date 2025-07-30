#  API NEWS | 国际最新API安全漏洞   
传递资讯的  星阑科技   2022-06-09 13:18  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Cc8QqLUKOeiaFHTFtiatmEIxZQcXOHfyr6GOBM88IeMm28ybjSAHEJKicuQxPxN5L5NFZ5mza2NOnuokf9ant2fUQ/640?wx_fmt=gif "")  
  
  
欢迎大家围观小阑精心整理的API安全最新资讯，在这里你能看到最专业、最前沿的API安全技术和产业资讯，我们提供关于全球API安全资讯与信息安全深度观察。  
  
**本周，我们带来的分享如下：**  
- 开放自动化软件（OAS）平台的一个高危远程代码执行（RCE）和API访问漏洞；  
  
- 云麦智能秤API存在大规模帐户接管漏洞；  
  
- 如何防止API滥用；  
  
- 如何使用渗透测试方法来防止应用程序受到的API攻击。  
  
  
  
**OAS平台存在严重的RCE和API访问漏洞**  
  
  
  
Bleeping Computer曾发布过一则新闻，提到广泛使用的开放自动化软件（OAS）平台存在两个漏洞。OAS平台是一种广泛应用于工业控制系统的数据连接平台，为各种设备和协议之间提供互操性。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Cc8QqLUKOejiczIQmWPnt9AZa8OZMskd4Pq1MNbKiaPveVPexwR8LHgIUjiaPLnfXWdiaTj1tibA2aTWu9Ru0ib1icWzA/640?wx_fmt=png "")  
  
  
第一个漏洞是一个高危的RCE漏洞，可能危及整个平台：一个API端点允许对平台进行远程管理。研究人员发现，他们可以使用空白用户名和密码访问相关终端，允许任意远程访问平台。该问题的CVSS评级为9.4，编号为CVE-2022-26833，是API2：2019 ——失效认证的一个例子。  
  
  
第二个漏洞源于API端点缺少身份验证，与平台安全文件传输模块中的文件写入漏洞有关。研究人员发现，他们可以向允许加载任意文件的API端点发送特殊请求，包括向根用户的SSH目录中的一个新的authorized_keys文件，从而实现完全远程访问。该漏洞的CVSS评级为9.1，编号为CVE-2022-26082。  
  
  
这些漏洞是负责任地披露的，并在2022年5月22日发布的版本16.00.0.113中得到了修复。研究人员建议，要么升级到最新版本的平台，要么明确停用受影响的服务端点。  
  
  
  
**云麦智能秤API中大量账户被接管**  
  
  
  
本周的第二个漏洞消息是，Fortbridge的安全团队在云麦智能秤的API中发现了一系列漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Cc8QqLUKOejiczIQmWPnt9AZa8OZMskd4Pz4gDib3icwM07PLyJpzx5ajCP8HBkpdjf81bJMwKyjQ2CibfMfTMLXAw/640?wx_fmt=jpeg "")  
  
  
研究人员对这款智能秤应用的Android和iOS版本进行了渗透测试，检测到四个与后端API相关的漏洞。通过结合这些漏洞，他们成功地实现了大规模账户接管。相关人员已负责任地向供应商披露了这些漏洞，但撰写本文时尚不清楚问题是否已得到解决。  
  
  
  
**第一个漏洞允许攻击者绕过每个帐户家庭成员数量的限制。**该应用程序只允许在一个家庭中创建16个帐户，但直接使用API没有任何数量限制，根本原因是限制只在客户端实施，而不是在后端API中。这是一个常见的应用程序设计缺陷—总是确保在后端API中强制执行限制和限制。  
  
  
**第二个漏洞允许通过使用Burp Suite自动化猜测ID来任意枚举用户ID。**API没有充分授权对猜测ID的访问，而是返回完整的用户信息，包括敏感的、PII。这是API1:2019的一个例子——失效的对象级授权——记住始终针对对象所有者对对象的访问进行完全授权。  
  
  
**第三个漏洞是API2:2019的一个例子——失效的认证，该漏洞是允许研究人员使用枚举用户ID从其他人的账户中添加和删除用户。**始终确保所有API端点都经过身份验证。  
  
  
**第四个漏洞允许研究人员在创建新用户时同时获得刷新令牌和访问令牌，**通过检查Burp Suite中的反应，研究人员发现这些代币被意外泄露，如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Cc8QqLUKOejiczIQmWPnt9AZa8OZMskd4icjYqu89rOxOkQH9U8XJGjmCUqNU0Ou9fpG0bSH3utKXqficQ8eYTZibw/640?wx_fmt=jpeg "")  
  
  
攻击者可以利用这些令牌组合效地获得永久访问平台的权限。这是API3：2019的一个例子——过度的数据暴露——始终要警惕泄露信息，特别是访问令牌。  
  
致命一击——研究人员能够结合三个漏洞，使用遗忘密码流执行大规模帐户接管攻击。  
  
这是一篇非常棒的文章，展示了API安全Top10中的三个，以及漏洞是如何轻易进行组合的——感谢作者对社区的贡献！  
  
  
  
**如何防止API滥用**  
  
  
  
关于如何防止API滥用。越来越多的组织正在经历对其API的恶意使用，企图以意想不到的方式利用它们。通常，这种滥用攻击可能会导致过度的数据泄露、数据挖掘或拒绝服务（DoS）。API滥用通常被认为与API攻击不同，后者往往专注于特定的API漏洞——尽管如此，API构建者应该采取措施来减少滥用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Cc8QqLUKOejiczIQmWPnt9AZa8OZMskd4NHhq3PyeMblgWeKruEnnrDpIKwlFjgXyiciaTWj36wU5iccgmp9JmmVDA/640?wx_fmt=jpeg "")  
  
  
**常见的API滥用包括：**  
  
**•**中间人（MITM）攻击  
  
• 重新打包或修改的应用程序  
  
• 脚本或机器人  
  
• 逆向工程的应用  
  
  
**Approov建议采取以下措施减少API滥用：**  
  
**•**监控和日志记录  
  
• 速率限制  
  
• 身份验证和授权  
  
• 证书锁定  
  
  
**通过渗透测试预防API攻击**  
  
  
  
在给大家分享一篇渗透测试文章，这次是针对使用Java-RMI服务的web应用程序。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Cc8QqLUKOejiczIQmWPnt9AZa8OZMskd4QuPyWrcLA7Vv29Mt85IdPJQxbkjOlLJImDS2kSqgT7v4pJcic6jzSkw/640?wx_fmt=png "")  
  
文章阐述了各种利用web应用程序和底层API却没有成功的技术，但却发现后端使用Java远程方法调用（RMI）服务可以打开通过各种技术来利用该Java平台的途径，最终导致了概念验证。  
  
  
  
**研究人员推荐以下保护Java-RMI服务的最佳安全实践：**  
  
**•**通过SSL/TLS协议运行RMI服务，防止MITM攻击。  
  
• 服务器和客户端都需要身份验证。  
  
• 使用RMI时运行安全管理器。  
  
• 确保属性“java.rmi.server.useCodebaseOnly”的值为“true”。  
  
  
  
感谢 APIsecurity.io 提供相关内容  
  
  
**关于星阑**  
  
  
  
  
  
星阑科技基于AI深度感知和强大的自适应机器学习技术，帮助用户迅速发现并解决面临的安全风险和外部威胁，并凭借持续的创新理念和以实战攻防为核心的安全能力，发展成为国内人工智能、信息安全领域的双料科技公司。为解决API安全问题，公司从攻防能力、大数据分析能力及云原生技术体系出发，提供全景化API识别、API高级威胁检测、复杂行为分析等能力，构建API Runtime Protection体系。  
  
**星阑科技产品——萤火 (API Intelligence) 拥有不同应用场景的解决方案**，适配服务器、容器集群、微服务架构以及云平台等多种架构。**通过API资产梳理、漏洞管理、威胁监测、运营与响应能力，解决企业API漏洞入侵、数据泄露两大核心风险。**  
  
  
  
  
**往期 · 推荐**  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247493320&idx=1&sn=41d96f17d2a226c31b23b35d93a36f2a&chksm=c0074b54f770c242d6897443eb4980fb58a0f065ea2d8593cb3b8548b370bc075acc57a7c1c1&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247493183&idx=1&sn=2af1758db0a3a191fab5a06c5d42d5e2&chksm=c0074ba3f770c2b5f823d3d51f8dca78e4992fed1af362fd343cccff4869215b4cdd1d530c14&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247493126&idx=1&sn=58636a0f6eb16b77ab08166257c8ac39&chksm=c0074b9af770c28c03fb7893f6f2f624955bcf1791a34be921b46b139084690227b01e8a79e7&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247493022&idx=1&sn=a39a77fbab2b9b01c50c77ab9e9f3cda&chksm=c0074802f770c11453cbfb45123934a5fa24979d0a0d779dbb9b390d8a276fd06bc80ffddb4a&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Cc8QqLUKOehwcHoxicoOah5mxDjLHMZ9RHUxNeibERphRXOj3AEupxt7JyOt3LF1RmmWQibYmicTv2DxM93iaEJhLxw/640?wx_fmt=gif "")  
