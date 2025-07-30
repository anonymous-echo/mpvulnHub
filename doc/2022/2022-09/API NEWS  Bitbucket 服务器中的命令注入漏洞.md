#  API NEWS | Bitbucket 服务器中的命令注入漏洞   
 星阑科技   2022-09-08 10:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Cc8QqLUKOeiaFHTFtiatmEIxZQcXOHfyr6GOBM88IeMm28ybjSAHEJKicuQxPxN5L5NFZ5mza2NOnuokf9ant2fUQ/640?wx_fmt=gif "")  
  
  
欢迎大家围观小阑精心整理的API安全最新资讯，在这里你能看到最专业、最前沿的API安全技术和产业资讯，我们提供关于全球API安全资讯与信息安全深度观察。  
  
**本周，我们带来的分享如下：**  
- 关于 Atlassian Bitbucket 服务器中的命令注入漏洞  
  
- 关于每月发生的API安全事件  
  
- 关于 API 安全最佳实践前五名的文章  
  
  
  
**Bitbucket 服务器中的命令注入漏洞**  
  
  
本周一个重要的新闻是Bitbucket 中的关键命令注入漏洞，该漏洞可能允许对公共或私有 Bitbucket 存储库具有读取权限的远程攻击者通过发送恶意 HTTP 请求来执行任意代码。  
  
该漏洞编号为 CVE-2022-36804，是Bitbucket Server 和 Data Center的多个 API 端点中的命令注入漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Cc8QqLUKOehiaJkhRfSFyLI2mPfva3ia2DKTUfAP02iaXYOQUcRInBfo1FBTzHdfamicrhXicsgCWBAL7Gcd9WhMq9g/640?wx_fmt=jpeg "")  
  
  
根据公告，受影响的产品是 Bitbucket 服务器和数据中心（6.10.17 之后发布的版本，最高为 8.3.0）。通常的指导适用 - 尽快更新到最新版本的软件。  
  
  
  
**每月发生的 API 安全事件**  
  
  
  
Postman 发布了 2022 年 API 状况报告的结果，该报告对 37,000 多名开发人员和 API 专业人士进行了一系列主题的调查，包括组织的优先事项、如何完成工作以及对行业发展的看法。今年，问题扩大到包括经济、就业和远程工作，以深入了解科技行业如何看待当今最紧迫的商业问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Cc8QqLUKOehiaJkhRfSFyLI2mPfva3ia2DicWS74QcTdG3JVLrb2DfLzZhme0wahwstnJybeHTiah5DOhicA4hy9OOQ/640?wx_fmt=jpeg "")  
  
  
Postman首席执行官Abhinav Asthana说：“今年，我们发现不仅大多数组织的开发工作都集中在 API 上，而且走得更远并建立 API 优先方法的公司往往表现出色，业务前景更加乐观。随着组织在不确定的经济环境中航行，API 优先战略正在成为使组织能够快速无缝响应的支柱。”   
  
  
  
**该报告的主要发现有：**  
  
**• 组织现在将大部分开发工作都花在 API 上：**约51%的受访者表示，他们组织一半以上的开发工作都花在了API上——相比之下，2020年和去年分别为40%和49%的受访者强调了API角色作为现代软件的构建块。  
  
**• 尽管经济逆风，API 投资仍将保持强劲：**89%的全球受访者表示，未来12个月对 API 的投资将增加或保持不变。仅对高管进行民意调查时，1,400名CEO、CIO和CTO中出现了类似的信心水平。这些预测是在三分之二的受访者对当今经济表示负面看法的情况下做出的。  
  
• API优先的领导者表现出色：虽然只有8%的受访者认为自己是API优先的领导者，但这个精英群体生产API的速度更快，部署的频率更高，故障更少，并且在发生故障时恢复得更快。他们也有更光明的业务前景——他们更有可能预测未来12个月的招聘、员工保留和内部支出会增加。  
  
**• 远程工作“非常重要”：**世界上许多人都认为远程工作至关重要。在北美，78%的开发人员和API专业人士称其“非常重要”，超过了全球72%的数字。其他地区，如亚洲和欧洲，对它的重视程度较低。调查结果来自许多远程员工拒绝返回办公室。  
  
**• 许多公司每月都会发生API安全事件：**约20%的受访者在其组织中至少每月报告一次API安全事件或违规事件。虽然总体情况更令人放心（52%的人表示事件每年发生不到一次），但数据强调了在API生命周期早期整合安全性的重要性。  
  
  
**前五名的 API 安全最佳实践**  
  
  
  
Traefiklabs 发布了他们  对 API 的保护、弹性、可靠性和可扩展性的前五名最佳实践的建议。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Cc8QqLUKOehiaJkhRfSFyLI2mPfva3ia2DeQemH2Dsfa3ibyyXzjmTUYtcz1UxTEYiceEsKQ741rsNxxInqFy4PbgA/640?wx_fmt=png "")  
  
  
**他们的主要建议是：**  
  
**• 保持负载平衡：**负载平衡可确保网络和系统的正常运行时间、可靠性和弹性，同时实现动态扩展。如果应用程序、服务器或网络出现故障，服务操作将继续处理请求，应用程序将继续平稳安全地运行。  
  
确保在堆栈的每一层内实现冗余，以平衡 API 网关和后端应用程序中的流量。强大的网络解决方案提供跨两个或多个副本的多层负载平衡流量，将请求路由到健康实例以均匀分配流量。此外，您可以对 API 网关本身进行负载平衡，以在多个 TE 实例之间分配负载。  
  
**• 通过身份验证和授权控制对 API 的访问：**确保用户是他们所说的那样，并且只允许他们访问经过批准的系统。常见的身份验证和授权协议包括 LDAP、JWT、OAuth2、OpenID Connect、HMAC 等。  
  
在入口处集中和自动化身份验证和授权协议是一个好主意，以减轻单个应用程序处理协议的负担。通过在更高层平面抽象这些功能，您的网络解决方案应该消除协议实现错误，并使开发人员能够专注于应用程序特性和功能。这还将为开发、网络和安全团队创建一个标准的安全流程。  
  
**• 使用加密和 TLS/SSL 证书保护您的数据：**使用 HTTPS加密和证书保护通过网络传输的数据是防止不良行为者获取您的数据的最佳方法。自动化加密和证书管理消除了与手动错误相关的风险。自动生成动态证书会生成私钥，将其提交给 CA，然后等待验证和签名过程完成。强大的 API 网关还支持用于 TLS 证书管理的各种行业标准集成，例如 HashiCorp Vault 或 Let's Encrypt 等 ACME 提供商。  
  
**• 不要忘记速率限制：**这种做法有助于确保应用程序安全且具有弹性，同时公平对待用户。速率限制控制互联网流量的流量和分布，因此您的基础设施永远不会过载。如果没有速率限制，流量可能会变得拥塞，导致应用程序运行缓慢甚至失败。  
  
通过将流量流与您的基础架构的容量相匹配，速率限制可防止 API 接收过多的调用。通过限制 API 的调用频率和限制连接，您可以防止流量高峰和 DDoS 攻击。  
  
速率限制有两个需要考虑的参数。代理收到的请求数，以及中间件持有的绝对请求数。  
  
**• 维护可靠的访问日志：**详细的审计日志对于事后调查很重要。审计日志监控数据，同时跟踪潜在的信息滥用和网络安全漏洞，以降低风险、遵守法规、深入了解潜在的恶意活动并实现运营效率。它们有助于促进持续监控和事件响应，因为它们包含详细信息，有助于了解谁在何时访问哪些端点，这对于了解消费趋势和主动检测恶意行为非常有益。如果发生任何类型的安全事件，这些日志同样有助于事后分析和审计。  
  
随着 API 数量的增加，自动化和集中化变得越来越重要。应该授权开发团队专注于他们最擅长的事情，而不是陷入使用这些不同组件的细枝末节。  
  
这些最佳实践的应用将有助于确保您的分布式系统安全、有弹性、可靠和可扩展。管理分布式系统的 API 安全性需要对不断扩大的企业边界有广阔的视野。通过保护 API，您可以可靠地保护整个应用程序服务链，因为请求从一个服务路由到另一个服务。  
  
  
  
感谢 APIsecurity.io 提供相关内容  
  
  
  
**关于星阑**  
  
  
  
  
  
星阑科技基于AI深度感知和强大的自适应机器学习技术，帮助用户迅速发现并解决面临的安全风险和外部威胁，并凭借持续的创新理念和以实战攻防为核心的安全能力，发展成为国内人工智能、信息安全领域的双料科技公司。为解决API安全问题，公司从攻防能力、大数据分析能力及云原生技术体系出发，提供全景化API识别、API高级威胁检测、复杂行为分析等能力，构建API Runtime Protection体系。  
  
**星阑科技产品——萤火 (API Intelligence) 拥有不同应用场景的解决方案**，适配服务器、容器集群、微服务架构以及云平台等多种架构。**通过API资产梳理、漏洞管理、威胁监测、运营与响应能力，解决企业API漏洞入侵、数据泄露两大核心风险。**  
  
  
  
  
**往期 · 推荐**  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247493320&idx=1&sn=41d96f17d2a226c31b23b35d93a36f2a&chksm=c0074b54f770c242d6897443eb4980fb58a0f065ea2d8593cb3b8548b370bc075acc57a7c1c1&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247493183&idx=1&sn=2af1758db0a3a191fab5a06c5d42d5e2&chksm=c0074ba3f770c2b5f823d3d51f8dca78e4992fed1af362fd343cccff4869215b4cdd1d530c14&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247493126&idx=1&sn=58636a0f6eb16b77ab08166257c8ac39&chksm=c0074b9af770c28c03fb7893f6f2f624955bcf1791a34be921b46b139084690227b01e8a79e7&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247493022&idx=1&sn=a39a77fbab2b9b01c50c77ab9e9f3cda&chksm=c0074802f770c11453cbfb45123934a5fa24979d0a0d779dbb9b390d8a276fd06bc80ffddb4a&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Cc8QqLUKOehwcHoxicoOah5mxDjLHMZ9RHUxNeibERphRXOj3AEupxt7JyOt3LF1RmmWQibYmicTv2DxM93iaEJhLxw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
