> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070217&idx=4&sn=24357525bac3eedf8eb46ebe78022a55

#  【安全圈】“Grafana Ghost”漏洞曝光，近四成公网实例仍未修复  
 安全圈   2025-06-17 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaYlamicbH6OGokianaWfkMtdLSc10cHYzHV9HyzTmrPWQvZEWiczdmyY8qKctUClu6ERvibyJCPCv1aA/640?wx_fmt=png&from=appmsg "")  
  
2025年5月21日，Grafana Labs 发布安全更新，修复了由安全研究人员 Alvaro Balada 报告的一个严重漏洞，编号为 CVE-2025-4123。该漏洞存在于 Grafana 客户端路径解析与重定向逻辑中，允许攻击者通过构造恶意链接，引导用户加载并执行伪造插件，实现账户接管。目前已有超过 46,000 个公网暴露的 Grafana 实例仍未打补丁，面临实质性风险。  
  
Grafana 是广泛部署的开源可视化平台，被用于监控基础设施、云服务和应用性能。此次漏洞主要影响其客户端 JavaScript 路由逻辑，并可被用来绕过 URL 规范化、内容安全策略（CSP）等机制，从而执行跨站脚本（XSS）攻击。  
  
研究人员指出，该漏洞不需要攻击者具备系统权限，也不要求目标系统启用身份认证即可触发，攻击链条包括：构造具有“路径穿越 + 开放重定向”特征的恶意 URL、诱导活跃登录用户点击、加载伪造插件、在浏览器中执行任意 JavaScript 代码。最终效果包括用户会话劫持、重置密码、修改邮箱，甚至执行 SSRF 读取内网资源（如存在 Image Renderer 插件）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaYlamicbH6OGokianaWfkMtdledd9vfibbibBXd884eicicrqjJdOugDLp49m66Rq4npqkGVRZiaCWPj5yg/640?wx_fmt=png&from=appmsg "")  
  
尽管 Grafana 默认启用了一定的 CSP 安全策略，但其客户端侧执行特性使得该漏洞可绕过防护。攻击场景不依赖服务器行为，而是完全由浏览器渲染逻辑执行，因此防御难度更高。  
  
据应用安全公司 OX Security 的测算，目前全球约有 128,864 个可被探测的 Grafana 实例，其中仍有 46,506 个（约 36%）运行受影响版本，漏洞仍可被利用。该公司称本漏洞为 “The Grafana Ghost”，并通过实证验证漏洞的可武器化能力，包括插件加载链条、用户邮箱替换与会话持久劫持。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaYlamicbH6OGokianaWfkMtd9ES2dLef7CSrictZVHlOicoFQUrMvBQhkdemjAs5vSoGWNL7x6Kib89qQ/640?wx_fmt=png&from=appmsg "")  
  
该漏洞危害严重，尽管需要用户点击并处于活跃登录状态，但考虑到 Grafana 部署在许多自动化平台、CI/CD 系统、运维面板和监控大屏中，管理员与开发者往往处于长时间保持登录状态，攻击者可通过钓鱼邮件、社交工程等方式引导访问，从而构成实际风险。  
  
目前，Grafana 官方已发布多个版本补丁，推荐所有管理员立即升级至以下版本之一：  
- 10.4.18+security-01  
  
- 11.2.9+security-01  
  
- 11.3.6+security-01  
  
- 11.4.4+security-01  
  
- 11.5.4+security-01  
  
- 11.6.1+security-01  
  
- 12.0.0+security-01  
  
建议进一步采取的安全措施还包括：  
- 临时关闭插件功能（如不依赖）  
  
- 禁用匿名访问  
  
- 启用更严格的反向代理 URL 验证与 CSP 白名单  
  
- 定期强制刷新用户会话并审计活跃连接  
  
Grafana Ghost 暴露出客户端框架在安全逻辑上的设计薄弱，也提醒各类 DevOps 工具厂商必须加强对前端路径处理、URL 解析与插件机制的审查。对于依赖 Grafana 的企业，应尽快排查受影响版本并制定紧急更新策略。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】Windows SMB客户端提权漏洞（CVE-2025-33073）及其在未启用SMB签名环境中的攻击原理](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070197&idx=1&sn=2ea19a473759ade49d28c33654512b51&scene=21#wechat_redirect)  
  
  
  
[【安全圈】全球超4万摄像头“裸奔”，美国家庭隐私首当其冲](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070197&idx=2&sn=7e5d70ffd124440138090e721143d413&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Discord邀请链接被劫持：AsyncRAT与Skuld木马悄然窃取加密资产](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070197&idx=3&sn=f2b22042bcb80b88f3dd4f8a59e482c1&scene=21#wechat_redirect)  
  
  
  
[【安全圈】起亚厄瓜多尔车型钥匙系统存在严重漏洞，数千辆车面临被盗风险](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070197&idx=4&sn=ec2e30a1b4bdbaba363c267c6b615863&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
