#  【安全圈】GitLab 警告多个漏洞可让攻击者以有效用户身份登录   
 安全圈   2025-03-14 19:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliajjvdWakRvnUcaa8z3dOXPbzoqMzwXAuFmoPnpo2riaFQbUys3hic20IeajZcb92lANOMPftdmOzyw/640?wx_fmt=png&from=appmsg "")  
  
GitLab 发布了针对多个漏洞的关键安全补丁，这些漏洞可能允许攻击者以合法用户身份进行身份验证，甚至在特定情况下执行远程代码。   
  
该公司已敦促所有自行管理的 GitLab 安装立即升级到社区版 (CE) 和企业版 (EE) 17.9.2、17.8.5 或 17.7.7 版本，以解决这些安全问题。  
## 严重的身份验证绕过漏洞  
  
发现的最严重的安全问题是 CVE-2025-25291 和 CVE-2025-25292，它们影响 GitLab 用于 SAML单点登录 (SSO)身份验证的 ruby-saml 库。   
  
由于这些漏洞对身份验证系统有潜在影响，其严重程度被列为“严重”。   
  
根据 GitLab 的安全公告，可以访问身份提供商 (IdP) 提供的有效签名 SAML 文档的攻击者可以利用这些漏洞在环境的 SAML IdP 中以另一个合法用户的身份进行身份验证。  
  
对于无法立即更新其 GitLab 实例的组织，我们建议采取几种缓解措施。   
  
这些包括为所有用户帐户启用 GitLab 的本机双因素身份验证，禁用 SAML 双因素绕过选项，并通过在配置中设置 gitlab_rails['omniauth_block_auto_created_users'] = true 来要求自动创建的新用户获得管理员批准。  
  
<table><tbody><tr style="background-color: rgb(240, 240, 240);"><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">风险因素</td><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">细节</td></tr><tr><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">受影响的产品</td><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">GitLab CE/EE 使用 SAML SSO；ruby-saml 库（版本 &gt;= 1.13.0、&lt; 1.18.0 和 &lt; 1.12.4）</td></tr><tr style="background-color: rgb(240, 240, 240);"><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">影响</td><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">身份验证绕过</td></tr><tr><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">漏洞利用前提条件</td><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">从 IdP 访问已签名的 SAML 文档</td></tr><tr style="background-color: rgb(240, 240, 240);"><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">CVSS 3.1 分数</td><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">批判的</td></tr></tbody></table>## GraphQL 库中的远程代码执行风险  
  
此外，GitLab 还解决了 Ruby graphql 库中发现的“高”严重性漏洞 CVE-2025-27407。  
  
此漏洞存在特别令人担忧的风险，因为它可能在特定情况下启用远程代码执行。   
  
如果攻击者控制的经过身份验证的用户帐户尝试通过直接传输功能传输恶意制作的项目，则可以利用此漏洞，该功能目前处于测试阶段，并且默认情况下对所有自管理的 GitLab 实例禁用。  
  
无法立即更新的组织可以通过确保直接传输功能保持禁用状态来降低这种风险，这是自管理安装的默认状态。   
  
GitLab 已对安全研究员“yvvdwf”的工作表示感谢，他通过他们的 HackerOne漏洞赏金计划报告了此漏洞，同时也对 ruby-graphql 的 Robert Mosolgo 在跨供应商披露和补救工作上的合作表示感谢。  
  
<table><tbody><tr style="background-color: rgb(240, 240, 240);"><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">风险因素</td><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">细节</td></tr><tr><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">受影响的产品</td><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">GitLab CE/EE，Ruby graphql 库</td></tr><tr style="background-color: rgb(240, 240, 240);"><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">影响</td><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">远程代码执行</td></tr><tr><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">漏洞利用前提条件</td><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">经过身份验证的用户帐户</td></tr><tr style="background-color: rgb(240, 240, 240);"><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">CVSS 3.1 分数</td><td style="padding: 2px 8px;border-color: rgba(0, 0, 0, 0);word-break: break-word;">高的</td></tr></tbody></table>## PostgreSQL 更新和错误修复  
  
作为此次安全版本的一部分，GitLab 还将其 PostgreSQL 版本升级到 14.17 和 16.8，以遵循 PostgreSQL 项目自身的安全更新。   
  
补丁版本包括各种错误修复，解决了特殊字符的搜索超时问题、项目存储库逻辑以及开发工具包组件的改进等问题。  
  
GitLab 已经在运行修补版本，这意味着云用户已受到保护，免受这些漏洞的影响。  
  
GitLab Dedicated 客户已被告知他们不需要立即采取行动，一旦他们的实例自动修补，他们就会收到通知。  
  
安全专家建议运行 GitLab 的组织尽快实施这些更新，尤其是使用SAML 身份验证或考虑启用直接传输功能的组织。  
  
来源：https://cybersecuritynews.com/gitlab-warns-of-multiple-vulnerabilities/  
  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】PHP XXE 注入漏洞让攻击者读取配置文件和私钥](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068467&idx=2&sn=8209e2048ee474d6b91f16029aa9c134&scene=21#wechat_redirect)  
  
  
  
[【安全圈】施乐打印机漏洞使攻击者能够从 LDAP 和 SMB 中获取身份验证数据](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068467&idx=3&sn=a464bcdd8889a7e0e65921296df9fdd8&scene=21#wechat_redirect)  
  
  
  
[【安全圈】谷歌警告 Chromecast 用户不要恢复出厂设置](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068467&idx=4&sn=7af960ec5a3791a46142d0250eee6895&scene=21#wechat_redirect)  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068401&idx=1&sn=5600b75d725f6e90a4cbfddf6a7e10cc&scene=21#wechat_redirect)  
[【安全圈】美国政府称 2024 年美国人因欺诈损失创纪录 125 亿美元](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068449&idx=1&sn=7aa71495a16a8590c5a5dbaf2a299a09&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
