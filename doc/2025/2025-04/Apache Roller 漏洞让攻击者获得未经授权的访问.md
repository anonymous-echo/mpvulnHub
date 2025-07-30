#  Apache Roller 漏洞让攻击者获得未经授权的访问   
邑安科技  邑安全   2025-04-16 08:45  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8sdyR6ic0M2acDAVJDe45WPqvicbyicz44VZnwXN56s6RuAvLQthohm1WD3dfxFP1qSibsqTDC2704s4w/640?wx_fmt=png&from=appmsg "")  
  
在 Apache Roller 中发现了一个严重的安全漏洞，允许攻击者在更改密码后保持对博客系统的未经授权的访问。  
  
漏洞 CVE-2025-24859 已获得 CVSS v4 的最高评分 10，表明受影响的系统面临严重风险。  
  
该安全漏洞源于 Apache Roller 版本 1.0.0 到 6.1.4 中的基本会话管理问题。  
  
当用户或管理员更改帐户密码时，系统无法使现有活动会话失效。这种关键的疏忽意味着，即使在凭据更改后，所有预先存在的会话仍能完全正常运行。  
  
“在 6.1.5 版本之前的 Apache Roller 中存在会话管理漏洞，其中活动用户会话在更改密码后无法正确失效，”公告中写道。  
  
Apache Roller 漏洞  
  
“即使在更改密码后，这也允许通过旧会话继续访问应用程序，如果凭据被盗用，则可能会启用未经授权的访问。”  
  
安全研究员 Haining Meng 发现了该漏洞，该漏洞已被确认会影响所有尚未更新到最新版本的 Apache Roller 安装。  
  
对于组织博客部署，其影响尤其令人担忧，因为凭据泄露是常见的第一响应触发因素。  
  
漏洞摘要如下：  
<table><tbody><tr><td><strong msttexthash="14330498" msthash="70"><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;"><span textstyle="" style="font-size: 15px;">风险因素</span></span></strong></td><td><strong msttexthash="3259074" msthash="71"><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;"><span textstyle="" style="font-size: 15px;">详</span></span></strong></td></tr><tr><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;"><span textstyle="" style="font-size: 15px;">受影响的产品</span></span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;"><span textstyle="" style="font-size: 15px;">Apache Roller 1.0.0 &lt; 6.1.5</span></span></section></td></tr><tr><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;"><span textstyle="" style="font-size: 15px;">冲击</span></span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;"><span textstyle="" style="font-size: 15px;">更改密码后通过活动会话进行未经授权的访问;会话劫持风险;机密性、完整性和可用性都处于高风险状态。</span></span></section></td></tr><tr><td><font mstmutation="1" msttexthash="17124536" msthash="76"><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;"><span textstyle="" style="font-size: 15px;">利用先决条件</span></span></font><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;"><br/></span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;"><span textstyle="" style="font-size: 15px;">在更改密码之前访问有效会话;无需用户交互;攻击复杂度低。</span></span></section></td></tr><tr><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;"><span textstyle="" style="font-size: 15px;">CVSS 3.1 分数</span></span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;"><span textstyle="" style="font-size: 15px;">10.0（严重）</span></span></section></td></tr></tbody></table>  
该漏洞造成了标准安全实践失效的场景。  
  
当怀疑凭据被盗用时，立即响应通常是更改密码——但有了这个缺陷，已经建立会话的攻击者可以继续在系统内不受阻碍地作。  
  
技术问题涉及缺乏集中式会话管理，无法在凭据更改时正确跟踪和终止活动会话。  
  
相反，受影响的版本会维护独立的会话状态，这些状态不会与身份验证更改正确同步。  
  
Apache Roller 是一个基于 Java 的博客平台，作为 Web 应用程序在 Java EE 服务器上运行，广泛用于个人博客和企业级发布系统。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8sdyR6ic0M2acDAVJDe45WPqz1hFaUAh81sicDkmGE2FbWlQXToibjNYepYKUgAEz9liaB2YcFYvDyW4Q/640?wx_fmt=png&from=appmsg "")  
  
它的多用户功能使其在组织部署中很受欢迎，这可能会放大此漏洞的影响。Apache Software Foundation 已解决与披露同时发布的 Apache Roller 6.1.5 中的漏洞。  
  
修补版本实施了适当的集中式会话管理，确保在更改密码或禁用用户帐户时立即终止所有活动会话。  
  
强烈建议 Apache Roller 用户尽快更新到 6.1.5 版本，以降低此安全风险。  
  
对于无法立即更新的组织，安全专家建议实施额外的保护层：  
  
通过应用程序日志密切监控所有会话活动  
  
实施网络级控制以限制对 Roller 实例的访问  
  
如果受影响的系统包含敏感信息，请考虑暂时禁用受影响的系统  
  
这不是影响 Apache Roller 的第一个安全问题。以前的漏洞包括 5.0.2 之前版本中通过 OGNL 注入实现的远程代码执行缺陷 （CVE-2013-4212），以及允许在版本 5.0.3 中泄露文件的 XML 外部实体注入漏洞 （CVE-2014-0030）。  
  
由于该漏洞的严重性以及攻击者很容易利用该漏洞，因此敦促管理员优先考虑此更新。  
  
原文来自: cybersecuritynews.com  
  
原文链接:   
https://cybersecuritynews.com/apache-roller-vulnerability/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
