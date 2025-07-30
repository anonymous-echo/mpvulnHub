#  Roundcube Webmail 多个XSS高危漏洞安全风险通告   
 奇安信 CERT   2024-08-06 14:15  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr style="outline: 0px;visibility: visible;"><td valign="middle" align="center" rowspan="1" colspan="4" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);background-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;color: rgb(255, 255, 255);letter-spacing: 0px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;letter-spacing: 0px;visibility: visible;">漏洞概述</span></strong><br style="outline: 0px;visibility: visible;"/></span></p></td></tr><tr style="outline: 0px;visibility: visible;"><td valign="middle" align="left" width="136" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;font-size: 13px;letter-spacing: 0px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;color: rgb(0, 0, 0);font-size: 13px;caret-color: rgb(255, 0, 0);letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">Roundcube Webmail 多个XSS高危漏洞</span></p></td></tr><tr style="outline: 0px;visibility: visible;"><td valign="middle" align="left" rowspan="1" colspan="1" width="136" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><strong style="outline: 0px;visibility: visible;">漏洞编号</strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;color: rgb(0, 0, 0);font-size: 13px;caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">CVE-2024-42008、CVE-2024-42009</span></p></td></tr><tr style="outline: 0px;visibility: visible;"><td valign="middle" align="left" width="136" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;font-size: 13px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">公开时间</span></strong></span></p></td><td valign="middle" align="left" width="157" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">2024-08-04</span></p></td><td valign="middle" align="left" width="169" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;font-size: 13px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">影响量级</span></strong></span></p></td><td valign="middle" align="left" width="95" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);line-height: 1em;visibility: visible;letter-spacing: 0.544px;"><p style="outline: 0px;line-height: 1em;visibility: visible;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);letter-spacing: 0.544px;"><span style="outline: 0px;font-size: 13px;visibility: visible;">十万级</span></p></td></tr><tr style="outline: 0px;visibility: visible;"><td valign="middle" align="left" width="136" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;font-size: 13px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" width="157" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><strong style="cursor: text;color: rgb(0, 0, 0);caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;visibility: visible;max-inline-size: 100%;outline: none 0px !important;"><span style="cursor: text;color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;max-inline-size: 100%;outline: none 0px !important;">高危</span></strong></span></p></td><td valign="middle" align="left" width="169" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;font-size: 13px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><strong style="cursor: text;color: rgb(0, 0, 0);caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;visibility: visible;max-inline-size: 100%;outline: none 0px !important;">CVSS 3.1分数</strong></span></strong></span></p></td><td valign="middle" align="left" width="95" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;caret-color: rgb(255, 0, 0);font-size: 13px;color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">9.8</span></strong></p></td></tr><tr style="outline: 0px;visibility: visible;"><td valign="middle" align="left" width="136" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;font-size: 13px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">威胁类型</span></strong><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"></span></strong></span></p></td><td valign="middle" align="left" width="157" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;font-size: 13px;visibility: visible;">代码执行</span></p></td><td valign="middle" align="left" width="169" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;visibility: visible;">利用可能性</span></strong></p></td><td valign="middle" align="left" width="95" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;color: rgb(255, 0, 0);visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;visibility: visible;">高</span></strong></span></p></td></tr><tr style="outline: 0px;visibility: visible;"><td valign="middle" colspan="1" rowspan="1" align="left" width="136" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;font-size: 13px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="157" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;color: rgb(255, 0, 0);font-size: 13px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><span style="outline: 0px;color: rgb(0, 0, 0);letter-spacing: 0.544px;visibility: visible;"></span></span></strong></span><span style="outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;font-size: 13px;letter-spacing: 0.544px;visibility: visible;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="169" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;font-size: 13px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="95" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);line-height: 1em;visibility: visible;letter-spacing: 0.544px;"><p style="outline: 0px;line-height: 1em;visibility: visible;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);letter-spacing: 0.544px;"><span style="outline: 0px;font-size: 13px;visibility: visible;">未发现</span></p></td></tr><tr style="outline: 0px;visibility: visible;"><td valign="middle" colspan="1" rowspan="1" align="left" width="136" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;font-size: 13px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="157" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);line-height: 1em;visibility: visible;letter-spacing: 0.544px;"><p style="outline: 0px;line-height: 1em;visibility: visible;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);letter-spacing: 0.544px;"><span style="outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;font-size: 13px;letter-spacing: 0.544px;visibility: visible;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="169" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;font-size: 13px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="95" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><span style="outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;font-size: 13px;letter-spacing: 0.544px;visibility: visible;">未公开</span><span style="outline: 0px;font-size: 13px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><span style="outline: 0px;color: rgb(0, 0, 0);letter-spacing: 0.544px;visibility: visible;"></span></span></strong></span></p></td></tr><tr style="outline: 0px;visibility: visible;"><td valign="middle" colspan="4" rowspan="1" align="left" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;line-height: 1em;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;visibility: visible;">危害描述：</span></strong><span style="outline: 0px;font-size: 13px;letter-spacing: 0.544px;visibility: visible;"><span style="outline: 0px;letter-spacing: 0.544px;visibility: visible;"></span>未经身份验证的攻击者可以窃取电子邮件、联系人和密码等敏感信息。<span style="outline: 0px;letter-spacing: 0.544px;visibility: visible;"></span></span></p></td></tr></tbody></table>  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
Roundcube Webmail是一个开源的基于Web的电子邮件客户端，使用户能够随时随地访问和处理他们的电子邮件。  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT监测到官方修复**Roundcube Webmail 跨站脚本漏洞(CVE-2024-42008)**和**Roundcube Webmail 跨站脚本漏洞(CVE-2024-42009)**。Roundcube Webmail在处理HTML和SVG等附件的过程中存在跨站脚本漏洞。未经身份验证的攻击者可以窃取电子邮件、联系人和密码等敏感信息。  
**鉴于之前的Roundcube Webmai漏洞曾多次在2023年被APT28、Winter Vivern等APT组织利用过，建议客户尽快做好自查及防护。**  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
Roundcube Webmai < 1.6.8  
  
Roundcube Webmai < 1.5.8  
  
**>**  
**>**  
**>**  
**>**  
  
**其他受影响组件**  
  
无  
  
  
**03**  
  
**受影响资产情况**  
  
奇安信鹰图资产测绘平台数据显示，**Roundcube Webmail 跨站脚本漏洞(CVE-2024-42008)**和**Roundcube Webmail 跨站脚本漏洞(CVE-2024-42009)**关联的全球风险资产总数为3003195个，关联IP总数为342649个。全球风险资产分布情况如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icshasXShCm6C27W3D3gLT5Jw0icLFqljT9dibtjo9xYia60SiaKlJ9OichvcattAg6PUtveKYNO9xZWAA/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**处置建议**  
  
**>**  
**>**  
**>**  
**>**  
  
**安全更新**  
  
目前官方已发布更新补丁，请及时升级至最新版本：  
  
https://github.com/roundcube/roundcubemail/releases  
  
  
**05**  
  
**参考资料**  
  
[1]https://roundcube.net/news/2024/08/04/security-updates-1.6.8-and-1.5.8  
  
[2]https://www.sonarsource.com/blog/government-emails-at-risk-critical-cross-site-scripting-vulnerability-in-roundcube-webmail/  
  
  
**06**  
  
**时间线**  
  
2024年8月6日，奇安信 CERT发布安全风险通告。  
  
  
  
**07**  
  
**漏洞情报服务**  
  
奇安信ALPH  
A威胁分析平台已支持漏洞情报订阅服务：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibpFEkqfMZfO3smS6RKd9BY9IJ0MPzeiashvK2XLpdl3XtTtCD91h0jS26fqvuWpEMXgmXa85qLkoA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other&tp=webp "漏洞订阅上线.png")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibpFEkqfMZfO3smS6RKd9BYBVaibvBq1vXprZIc191LXKibdiaApA16q3UgmibQDv4yW09qT88J3jRUfA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other&tp=webp "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到**ALPHA威胁分析平台**  
订阅更多漏洞信息。  
  
