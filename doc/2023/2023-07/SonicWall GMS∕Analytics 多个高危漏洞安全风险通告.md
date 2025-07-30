#  SonicWall GMS/Analytics 多个高危漏洞安全风险通告   
 奇安信 CERT   2023-07-13 16:58  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody><tr><td valign="middle" align="center" rowspan="1" colspan="4" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #ffffff;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;">漏洞概述</span></strong><br/></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="104"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;letter-spacing: 0px;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">SonicWall GMS/Analytics多个高危漏洞</span></p></td></tr><tr><td valign="middle" align="left" rowspan="1" colspan="1" style="border-color: #4676d9;" width="104"><p style="line-height:1em;"><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞编号</strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">CVE-2023-34133、CVE-2023-34124、CVE-2023-34137</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="104"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">公开时间</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="222"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2023-07-12</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="151"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">影响对象数量级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="80"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">十万级</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="104"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="222"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #ff0000;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高危</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="151"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;">CVSS 3.1分数</strong></span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="80"><p style="line-height: 1em;"><strong><span style="text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-size: 13px;color: #ff0000;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">9.8</span></strong></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="104"><p style="line-height: 1em;"><span style="font-size:13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">威胁类型</span></strong><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"></span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="222"><p style="line-height: 1em;"><span style="font-size:13px;">代码执行、身份认证绕过</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="151"><p style="line-height:1em;"><strong><span style="font-size:13px;">利用可能性</span></strong></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="80"><p style="line-height: 1em;"><span style="color:#ff0000;"><span style="font-size: 13px;color: #ffc000;"><strong>中</strong></span></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="104"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="222"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="151"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="80"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="104"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="222"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="151"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="80"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td></tr><tr><td valign="middle" colspan="4" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><strong><span style="font-size:13px;">危害描述：</span></strong><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">未经身份验证的远程攻击者利用这些漏洞可以获取敏感信息或执行危险操作。</span></p></td></tr></tbody></table>  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
SonicWall Global Management System (GMS) Series为组织、分布式企业和服务提供商提供了一个强大、直观的解决方案，可以快速部署和集中管理 SonicWall防火墙、反垃圾邮件、备份和恢复以及安全远程访问解决方案。  
  
  
SonicWall Analytics 是高性能管理和报告引擎，可以实现即时查看网络和用户的威胁情报。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT监测到SonicWall官方发布的安全风险通告中包括多个高危漏洞，**SonicWall GMS/Analytics SQL注入漏洞(CVE-2023-34133)**  
、**SonicWall GMS/Analytics Web服务身份认证绕过漏洞(CVE-2023-34124)**  
、**SonicWall GMS/Analytics CAS 身份验证绕过漏洞(CVE-2023-34137)**  
。未经身份验证的远程攻击者利用这些漏洞可以获取敏感信息或执行危险操作。  
**鉴于这些漏洞影响范围较大，建议用户尽快自查更新。**  
  
<table><tbody><tr><td valign="middle" style="border-width: 1px;border-style: solid;border-color: #4676d9;background-color: #4676d9;" align="left"><p style="line-height: 1.5em;"><strong><span style="font-size: 13px;letter-spacing: 0.5px;color: #ffffff;">漏洞名称</span></strong></p></td><td valign="middle" style="border-width: 1px;border-style: solid;border-color: #4676d9;background-color: #4676d9;" align="left"><p style="line-height: 1.5em;"><strong><span style="font-size: 13px;letter-spacing: 0.5px;color: #ffffff;">漏洞描述</span></strong></p></td></tr><tr><td valign="middle" style="border-width: 1px;border-style: solid;border-color: #4676d9;" align="left"><p style="line-height: 1.5em;"><span style="font-size: 13px;letter-spacing: 0.5px;">SonicWall GMS/Analytics SQL注入漏洞(CVE-2023-34133)</span></p></td><td valign="middle" style="border-width: 1px;border-style: solid;border-color: #4676d9;" align="left"><p style="line-height: 1.5em;"><span style="font-size: 13px;letter-spacing: 0.5px;">SonicWall GMS/Analytics中存在SQL注入漏洞，未经身份认证的远程攻击者利用该漏洞可以执行SQL语句获取敏感信息，进一步利用可能获取目标系统权限等。</span></p></td></tr><tr><td valign="middle" style="border-width: 1px;border-style: solid;border-color: #4676d9;" align="left"><p style="line-height: 1.5em;"><span style="font-size: 13px;letter-spacing: 0.5px;">SonicWall GMS/Analytics Web服务身份认证绕过漏洞(CVE-2023-34124)</span></p></td><td valign="middle" style="border-width: 1px;border-style: solid;border-color: #4676d9;" align="left"><p style="line-height: 1.5em;"><span style="font-size: 13px;letter-spacing: 0.5px;">SonicWall GMS/Analytics中存在Web 服务身份验证绕过漏洞，未经身份认证的远程攻击者利用该漏洞可以绕过身份认证登录系统，获取敏感信息或执行敏感操作。</span></p></td></tr><tr><td valign="middle" style="border-width: 1px;border-style: solid;border-color: #4676d9;" align="left"><p style="line-height: 1.5em;"><span style="font-size: 13px;letter-spacing: 0.5px;">SonicWall GMS/Analytics CAS 身份验证绕过漏洞(CVE-2023-34137)</span></p></td><td valign="middle" style="border-width: 1px;border-style: solid;border-color: #4676d9;" align="left"><p style="line-height: 1.5em;"><span style="font-size: 13px;letter-spacing: 0.5px;">SonicWall GMS/Analytics中存在CAS 身份验证绕过漏洞，未经身份认证的远程攻击者利用该漏洞可以绕过身份认证登录系统，获取敏感信息或执行敏感操作。</span></p></td></tr></tbody></table>  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
SonicWall GMS <= 9.3.2-SP1   
  
SonicWall Analytics <= 2.5.0.4-R7  
  
  
**>**  
**>**  
**>**  
**>**  
  
**其他受影响组件**  
  
  
无  
  
  
**03**  
  
**处置建议**  
  
**>**  
**>**  
**>**  
**>**  
  
**安全更新**  
  
目前官方已发布安全版本修复该漏洞，建议受影响用户尽快更新安全版本：  
  
SonicWall GMS 9.3.3及以上  
  
SonicWall Analytics 2.5.2及以上  
  
  
部署指南详见：  
  
**1、GMS 9.3.x：**  
  
https://www.sonicwall.com/techdocs/pdf/gms-9-3-upgrade-guide.pdf  
  
**2、Analytics 2.5.x ：**  
  
https://www.sonicwall.com/techdocs/pdf/232-005167-00_RevC_Analytics_2.5_ESXi_DeploymentGuide.pdf  
  
https://www.sonicwall.com/techdocs/pdf/232-004743-00_RevD_On-Prem_Analytics_Hyper-V_DeploymentGuide.pdf  
  
https://www.sonicwall.com/techdocs/pdf/232-004741-00_RevE_Analytics_2.5_Azure_DeploymentGuide.pdf  
  
  
更多信息请参考：  
  
https://www.sonicwall.com/support/product-notification/urgent-security-notice-sonicwall-gms-analytics-impacted-by-suite-of-vulnerabilities/230710150218060/  
  
  
  
**04**  
  
**参考资料**  
  
[1]https://www.sonicwall.com/support/product-notification/urgent-security-notice-sonicwall-gms-analytics-impacted-by-suite-of-vulnerabilities/230710150218060/  
  
  
  
**05**  
  
**时间线**  
  
2023年7月13日，奇安信 CERT发布安全风险通告。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs48Q38jiaKibXicJC1XMdSe9dnBiaib9fAjmLEDdPia9hSzoEtP8u8BZ1mZwv6Kh9HCaXE0UjlQUFqI6pmaw/640 "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到**NOX安全监测平台**  
查看更多漏洞信息。  
  
