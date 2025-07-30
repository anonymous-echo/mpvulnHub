#  NetScaler ADC 和 NetScaler Gateway 多个在野漏洞安全风险通告   
 奇安信 CERT   2024-01-17 16:37  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody><tr><td valign="middle" align="center" rowspan="1" colspan="4" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 1.5em;"><span style="color: #ffffff;letter-spacing: 0px;"><strong><span style="color: #ffffff;font-size: 13px;letter-spacing: 0px;">漏洞概述</span></strong><br/></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="113"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;caret-color: red;letter-spacing: 0px;">NetScaler ADC和NetScaler Gateway 多个在野漏洞</span></p></td></tr><tr><td valign="middle" align="left" rowspan="1" colspan="1" style="border-color: #4676d9;" width="113"><p style="line-height:1em;"><span style="font-family:微软雅黑, Microsoft YaHei;"><span style="font-size: 13px;"><strong>漏洞编号</strong></span></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">CVE-2023-6548,CVE-2023-6549</span></p></td></tr><tr><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="113"><p style="line-height:1em;"><strong><span style="font-size:13px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">公开时间</span></strong></span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="191"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2024-01-17</span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="151"><p style="line-height:1em;"><strong><span style="font-size:13px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">影响量级</span></strong></span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="102"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">十万级</span></p></td></tr><tr><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="113"><p style="line-height:1em;"><span style="font-size:13px;"><strong>威胁类型</strong></span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="191"><p style="line-height:1em;"><span style="font-size: 13px;">代码执行,拒绝服务</span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="151"><p style="line-height:1em;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;">利用可能性</span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="102"><p style="line-height:1em;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;color: #ff0000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;">高</span></strong></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="113"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="191"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="151"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="102"><p style="line-height: 1em;"><span style="color:#ff0000;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">已发现</span></strong></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="113"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="191"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="151"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="102"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td></tr><tr><td valign="middle" colspan="4" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><strong><span style="font-size:13px;">利用条件：</span></strong><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;caret-color: red;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">CVE-2023-6548 需低权限 ，通过管理界面访问 NSIP、CLIP 或 SNIP；</span><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;caret-color: red;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">CVE-2023-6549 设备必须配置为网关（VPN 虚拟服务器、ICA 代理、CVPN、RDP 代理）或 AAA 虚拟服务器。</span></p></td></tr></tbody></table>  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
Citrix NetScaler Gateway（以前称为Citrix Gateway）和NetScaler ADC（以前称为Citrix ADC）都是Citrix公司的产品。Citrix NetScaler Gateway是一套安全的远程接入解决方案。该方案可为管理员提供应用级和数据级管控功能，以实现用户从任何地点远程访问应用和数据。Citrix Systems NetScaler ADC是一个应用程序交付和安全平台。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT监测到官方发布安全公告说明**NetScaler ADC 和 NetScaler Gateway代码执行漏洞(CVE-2023-6548)与NetScaler ADC 和 NetScaler Gateway 拒绝服务漏洞(CVE-2023-6549)****存在在野利用**  
。具有低权限的相邻网络的攻击者可通过管理界面访问 NSIP、CLIP 或 SNIP后利用CVE-2023-6548在系统上执行代码；未经身份验证的远程攻击者利用CVE-2023-6549可以造成系统拒绝服务。  
  
  
**鉴于这些漏洞影响范围较大，且已监测到在野利用，建议客户尽快做好自查及防护。**  
  
<table><tbody><tr><td valign="middle" align="center" style="background-color: #4676d9;border-color: #4676d9;" width="178"><strong><span style="font-size: 14px;letter-spacing: 0px;color: #ffffff;">漏洞名称</span></strong></td><td valign="middle" align="center" style="background-color: #4676d9;border-color: #4676d9;" width="379"><strong><span style="font-size: 14px;letter-spacing: 0px;color: #ffffff;">漏洞描述</span></strong></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="178"><span style="font-size: 14px;letter-spacing: 0px;">NetScaler ADC 和 NetScaler Gateway代码执行漏洞(CVE-2023-6548)</span></td><td valign="middle" align="left" style="border-color: #4676d9;" width="379"><span style="font-size: 14px;letter-spacing: 0px;">NetScaler ADC 和 NetScaler Gateway上存在代码注入漏洞，相邻网络上具有低权限的攻击者可通过管理界面访问 NSIP、CLIP 或 SNIP后利用该漏洞在系统上执行代码。</span></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="178"><span style="font-size: 14px;letter-spacing: 0px;">NetScaler ADC 和 NetScaler Gateway拒绝服务漏洞(CVE-2023-6549)</span></td><td valign="middle" align="left" style="border-color: #4676d9;" width="379"><span style="font-size: 14px;letter-spacing: 0px;">NetScaler ADC 和 NetScaler Gateway上存在内存溢出漏洞，未经身份验证的远程攻击者利用该漏洞可以造成系统拒绝服务。</span></td></tr></tbody></table>  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
NetScaler ADC and NetScaler Gateway 14.1.x < 14.1-12.35  
  
NetScaler ADC and NetScaler Gateway 13.1.x <13.1-51.15  
  
NetScaler ADC and NetScaler Gateway 13.0.x < 13.0-92.21  
  
NetScaler ADC 13.1-FIPS.x < 13.1-37.176  
  
NetScaler ADC 12.1-FIPS.x < 12.1-55.302  
  
NetScaler ADC 12.1-NDcPP.x < 12.1-55.302****  
  
**注意：**  
NetScaler ADC 和 NetScaler Gateway 版本 12.1 现已停产 (EOL)，并且容易受到攻击。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**其他受影响组件**  
  
无  
  
  
**03**  
  
**受影响资产情况**  
  
奇安信鹰图资产测绘平台数据显示，NetScaler ADC和NetScaler Gateway代码执行漏洞(CVE-2023-6548)与拒绝服务漏洞(CVE-2023-6549)关联的国内风险资产总数为173434个，关联IP总数为2456个。国内风险资产分布情况如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibvrEr91YCcic4b9TKjUNqQqca3MO2thAwfxrIibDk7maShr8VtfED5HPBWGpLqJD5XVhxHO4zyWBXg/640 "")  
  
  
NetScaler ADC和NetScaler Gateway代码执行漏洞(CVE-2023-6548)与拒绝服务漏洞(CVE-2023-6549)关联的全球风险资产总数为425325个，关联IP总数为28124个。全球风险资产分布情况如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibvrEr91YCcic4b9TKjUNqQqrZTdnh3QkyCzkMicmyCrJbTsY2iaX1mwQnarhBL42Wquw2SZapteLLDA/640 "")  
  
  
  
  
**04**  
  
**处置建议**  
  
**>**  
**>**  
**>**  
**>**  
  
**安全更新**  
  
目前，Citrix官方已发布漏洞修复补丁，建议受影响的NetScaler ADC和NetScaler Gateway客户尽快安装相应版本：  
  
NetScaler ADC and NetScaler Gateway 14.1.x >= 14.1-12.35  
  
NetScaler ADC and NetScaler Gateway 13.1.x >=13.1-51.15  
  
NetScaler ADC and NetScaler Gateway 13.0.x >= 13.0-92.21  
  
NetScaler ADC 13.1-FIPS.x >= 13.1-37.176  
  
NetScaler ADC 12.1-FIPS.x >= 12.1-55.302  
  
NetScaler ADC 12.1-NDcPP.x >= 12.1-55.302  
  
注意：NetScaler ADC 和 NetScaler Gateway 版本 12.1 现已停产 (EOL)。建议客户将其设备升级到可解决漏洞的受支持版本之一。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**缓解措施**  
  
CVE-2023-6548只影响管理接口。建议将流向设备管理接口的网络流量与正常的网络流量通过物理或逻辑方式进行分离。此外，不要将管理接口暴露在互联网上。  
  
  
  
**05**  
  
**参考资料**  
  
[1]https://support.citrix.com/article/CTX584986/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve20236548-and-cve20236549  
  
  
  
**06**  
  
**时间线**  
  
2024年1月17日，奇安信 CERT发布安全风险通告。  
  
  
  
**07**  
  
**漏洞情报服务**  
  
奇安信ALPHA威胁分析平台已支持漏洞情报订阅服务：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibvrEr91YCcic4b9TKjUNqQqEp0iaKHB9DJO0pamKYPWdNYziaQG2ru8ibMicjgllATLDRyz1zFQzNJX1w/640 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs49Igdxlxc1q7BeE5iboX6paDVVsREZWW2IdEchn6jxzl58jEzK9ac28icrV76htzjib85icjXstPS5VmQ/640 "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到  
**ALHA威胁分析平台**  
订阅更多漏洞信息。  
  
