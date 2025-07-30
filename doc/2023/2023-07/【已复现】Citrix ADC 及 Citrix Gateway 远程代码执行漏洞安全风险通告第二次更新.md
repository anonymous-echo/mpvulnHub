#  【已复现】Citrix ADC 及 Citrix Gateway 远程代码执行漏洞安全风险通告第二次更新   
原创 QAX CERT  奇安信 CERT   2023-07-26 17:26  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody><tr><td valign="middle" align="center" rowspan="1" colspan="4" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #ffffff;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;">漏洞概述</span></strong><br/></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="127"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;letter-spacing: 0px;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Citrix ADC 及 Citrix Gateway 远程代码执行漏洞</span></p></td></tr><tr><td valign="middle" align="left" rowspan="1" colspan="1" style="border-color: #4676d9;" width="127"><p style="line-height:1em;"><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞编号</strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2023-16711、CVE-2023-3519</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="127"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">公开时间</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="153"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2023-07-19</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="178"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">影响对象数量级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="99"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">百万级</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="127"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="153"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #ff0000;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高危</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="178"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;">CVSS 3.1分数</strong></span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="99"><p style="line-height: 1em;"><strong><span style="text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-size: 13px;color: #ff0000;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">9.8</span></strong></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="127"><p style="line-height: 1em;"><span style="font-size:13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">威胁类型</span></strong><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"></span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="153"><p style="line-height: 1em;"><span style="font-size:13px;">代码执行</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="178"><p style="line-height:1em;"><strong><span style="font-size:13px;">利用可能性</span></strong></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="99"><p style="line-height: 1em;"><span style="color: #ff0000;"><strong><span style="font-size: 13px;">高</span></strong></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="127"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="153"><p style="line-height: 1em;"><span style="color:#ff0000;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">已公开</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="178"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="99"><p style="line-height: 1em;"><span style="color:#ff0000;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">已发现</span></strong></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="127"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="153"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="178"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="99"><p style="line-height: 1em;"><span style="color:#ff0000;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">已公开</span></strong></span></p></td></tr><tr><td valign="middle" colspan="4" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><strong><span style="font-size:13px;">利用条件：</span></strong><span style="font-size: 13px;letter-spacing: 0px;caret-color: red;">设备必须配置为网关（VPN 虚拟服务器、ICA 代理、CVPN、RDP 代理）或 AAA 虚拟服务器。</span></p></td></tr></tbody></table>  
  
  
**（注：奇安信CERT的漏洞深度分析报告包含此漏洞的POC及技术细节，订阅方式见文末。）**  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
Citrix Gateway是一套安全的远程接入解决方案，可提供应用级和数据级管控功能，以实现用户从任何地点远程访问应用和数据；Citrix ADC是一个应用程序交付和负载平衡解决方案，用于实现应用程序安全性、整体可见性和可用性。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT监测到**Citrix ADC 及 Citrix Gateway 远程代码执行漏洞(CVE-2023-3519)**  
，Citrix ADC 及 Citrix Gateway 中存在远程代码执行漏洞，远程未授权攻击者可利用此漏洞在目标设备上执行任意代码。**目前已监测到在野利用，同时近日监测到POC及技术细节在互联网上公开，奇安信CERT成功复现此漏洞POC。鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。**  
  
  
**本次更新内容：**  
  
**奇安信CERT已复现此漏洞，新增漏洞复现截图；**  
  
**更新漏洞现时威胁状态；**  
  
**新增奇安信产品线解决方案及Snort检测方案。**  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
NetScaler ADC 、NetScaler Gateway 13.1 < 13.1-49.13   
  
NetScaler ADC 、NetScaler Gateway 13.0 < 13.0-91.13   
  
NetScaler ADC 13.1-FIPS < 13.1-37.159  
  
NetScaler ADC 12.1-FIPS < 12.1-55.297  
  
NetScaler ADC 12.1-NDcPP < 12.1-55.297  
  
**注意：NetScaler ADC 和 NetScaler Gateway 12.1 版本现已终止生命周期 (EOL)，并且容易受到攻击。**  
  
  
**>**  
**>**  
**>**  
**>**  
  
**其他受影响组件**  
  
无  
  
  
  
**03**  
  
**复现情况**  
  
目前，奇安信CERT已成功复现**Citrix ADC及Citrix Gateway 远程代码执行漏洞(CVE-2023-3519) POC**  
，截图如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibicOmibBBx9ZVraqzfSmQpYnfGVf0ABWxMEqeAGscYEwnM6ZWPclTf47nRcrViaBrnx3RTNJp7y2WxQ/640 "")  
  
  
  
  
**04**  
  
**处置建议**  
  
**>**  
**>**  
**>**  
**>**  
  
**安全更新**  
  
目前官方已发布漏洞修复版本，其中**NetScaler ADC 和 NetScaler Gateway 12.1 版本现已终止生命周期 (EOL)**  
，强烈建议客户将受影响的NetScaler ADC和NetScaler Gateway设备升级到可解决漏洞的受支持版本之一：  
  
NetScaler ADC、NetScaler Gateway >= 13.1-49.13    
  
NetScaler ADC、NetScaler Gateway 13.0 >= 13.0-91.13   
  
NetScaler ADC 13.1-FIPS >= 13.1-37.159  
  
NetScaler ADC 12.1-FIPS >= 12.1-55.297   
  
NetScaler ADC 12.1-NDcPP >= 12.1-55.297  
  
https://support.citrix.com/article/CTX561482/citrix-adc-and-citrix-gateway-security-bulletin-for-cve20233519-cve20233466-cve20233467  
  
  
**>**  
**>**  
**>**  
**>**  
  
**缓解措施**  
  
避免开放至公网，仅对可信任网段开放。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**产品解决方案**  
  
**奇安信网站应用安全云防护系统已更新防护特征库**  
  
奇安信网神网站应用安全云防护系统已全局更新所有云端防护节点的防护规则，支持对Citrix ADC 及 Citrix Gateway 远程代码执行漏洞(CVE-2023-3519)的防护。  
  
  
**奇安信网神网络数据传感器系统产品检测方案**  
  
奇安信网神网络数据传感器（NDS5000/7000/9000系列）产品，已具备该漏洞的检测能力。规则ID为：7817，建议用户尽快升级检测规则库至2307261730以上；  
  
  
**奇安信天眼检测方案**  
  
奇安信天眼新一代安全感知系统已经能够有效检测针对该漏洞的攻击，请将规则版本升级到3.0.0726.13983或以上版本。规则ID及规则名称：0x1002170D，Citrix Gateway 远程代码执行漏洞(CVE-2023-3519)。奇安信天眼流量探针规则升级方法：系统配置->设备升级->规则升级，选择“网络升级”或“本地升级”。  
  
  
**Snort 检测方案**  
  
Snort是一个开源的入侵检测系统，使用规则来检测网络流量中的恶意行为。用户可参考以下Snort检测规则，进行检测：  
  
alert tcp any any -> any any (msg:"Citrix ADC and Citrix Gateway RCE"; flow:to_server,established; content:"GET"; http_method; uricontent:"/gwtest/formssso\?event=start&target="; http_uri; sid:1000001; rev:1;)  
  
  
**05**  
  
**参考资料**  
  
[1]https://support.citrix.com/article/CTX561482/citrix-adc-and-citrix-gateway-security-bulletin-for-cve20233519-cve20233466-cve20233467  
  
  
  
**06**  
  
**时间线**  
  
2023年7月19日，奇安信 CERT发布安全风险通告；  
  
2023年7月26日，奇安信 CERT发布安全风险通告第二次更新。  
  
  
  
**07**  
  
**深度分析报告**  
  
深度分析报告（含PoC和技术细节）已开通订阅，扫描图片  
下方二维码申请：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibicOmibBBx9ZVraqzfSmQpYn4Wnnk7q5w71BEicpmRyWRMwhndhvxNx5EicDibSBSdAFgwWR7Khfibj9hQ/640 "漏洞深度分析报告介绍（7.26）.png")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs48DkDCEJl9PFqjYwibcoIgYJhHoQIibOcc0APRabZWrSH9Qw7ZX50dCXb09iaof8T219K1FC0BicEibPRQ/640 "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到**NOX安全监测平台**  
查看更多漏洞信息。  
  
