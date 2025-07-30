#  【已复现】泛微E-Cology XML外部实体注入漏洞安全风险通告   
原创 QAX CERT  奇安信 CERT   2023-07-13 16:58  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody><tr><td valign="middle" align="center" rowspan="1" colspan="4" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #ffffff;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;">漏洞概述</span></strong><br/></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="125"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;letter-spacing: 0px;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">泛微E-Cology XML外部实体注入漏洞</span></p></td></tr><tr><td valign="middle" align="left" rowspan="1" colspan="1" style="border-color: #4676d9;" width="125"><p style="line-height:1em;"><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞编号</strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2023-16177</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="125"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">公开时间</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="180"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2023-07-11</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="158"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">影响对象数量级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="94"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">万级</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="125"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="180"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #ff0000;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高危</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="158"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;">CVSS 3.1分数</strong></span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="94"><p style="line-height: 1em;"><strong><span style="text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-size: 13px;color: #ff0000;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">9.4</span></strong></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="125"><p style="line-height: 1em;"><span style="font-size:13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">威胁类型</span></strong><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"></span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="180"><p style="line-height: 1em;"><span style="font-size:13px;">代码执行,信息泄露</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="158"><p style="line-height:1em;"><strong><span style="font-size:13px;">利用可能性</span></strong></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="94"><p style="line-height: 1em;"><span style="color: #ff0000;"><strong><span style="font-size: 13px;">高</span></strong></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="125"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="180"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="158"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="94"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="125"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="180"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="158"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="94"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td></tr><tr><td valign="middle" colspan="4" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><strong><span style="font-size:13px;">危害描述：</span></strong><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">远</span><span style="font-size: 13px;letter-spacing: 0px;caret-color: red;">程未授权攻击者可绕过现有防护实现 XML 外部实体注入，最终可能造成敏感信息泄露，且进一步配合其他漏洞可能造成RCE等危害。</span></p></td></tr></tbody></table>  
  
  
**（注：奇安信CERT的漏洞深度分析报告包含此漏洞的POC及技术细节，订阅方式见文末。）**  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
泛微协同管理应用平台E-Cology是一套兼具企业信息门户、知识文档管理、工作流程管理、人力资源管理、客户关系管理、项目管理、财务管理、资产管理、供应链管理、数据中心功能的企业大型协同管理平台。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT监测到厂商发布安全补丁更新，修复**泛微E-Cology XML外部实体注入漏洞(QVD-2023-16177)**  
。由于后台逻辑对 XXE 漏洞防护存在缺陷，导致远程未授权攻击者可绕过现有防护实现 XML 外部实体注入，最终可能造成敏感信息泄露，且进一步配合其他漏洞可能造成RCE等危害。  
**鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。**  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
泛微 EC 9.x 且补丁版本 < 10.58.2  
  
泛微 EC 8.x 且补丁版本 < 10.58.2  
  
  
**>**  
**>**  
**>**  
**>**  
  
**其他受影响组件**  
  
无  
  
  
  
**03**  
  
**复现情况**  
  
目前，奇安信CERT已成功复现此漏洞，截图如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibOdxXQIibEpSV3eMLe60bnPvpv3EDfVG3E6fw97KKrmaVCG6xibmgFSZvqtoYGBdMibNvYWAtSMHB0Q/640 "")  
  
  
  
  
**04**  
  
**处置建议**  
  
**>**  
**>**  
**>**  
**>**  
  
**安全更新**  
  
目前官方已发布10.58.2来修复此漏洞，建议受影响用户更新至10.58.2：  
  
https://www.weaver.com.cn/cs/securityDownload.html#  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibOdxXQIibEpSV3eMLe60bnPhFWibHOf7So3LVAygrVbhKGDLrmNuRJBdiaghNNnDZzjwThWd3EC33Lg/640 "")  
  
  
  
**>**  
**>**  
**>**  
**>**  
  
**产品解决方案**  
  
**奇安信网神网络数据传感器系统产品检测方案**  
  
奇安信网神网络数据传感器（NDS5000/7000/9000系列）产品，已具备该漏洞的检测能力。规则ID为：7809，建议用户尽快升级检测规则库至2307131200以上。  
  
  
**奇安信网站应用安全云防护系统检测方案**  
  
奇安信网神网站应用安全云防护系统已全局更新所有云端防护节点的防护规则，支持对泛微E-Cology XML外部实体注入漏洞(QVD-2023-16177)的防护。  
  
  
**奇安信天眼产品解决方案**  
  
奇安信天眼新一代威胁感知系统在第一时间加入了该漏洞的检测规则，请将规则包升级到3.0.0713.13967上版本。规则名称：泛微E-Cology XML外部实体注入漏洞，规则ID：0x100216F4。奇安信天眼流量探针（传感器）升级方法：系统配置->设备升级->规则升级，选择“网络升级”或“本地升级”。  
  
  
**Snort检测方案**  
  
Snort是一个开源的入侵检测系统，使用规则来检测网络流量中的恶意行为。用户可参考以下Snort检测规则，进行检测：  
  
alert tcp any any -> any any (msg:"Weaver E-Cology XXE"; content:"rest"; http_uri; content:"ofs"; http_uri; content:"ByXml"; http_uri; pcre:"/\b(SYSTEM|PUBLIC)\b/i"; classtype:web-application-attack; sid:1000002; rev:1;)  
  
  
**05**  
  
**参考资料**  
  
[1]https://www.weaver.com.cn/cs/securityDownload.asp  
  
  
  
**06**  
  
**时间线**  
  
2023年7月13日，奇安信 CERT发布安全风险通告。  
  
  
  
**07**  
  
**深度分析报告**  
  
深度分析报告（含PoC和技术细节）已开通订阅，扫描图片  
下方二维码申请：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs48Q38jiaKibXicJC1XMdSe9dnBPKpwgBDGIuBJD1zib5Ob4G47GdNq5PdycfhEEUdxyFZBdcJRkGRA71g/640 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs48Q38jiaKibXicJC1XMdSe9dnBiaib9fAjmLEDdPia9hSzoEtP8u8BZ1mZwv6Kh9HCaXE0UjlQUFqI6pmaw/640 "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到**NOX安全监测平台**  
查看更多漏洞信息。  
  
