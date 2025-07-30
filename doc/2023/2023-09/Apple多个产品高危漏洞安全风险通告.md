#  Apple多个产品高危漏洞安全风险通告   
 奇安信 CERT   2023-09-08 13:52  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody><tr><td valign="middle" align="center" rowspan="1" colspan="4" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 1.5em;"><span style="color: #ffffff;letter-spacing: 0px;"><strong><span style="color: #ffffff;font-size: 13px;letter-spacing: 0px;">漏洞概述</span></strong><br/></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="132"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;caret-color: red;letter-spacing: 0px;">Apple多个产品高危漏洞</span></p></td></tr><tr><td valign="middle" align="left" rowspan="1" colspan="1" style="border-color: #4676d9;" width="132"><p style="line-height:1em;"><span style="font-family:微软雅黑, Microsoft YaHei;"><span style="font-size: 13px;"><strong>漏洞编号</strong></span></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">CVE-2023-41064、CVE-2023-41061</span></p></td></tr><tr><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="132"><p style="line-height:1em;"><strong><span style="font-size:13px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">公开时间</span></strong></span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="152"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2023-09-08</span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="178"><p style="line-height:1em;"><strong><span style="font-size:13px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">影响对象数量级</span></strong></span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="95"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">百万级</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="132"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;cursor: text;font-size: 13px;letter-spacing: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="152"><p style="line-height: 1em;"><span style="letter-spacing:0px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #ff0000;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;cursor: text;font-size: 13px;letter-spacing: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;">高危</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="178"><p style="line-height: 1em;"><strong><span style="font-size: 13px;letter-spacing: 0px;">CVSS 3.1分数</span></strong></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="95"><p style="line-height: 1em;"><span style="color: #ff0000;font-size: 13px;letter-spacing: 0px;"><strong>9.4</strong></span></p></td></tr><tr><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="132"><p style="line-height:1em;"><span style="font-size:13px;"><strong>威胁类型</strong></span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="152"><p style="line-height:1em;"><span style="font-size: 13px;">代码执行</span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="178"><p style="line-height:1em;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;">利用可能性</span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="95"><p style="line-height:1em;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;color: #ff0000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;">高</span></strong></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="132"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="152"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="178"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="95"><p style="line-height: 1em;"><span style="color:#ff0000;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">已发现</span></strong></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="132"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="152"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="178"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="95"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td></tr><tr><td valign="middle" colspan="4" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><strong><span style="font-size:13px;">危害描述：</span></strong><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">攻击者可利用漏洞在不与受害者进行任何交互的情况下执行任意代码。</span></p></td></tr></tbody></table>  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
iOS 、iPadOS系统是美国苹果（Apple）公司所研发的移动操作系统。为Apple公司多款产品提供相关功能。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本漏洞描述**  
  
近日，奇安信CERT监测到Apple官方发布了多个产品高危漏洞，包括两个任意代码执行漏洞，分别是**CVE-2023-41064**  
和**CVE-2023-41061**  
，这两个漏洞被称为**BLASTPASS漏洞利用链**  
，攻击者能够在不与受害者进行任何交互的情况下借助PassKit附件进行利用，从攻击者 iMessage 帐户发送恶意图像给受害者从而执行任意代码。  
  
  
**奇安信CERT监测到该利用链正在被NSO Group组织的 Pegasus 雇佣间谍软件所广泛利用，现实危害升级，建议客户尽快做好自查及防护。**  
  
****<table><tbody><tr><td valign="middle" style="background-color: #4676d9;border-color: #4676d9;" width="170" align="center"><p style="line-height: 2em;"><span style="color:#ffffff;"><strong><span style="font-size: 14px;color: #ffffff;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" style="background-color: #4676d9;border-color: #4676d9;" width="387" align="center"><p style="line-height: 2em;"><span style="color:#ffffff;"><strong><span style="color: #ffffff;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞描述</span></strong></span></p></td></tr><tr><td valign="top" style="border-color: #4676d9;" width="170"><p style="line-height: 2em;"><span style="font-family:微软雅黑, Microsoft YaHei;">Apple 多个产品任意代码执行漏洞(CVE-2023-41064)</span></p></td><td valign="top" style="border-color: #4676d9;" width="387"><p style="line-height: 2em;"><span style="font-family:微软雅黑, Microsoft YaHei;">Apple多个产品中存在缓冲区溢出漏洞，攻击者从 iMessage 帐户发送恶意图像给受害者，在不与受害者进行任何交互的情况下执行任意代码。</span></p></td></tr><tr><td valign="top" style="border-color: #4676d9;" width="170"><p style="line-height: 2em;"><span style="font-family:微软雅黑, Microsoft YaHei;">Apple 多个产品任意代码执行漏洞(CVE-2023-41061)</span></p></td><td valign="top" style="border-color: #4676d9;" width="387"><p style="line-height: 2em;"><span style="font-family:微软雅黑, Microsoft YaHei;">Apple多个产品中存在逻辑验证错误问题，攻击者借助恶意制作的PassKit附件，在不与受害者进行任何交互的情况下执行任意代码。</span></p></td></tr></tbody></table>  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
Apple 多个产品任意代码执行漏洞(CVE-2023-41064):  
  
macOS Ventura < 13.5.2  
  
iOS < 16.6.1  
  
iPadOS < 16.6.1   
  
  
Apple 多个产品任意代码执行漏洞(CVE-2023-41061):  
  
iOS < 16.6.1  
  
iPadOS < 16.6.1   
  
watchOS < 9.6.2  
  
  
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
  
目前，官方已发布最新版本修复这些漏洞，建议用户尽快更新设备。  
  
更新信息参考：  
  
https://support.apple.com/kb/HT213905  
  
https://support.apple.com/kb/HT213906  
  
https://support.apple.com/kb/HT213907  
  
  
**>**  
**>**  
**>**  
**>**  
  
**缓解措施**  
  
设备开启**锁定模式**  
。  
  
关于锁定模式请参考官方介绍：https://support.apple.com/en-ca/HT212650  
  
  
  
**04**  
  
**参考资料**  
  
[1]https://support.apple.com/kb/HT213905  
  
[2]https://support.apple.com/kb/HT213906  
  
[3]https://support.apple.com/kb/HT213907  
  
[4]https://support.apple.com/en-ca/HT212650  
  
  
  
**05**  
  
**时间线**  
  
2023年9月8日，奇安信 CERT发布安全风险通告。  
  
  
  
**06**  
  
**漏洞情报服务**  
  
奇安信ALPHA威胁分析平台已支持漏洞情报订阅服务：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs49lGI47ENnn1WC4iaL5OQJQic1kcN7h5ENWZQ3aWS8AekGiajWKaZOUI0GBITuaiah8hSfF9GycnndcyA/640 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs49lGI47ENnn1WC4iaL5OQJQicYSEHcLDKrXhx5Jku20SDpvkFiaDG2sBzJmnvA8Tia5CP9mcMXlwGibKUA/640 "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到  
**ALHA威胁分析平台**  
订阅更多漏洞信息。  
  
