#  Apple 多产品多个高危漏洞安全风险通告   
 奇安信 CERT   2023-09-22 14:30  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody><tr><td valign="middle" align="center" rowspan="1" colspan="4" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 1.5em;"><span style="color: #ffffff;letter-spacing: 0px;"><strong><span style="color: #ffffff;font-size: 13px;letter-spacing: 0px;">漏洞概述</span></strong><br/></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="88"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;caret-color: red;letter-spacing: 0px;">Apple 多产品多个高危漏洞</span></p></td></tr><tr><td valign="middle" align="left" rowspan="1" colspan="1" style="border-color: #4676d9;" width="88"><p style="line-height:1em;"><span style="font-family:微软雅黑, Microsoft YaHei;"><span style="font-size: 13px;"><strong>漏洞编号</strong></span></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">CVE-2023-41991、CVE-2023-41992、CVE-2023-41993</span></p></td></tr><tr><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="88"><p style="line-height:1em;"><strong><span style="font-size:13px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">公开时间</span></strong></span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="245"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2023-09-21</span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="119"><p style="line-height:1em;"><strong><span style="font-size:13px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">影响对象数量级</span></strong></span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="105"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">千万级</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="88"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;cursor: text;font-size: 13px;letter-spacing: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="245"><p style="line-height: 1em;"><span style="letter-spacing:0px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #ff0000;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;cursor: text;font-size: 13px;letter-spacing: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;">高危</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="119"><p style="line-height: 1em;"><strong><span style="font-size: 13px;letter-spacing: 0px;">利用可能性</span></strong><span style="font-size: 13px;letter-spacing: 0px;"></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="105"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;color: rgb(0, 0, 0);"><strong style="letter-spacing: 0.578px;text-align: -webkit-left;text-wrap: wrap;cursor: text;caret-color: rgb(255, 0, 0);color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;max-inline-size: 100%;outline: none 0px !important;"><span style="cursor: text;font-size: 13px;max-inline-size: 100%;outline: none 0px !important;">高</span></strong></span><span style="color: #ff0000;font-size: 13px;letter-spacing: 0px;"></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="88"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="245"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="119"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="105"><p style="line-height: 1em;"><span style="color:#ff0000;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">已发现</span></strong></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="88"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="245"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="119"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="105"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></span></p></td></tr><tr><td valign="middle" colspan="4" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><strong><span style="font-size:13px;">利用条件：</span></strong><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">需要低权限。</span></p></td></tr></tbody></table>  
  
  
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
  
近日，奇安信CERT监测到Apple修复多个高危在野利用漏洞，包括CVE-2023-41991 Apple 多产品安全特性绕过漏洞、 CVE-2023-41992 Apple 多产品权限提升漏洞、 CVE-2023-41993 Apple 多产品代码执行漏洞。**目前这三个漏洞已发现在野利用事件，鉴于这些漏洞影响范围极大，建议客户尽快做好自查及防护。**  
  
<table><tbody><tr><td valign="middle" style="border-color: #4676d9;background-color: #4676d9;" align="left" width="167"><p style="line-height: 1.5em;"><span style="color: rgb(255, 255, 255);font-size: 12px;"><strong><span style="color: rgb(255, 255, 255);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" style="border-color: #4676d9;background-color: #4676d9;" align="left" width="390"><p style="line-height: 1.5em;"><span style="color: rgb(255, 255, 255);font-size: 12px;"><strong><span style="color: rgb(255, 255, 255);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞描述</span></strong></span></p></td></tr><tr><td valign="middle" style="border-color: #4676d9;" align="left" width="167"><section style="line-height: 2em;"><span style="font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;font-size: 14px;">Apple iOS 安全特性绕过漏洞(CVE-2023-41991)</span></section></td><td valign="middle" style="border-color: #4676d9;" align="left" width="390"><section style="line-height: 2em;"><span style="font-size: 14px;">在Apple iOS中，由于签名验证不恰当，App可以绕过签名验证。</span></section></td></tr><tr><td valign="middle" style="border-color: #4676d9;" align="left" width="167"><section style="line-height: 2em;"><span style="font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;font-size: 14px;">Apple iOS 权限提升漏洞(CVE-2023-41992)</span></section></td><td valign="middle" style="border-color: #4676d9;" align="left" width="390"><section style="line-height: 2em;"><span style="font-size: 14px;">在Apple iOS中存在权限提升漏洞，本地攻击者可以利用内核框架的缺陷提升权限。</span></section></td></tr><tr><td valign="middle" style="border-color: #4676d9;" align="left" width="167"><section style="line-height: 2em;"><span style="font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;font-size: 14px;">Apple iOS 代码执行漏洞(CVE-2023-41993)</span></section></td><td valign="middle" style="border-color: #4676d9;" align="left" width="390"><section style="line-height: 2em;"><span style="font-size: 14px;">在Apple iOS中存在内存损坏漏洞，攻击者可以诱使受害者访问恶意web内容利用该漏洞，成功利用则会在受害者系统上执行任意代码。</span></section></td></tr></tbody></table>  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
**Apple iOS 安全特性绕过漏洞(CVE-2023-41991)：**  
  
Apple iOS < 16.7  
  
iPadOS < 16.7  
  
17.0.0 <= iOS < 17.0.1  
  
17.0.0 <= iPadOS < 17.0.1  
  
watchOS < 9.6.3  
  
macOS Ventura < 13.6  
  
10.0.0 <= watchOS < 10.0.1  
  
  
**Apple iOS 权限提升漏洞(CVE-2023-41992)：**  
  
Apple iOS < 16.7  
  
iPadOS < 16.7  
  
17.0.0 <= iOS < 17.0.1  
  
17.0.0 <= iPadOS < 17.0.1  
  
watchOS < 9.6.3  
  
macOS Ventura < 13.6  
  
macOS Monterey < 12.7  
  
10.0.0 <= watchOS < 10.0.1  
  
  
**Apple iOS 代码执行漏洞(CVE-2023-41993)：**  
  
Safari < 16.6.1  
  
Apple iOS < 16.7  
  
iPadOS < 16.7  
  
17.0.0 <= iOS < 17.0.1  
  
17.0.0 <= iPadOS < 17.0.1  
  
macOS Ventura < 13.6  
  
  
**>**  
**>**  
**>**  
**>**  
  
**不影响版本**  
  
**Apple iOS 安全特性绕过漏洞(CVE-2023-41991)：**  
  
Apple iOS >= 16.7  
  
iPadOS >= 16.7  
  
Apple iOS >= 17.0.1  
  
iPadOS >= 17.0.1  
  
watchOS >= 9.6.3  
  
macOS Ventura >= 13.6  
  
watchOS >= 10.0.1  
  
  
**Apple iOS 权限提升漏洞(CVE-2023-41992)：**  
  
Apple iOS >= 16.7  
  
iPadOS >= 16.7  
  
Apple iOS >= 17.0.1  
  
iPadOS >= 17.0.1  
  
watchOS >= 9.6.3  
  
macOS Ventura >= 13.6  
  
macOS Monterey >= 12.7  
  
watchOS >= 10.0.1  
  
  
**Apple iOS 代码执行漏洞(CVE-2023-41993)：**  
  
Safari >= 16.6.1  
  
Apple iOS >= 16.7  
  
iPadOS >= 16.7  
  
Apple iOS >= 17.0.1  
  
iPadOS >= 17.0.1  
  
macOS Ventura >= 13.6  
  
  
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
  
Apple已发布安全更新，请在**设置-通用-软件更新**下载最新版本系统。  
  
参考https://support.apple.com/zh-cn/HT213927  
  
  
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
  
[1]https://support.apple.com/kb/HT213927  
  
[2]https://support.apple.com/kb/HT213929  
  
[3]https://support.apple.com/kb/HT213928  
  
[4]https://support.apple.com/kb/HT213926  
  
[5]https://support.apple.com/kb/HT213931  
  
[6]https://support.apple.com/en-us/HT213926  
  
[7]https://support.apple.com/en-us/HT213927  
  
[8]https://support.apple.com/en-us/HT213928  
  
[9]https://support.apple.com/en-us/HT213929  
  
[10]https://support.apple.com/en-us/HT213931  
  
  
  
**05**  
  
**时间线**  
  
2023年9月22日，奇安信 CERT发布安全风险通告。  
  
  
  
**06**  
  
**漏洞情报服务**  
  
奇安信ALPHA威胁分析平台已支持漏洞情报订阅服务：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs48m2GZhyjlpww1iajmMOdKfdrvo5aBP7lKKkVc4dC7yyz4ib5kBrGutNClJ0d1IOjZDRjWHR1Ce4q4A/640 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4iciaxkpvTUUbm2Zw2OeqsRvwzicdCf9P9ZGdrZ34jFpO6ScVkwiaeJzsXLibz6KHx7uq6BGNE3zhWcNibQ/640 "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到  
**ALHA威胁分析平台**  
订阅更多漏洞信息。  
  
