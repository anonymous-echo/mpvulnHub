#  Apple多个产品高危漏洞安全风险通告   
 奇安信 CERT   2023-06-22 15:12  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody><tr><td valign="middle" align="center" rowspan="1" colspan="4" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #ffffff;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;">漏洞概述</span></strong><br/></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="135"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;letter-spacing: 0px;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Apple多个产品高危漏洞</span></p></td></tr><tr><td valign="middle" align="left" rowspan="1" colspan="1" style="border-color: #4676d9;" width="135"><p style="line-height:1em;"><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞编号</strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="font-size: 13px;letter-spacing: 0px;caret-color: red;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2023-14375、CVE-2023-32434</span><br/></p><p><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2023-14376、CVE-2023-32439</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="135"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">公开时间</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="151"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2023-06-21</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="177"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">影响对象数量级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="94"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">万级</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="135"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="151"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #ff0000;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高危</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="177"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;">CVSS 3.1分数</strong></span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="94"><p style="line-height: 1em;"><strong><span style="text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-size: 13px;color: #ff0000;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">7.8</span></strong></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="135"><p style="line-height: 1em;"><span style="font-size:13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">威胁类型</span></strong><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"></span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="151"><p style="line-height: 1em;"><span style="font-size:13px;">权限提升</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="177"><p style="line-height:1em;"><strong><span style="font-size:13px;">利用可能性</span></strong></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="94"><p style="line-height: 1em;"><span style="color: #ff0000;"><strong><span style="font-size: 13px;">高</span></strong></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="135"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="151"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="177"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="94"><p style="line-height: 1em;"><span style="color:#ff0000;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">已发现</span></strong></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="135"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="151"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="177"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="94"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td></tr><tr><td valign="middle" colspan="4" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><strong><span style="font-size:13px;">利用条件：</span></strong><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">Apple WebKit任意代码执行漏洞：需要交互。</span></p></td></tr></tbody></table>  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
Apple WebKit 是由苹果公司开发的一款开源浏览器引擎，它是/ Safari 浏览器的核心组件，也被 Google、Adobe 等公司使用在其产品中。WebKit 引擎采用 C++ 语言编写，支持 HTML、CSS、JavaScript 等 Web 标准，并提供了高性能的渲染和布局引擎，能够快速准确地呈现网页内容。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT监测到Apple官方发布了多个产品高危漏洞，包括**A****pple WebKit 任意代码执行漏洞(CVE-2023-32439)**  
和**Apple Kernel 权限提升漏洞(CVE-2023-32434****)**  
。**鉴于这些漏洞影响范围较大，且已发现在野利用，建议客户尽快做好自查及防护。**  
  
<table><tbody><tr><td valign="middle" style="background-color: #4676d9;border-color: #4676d9;" align="center" width="164"><p style="line-height:1.6em;"><span style="color:#ffffff;"><strong><span style="font-size: 13px;letter-spacing: 1px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" style="background-color: #4676d9;border-color: #4676d9;" align="center" width="393"><p style="line-height:1.6em;"><span style="color:#ffffff;"><strong><span style="font-size: 13px;letter-spacing: 1px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞描述</span></strong></span></p></td></tr><tr><td valign="top" style="border-color: #4676d9;" width="164"><p style="line-height:1.6em;"><span style="font-size: 13px;letter-spacing: 1px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Apple Kernel 权限提升漏洞(CVE-2023-32434)</span></p></td><td valign="top" style="border-color: #4676d9;" width="393"><p style="line-height:1.6em;"><span style="font-size: 13px;letter-spacing: 1px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Apple Kernel 存在整数溢出漏洞，本地应用程序可以利用该漏洞以内核权限执行任意代码</span></p></td></tr><tr><td valign="top" style="border-color: #4676d9;" width="164"><p style="line-height:1.6em;"><span style="font-size: 13px;letter-spacing: 1px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Apple WebKit任意代码执行漏洞(CVE-2023-32439)</span></p></td><td valign="top" style="border-color: #4676d9;" width="393"><p style="line-height:1.6em;"><span style="font-size: 13px;letter-spacing: 1px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Apple WebKit 中存在类型混淆漏洞，远程攻击者可以诱骗受害者打开特制网页触发类型混淆错误，成功利用此漏洞可在目标系统上执行任意代码。</span></p></td></tr></tbody></table>  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
Apple Kernel 权限提升漏洞：  
  
iOS 15 < 15.7.7  
  
iOS 16 < 16.5.1  
  
iPadOS 15 < 15.7.7  
  
iPadOS 16 < 16.5.1  
  
macOS Ventura < 13.4.1  
  
macOS Monterey < 12.6.7  
  
macOS Big Sur < 11.7.8  
  
watchOS 8 < 8.8.1  
  
watchOS 9 < 9.5.2  
  
  
Apple WebKit任意代码执行漏洞：  
  
iOS 15 < 15.7.7  
  
iOS 16 < 16.5.1  
  
iPadOS 15 < 15.7.7  
  
iPadOS 16 < 16.5.1  
  
macOS Ventura < 13.4.1  
  
  
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
  
目前，官方已发布漏洞修复补丁，建议用户尽快更新。  
  
  
  
  
**04**  
  
**参考资料**  
  
[1]https://support.apple.com/en-us/HT213814  
  
[2]https://support.apple.com/en-us/HT213811  
  
  
  
**05**  
  
**时间线**  
  
2023年6月22日，奇安信 CERT发布安全风险通告。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibyIIibC4QGs2DrJTIRfISrwr6Dsa7ibgUhwFbicRYLy6JlSAxjOIHqJnFPVNtgicRVjeS8arhVvEU3yA/640 "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到**NOX安全监测平台**  
查看更多漏洞信息。  
  
