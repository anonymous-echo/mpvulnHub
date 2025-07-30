#  【在野利用】Apple iOS 与 iPadOS 多个在野高危漏洞安全风险通告   
 网安百色   2024-03-07 19:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1QIbxKfhZo6TLA19pviaCFfbrwwfDkd81KlLEPjVUhNmpUTv82EJhu2QnczPmf7nU0UicVQhD3icJZp2vicGaWur0w/640?wx_fmt=gif "")  
  
  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody><tr class="firstRow"><td valign="middle" align="center" rowspan="1" colspan="4" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 1.5em;"><span style="color: #ffffff;letter-spacing: 0px;"><strong><span style="color: #ffffff;font-size: 13px;letter-spacing: 0px;">漏洞概述</span></strong><br/></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="135"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;font-family:微软雅黑, Microsoft YaHei;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;caret-color: red;letter-spacing: 0px;">Apple iOS 与 iPadOS 多个在野高危漏洞</span></p></td></tr><tr><td valign="middle" align="left" rowspan="1" colspan="1" style="border-color: #4676d9;" width="135"><p style="line-height:1em;"><span style="font-family:微软雅黑, Microsoft YaHei;"><span style="font-size: 13px;"><strong>漏洞编号</strong></span></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family:微软雅黑, Microsoft YaHei;">CVE-2024-23296、CVE-2024-23225</span></p></td></tr><tr><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="135"><p style="line-height:1em;"><strong><span style="font-size:13px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family:微软雅黑, Microsoft YaHei, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;font-family:微软雅黑, Microsoft YaHei;">公开时间</span></strong></span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="161"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family:微软雅黑, Microsoft YaHei;">2024-03-05</span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="164"><p style="line-height:1em;"><strong><span style="font-size:13px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family:微软雅黑, Microsoft YaHei, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;font-family:微软雅黑, Microsoft YaHei;">影响量级</span></strong></span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="97"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family:微软雅黑, Microsoft YaHei;">千万级</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="135"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family:微软雅黑, Microsoft YaHei, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;cursor: text;font-size: 13px;letter-spacing: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="161"><p style="line-height: 1em;"><span style="letter-spacing:0px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #ff0000;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family:微软雅黑, Microsoft YaHei, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;cursor: text;font-size: 13px;letter-spacing: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;">高危</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="164"><p style="line-height: 1em;"><strong><span style="font-size: 13px;letter-spacing: 0px;">CVSS 3.1分数</span></strong></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="97"><p style="line-height: 1em;"><span style="color: #ff0000;font-size: 13px;letter-spacing: 0px;"><strong>7.8</strong></span></p></td></tr><tr><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="135"><p style="line-height:1em;"><span style="font-size:13px;"><strong>威胁类型</strong></span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="161"><p style="line-height:1em;"><span style="font-size:13px;">安全特性绕过</span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="164"><p style="line-height:1em;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family:微软雅黑, Microsoft YaHei, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;">利用可能性</span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="97"><p style="line-height:1em;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;color: #ff0000;font-family:微软雅黑, Microsoft YaHei, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;">高</span></strong></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="135"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family:微软雅黑, Microsoft YaHei;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="161"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family:微软雅黑, Microsoft YaHei;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="164"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family:微软雅黑, Microsoft YaHei;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="97"><p style="line-height: 1em;"><span style="color:#ff0000;"><strong><span style="font-size: 13px;font-family:微软雅黑, Microsoft YaHei;">已发现</span></strong></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="135"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family:微软雅黑, Microsoft YaHei;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="161"><p style="line-height: 1em;"><span style="font-size: 13px;font-family:微软雅黑, Microsoft YaHei;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="164"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family:微软雅黑, Microsoft YaHei;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="97"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family:微软雅黑, Microsoft YaHei;">未公开</span></p></td></tr><tr><td valign="middle" colspan="4" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><strong><span style="font-size:13px;">危害描述：</span></strong><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family:system-ui, -apple-system, BlinkMacSystemFont, Helvetica Neue, PingFang SC, Hiragino Sans GB, Microsoft YaHei UI, Microsoft YaHei, Arial, sans-serif;">需要本地触发、低权限用户。</span></p></td></tr></tbody></table>  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
iOS是由苹果公司开发的移动操作系统。iPadOS（英文全称：iPad Operating System）是苹果公司基于iOS研发的移动端操作系统系列，于2019年6月4日推出。iPadOS主要运用于iPad等设备，聚焦了Apple Pencil、分屏和多任务互动功能，并可与Mac进行任务分享。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT监测到Apple iOS 与 iPadOS 发布新版本修复了存在在野利用的**Apple iOS 与 iPadOS RTKit 安全特性绕过漏洞(CVE-2024-23296) 和 Apple iOS 与 iPadOS Kernel 安全特性绕过漏洞(CVE-2024-23225)**  
，具有任意内核读写能力的攻击者可能能够绕过内核内存保护。  
  
  
苹果公司据一份报告称该漏洞可能已被利用。**鉴于这些漏洞已发现在野利用，建议客户尽快做好自查及防护。**  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
**CVE-2024-23296：**  
  
iOS < 17.4   
  
iPadOS < 17.4  
  
  
**CVE-2024-23225：**  
  
iOS 17 < 17.4  
  
iOS 16 < 16.7.6  
  
iPadOS 17 < 17.4  
  
iPadOS 16 < 16.7.6  
  
  
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
  
目前官方已有可更新版本，建议受影响用户升级至最新版本：  
  
**CVE-2024-23296：**  
  
iOS >= 17.4   
  
iPadOS >= 17.4  
  
  
**CVE-2024-23225：**  
  
iOS 17 >= 17.4  
  
iOS 16 >= 16.7.6  
  
iPadOS 17 >= 17.4  
  
iPadOS 16 >= 16.7.6  
  
  
https://support.apple.com/en-us/HT214081  
  
https://support.apple.com/en-us/HT214082  
  
  
**04**  
  
**参考资料**  
  
[1]https://support.apple.com/en-us/HT214081  
  
[2]https://support.apple.com/en-us/HT214082  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo6M60aLu6MNdy20VjcnyaGECz7d9mYhdbclWg7wibJsickPUrnmNyFcvsjSYUqq5OPVPEXfW1SwkXCw/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1QIbxKfhZo57Spb4ibrib8VUZd2ibdF9wHbvr4RwYJ4H2z6571icFIdSZXIpNH2YfW16ETwHh3ict3gtpW3W2fJqDmw/640?wx_fmt=gif "")  
  
长按添加关注，为您保驾护航！  
  
  
