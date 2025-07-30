#  Smartbi 登录代码逻辑漏洞安全风险通告   
 奇安信 CERT   2023-07-03 16:54  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody><tr><td valign="middle" align="center" rowspan="1" colspan="4" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #ffffff;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;">漏洞概述</span></strong><br/></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="135"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;letter-spacing: 0px;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Smartbi 登录代码逻辑漏洞</span></p></td></tr><tr><td valign="middle" align="left" rowspan="1" colspan="1" style="border-color: #4676d9;" width="135"><p style="line-height:1em;"><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞编号</strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2023-15129</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="135"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">公开时间</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="151"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2023-07-03</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="177"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">影响对象数量级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="94"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">万级</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="135"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="151"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #ff0000;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高危</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="177"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;">CVSS 3.1分数</strong></span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="94"><p style="line-height: 1em;"><span style="text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-size: 13px;color: #000000;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">7.5</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="135"><p style="line-height: 1em;"><span style="font-size:13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">威胁类型</span></strong><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"></span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="151"><p style="line-height: 1em;"><span style="font-size:13px;">信息泄露</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="177"><p style="line-height:1em;"><strong><span style="font-size:13px;">利用可能性</span></strong></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="94"><p style="line-height: 1em;"><span style="color:#ff0000;"><span style="font-size: 13px;color: #ffc000;"><strong>中</strong></span></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="135"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="151"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="177"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="94"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="135"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="151"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="177"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="94"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td></tr><tr><td valign="middle" colspan="4" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><strong><span style="font-size:13px;">危害描述：</span></strong><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">攻击者可利用该漏洞对目标系统进行攻击，最终可导致敏感信息泄露。</span></p></td></tr></tbody></table>  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
Smartbi是广州思迈特软件有限公司旗下的商业智能BI和数据分析品牌，为企业客户提供一站式商业智能解决方案。Smartbi大数据分析产品融合BI定义的所有阶段，对接各种业务数据库、数据仓库和大数据分析平台，进行加工处理、分析挖掘和可视化展现；满足所有用户的各种数据分析应用需求，如大数据分析、可视化分析、探索式分析、复杂报表、应用分享等等。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT监测到Smartbi官方发布安全更新，修复了**Smartbi 登录代码逻辑漏洞(QVD-2023-15129)**  
。Smartbi大数据分析平台的登录代码存在逻辑缺陷，攻击者可利用该漏洞对目标系统进行攻击，最终可导致敏感信息泄露。  
**鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。**  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
Smartbi >= V9  
  
  
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
  
目前 Smartbi官方已发布安全版本修复该漏洞，建议受影响用户尽快进行安全更新。  
  
  
**自动升级：**  
  
登录后台->右上角系统监控->系统补丁->安装补丁->在线更新  
  
**手动升级：**  
  
下载补丁->登录后台->右上角系统监控->系统补丁->安装补丁->手动更新  
  
补丁下载地址：https://www.smartbi.com.cn/patchinfo  
  
  
详情可参考：****  
  
https://wiki.smartbi.com.cn/pages/viewpage.action?pageId=50692623  
  
  
  
**04**  
  
**参考资料**  
  
[1]https://www.smartbi.com.cn/patchinfo  
  
[2]https://www.smartbi.com.cn/index/news_cont/nid/6010   
  
  
  
**05**  
  
**时间线**  
  
2023年7月3日，奇安信 CERT发布安全风险通告。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icrCTtcYnAmWuGarLwwAIOgQJ4WTA3wfS7J4dlr3jPxOAyhottyaksFVDtNibuMicaDlE2euFes7Kkw/640 "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到**NOX安全监测平台**  
查看更多漏洞信息。  
  
