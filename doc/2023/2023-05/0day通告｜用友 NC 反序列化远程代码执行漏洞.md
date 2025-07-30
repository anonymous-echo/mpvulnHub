#  0day通告｜用友 NC 反序列化远程代码执行漏洞   
原创 微步情报局  微步在线研究响应中心   2023-05-17 18:33  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKKIwzXUMSTRxJbmEAibibMabggxYnpFRmPXP4YIicg335GmW5s2lb5jibiaEImQXzbHnA7icXL3Z8Skpwg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
01 漏洞概况****  
  
  
  
用友NC是一款企业级ERP软件。作为一种信息化管理工具，用友NC提供了一系列业务管理模块，包括财务会计、采购管理、销售管理、物料管理、生产计划和人力资源管理等，帮助企业实现数字化转型和高效管理。近日，微步在线漏洞团队通过“X漏洞奖励计划”获取到用友NC反序列化远程代码执行漏洞情报(0day)，攻击者可以通过该漏洞执行任意代码，导致系统被攻击与控制。  
**经过分析与研判，该漏洞利用难度低，可以直接远程代码执行，影响范围较大，建议尽快修复。**  
  
****  
  
  
**复现过程：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLtD0DdwkFjuLWBH5c1lYlI5coobzhDH2e8L7vYxdBfwHIIraBoAkWACDP3cicVQJtibSMUA9BjFNZA/640?wx_fmt=png "")  
  
**此次受影响版本如下：**  
<table><tbody><tr style="height:18.3000pt;"><td style="padding: 0pt 5.4pt;border-color: rgb(0, 0, 0);border-style: solid;border-width: 1pt;word-break: break-all;" width="284" valign="top"><p style="text-indent:10.5000pt;line-height:150%;"><strong style="font-family: mp-quote, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style="font-size: 15px;text-decoration-style: solid;text-decoration-color: rgb(51, 51, 51);">用友 NC</span></strong><strong style="font-size: 15px;text-indent: 10.5pt;font-family: mp-quote, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style="font-family: 黑体;"></span></strong></p></td><td style="padding: 0pt 5.4pt;border-color: rgb(0, 0, 0) rgb(0, 0, 0) rgb(0, 0, 0) currentcolor;border-style: solid solid solid none;border-width: 1pt 1pt 1pt medium;word-break: break-all;" width="193" valign="top"><section style="text-align: center;line-height: 150%;text-indent: 0em;"><strong style="mso-bidi-font-weight:normal;"><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;mso-ansi-font-weight:bold;font-size:10.5000pt;mso-font-kerning:1.0000pt;"><span style="font-family:黑体;">是否受影响</span></span></strong><strong style="mso-bidi-font-weight:normal;"><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;mso-ansi-font-weight:bold;font-size:10.5000pt;mso-font-kerning:1.0000pt;"></span></strong></section></td></tr><tr style="height:18.6000pt;"><td style="padding: 0pt 5.4pt;border-color: currentcolor rgb(0, 0, 0) rgb(0, 0, 0);border-style: none solid solid;border-width: medium 1pt 1pt;word-break: break-all;" width="284" valign="top"><p style="text-indent:10.5000pt;text-align:left;line-height:150%;"><span style="font-size: 14px;text-indent: 2em;font-family: mp-quote, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style="font-size: 14px;letter-spacing: 0.578px;text-decoration: rgba(0, 0, 0, 0.9);">version &lt;= 6.5</span></span><span style="font-family: 黑体;font-size: 10.5pt;text-indent: 10.5pt;"></span></p></td><td style="padding: 0pt 5.4pt;border-color: currentcolor rgb(0, 0, 0) rgb(0, 0, 0) currentcolor;border-style: none solid solid none;border-width: medium 1pt 1pt medium;word-break: break-all;" width="213.33333333333337" valign="top"><section style="text-align: center;line-height: 150%;text-indent: 0em;"><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;mso-font-kerning:1.0000pt;"><span style="font-family:黑体;">是</span></span></section></td></tr></tbody></table>  
  
02 漏洞评估  
  
  
  
**公开程度：**  
PoC 未公开  
  
**利用条件：**  
无权限要求  
  
**交互要求：**  
0-click  
  
**漏洞危害：**  
高危、远程代码执行  
  
**影响范围：**  
用友 NC  
  
03 修复方案   
  
  
  
1.	官方修复措施：官方已发布修复方案，受影响的用户建议联系用友官方获取安全补丁  
https://security.yonyou.com/#/noticeInfo?id=2932.	临时处置和应对措施：非必要不建议将该系统暴露在公网。3.流量侧检测排查：微步在线威胁感知平台TDP已支持检测该漏洞，规则 ID：3100031483、3100031488。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLtD0DdwkFjuLWBH5c1lYlIsUxMtnp1LZKZAp6YoibusC2pQjoPEgAuOnXoLhbBDiaFY6AwbBhU5QfA/640?wx_fmt=png "")  
  
### 04 时间线 2022.9 微步“X漏洞奖励计划”获取该漏洞相关情报2022.9上报监管和厂商2022.9 微步在线威胁感知平台TDP支持检测2023.3 厂商修复2023.5 微步发布报告  
### ---End---  
  
**X漏洞奖励计划**  
  
  
“X漏洞奖励计划”是微步在线X情报社区推出的一款0day漏洞奖励计划，我们鼓励白帽子提交挖掘到的0day漏洞，并给予白帽子可观的奖励。我们期望通过该计划与白帽子共同努力，提升0day防御能力，守护数字世界安全。  
  
  
**活动详情：**  
  
**https://x.threatbook.com/v5/vulReward**  
  
