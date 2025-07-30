#  0day通告！WebLogic JNDI 注入远程代码执行漏洞   
原创 微步情报局  微步在线研究响应中心   2023-04-19 16:09  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKKIwzXUMSTRxJbmEAibibMabggxYnpFRmPXP4YIicg335GmW5s2lb5jibiaEImQXzbHnA7icXL3Z8Skpwg/640?wx_fmt=png "")  
  
01 漏洞概况   
  
  
  
2023 年 4 月 19 日 ， Oracle 发 布 安 全 补 丁 修 复 WebLogic 中 间 件 漏 洞 。其 中 CVE-2023-21931 由微步在线漏洞团队挖掘，并报告给监管和厂商。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicML8h6dG3ADAPjAN4icIPzNOkvJZ1dxu3yq8gn3mXRbpvvUfpjbGchwZblTjPmWv0Um4fwvzN0BU1Yg/640?wx_fmt=png "")  
  
**经过分析与研判，该漏洞利用难度低，可以直接远程代码执行，影响范围较大，建议尽快修复。**  
  
  
  
  
******复现过程：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicML8h6dG3ADAPjAN4icIPzNOk1hJYfqCJxJM33MgibwauKZibKsYsibSgHMiaDm4fmoSJpnX3AyOCobdU8A/640?wx_fmt=png "")  
  
**此次受影响版本如下：**  
<table><tbody><tr style="height:18.3000pt;"><td style="padding: 0pt 5.4pt;border-color: rgb(0, 0, 0);border-style: solid;border-width: 1pt;word-break: break-all;" width="284" valign="top"><p style="text-indent:10.5000pt;line-height:150%;"><strong style="font-family: mp-quote, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style="font-size: 15px;text-decoration-style: solid;text-decoration-color: rgb(51, 51, 51);">WebLogic</span></strong><strong style="font-size: 15px;text-indent: 10.5pt;font-family: mp-quote, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style="font-family: 黑体;"></span></strong></p></td><td style="padding: 0pt 5.4pt;border-color: rgb(0, 0, 0) rgb(0, 0, 0) rgb(0, 0, 0) currentcolor;border-style: solid solid solid none;border-width: 1pt 1pt 1pt medium;word-break: break-all;" width="177.33333333333334" valign="top"><section style="text-align: center;line-height: 150%;text-indent: 0em;"><strong style="mso-bidi-font-weight:normal;"><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;mso-ansi-font-weight:bold;font-size:10.5000pt;mso-font-kerning:1.0000pt;"><span style="font-family:黑体;">是否受影响</span></span></strong><strong style="mso-bidi-font-weight:normal;"><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;mso-ansi-font-weight:bold;font-size:10.5000pt;mso-font-kerning:1.0000pt;"></span></strong></section></td></tr><tr style="height:18.6000pt;"><td style="padding: 0pt 5.4pt;border-color: currentcolor rgb(0, 0, 0) rgb(0, 0, 0);border-style: none solid solid;border-width: medium 1pt 1pt;word-break: break-all;" width="284" valign="top"><p style="text-indent:10.5000pt;text-align:left;line-height:150%;"><span style="font-size: 14px;text-indent: 2em;font-family: mp-quote, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">12.2.1.3.0</span></p><p style="text-indent:10.5000pt;text-align:left;line-height:150%;"><span style="font-size: 14px;text-indent: 2em;font-family: mp-quote, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">12.2.1.4.0</span></p><p style="text-indent:10.5000pt;text-align:left;line-height:150%;"><span style="font-size: 14px;text-indent: 2em;font-family: mp-quote, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">14.1.1.0.0</span><span style="font-family: 黑体;font-size: 10.5pt;text-indent: 10.5pt;"></span></p></td><td style="padding: 0pt 5.4pt;border-color: currentcolor rgb(0, 0, 0) rgb(0, 0, 0) currentcolor;border-style: none solid solid none;border-width: medium 1pt 1pt medium;" width="182.33333333333337" valign="top"><section style="text-align: center;line-height: 150%;text-indent: 0em;"><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;mso-font-kerning:1.0000pt;"><span style="font-family:黑体;">是</span></span><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;mso-font-kerning:1.0000pt;"></span></section></td></tr></tbody></table>  
  
02 漏洞评估   
  
  
  
**公开程度：**PoC未公开  
**利用条件：**  
无权限要求  
  
**交互要求：**  
0-click  
  
**漏洞危害：**  
命令高危、远程代码执行  
  
**影响范围：**  
WebLogic  
  
03 修复方案   
  
  
  
**1. 官方修复措施**  
Oracle官方已发布修复方案，建议及时更新。  
https://www.oracle.com/security-alerts/cpuapr2023.html  
  
**2. 临时处置和应对措施**  
若非必须开启，请禁用T3协议，或者对协议端口进行严格的权限控制。  
  
**3. 流量侧检测排查**  
  
微步威胁感知平台TDP已支持检测该漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicML8h6dG3ADAPjAN4icIPzNOkRvSImcpyU70A1bOdLB0XOZfziaicgqgyf5Na89GcvY2vwfmsdmkztqrQ/640?wx_fmt=png "")  
  
  
### 04 时间线 2022.08 漏洞挖掘与分析2022.08 微步威胁感知平台TDP已支持检测该漏洞2023.01 上报厂商2023.04 厂商发布补丁2023.04 微步发布报告  
###   
  
点击下方名片，关注我们  
  
第一时间为您推送最新威胁情报  
  
  
