#  Palo Alto Networks PAN-OS身份认证绕过+远程代码执行漏洞   
原创 微步情报局  微步在线研究响应中心   2024-11-21 00:59  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKNkm4Pg1Ed6nv0proxQLEKJ2CUCIficfAwKfClJ84puialc9eER0oaibMn1FDUpibeK1t1YvgZcLYl3A/640?wx_fmt=png "")  
  
  
**漏洞概况**  
  
  
  
PAN-OS 是 Palo Alto Networks 公司开发的下一代防火墙操作系统，为 Palo Alto Networks 防火墙提供安全功能和集中管理能力。  
  
微步情报局近日捕获到Palo Alto Networks PanOS身份认证绕过漏洞情报(CVE-2024-0012，https://x.threatbook.com/v5/vul/XVE-2024-0659)和Palo Alto Networks PanOS 远程代码执行漏洞情报(CVE-2024-9474，https://x.threatbook.com/v5/vul/XVE-2024-33390)。  
  
CVE-2024-0012   
漏洞可绕过身份认证，访问后台接口。  
  
CVE-2024-9474   
漏洞可在身份认证后，实现命令注入。  
  
二者形成结合利用链，即可实现未授权条件下的前台远程命令执行漏洞，利用难度较低。CISA（  
https://www.cisa.gov/known-exploited-vulnerabilities-catalog） 和 Palo Alto官方（  
https://unit42.paloaltonetworks.com/cve-2024-0012-cve-2024-9474/）称已观察到上述漏洞的利用行为，建议受影响的用户尽快修复  
。  
  
  
**漏洞处置优先级(VPT)**  
  
  
  
**综合处置优先级：高**  
<table><tbody style="outline: 0px;"><tr style="outline: 0px;height: 31.0667px;"><td width="110" colspan="1" rowspan="2" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><strong style="outline: 0px;">基本信息</strong></span><o:p style="outline: 0px;"></o:p></p></td><td width="186" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">微步编号</span><o:p style="outline: 0px;"></o:p></p></td><td width="88" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);"><span style="outline: 0px;">XVE</span>-2024-0659</span><p><span style="font-size: 14px;color: rgb(84, 84, 84);">XVE-2024-33390</span></p></td></tr><tr style="padding-right: 7.2px;padding-left: 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 31.0667px;"><td colspan="1" rowspan="1" width="189" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="31"><span style="outline: 0px;font-size: 14px;color: rgb(84, 84, 84);">漏洞类型</span><br style="outline: 0px;"/></td><td colspan="1" rowspan="1" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="31"><p><span style="font-size: 14px;color: rgb(84, 84, 84);">身份认证绕过</span></p><p><span style="letter-spacing: 0.578px;font-size: 14px;color: rgb(84, 84, 84);">远程命令执行</span></p></td></tr><tr style="outline: 0px;height: 31.0667px;"><td width="135" colspan="1" rowspan="5" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用条件评估</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="169" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用漏洞的网络条件<br style="outline: 0px;"/></span><o:p style="outline: 0px;"></o:p></p></td><td width="221" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">远程</span></td></tr><tr style="outline: 0px;height: 31.0667px;"><td width="189" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;">是否需要绕过安全机制</span><o:p style="outline: 0px;"></o:p></p></td><td width="221" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">不需要</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="189" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">对被攻击系统的要求<br style="outline: 0px;"/></span><o:p style="outline: 0px;"></o:p></p></td><td width="221" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">默认配置</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="189" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;text-wrap: wrap;">利用漏洞的权限要求</span><o:p style="outline: 0px;"></o:p></p></td><td width="221" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">无需任何权限</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="189" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">是否需要受害者配合</span><o:p style="outline: 0px;"></o:p></p></td><td width="88" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">不需要</span></td></tr><tr style="outline: 0px;height: 27.2px;"><td width="115" colspan="1" rowspan="2" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用情报</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="169" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;">POC是否公开</span><o:p style="outline: 0px;"></o:p></p></td><td width="88" colspan="1" rowspan="1" style="margin-top: 16px;margin-bottom: 0px;"><span style="color: rgb(219, 0, 0);letter-spacing: 1px;font-size: 14px;">是</span><span></span></td></tr><tr style="padding-right: 7.2px;padding-left: 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 27.2px;"><td colspan="1" rowspan="1" width="169" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="27"><span style="outline: 0px;color: rgb(84, 84, 84);"><span style="font-size: 14px;">已知利用行为</span><span style="font-size: 14px;"><br style="outline: 0px;"/></span></span></td><td colspan="1" rowspan="1" width="222" height="27" style="margin-top: 16px;margin-bottom: 0px;outline: 0px;height: 27.2px;"><span style="color: rgb(219, 0, 0);letter-spacing: 1px;font-size: 14px;">是</span><br/></td></tr></tbody></table>#   
  
**漏洞影响范围**  
  
  
  
<table><tbody style="outline: 0px;"><tr style="outline: 0px;height: 33.2px;"><td width="152" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">产品名称</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">Palo Alto Networks - PAN-OS</span><span style="font-size: 14px;"></span></td></tr><tr style="outline: 0px;height: 27px;"><td width="172" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">受影响版本</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p><span style="font-size: 14px;color: rgb(84, 84, 84);">CVE-2024-0012漏洞影响范围：</span></p><p><span style="font-size: 14px;color: rgb(84, 84, 84);letter-spacing: 1px;">10.2.0 ≤ version &lt; 10.2.12</span></p><p><span style="font-size: 14px;color: rgb(84, 84, 84);letter-spacing: 1px;">11.0.0 ≤ version &lt; 11.0.6</span></p><p><span style="font-size: 14px;color: rgb(84, 84, 84);letter-spacing: 1px;">11.1.0 ≤ version &lt; 11.1.5</span></p><section style="margin-bottom: 16px;"><span style="font-size: 14px;color: rgb(84, 84, 84);letter-spacing: 1px;">11.2.0 ≤ version &lt; 11.2.4</span><span style="font-size: 14px;color: rgb(84, 84, 84);letter-spacing: 1px;"></span></section><p><span style="font-size: 14px;color: rgb(84, 84, 84);">CVE-2024-9474漏洞影响范围：</span></p><p><span style="font-size: 14px;color: rgb(84, 84, 84);letter-spacing: 1px;">10.1.0 ≤ version &lt; 10.1.14</span></p><p><span style="font-size: 14px;color: rgb(84, 84, 84);letter-spacing: 1px;">10.2.0 ≤ version &lt; 10.2.12</span></p><p><span style="font-size: 14px;color: rgb(84, 84, 84);letter-spacing: 1px;">11.0.0 ≤ version &lt; 11.0.6</span></p><p><span style="font-size: 14px;color: rgb(84, 84, 84);letter-spacing: 1px;">11.1.0 ≤ version &lt; 11.1.5</span></p><p><span style="font-size: 14px;color: rgb(84, 84, 84);letter-spacing: 1px;">11.2.0 ≤ version &lt; 11.2.4</span></p><p><span style="font-size: 14px;"><br/></span></p><p><span style="font-size: 14px;color: rgb(219, 0, 0);">注意：两个漏洞的影响范围并不完全一致，10.1.x版本存在认证后命令注入漏洞，但不存在认证绕过，无法实现前台rce</span></p></td></tr><tr style="outline: 0px;height: 35.6px;"><td width="172" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">有无修复补丁</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="letter-spacing: 0.578px;font-size: 14px;color: rgb(84, 84, 84);">有</span></td></tr></tbody></table>  
  
前往X情报社区资产测绘查看影响资产详情：  
  
https://x.threatbook.com/v5/survey?q=app%3D%22Palo%20Alto%20Networks%20PAN-OS%20Firewall%22  
  
  
**漏洞复现**  
  
  
  
  
绕过身份认证并实现远程命令执行：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMI9AicGNHltEFNliaEU67CwgSzq16ohMRc6ib9YZpL7a4yeyxn1yXQoibaMLshr9P5Yu858p0YQgmdygQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMI9AicGNHltEFNliaEU67CwgSz0qmWzS8haOt0AVZ1woqNy1ayIusyCwXBP6ro8ZpsfWyHccWjvcKmw/640?wx_fmt=png "")  
  
  
**修复方案**  
  
  
  
  
**官方修复方案：**  
  
官方已发布漏洞公告，请尽快更新至  
PAN-OS 10.1.14-h6、PAN-OS 10.2.12-h2、PAN-OS 11.0.6-h1、PAN-OS 11.1.5-h1、PAN-OS 11.2.4-h1 及所有更高版本的 PAN-OS。  
  
漏洞公告地址：  
1. https://security.paloaltonetworks.com/CVE-2024-0012  
  
1. https://security.paloaltonetworks.com/CVE-2024-9474  
  
## 临时修复方案：  
- 将对管理接口的访问限制为仅受信任的内部 IP 地址，以防止来自互联网的外部访问。  
  
- 使用防护类设备进行防护，重点关注和监控Header中带有“X-PAN-AUTHCHECK: off”的请求。  
  
  
**相关攻击IP**  
  
  
  
9  
1.208.197[.]167  
  
104.28.208[.]123  
  
136.144.17[.]146  
  
136.144.17[.]149  
  
136.144.17[.]154  
  
136.144.17[.]158   
  
136.144.17[.]161  
  
136.144.17[.]164  
  
136.144.17[.]166  
  
136.144.17[.]167  
  
136.144.17[.]170  
  
136.144.17[.]176  
  
136.144.17[.]177  
  
136.144.17[.]178  
  
136.144.17[.]180  
  
173.239.218[.]248   
  
173.239.218[.]251  
  
209.200.246[.]173  
  
209.200.246[.]184  
  
216.73.162[.]69  
  
216.73.162[.]71  
  
216.73.162[.]73  
  
216.73.162[.]74  
  
  
来源：https://unit42.paloaltonetworks.com/cve-2024-0012-cve-2024-9474/  
  
  
**微步产品侧支持情况**  
  
  
  
微步威胁感知平台TDP已于2024年11月20日支持检测，检测ID为  
S3100157358、S3100157359，模型/规则高于   
20241120000000 可检出。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMI9AicGNHltEFNliaEU67CwgSYLX50UibWn0iaOkStP3FLFv1qyz5r9znAxdpPPMHan2plJad6S0Ac2lg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMI9AicGNHltEFNliaEU67CwgSgvYDmBmANuSSDiaHfNXgGiaiasfqbQzScUM8swiaTvHe2eiaKfLNYvPibNlA/640?wx_fmt=png "")  
  
  
  
  
- END -  
  
  
  //    
  
**微步漏洞情报订阅服务**  
  
  
微步提供漏洞情报订阅服务，精准、高效助力企业漏洞运营：  
- 提供高价值漏洞情报，具备及时、准确、全面和可操作性，帮助企业高效应对漏洞应急与日常运营难题；  
  
- 可实现对高威胁漏洞提前掌握，以最快的效率解决信息差问题，缩短漏洞运营MTTR；  
  
- 提供漏洞完整的技术细节，更贴近用户漏洞处置的落地；  
  
- 将漏洞与威胁事件库、APT组织和黑产团伙攻击大数据、网络空间测绘等结合，对漏洞的实际风险进行持续动态更新。  
  
  
扫码在线沟通  
  
↓  
↓↓  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hQl5bZ5Mx6PTAQg6tGLiciarvXajTdDnQiacxmwJFZ0D3ictBOmuYyRk99bibwZV49wbap77LibGQHdQPtA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTIdM9koHZFkrtYe5WU5rHxSDicbiaNFjEBAs1rojKGviaJGjOGd9KwKzN4aSpnNZDA5UWpY2E0JAnNg/640?wx_fmt=png "")  
  
[点此电话咨询]()  
  
  
  
  
**X漏洞奖励计划**  
  
  
“X漏洞奖励计划”是微步X情报社区推出的一款  
针对未公开  
漏洞的奖励计划，我们鼓励白帽子提交挖掘到的0day漏洞，并给予白帽子可观的奖励。我们期望通过该计划与白帽子共同努力，提升0day防御能力，守护数字世界安全。  
  
活动详情：  
https://x.threatbook.com/v5/vulReward  
  
  
  
