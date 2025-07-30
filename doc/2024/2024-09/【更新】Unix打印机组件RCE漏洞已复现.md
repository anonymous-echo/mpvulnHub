#  【更新】Unix打印机组件RCE漏洞已复现   
 微步在线   2024-09-27 19:23  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKNkm4Pg1Ed6nv0proxQLEKJ2CUCIficfAwKfClJ84puialc9eER0oaibMn1FDUpibeK1t1YvgZcLYl3A/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**漏洞概况**  
  
  
  
  
cups-browsed是CUPS(Common Unix Printing System，通用Unix打印系统)一个重要组件，它是一个轻量级的后台服务，用于在本地网络中自动发现和共享打印机。  
  
微步情报局已复现cups-browsed远程代码执行漏洞(https://x.threatbook.com/v5/vul/XVE-2024-28256)并初步确认漏洞原理。该漏洞是CVE-2024-47076(https://x.threatbook.com/v5/vul/XVE-2024-28262),CVE-2024-47175(https://x.threatbook.com/v5/vul/XVE-2024-28259),CVE-2024-47177(https://x.threatbook.com/v5/vul/XVE-2024-28261)的组合利用，涉及到libppd，libcupsfilters，cups-filters等CUPS组件。  
攻击者需要模拟一个恶意的打印机服务，通过诱使受害者将打印任务发送给恶意的打印机服务，从而触发漏洞，执行恶意命令。  
从漏洞利用方式来看，  
该漏洞的利用需要配合相对钓鱼手段  
，由此可以推断Linux桌面版面临的风险更高。  
  
另外值得一提的是，根据公开信息(https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/)披露，  
cups-browsed服务中还存在缓冲区溢出和条件竞争，但暂无公开PoC。  
  
**漏洞处置优先级(VPT)**  
  
  
**综合处置优先级：高**  
<table><tbody style="outline: 0px;"><tr style="outline: 0px;height: 31.0667px;"><td width="110" colspan="1" rowspan="2" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><strong style="outline: 0px;">基本信息</strong></span><o:p style="outline: 0px;"></o:p></p></td><td width="186" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">微步编号</span><o:p style="outline: 0px;"></o:p></p></td><td width="88" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="outline: 0px;font-size: 14px;color: rgb(84, 84, 84);">XVE-2024-28256</span></td></tr><tr style="padding-right: 7.2px;padding-left: 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 31.0667px;"><td colspan="1" rowspan="1" width="189" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="31"><span style="outline: 0px;font-size: 14px;color: rgb(84, 84, 84);">漏洞类型</span><br style="outline: 0px;"/></td><td colspan="1" rowspan="1" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="31"><span style="font-size: 14px;color: rgb(84, 84, 84);">远程命令执行</span></td></tr><tr style="outline: 0px;height: 31.0667px;"><td width="135" colspan="1" rowspan="5" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用条件评估</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="169" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用漏洞的网络条件<br style="outline: 0px;"/></span><o:p style="outline: 0px;"></o:p></p></td><td width="88" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">远程</span></td></tr><tr style="outline: 0px;height: 31.0667px;"><td width="189" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;">是否需要绕过安全机制</span><o:p style="outline: 0px;"></o:p></p></td><td width="221" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">不需要</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="189" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">对被攻击系统的要求<br style="outline: 0px;"/></span><o:p style="outline: 0px;"></o:p></p></td><td width="221" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p><span style="color: rgb(84, 84, 84);font-size: 14px;">非默认配置</span></p></td></tr><tr style="outline: 0px;height: 27px;"><td width="189" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;text-wrap: wrap;">利用漏洞的权限要求</span><o:p style="outline: 0px;"></o:p></p></td><td width="221" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">无需任何权限</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="189" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">是否需要受害者配合</span><o:p style="outline: 0px;"></o:p></p></td><td width="221" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">需要被动配合</span></td></tr><tr style="outline: 0px;height: 27.2px;"><td width="115" colspan="1" rowspan="2" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用情报</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="169" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;">POC是否公开</span><o:p style="outline: 0px;"></o:p></p></td><td width="88" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="color:#545454;"><span style="font-size: 14px;">是</span></span></td></tr><tr style="padding-right: 7.2px;padding-left: 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 27.2px;"><td colspan="1" rowspan="1" width="169" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="27"><span style="outline: 0px;font-size: 14px;color: rgb(84, 84, 84);">已在野利用<br style="outline: 0px;"/></span></td><td colspan="1" rowspan="1" width="222" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="27"><span style="color:#545454;"><span style="font-size: 14px;">否</span></span></td></tr></tbody></table>#   
  
**漏洞影响范围**  
  
  
  
<table><tbody style="outline: 0px;"><tr style="outline: 0px;height: 33.2px;"><td width="152" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">产品名称</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="27"><span style="font-size: 14px;color: rgb(84, 84, 84);">OpenPrinting - cups-browsed</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="172" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">受影响版本</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="27"><p style="padding-right: 7.2px;padding-left: 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 27px;"><span style="font-size: 14px;color: rgb(84, 84, 84);">&lt;= 2.0.1</span></p></td></tr><tr style="outline: 0px;height: 35.6px;"><td width="172" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">有无修复补丁</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">无</span></td></tr></tbody></table>  
**漏洞复现**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTtdVvQsuhQg18icPfSiaccicnht6KJC2ZIw0ibxaYrfm1sQLiaictoibqct6ZtexGDt4IL9a0aUv1gG3VTw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTtdVvQsuhQg18icPfSiaccicnqerzXlobpVXujGtCWUpl7YHKOdPA2fZHpHVXcPPN9fJbbI0Sa9Hcmw/640?wx_fmt=png&from=appmsg "")  
  
****  
**修复方案**  
  
  
  
  
**官方修复方案：**  
  
暂无官方修复方案  
  
  
## 临时修复方案：  
  
1.  
排查  
主机上是否启用  
cups-browsed服务  
。  
例如  
RedHat系统使用sudo systemctl status cups-browsed  
  
2.排查该服务是否绑定在0.0.0.0，且对外开放。该服务默认绑定在631端口，使用netstat -ano | grep 631  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKEMKFyAyJBiafkl03aOaCOeH8X5koAPapFQIHgszpu5SmDXYTVDK9p9F5fKazP4HUP3pHib0OP6ibQQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
3.若确认已开启该服务，如果业务场景不需要打印的情况下可禁用该服务。例如 RedHat系统使用sudo systemctl disable cups-browsed  
  
**微步在线产品侧支持情况**  
  
  
  
微步威胁感知平台TDP已支持检测，检测ID为S3100154554，模型/规则高于20240927000000可检出。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTtdVvQsuhQg18icPfSiaccicnhJaeuKx7lhicCExtPlKEznKYyx2qA83TiblFS2MTBgCX3WiaG307XMzVw/640?wx_fmt=png&from=appmsg "")  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hQl5bZ5Mx6PTAQg6tGLiciarvXajTdDnQiacxmwJFZ0D3ictBOmuYyRk99bibwZV49wbap77LibGQHdQPtA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTIdM9koHZFkrtYe5WU5rHxSDicbiaNFjEBAs1rojKGviaJGjOGd9KwKzN4aSpnNZDA5UWpY2E0JAnNg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
[点此电话咨询]()  
  
  
  
  
**X漏洞奖励计划**  
  
  
“X漏洞奖励计划”是微步X情报社区推出的一款  
针对未公开  
漏洞的奖励计划，我们鼓励白帽子提交挖掘到的0day漏洞，并给予白帽子可观的奖励。我们期望通过该计划与白帽子共同努力，提升0day防御能力，守护数字世界安全。  
  
活动详情：  
https://x.threatbook.com/v5/vulReward  
  
  
