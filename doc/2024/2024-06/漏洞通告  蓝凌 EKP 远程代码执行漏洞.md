#  漏洞通告 | 蓝凌 EKP 远程代码执行漏洞   
原创 微步情报局  微步在线研究响应中心   2024-06-24 17:07  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKNkm4Pg1Ed6nv0proxQLEKJ2CUCIficfAwKfClJ84puialc9eER0oaibMn1FDUpibeK1t1YvgZcLYl3A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**漏洞概况**  
  
  
  
蓝凌 EKP 是由深圳市蓝凌软件股份有限公司开发，是一款针对中小企业的移动化智能办公产品。  
  
近日，微步漏洞团队获取到蓝凌 EKP 远程代码执行漏洞情报（https://x.threatbook.com/v5/vul/XVE-2023-18344）。攻击者可通过该漏洞执行恶意代码，进而控制服务器。  
该漏洞利用难度低，造成危害大，建议用户尽快修复。  
  
  
**漏洞处置优先级(VPT)**  
  
  
  
**综合处置优先级：高**  
<table><tbody style="outline: 0px;"><tr style="outline: 0px;height: 31.0667px;"><td width="110" colspan="1" rowspan="2" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><strong style="outline: 0px;">基本信息</strong></span><o:p style="outline: 0px;"></o:p></p></td><td width="186" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">微步编号</span><o:p style="outline: 0px;"></o:p></p></td><td width="88" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="outline: 0px;font-size: 14px;color: rgb(84, 84, 84);">XVE-2023-18344</span></td></tr><tr style="padding-right: 7.2px;padding-left: 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 31.0667px;"><td colspan="1" rowspan="1" width="189" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="31"><span style="outline: 0px;font-size: 14px;color: rgb(84, 84, 84);">漏洞类型</span><br style="outline: 0px;"/></td><td colspan="1" rowspan="1" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="31"><span style="font-size: 14px;color: rgb(84, 84, 84);">远程代码执行</span></td></tr><tr style="outline: 0px;height: 31.0667px;"><td width="135" colspan="1" rowspan="5" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用条件评估</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="169" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用漏洞的网络条件<br style="outline: 0px;"/></span><o:p style="outline: 0px;"></o:p></p></td><td width="88" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">远程</span></td></tr><tr style="outline: 0px;height: 31.0667px;"><td width="189" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;">是否需要绕过安全机制</span><o:p style="outline: 0px;"></o:p></p></td><td width="221" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">不需要</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="189" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">对被攻击系统的要求<br style="outline: 0px;"/></span><o:p style="outline: 0px;"></o:p></p></td><td width="221" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">默认配置</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="189" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;text-wrap: wrap;">利用漏洞的权限要求</span><o:p style="outline: 0px;"></o:p></p></td><td width="221" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">无需任何权限</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="189" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">是否需要受害者配合</span><o:p style="outline: 0px;"></o:p></p></td><td width="221" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">不需要</span></td></tr><tr style="outline: 0px;height: 27.2px;"><td width="115" colspan="1" rowspan="2" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">利用情报</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="169" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;">POC是否公开</span><o:p style="outline: 0px;"></o:p></p></td><td width="88" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">否</span></td></tr><tr style="padding-right: 7.2px;padding-left: 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 27.2px;"><td colspan="1" rowspan="1" width="169" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="27"><span style="outline: 0px;font-size: 14px;color: rgb(84, 84, 84);">微步已捕获攻击行为<br style="outline: 0px;"/></span></td><td colspan="1" rowspan="1" width="222" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;" height="27"><span style="font-size: 14px;color: rgb(84, 84, 84);">否<br/></span></td></tr></tbody></table>#   
  
**漏洞影响范围**  
  
  
  
<table><tbody style="outline: 0px;"><tr style="outline: 0px;height: 33.2px;"><td width="152" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">产品名称</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">深圳市蓝凌软件股份有限公司-蓝凌EKP</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="172" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">受影响版本</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">version = V16</span></td></tr><tr style="outline: 0px;height: 27px;"><td width="172" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">影响范围</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">千级</span></td></tr><tr style="outline: 0px;height: 35.6px;"><td width="172" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;">有无修复补丁</span></strong><o:p style="outline: 0px;"></o:p></p></td><td width="346" colspan="1" rowspan="1" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);">有<br/></span></td></tr></tbody></table>  
  
前往X情报社区资产测绘查看影响资产详情：  
  
https://x.threatbook.com/v5/survey?q=app%3D%22Landray-OA%22  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMI6PiabnkrkxqTUVPr3ucMAzO8bL0eUdrfnH9ia39NJECN19lHE96plp27dsJ8TfbClPY80EKaicI8jw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**漏洞复现**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMI6PiabnkrkxqTUVPr3ucMAzfP85Xagqj7qiasbfEY1ymnATZt1GCynqpxIRteapq2Wiaia6GiajuYiarUQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMI6PiabnkrkxqTUVPr3ucMAzVtA4VWKgXJmuiap7s2bRgONUFcSpqdOZZqomOee44agziaGCYZzickusw/640?wx_fmt=png&from=appmsg "")  
  
  
**修复方案**  
  
  
  
  
**官方修复方案：**  
  
厂商已发布补丁修复此漏洞，漏洞内部编号为EKP-1216，请尽快联系厂商(https://www.landray.com.cn/)获取补丁下载更新。  
  
## 临时修复方案：  
- 使用防护类设备对相关资产进行防护，拦截请求中的恶意命令执行语句。  
  
- 如非必要，避免将资产暴露在互联网。  
  
**微步产品侧支持情况**  
  
  
  
微步威胁感知平台TDP已支持检测，检测ID为 S3100121131、S3100121135、S3100121142，模型/规则高于20230703000000可检出。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMI6PiabnkrkxqTUVPr3ucMAzHKU7XODZAKKZE5lIhNLfzicSByxzJnRUVs4XWibDQtPTm6kQGAdknzRA/640?wx_fmt=png&from=appmsg "")  
  
微步威胁防御系统OneSIG已支持防护，规则ID为3100121131、3100121135。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMI6PiabnkrkxqTUVPr3ucMAzSSC4SiaDyfkibUv1qibWia5yjCCbfib3h067x5EwJqWLKldNUIG61x8dqVw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hQl5bZ5Mx6PTAQg6tGLiciarvXajTdDnQiacxmwJFZ0D3ictBOmuYyRk99bibwZV49wbap77LibGQHdQPtA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTIdM9koHZFkrtYe5WU5rHxSDicbiaNFjEBAs1rojKGviaJGjOGd9KwKzN4aSpnNZDA5UWpY2E0JAnNg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
[点此电话咨询]()  
  
  
  
  
**X漏洞奖励计划**  
  
  
“X漏洞奖励计划”是微步X情报社区推出的一款  
针对未公开  
漏洞的奖励计划，我们鼓励白帽子提交挖掘到的0day漏洞，并给予白帽子可观的奖励。我们期望通过该计划与白帽子共同努力，提升0day防御能力，守护数字世界安全。  
  
活动详情：  
https://x.threatbook.com/v5/vulReward  
  
  
  
