#  0day 速修！Smartbi 远程命令执行漏洞   
原创 微步情报局  微步在线研究响应中心   2023-03-01 14:58  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/fFyp1gWjicMKfKRFs38NM1VwWwgdcibkbZDR4HSKNiboI5RjPvcFIlraPg33FWhm9sz0ZAsdFJspp4l3icRyNE7bQA/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
01 漏洞概况   
  
  
  
近日，微步在线通过“X漏洞奖励计划”获取到Smartbi大数据分析平台远程命令执行漏洞的0day相关漏洞情报，攻击者可以通过此漏洞进行任意命令执行，导致系统被攻击与控制。Smartbi是思迈特软件推出的商业智能BI软件，满足BI产品的发展阶段。思迈特软件整合了各行业的数据分析和决策支持的功能需求，满足最终用户在企业级报表、数据可视化分析、自助探索分析、数据挖掘建模、AI 智能分析等场景的大数据分析需求。  
**自查检测：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLSfha8Xprsk9MWCa28ibqwCibudqlxiaKgVZyDwE2O8ZmKnBkgglgJUc1SRT11vfZQY2KUXiciap5TLpg/640?wx_fmt=png "")  
  
**此次受影响版本如下：**  
<table><tbody><tr style="height:18.3000pt;"><td style="padding: 0pt 5.4pt;border-color: rgb(0, 0, 0);border-style: solid;border-width: 1pt;word-break: break-all;" width="292" valign="top"><p style="text-indent:10.5000pt;line-height:150%;"><strong><span style="mso-spacerun:&#39;yes&#39;;font-family:微软雅黑;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;mso-font-kerning:1.0000pt;">Smartbi大数据分析平台</span></strong></p></td><td style="padding: 0pt 5.4pt;border-color: rgb(0, 0, 0) rgb(0, 0, 0) rgb(0, 0, 0) currentcolor;border-style: solid solid solid none;border-width: 1pt 1pt 1pt medium;word-break: break-all;" width="177" valign="top"><p style="text-align:center;text-indent:10.5000pt;line-height:150%;"><strong><span style="mso-spacerun:&#39;yes&#39;;font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-weight:bold;font-size:10.5000pt;mso-font-kerning:1.0000pt;">是否受影响</span></strong></p></td></tr><tr style="height:18.6000pt;"><td style="padding: 0pt 5.4pt;border-color: currentcolor rgb(0, 0, 0) rgb(0, 0, 0);border-style: none solid solid;border-width: medium 1pt 1pt;" width="298" valign="top"><p style="text-indent:10.5000pt;text-align:left;line-height:150%;"><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;mso-font-kerning:1.0000pt;">V</span><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;mso-font-kerning:1.0000pt;">7</span><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;mso-font-kerning:1.0000pt;">&lt;</span><span style="mso-spacerun:&#39;yes&#39;;font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;mso-font-kerning:1.0000pt;">=Smartbi&lt;= V10.5.8</span><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;mso-font-kerning:1.0000pt;"></span></p></td><td style="padding: 0pt 5.4pt;border-color: currentcolor rgb(0, 0, 0) rgb(0, 0, 0) currentcolor;border-style: none solid solid none;border-width: medium 1pt 1pt medium;" width="177" valign="top"><p style="text-align:center;text-indent:10.5000pt;line-height:150%;"><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;mso-font-kerning:1.0000pt;">是</span><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;mso-font-kerning:1.0000pt;"></span></p></td></tr></tbody></table>  
  
02 漏洞评估   
  
  
  
**公开程度**  
：PoC未公开  
**利用条件**  
：无权限要求**交互要求**：0-click**漏洞危害**：高危、命令执行**影响范围**：Smartbi大数据分析平台  
  
03 修复方案   
  
  
  
**1、官方修复缓解措施**  
**自动升级**：登录后台->右上角系统监控->系统补丁->安装补丁->在线更新  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLSfha8Xprsk9MWCa28ibqwChKfWFMSbeVhYicasph4552mcP1waIAcBobvQQSm4rm23fX0KPz1goZQ/640?wx_fmt=png "")  
  
**手动升级**：下载补丁->登录后台->右上角系统监控->系统补丁->安装补丁->手动更新**（1）补丁地址：**  
https://www.smartbi.com.cn/patchinfo**（2）参考链接：**https://www.smartbi.com.cn/patchinfohttps://wiki.smartbi.com.cn/pages/viewpage.action?pageId=50692623  
**2、流量侧检测排查**  
微步在线威胁感知平台TDP已支持检测该漏洞：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLSfha8Xprsk9MWCa28ibqwCJxBmQpq3ibvUY4QzdP8g5EnaGd9kpRqEgQXZibm4a1mxXORlMlWrpgug/640?wx_fmt=png "")  
  
  
**3、受影响资产排查**  
微步在线攻击面管理平台OneRisk可以检出该漏洞：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLSfha8Xprsk9MWCa28ibqwC8FhX7ewXGpGwLGcnALox2p4QkHI1hfGWBw4139icPKCicCJjibib7Iia1pA/640?wx_fmt=png "")  
  
微 步 在 线 OneCare 安 全 服 务 已 支 持 该 漏 洞 的 风 险 排 查 和 处 置https://www.threatbook.cn/next/onecare  
### 04 时间线 2022.11 微步“X漏洞奖励计划”获取该漏洞相关情报2022.12 漏洞分析与研究2022.12 TDP 支持检测2023.01 OneRisk 支持检测2023.02 厂商发布补丁2023.03 微步发布报告  
###   
  
点击下方名片，关注我们  
  
第一时间为您推送最新威胁情报  
  
  
  
