#  0day 速修！瑞友天翼应用虚拟化系统远程代码执行漏洞   
原创 微步情报局  微步在线研究响应中心   2023-04-10 17:25  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKKIwzXUMSTRxJbmEAibibMabggxYnpFRmPXP4YIicg335GmW5s2lb5jibiaEImQXzbHnA7icXL3Z8Skpwg/640?wx_fmt=png "")  
  
01 漏洞概况   
  
  
  
近日，微步在线漏洞团队通过“X漏洞奖励计划”获取到瑞友天翼应用虚拟化系统远程代码执行漏洞情报(0day)，攻击者可以通过该漏洞执行任意代码，导致系统被攻击与控制。瑞友天翼应用虚拟化系统是基于服务器计算架构的应用虚拟化平台，它将用户各种应用软件集中部署到瑞友天翼服务集群，客户端通过WEB即可访问经服务器上授权的应用软件，实现集中应用、远程接入、协同办公等。  
**经过微步在线漏洞团队分析与研判，该漏洞利用难度低，可以直接远程代码执行，影响范围较大且覆盖多个行业，建议尽快修复。**  
  
  
  
******自查检测：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMIyA0CjR38XEp60ickhzibrH3SibQ231JyXEPpEicpIibKDjMmHyd8kNiagNXiaoPZF4QOVlRdo8k4tYJyxg/640?wx_fmt=png "")  
  
**此次受影响版本如下：**  
<table><tbody><tr style="height:18.3000pt;"><td style="padding: 0pt 5.4pt;border-color: rgb(0, 0, 0);border-style: solid;border-width: 1pt;word-break: break-all;" width="295.3333333333333" valign="top"><p style="text-indent:10.5000pt;line-height:150%;"><span style="font-size: 15px;"><strong><span style="font-size: 15px;font-family: 黑体;">瑞友天翼应用虚拟化系统</span></strong></span></p></td><td style="padding: 0pt 5.4pt;border-color: rgb(0, 0, 0) rgb(0, 0, 0) rgb(0, 0, 0) currentcolor;border-style: solid solid solid none;border-width: 1pt 1pt 1pt medium;word-break: break-all;" width="166.33333333333334" valign="top"><section style="text-align: center;line-height: 150%;text-indent: 0em;"><strong style="mso-bidi-font-weight:normal;"><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;mso-ansi-font-weight:bold;font-size:10.5000pt;mso-font-kerning:1.0000pt;"><span style="font-family:黑体;">是否受影响</span></span></strong><strong style="mso-bidi-font-weight:normal;"><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;mso-ansi-font-weight:bold;font-size:10.5000pt;mso-font-kerning:1.0000pt;"></span></strong></section></td></tr><tr style="height:18.6000pt;"><td style="padding: 0pt 5.4pt;border-color: currentcolor rgb(0, 0, 0) rgb(0, 0, 0);border-style: none solid solid;border-width: medium 1pt 1pt;word-break: break-all;" width="301" valign="top"><p style="text-indent:10.5000pt;text-align:left;line-height:150%;"><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;mso-font-kerning:1.0000pt;">5.x&lt;=version&lt;=7.0.2.1<br/></span><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;mso-font-kerning:1.0000pt;"></span></p></td><td style="padding: 0pt 5.4pt;border-color: currentcolor rgb(0, 0, 0) rgb(0, 0, 0) currentcolor;border-style: none solid solid none;border-width: medium 1pt 1pt medium;" width="171.33333333333337" valign="top"><section style="text-align: center;line-height: 150%;text-indent: 0em;"><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;mso-font-kerning:1.0000pt;"><span style="font-family:黑体;">是</span></span><span style="font-family:黑体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;mso-font-kerning:1.0000pt;"></span></section></td></tr></tbody></table>  
  
02 漏洞评估   
  
  
  
**公开程度：**PoC未公开  
**利用条件：**  
无权限要求  
  
**交互要求：**  
0-click  
  
**漏洞危害：**  
命令执行->代码执行  
  
**影响范围：**  
瑞友天翼应用虚拟化系统  
  
03 修复方案   
  
  
  
**1.   官方修复措施**  
官方已发布修复方案，建议升级至安全版本V7.0.3.1  
下载地址：http://soft.realor.cn:88/Gwt7.0.3.1.exe  
  
  
**2.   流量侧检测排查**  
  
微步在线威胁感知平台TDP已支持检测该漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMIyA0CjR38XEp60ickhzibrH3LYM25f0QGJnIsqiaxfpDvTSt6N5YoDHWUCXS3DEIzlAjCELLsqaZDKg/640?wx_fmt=png "")  
  
  
X情报社区-资产测绘已包含相关测绘数据  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMIyA0CjR38XEp60ickhzibrH3ibZqLicoWbrUibo7gyjlhhlUeiaCniabiahyvQGmAmnJssVWvia7tBK3O0tmQ/640?wx_fmt=png "")  
  
### 04 时间线 2023.01 微步“X漏洞奖励计划”获取该漏洞相关情报2023.02 漏洞分析与研究2023.02 TDP支持检测2023.03 厂商发布补丁2023.04 微步发布报告  
###   
  
点击下方名片，关注我们  
  
第一时间为您推送最新威胁情报  
  
  
