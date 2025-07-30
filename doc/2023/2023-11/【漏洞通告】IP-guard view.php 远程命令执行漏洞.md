#  【漏洞通告】IP-guard view.php 远程命令执行漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-11-10 17:17  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wyqlO8cfHb6RA0vh2rW94WVtLdSDLVDyAhXoCcxXxdNyRqayLwK9HmDg1NSPF2pAzcowQ4jaFRng/640?wx_fmt=gif "")  
  
**漏洞名称：**  
  
IP-guard view.php 远程命令执行漏洞  
  
**组件名称：**  
  
IP-guard  
  
**影响范围：**  
  
IP-guard<4.81.0307.0  
  
**漏洞类型：**  
  
远程代码执行  
  
**利用条件：**  
  
1、用户认证：无需认证  
  
2、前置条件：默认配置  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：容易，无需授权即可远程代码执行。  
  
<综合评定威胁等级>：高危，能造成远程代码执行。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wyqlO8cfHb6RA0vh2rW94WM0ftnDsCnkDJeHUsKDdibXrjibQo7ia63NTW7lCh47GaVGicbjiav1ibKpZg/640?wx_fmt=gif "")  
  
**组件介绍**  
  
IP Guard是一款终端安全软件，IP Guard主要用于组织和个人保护网络资源和隐私，防止数据泄露、黑客攻击和恶意软件感染等安全威胁。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wyqlO8cfHb6RA0vh2rW94WM0ftnDsCnkDJeHUsKDdibXrjibQo7ia63NTW7lCh47GaVGicbjiav1ibKpZg/640?wx_fmt=gif "")  
  
**漏洞简介**  
  
2023年11月10日，深瞳漏洞实验室监测到一则IP Guard组件存在远程代码执行漏洞的信息，漏洞编号：暂无，漏洞威胁等级：高危。  
  
该漏洞是由于view.php部分参数的过滤不严谨，可上传非法路径，**攻击者可利用该漏洞在未授权的情况下，构造恶意数据执行远程代码执行攻击，最终获取服务器权限。**  
  
  
**影响范围**  
  
目前受影响的IP-guard版本：  
  
IP-guard<4.81.0307.0  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wyqlO8cfHb6RA0vh2rW94WM0ftnDsCnkDJeHUsKDdibXrjibQo7ia63NTW7lCh47GaVGicbjiav1ibKpZg/640?wx_fmt=gif "")  
  
**官方修复建议**  
  
  
当前官方已发布最新版本，建议受影响的用户及时更新升级到最新版本。链接如下：  
  
https://www.ip-guard.net/  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wyqlO8cfHb6RA0vh2rW94WM0ftnDsCnkDJeHUsKDdibXrjibQo7ia63NTW7lCh47GaVGicbjiav1ibKpZg/640?wx_fmt=gif "")  
  
**深信服解决方案**  
  
  
**1.风险资产发现**  
  
支持对**IP-guard**的主动检测，可**批量检出**业务场景中该事件的**受影响资产**情况，相关产品如下：  
  
**【深信服云镜YJ】**已发布资产检测方案。  
  
  
**2.漏洞主动扫描**  
  
支持对IP-guard view.php 远程命令执行漏洞的主动扫描，可**批量快速检出**业务场景中是否存在**漏洞风险**，相关产品如下：  
  
**【深信服云镜YJ】**已发布扫描方案。  
  
**【深信服漏洞评估工具TSS】**预计2023年11月13日发布扫描方案。  
  
**【深信服安全托管服务MSS】**预计2023年11月13日发布扫描方案，（需要具备TSS组件能力）。  
  
**【深信服安全检测与响应平台XDR】**已发布扫描方案,（需要具备云镜组件能力）。  
  
  
**3.漏洞安全监测**  
  
支持对IP-guard view.php 远程命令执行漏洞的监测，可依据流量收集**实时监控**业务场景中的**受影响资产情况，快速检查受影响范围**，相关产品及服务如下：  
  
**【深信服安全感知管理平台SIP】**预计2023年11月13日发布监测方案。  
  
**【深信服安全托管服务MSS】**预计2023年11月13日发布监测方案（需要具备SIP组件能力）。  
  
**【深信服安全检测与响应平台XDR】**预计2023年11月13日发布监测方案。  
  
  
**4.漏洞安全防护**  
  
支持对IP-guard view.php 远程命令执行漏洞的防御，可阻断攻击者针对该事件的入侵行为，相关产品及服务如下：  
  
**【深信服下一代防火墙AF】**预计2023年11月13日发布防护方案。  
  
**【深信服终端安全管理系统aES】**预计2023年11月13日发布防护方案。  
  
**【深信服Web应用防火墙WAF】**预计2023年11月13日发布防护方案。  
  
**【深信服安全托管服务MSS】**预计2023年11月13日发布防护方案（需要具备AF组件能力）。  
  
**【深信服安全检测与响应平台XDR】**预计2023年11月13日发布防护方案（需要具备AF组件能力）。  
  
  
**参考链接**  
  
  
https://www.ip-guard.net/  
  
  
**时间轴**  
  
  
  
**2023/11/10**  
  
深瞳漏洞实验室监测到IP-guard view.php 远程命令执行漏洞攻击信息。  
  
  
**2023/11/10**  
  
深瞳漏洞实验室发布漏洞通告。  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5wyqlO8cfHb6RA0vh2rW94WKLy8z1L2w7iamLWffWXb8FOwegiaGTkAc1ku3116IxRpvtAg4k5H0S1g/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5wyqlO8cfHb6RA0vh2rW94WVKARTLM7s4OTaibQ14mlbbbbicfRSwPqLQzicud6K9MZqByJadABQI4hQ/640?wx_fmt=jpeg "")  
  
  
