#  【漏洞通告】Primeton EOS Platform远程代码执行漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2024-04-25 15:13  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xxdYpahJweib8N3ZpnJUmQJyG9HX8p1vrLaBNvm4OpanCV9C9PB95k9iaPHcWavTWsegSxO1hnmgRQ/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞名称：**  
  
Primeton EOS Platform远程代码执行漏洞  
  
**组件名称：**  
  
Primeton EOS Platform  
  
**影响范围：**  
  
Primeton EOS Platform ≤ 7.6  
  
**漏洞类型：**  
  
远程代码执行  
  
**利用条件：**  
  
1、用户认证：不需要用户认证  
  
2、前置条件：默认配置  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：容易，无需授权即可远程代码执行。  
  
<综合评定威胁等级>：高危，能造成远程代码执行。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xxdYpahJweib8N3ZpnJUmQJibQIKUZtMc7BtiaqxvZrfZ9CTibeUib09gfS2llmB77Lf27CQegic8Ky6Wg/640?wx_fmt=gif&from=appmsg "")  
  
**组件介绍**  
  
普元EOS是基于J2EE体系结构、采用面向构件技术实现企业级应用开发、运行、管理、监控和维护的中间件平台。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xxdYpahJweib8N3ZpnJUmQJibQIKUZtMc7BtiaqxvZrfZ9CTibeUib09gfS2llmB77Lf27CQegic8Ky6Wg/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞简介**  
  
2024年4月24日，深瞳漏洞实验室监测到一则Primeton EOS Platform组件存在远程代码执行漏洞的信息，漏洞威胁等级：高危。  
  
**未经身份验证的攻击者可以利用该漏洞在服务器上执行任意代码，导致服务器失陷。**  
  
  
**影响范围**  
  
Primeton EOS Platform ≤ 7.6  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xxdYpahJweib8N3ZpnJUmQJibQIKUZtMc7BtiaqxvZrfZ9CTibeUib09gfS2llmB77Lf27CQegic8Ky6Wg/640?wx_fmt=gif&from=appmsg "")  
  
**官方修复建议**  
  
  
当前官方已发布受影响版本的对应补丁，建议受影响的用户及时更新官方补丁，链接如下：  
  
https://doc.primeton.com:29091/pages/viewpage.action?pageId=118129732  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xxdYpahJweib8N3ZpnJUmQJibQIKUZtMc7BtiaqxvZrfZ9CTibeUib09gfS2llmB77Lf27CQegic8Ky6Wg/640?wx_fmt=gif&from=appmsg "")  
  
**深信服解决方案**  
  
  
**1.风险资产发现**  
  
支持对Primeton EOS Platform 的主动检测，可**批量检出**业务场景中该事件的**受影响资产**情况，相关产品如下：  
  
**【深信服主机安全检测响应平台CWPP】**已发布资产检测方案。  
  
**【深信服云镜YJ】**已发布资产检测方案。  
  
  
**2.漏洞主动检测**  
  
支持对Primeton EOS Platform远程代码执行漏洞的主动检测，可**批量快速检出**业务场景中是否存在**漏洞风险**，相关产品如下：  
  
**【深信服云镜YJ】**预计2024年4月28日发布检测方案。  
  
**【深信服漏洞评估工具TSS】**预2024年4月28日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2024年4月28日发布检测方案（需要具备TSS或CWPP组件能力）。  
  
**【深信服安全检测与响应平台XDR】**预计2024年4月28日发布检测方案（需要具备云镜或CWPP组件能力）。  
  
  
**3.漏洞安全监测**  
  
支持对Primeton EOS Platform远程代码执行漏洞的监测，可依据流量收集**实时监控**业务场景中的**受影响资产情况，快速检查受影响范围**，相关产品及服务如下：  
  
**【深信服安全感知管理平台SIP】**预计2024年05月07日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2024年05月07日发布检测方案（需要具备SIP组件能力）。  
  
【深信服安全检测与响应平台XDR】预计2024年05月07日发布检测方案。  
  
  
**4.漏洞安全防护**  
  
支持对Primeton EOS Platform远程代码执行漏洞的防御，**可阻断攻击者针对该事件的入侵行为**，相关产品及服务如下：  
  
**【深信服下一代防火墙AF】**预计2024年05月07日发布检测方案。  
  
**【深信服终端安全管理系统aES】**预计2024年05月07日发布检测方案。  
  
**【深信服Web应用防火墙WAF】**预计2024年05月07日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2024年05月07日发布检测方案（需要具备AF组件能力）。  
  
**【深信服安全检测与响应平台XDR】**预计2024年05月07日发布检测方案（需要具备AF组件能力）。  
  
  
**参考链接**  
  
  
https://doc.primeton.com:29091/pages/viewpage.action?pageId=118129732  
  
  
**时间轴**  
  
  
  
**2024/4/24**  
  
深瞳漏洞实验室监测到Primeton EOS Platform远程代码执行漏洞信息  
  
  
**2024/4/25**  
  
深瞳漏洞实验室发布漏洞通告。  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5xxdYpahJweib8N3ZpnJUmQJoD8LHt3UkXSOiaFHRAjaNZSXjg4XC6ycZwSlepIGrXPJFtRgpxWR33g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5xxdYpahJweib8N3ZpnJUmQJzzibSM5k7MM4tgiathr2mwRicf0icdl89TlBre4MGa1Y0nTWzbdpWE5XgA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
