#  【漏洞通告】宏景e-HR SQL注入漏洞 CNVD-2023-08743   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-05-12 18:52  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xe238VwRBCibBrqTexvPibJFx3Pmd6xMARNXIlpDyLbETWyYgE6zA2BIODBpiaxLZepSa7KTND6muoQ/640?wx_fmt=gif "")  
  
**漏洞名称：**  
  
宏景e-HR SQL注入漏洞  
  
**组件名称：**  
  
宏景e-HR  
  
**影响范围：**  
  
不详  
  
**漏洞类型：**  
  
SQL注入   
  
**利用条件：**  
  
1、用户认证：否  
  
2、前置条件：默认配置  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：容易，无需授权即可利用  
  
<综合评定威胁等级>：高危，能造成敏感信息泄露。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xe238VwRBCibBrqTexvPibJFlgJwuo8phvu8JrbvTm30JQEHmzu8YcJaU3bwyeybs4o7snqRTytnkw/640?wx_fmt=gif "")  
  
**组件介绍**  
  
宏景e-HR人力资源管理系统是一款专业的企业级人力资源管理软件，旨在帮助企业实现人力资源信息化管理。该系统包括员工档案管理、招聘管理、培训管理、绩效管理、薪酬管理、考勤管理等多个模块，可以帮助企业实现全面的人力资源管理。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xe238VwRBCibBrqTexvPibJFlgJwuo8phvu8JrbvTm30JQEHmzu8YcJaU3bwyeybs4o7snqRTytnkw/640?wx_fmt=gif "")  
  
**漏洞简介**  
  
2023年5月12日，深信服安全团队监测到一则宏景e-HR组件存在 SQL注入漏洞的信息，漏洞编号：CNVD-2023-08743，漏洞威胁等级：高危。  
  
该漏洞是由于宏景e-HR的某页面的过滤不严谨，导致**攻击者可利用该漏洞在未授权的情况下，构造恶意数据执行SQL注入攻击，最终造成服务器敏感性信息泄露。**  
  
  
**影响范围**  
  
宏景e-HR产品是较为流行的人力资源管理系统，属于商业软件，可能受影响的资产主要位于国内。  
  
目前受影响的宏景e-HR版本：不详  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xe238VwRBCibBrqTexvPibJFlgJwuo8phvu8JrbvTm30JQEHmzu8YcJaU3bwyeybs4o7snqRTytnkw/640?wx_fmt=gif "")  
  
**官方修复建议**  
  
  
当前官方已发布最新版本，建议受影响的用户及时更新升级到最新版本。链接如下：  
  
http://www.hjsoft.com.cn  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xe238VwRBCibBrqTexvPibJFlgJwuo8phvu8JrbvTm30JQEHmzu8YcJaU3bwyeybs4o7snqRTytnkw/640?wx_fmt=gif "")  
  
**深信服解决方案**  
  
  
**1.风险资产发现**  
  
支持对宏景e-HR的主动检测，可批量检出业务场景中该事件的受影响资产情况，相关产品如下：  
  
**【深信服主机安全检测响应平台CWPP】**已发布资产检测方案。  
  
**【深信服云镜YJ】**已发布资产检测方案。  
  
  
**2.漏洞主动检测**  
  
支持对宏景e-HR SQL注入漏洞的主动检测，可批量快速检出业务场景中是否存在漏洞风险，相关产品如下：  
  
**【深信服云镜YJ】**预计2023年5月12日发布检测方案。  
  
**【深信服漏洞评估工具TSS】**预计2023年5月15日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2023年5月12日发布检测方案。  
  
**【深信服安全检测与响应平台XDR】**预计2023年5月12日发布检测方案。  
  
  
**3.漏洞安全监测**  
  
支持对宏景e-HR SQL注入漏洞的监测，可依据流量收集实时监控业务场景中的受影响资产情况，快速检查受影响范围，相关产品及服务如下：  
  
**【深信服安全感知管理平台SIP】**已发布检测方案。  
  
**【深信服安全托管服务MSS】**已发布检测方案。  
  
**【深信服安全检测与响应平台XDR】**已发布检测方案。  
  
  
**4.漏洞安全防护**  
  
支持对宏景e-HR SQL注入漏洞的防御，可阻断攻击者针对该事件的入侵行为，相关产品及服务如下：  
  
**【深信服下一代防火墙AF】**已发布防护方案。  
  
**【深信服Web应用防火墙WAF】**已发布防护方案。  
  
**【深信服安全托管服务MSS】**已发布防护方案。  
  
**【深信服安全检测与响应平台XDR】**已发布防护方案。  
  
  
**参考链接**  
  
https://www.cnvd.org.cn/flaw/show/CNVD-2023-08743  
  
  
**时间轴**  
  
  
  
**2023/5/12**  
  
深信服监测到宏景e-HR SQL注入漏洞攻击信息。  
  
  
**2023/5/12**  
  
深信服千里目安全技术中心发布漏洞通告。  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5xe238VwRBCibBrqTexvPibJFT5vvZhiaHP7qiclvYWt9vqhxz9hjWUU65c2jqqRrEFHb4qkwibEcLAPFw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5xe238VwRBCibBrqTexvPibJFhYiad0SerFIe5MoE6lqSMFg03m6q8lAuzKwibQHvGw0Dngt5Y7uYs46w/640?wx_fmt=jpeg "")  
  
  
  
