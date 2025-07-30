#  【漏洞通告】Apache Superset 身份认证绕过漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-04-26 19:56  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zQRaSmUiaicHhcZSrQyEjuV5eBiakQ3Enz1UkXyB51fu5z1sTSvOVy7frISpISbmxTSPcJKPBNerWfg/640?wx_fmt=gif "")  
  
**漏洞名称：**  
  
Apache Superset 身份认证绕过漏洞(CVE-2023-27524)  
  
**组件名称：**  
  
Apache Superset  
  
**影响范围：**  
  
Apache Superset <= 2.0.1  
  
**漏洞类型：**  
  
身份认证绕过  
  
**利用条件：**  
  
1、用户认证：否  
  
2、前置条件：无  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：简单。  
  
<综合评定威胁等级>：高危，能获取管理员权限。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zQRaSmUiaicHhcZSrQyEjuV5RZWvrJiaP0cncy6t8wQqvFpdQQGXIWRcsIGtyR0zjR0TibBz7999UR4A/640?wx_fmt=gif "")  
  
**组件介绍**  
  
Apache Superset 是一款现代化的开源大数据工具，也是企业级商业智能 Web 应用，用于数据探索分析和数据可视化。它提供了简单易用的无代码可视化构建器和声称是最先进的 SQL 编辑器，用户可以使用这些工具快速地构建数据仪表盘。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zQRaSmUiaicHhcZSrQyEjuV5RZWvrJiaP0cncy6t8wQqvFpdQQGXIWRcsIGtyR0zjR0TibBz7999UR4A/640?wx_fmt=gif "")  
  
**漏洞简介**  
  
2023年4月26日，深信服安全团队监测到一则 Apache Superset 组件存在身份认证绕过漏洞的信息，漏洞编号：CVE-2023-27524，漏洞威胁等级：高危。  
  
  
该漏洞是由于Apache Superset 组件使用硬编码的密钥加密会话Cookie，导致攻击者可通过伪造Cookie实现身份认证绕过，远程且未经过身份认证的**攻击者可利用此漏洞进行身份认证绕过攻击，从而获取管理员权限。**  
  
  
**影响范围**  
  
目前受影响的 Apache Superset版本：  
  
Apache Superset <= 2.0.1  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zQRaSmUiaicHhcZSrQyEjuV5RZWvrJiaP0cncy6t8wQqvFpdQQGXIWRcsIGtyR0zjR0TibBz7999UR4A/640?wx_fmt=gif "")  
  
**官方修复建议**  
  
  
当前官方已发布最新版本，建议受影响的用户及时更新升级到最新补丁版本。链接如下：  
  
https://superset.apache.org/  
  
  
**参考链接**  
  
https://lists.apache.org/thread/n0ftx60sllf527j7g11kmt24wvof8xyk  
  
  
**时间轴**  
  
  
  
**2023/4/26**  
  
深信服监测到Apache Superset官方发布安全通告。  
  
  
**2023/4/26**  
  
深信服千里目安全技术中心发布漏洞通告。  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5zQRaSmUiaicHhcZSrQyEjuV5SmMtBicLs6CledGwSv7JOVaBy7xNhBr2FZia7VFqL5GM4ZxpL7fVicjLg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5zQRaSmUiaicHhcZSrQyEjuV5NekC0vTQOZ0y7aLsNs03wKk9jnzGKtfY8Ed0hrLHWiaJhyu4zymbq3Q/640?wx_fmt=jpeg "")  
  
  
  
