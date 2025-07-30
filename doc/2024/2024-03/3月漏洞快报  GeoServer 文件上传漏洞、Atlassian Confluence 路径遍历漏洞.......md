#  3月漏洞快报 | GeoServer 文件上传漏洞、Atlassian Confluence 路径遍历漏洞......   
原创 梆梆安全  梆梆安全   2024-03-28 14:23  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/YpfGdibD1mRlEhUENIEoRKT24icXeO3JJwibGtsO8Joic50gqlSvLmCHJreMjPSJ65ya8RqWGTpurGMxXM3xJN7faQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
近日，梆梆安全专家整理发布安全漏洞报告，主要涉及以下产品/组件：  
GeoServer、Atlassian Confluence、Fortinet FortiClientEMS、JetBrains TeamCity，  
**建议相关**  
**用户及时采取措施做好资产自查与预防工作。**  
  
**GeoServer 文件上传漏洞**  
  
**（CVE-2023-51444）**  
  
  
  
  
  
**组件介绍**  
  
GeoServer是一个用Java编写的开源软件服务器，允许用户共享和编辑地理空间数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YpfGdibD1mRnUERYwPWmG3HqUnl2KjLjMMD9957tTLvlMmYnsd331A4nGsoo9e1Klw3via4dzBPgrBjmHreIE8zA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**漏洞描述**  
  
GeoServer受影响版本中存在任意文件上传漏洞，由于未验证用户输入的文件包装器资源路径是否包含".."，  
**有登陆权限的攻击者可以通过构造恶意的REST Coverage Store API请求，上传任意文件以此执行任意代码。**  
  
  
  
  
**影响范围**  
  
org.geoserver:gs-restconfig＜2.23.4  
  
2.24.0≤org.geoserver:gs-platform＜ 2.24.12.24.0≤org.geoserver:gs-restconfig＜ 2.24.1org.geoserver:gs-platform＜2.23.4  
  
  
  
  
**官方修复建议**  
  
将组件org.geoserver:gs-restconfig升级至 2.24.1 及以上版本将org.geoserver:gs-platform升级至 2.23.4 及以上版本将组件org.geoserver:gs-restconfig升级至 2.23.4 及以上版本将组件org.geoserver:gs-platform升级至 2.24.1 及以上版本  
  
  
  
**Atlassian Confluence 路径遍历漏洞**  
  
**（CVE-2024-21677）**  
  
  
  
  
  
**组件介绍**  
  
Atlassian Confluence(简称Confluence)是一个专业的Wiki程序。它是一个知识管理的工具，通过它可以实现团队成员之间的协作和知识共享。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YpfGdibD1mRnUERYwPWmG3HqUnl2KjLjM5lGYudqfia6ly00wCo5iaHZL15ZLZWhAiaNYLfFjtxEHPnIwo0aNibGslg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**漏洞描述**  
  
Atlassian Confluence 路径遍历漏洞(CVE-2024-21677)，**未经身份验证的远程攻击者需要与受害者交互来利用该漏洞，成功后可对Confluence服务器机密性，完整性和可用性造成严重影响。**  
  
  
  
  
**影响范围**  
  
16.9≤GitLab≤16.9.1  
  
Confluence Data Center 8.8.0  
  
8.7.0 ≤ Confluence Data Center ≤ 8.7.2  
  
8.6.0 ≤ Confluence Data Center ≤ 8.6.2  
  
8.5.0 ≤ Confluence Data Center ≤ 8.5.6 (LTS)  
  
8.4.0 ≤ Confluence Data Center ≤ 8.4.5  
  
8.3.0 ≤ Confluence Data Center ≤ 8.3.4  
  
8.2.0 ≤ Confluence Data Center ≤ 8.2.3  
  
8.1.0 ≤ Confluence Data Center ≤ 8.1.4  
  
8.0.0 ≤ Confluence Data Center ≤ 8.0.4  
  
7.20.0 ≤ Confluence Data Center ≤ 7.20.3  
  
7.19.0 (LTS) ≤ Confluence Data Center ≤ 7.19.19 (LTS)  
  
7.18.0 ≤ Confluence Data Center ≤ 7.18.3  
  
7.17.0 ≤ Confluence Data Center ≤ 7.17.5  
  
Confluence Data Center ≤ 7.17.0  
  
8.7.0 ≤ Confluence Server ≤ 8.7.2  
  
8.6.0 ≤Confluence Server ≤ 8.6.2  
  
8.5.0 ≤ Confluence Server ≤ 8.5.6 (LTS)  
  
8.4.0 ≤ Confluence Server ≤ 8.4.5  
  
8.3.0 ≤ Confluence Server ≤ 8.3.4  
  
8.2.0 ≤ Confluence Server ≤ 8.2.3  
  
8.1.0 ≤ Confluence Server ≤ 8.1.4  
  
8.0.0 ≤ Confluence Server ≤ 8.0.4  
  
7.20.0 ≤ Confluence Server ≤ 7.20.3  
  
7.19.0 (LTS) ≤ Confluence Server ≤ 7.19.19 (LTS)  
  
7.18.0 ≤ Confluence Server ≤ 7.18.3  
  
7.17.0 ≤ Confluence Server ≤ 7.17.5  
  
Confluence Server   
≤ 7.17.0  
  
  
  
  
**官方修复建议**  
  
目前官方已发布安全更新，受影响用户可以更新到最新版本：  
  
Confluence Data Center ≥ 8.8.1  
  
Confluence Data Center ≥ 8.5.7 (LTS)  
  
Confluence Data Center ≥ 7.19.20 (LTS)  
  
Confluence Server ≥ 8.5.7 (LTS)  
  
Confluence Server ≥ 7.19.20 (LTS)  
  
如果无法升级，请将实例升级到指定支持的固定版本之一。  
  
  
请参阅发布说明：  
  
https://confluence.atlassian.com/doc/confluence-release-notes-327.html  
  
您可以从下载中心下载最新版本的 Confluence Data Center 和 Confluence Server：  
  
https://www.atlassian.com/software/confluence/download-archives  
  
  
  
**Fortinet FortiClientEMS SQL注入漏洞**  
  
**（CVE-2023-48788）**  
  
  
  
  
  
**组件介绍**  
  
Fortinet FortiClientEMS是美国Fortinet公司的一个集中式中央管理系统，它提供了一种安全管理解决方案，支持对多终端（如计算机）进行可扩展的集中管理。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YpfGdibD1mRnUERYwPWmG3HqUnl2KjLjMdYhxNfgUH9kICe4tzP46KL2sHicj7ddUVpCajnIKezibswu7WvYU25Pw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**漏洞描述**  
  
Fortinet FortiClientEMS 平台存在 SQL注入漏洞，未经认证的远程攻击者可向服务器发出精心制作的恶意数据，**成功利用此漏洞可在目标系统上执行任意命令。鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。**  
  
  
  
  
**影响范围**  
  
7.2.0   
≤ FortiClientEMS 7.2 < 7.2.3  
  
7.0.1   
≤ FortiClientEMS 7.0 < 7.0.11  
  
  
  
  
**官方修复建议**  
  
目前官方已有可更新版本，建议受影响用户升级至：  
  
FortiClientEMS 7.2   
≥ 7.2.3  
  
FortiClientEMS 7.0   
≥ 7.0.11  
  
  
**JetBrains TeamCity 身份验证绕过漏洞**  
  
**（CVE-2024-27198）**  
  
  
  
  
  
**组件介绍**  
  
eam City是Jetbrains在2000年开发的一个连续集成工具，它帮助商业开发者经常将他们的工作副本编译到共享的主线服务器上。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YpfGdibD1mRnUERYwPWmG3HqUnl2KjLjMFosWtWr7sibNibdH5b1JKlQk4gdWNcFBTezU7icHcxs9Mq8F5cicriby5Yg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**漏洞描述**  
  
**未经身份验证的远程攻击者利用CVE-2024-27198可以绕过系统身份验证，完全控制所有TeamCity项目、构建、代理和构件，为攻击者执行供应链攻击。**  
  
  
  
  
**影响范围**  
  
TeamCity < 2023.11.4  
  
  
  
  
**官方修复建议**  
  
目前官方已有可更新版本，建议受影响用户升级至：  
  
TeamCity   
≥ 2023.11.4   
  
参考：https://blog.jetbrains.com/teamcity/2024/03/teamcity-2023-11-4-is-out/  
  
推荐阅读  
  
  
Recommended  
  
# >标准应用 | GB/T 41391中“App嵌入第三方SDK”相关条款测试技术解析  
#   
# >API 安全专题（15）| 2024 年 API 安全风险趋势与预测  
#   
# >创新力 MAX！梆梆安全荣获高新技术企业创新能力最高5A级评定  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YpfGdibD1mRnDY5407c6UFGMlacqbuQrzVRU5sgjicTxqFdSDRLzgbfM5BibmVpNibL7Wlia0630UxgBIGaX18IJzqQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
