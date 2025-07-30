#  【复现】Nexus Repository3 任意文件下载漏洞的风险通告   
原创 赛博昆仑CERT  赛博昆仑CERT   2024-05-22 16:16  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iaZ7t7b9Dodvib7ddpGMC6vx4COAy4sBoGbGCkwVUIJSHBPI0z1Utrp1h5ys6ygT3albl3PgjejJcRRRiaDFFbMBA/640?wx_fmt=gif "")  
  
  
-  
赛博昆仑漏洞安全通告-  
  
Nexus Repository3 任意文件下载漏洞的风险通告   
  
![](https://mmbiz.qpic.cn/mmbiz_svg/7j1UQofaR9fsNXgsOXHVKZMJ1PCicm8s4RHQVjCJEjX63AsNibMx3So4wSMAvubEOoU2vLqYY7hIibIJbkEaPIDs5A4ianh5jibxw/640?wx_fmt=svg "")  
  
  
  
****  
**漏洞描述**  
  
近日，赛博昆仑CERT监测到 Sonatype Nexus Repository3 任意文件下载漏洞（CVE-2024-4956）的漏洞情报。Sonateype Nexus Repository 3中的路径遍历漏洞允许未经身份验证的攻击者读取远程操作系统上的任意文件。  
  
Nexus是一个强大且使用广泛的Maven仓库管理器，它极大地简化了自己内部仓库的维护和外部仓库的访问，利用Nexus你可以只在一个地方就能够完全控制访问和部署在你所维护仓库中的每个Artifact。  
<table><tbody><tr><td valign="top" style="border-width: 1pt;border-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞名称</strong><o:p></o:p></span></p></td><td colspan="3" valign="top" style="border-top-width: 1pt;border-color: rgb(221, 221, 221);border-right-width: 1pt;border-bottom-width: 1pt;border-left-width: initial;border-left-style: none;padding: 3pt 6pt 1.5pt;"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">Sonatype Nexus Repository3 任意文件下载漏洞<o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞公开编号</strong><o:p></o:p></span></p></td><td colspan="3" valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">CVE-2024-4956<o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>昆仑漏洞库编号</strong><o:p></o:p></span></p></td><td colspan="3" valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">CYKL-2024-009155<o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞类型</strong><o:p></o:p></span></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">文件下载</span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>公开时间</strong></span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">2024-05-16<o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞等级</strong><o:p></o:p></span></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">高危</span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>评分</strong></span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">7.5<o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞所需权限</strong><o:p></o:p></span></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">无权限要求</span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞利用难度</strong></span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">低<o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong><span lang="EN-US" style="font-family: Arial, sans-serif;">PoC</span></strong><strong>状态</strong><o:p></o:p></span></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">未知</span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong><span lang="EN-US" style="font-family: Arial, sans-serif;">EXP</span></strong><strong>状态</strong></span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">未知<o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞细节</strong><o:p></o:p></span></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">未知</span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>在野利用</strong></span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;word-break: break-all;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">未知</span></p></td></tr></tbody></table>  
  
**影响版本**  
  
Sonatype Nexus Repository3 < 3.68.1  
  
**利用条件**  
  
无需任何利用条件  
  
**漏洞复现**  
  
目前赛博昆仑CERT已确认漏洞原理，  
复现环境为官方的Docker sonatype/nexus3:3.68.0-java8，读取 /etc/passwd 作为证明：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaZ7t7b9DodsNsRnsPU5u21AmHuhGpReZqBuiaicXmpoDFs4YP8a0ol85L7NHt75XskMdAHHPcBWEN2zmAFXfHiboA/640?wx_fmt=png&from=appmsg "")  
  
**防护措施**  
  
【  
修复建议】：  
  
目前，官方已发布修复建议，建议受影响的用户尽快升级至安全版本。  
  
下载地址：https://help.sonatype.com/en/download-archives---repository-manager-3.htm  
l  
  
  
【  
临时缓解措施】：  
  
1.  
对于Sonateype Nexus Repository的每个实例，编辑（basedir）/etc/jetty/jetty.xml 并从文件中删除这一行：  
  
2.  
重新启动Nexus存储库，使更改生效。  
  
此更改可防止利用该漏洞，但也会防止应用程序从（installdir）/public目录加载文件，可能会导致轻微的UI渲染问题，而不会影响核心产品功能。  
  
**技术咨询**  
  
赛博昆仑支持对用户提供轻量级的检测规则或热补方式，可提供定制化服务适  
配多种产品及规则，帮助用户进行漏洞检测和修复。  
  
赛博昆仑CERT已开启年订阅服务，付费客户(可申请试用)将获取更多技术详情，并支持适配客户的需求。  
  
联系邮箱：cert@cyberkl.com  
  
公众号：赛博昆仑CERT  
  
**参考链接**  
  
https://support.sonatype.com/hc/en-us/articles/29416509323923-CVE-2024-4956-Nexus-Repository-3-Path-Traversal-2024-05-16  
  
**时间线**  
  
2024年05月16日，官方发布通告  
  
2024年05月22日，赛博昆仑CERT公众号发布漏洞风险通告  
  
