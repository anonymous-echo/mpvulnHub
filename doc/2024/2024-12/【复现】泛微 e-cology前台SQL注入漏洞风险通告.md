#  【复现】泛微 e-cology前台SQL注入漏洞风险通告   
原创 赛博昆仑CERT  赛博昆仑CERT   2024-12-03 11:20  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iaZ7t7b9Dodvib7ddpGMC6vx4COAy4sBoGbGCkwVUIJSHBPI0z1Utrp1h5ys6ygT3albl3PgjejJcRRRiaDFFbMBA/640?wx_fmt=gif "")  
  
  
-  
赛博昆仑漏洞安全通告-  
  
泛微 e-cology前台SQL注入漏洞风险通告  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/7j1UQofaR9fsNXgsOXHVKZMJ1PCicm8s4RHQVjCJEjX63AsNibMx3So4wSMAvubEOoU2vLqYY7hIibIJbkEaPIDs5A4ianh5jibxw/640?wx_fmt=svg "")  
  
  
  
****  
**漏洞描述**  
  
泛微协同管理应用平台(e-cology)是一套兼具企业信息门户、知识文档管理、工作流程管理、人力资源管理、客户关系管理、项目管理、财务管理、资产管理、供应链管理、数据中心功能的企业大型协同管理平台，形成了一系列的通用解决方案和行业解决方案。  
  
近日，赛博昆仑  
CERT监测到泛微官方发布了  
 v10.71_1 补丁版本。未经授权的远程攻击者可通过发送特殊的  
HTTP请求来造成  
SQL注入漏洞，最终可导致攻击者获取数据库中的敏感信息。  
  
<table><tbody><tr><td valign="top" style="border-width: 1pt;border-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞名称</strong><o:p></o:p></span></p></td><td colspan="3" valign="top" style="border-top-width: 1pt;border-color: rgb(221, 221, 221);border-right-width: 1pt;border-bottom-width: 1pt;border-left-width: initial;border-left-style: none;padding: 3pt 6pt 1.5pt;"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">泛微<span lang="EN-US" style="color: rgb(0, 122, 170);font-family: Arial, sans-serif;"> e-cology</span>前台<span lang="EN-US" style="color: rgb(0, 122, 170);font-family: Arial, sans-serif;">SQL</span>注入漏洞<o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞公开编号</strong><o:p></o:p></span></p></td><td colspan="3" valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">暂无<o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>昆仑漏洞库编号</strong><o:p></o:p></span></p></td><td colspan="3" valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><span lang="EN-US" style="color: rgb(0, 122, 170);font-family: Arial, sans-serif;">CYKL-2024-028619</span><o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞类型</strong><o:p></o:p></span></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><span lang="EN-US" style="font-family: Arial, sans-serif;">SQL</span>注入</span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>公开时间</strong></span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><span lang="EN-US" style="color: rgb(0, 122, 170);font-family: Arial, sans-serif;">2024-12-02</span><o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞等级</strong><o:p></o:p></span></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">高危</span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>评分</strong></span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><span lang="EN-US" style="color: rgb(0, 122, 170);font-family: Arial, sans-serif;">7.5</span><o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞所需权限</strong><o:p></o:p></span></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">无权限要求</span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞利用难度</strong></span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">低<o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong><span lang="EN-US" style="font-family: Arial, sans-serif;">PoC</span></strong><strong>状态</strong><o:p></o:p></span></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">未知</span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong><span lang="EN-US" style="font-family: Arial, sans-serif;">EXP</span></strong><strong>状态</strong></span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">未知<o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞细节</strong><o:p></o:p></span></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">未知</span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>在野利用</strong></span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">未知</span></p></td></tr></tbody></table>  
**影响版本**  
  
e-cology9 并且 补丁版本 < v10.71_01  
  
**漏洞利用条件**  
  
无需任何利用条件  
  
**漏洞复现**  
  
目前赛博昆仑  
CERT  
已确认漏洞原理，复现截图如下：  
  
使用延时5秒的poc进行验证。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaZ7t7b9DodvV3p1BpOrfPzYxnlXpjesLuZJLzg4u3BANVbTicicBU65OiaSiaZVnlNZJNAD6olDy1r0zj1p4kDAaRg/640?wx_fmt=png&from=appmsg "")  
  
  
**防护措施**  
- **修复建议**  
  
目前，官方已发布修复建议，建议受影响的用户尽快升级至安全版本。  
  
下载地址：https://www.weaver.com.cn/cs/securityDownload.html#  
  
- **技术业务咨询**  
  
  
  
赛博昆仑支持对用户提供轻量级的检测规则或热补方式，可提供定制化服务适配多种产品及规则，帮助用户进行漏洞检测和修复。  
  
赛博昆仑CERT已开启年订阅服务，付费客户(可申请试用)将获取更多技术详情，并支持适配客户的需求。  
  
联系邮箱：  
cert@cyberkl.com  
  
公众号：赛博昆仑CERT  
  
**参考链接**  
  
https://www.weaver.com.cn/cs/securityDownload.html#  
  
  
  
**时间线**  
  
   
  
2024年12月2日，泛微官网发布补丁  
  
2024年12月3日，赛博昆仑CERT发布漏洞应急通告  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iaZ7t7b9Dodvib7ddpGMC6vx4COAy4sBoGLJ1DKwHPSc2JX7FQat3De8XiaajuAHkJzOY9ic9bnaHiaLJqVHIe0E2wg/640?wx_fmt=gif "")  
  
