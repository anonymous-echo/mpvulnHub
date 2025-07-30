> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMDQyMTIzMA==&mid=2247484909&idx=1&sn=f7c17bd3c58d6e06afe0eee7178e533f

#  【复现】泛微Ecology前台SQL注入漏洞风险通告  
 赛博昆仑CERT   2025-07-09 02:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iaZ7t7b9Dodvib7ddpGMC6vx4COAy4sBoGbGCkwVUIJSHBPI0z1Utrp1h5ys6ygT3albl3PgjejJcRRRiaDFFbMBA/640?wx_fmt=gif "")  
  
  
-  
赛博昆仑漏洞  
安全风险通告  
-  
  
泛微Ecology前台SQL注入漏洞风险通告  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/7j1UQofaR9fsNXgsOXHVKZMJ1PCicm8s4RHQVjCJEjX63AsNibMx3So4wSMAvubEOoU2vLqYY7hIibIJbkEaPIDs5A4ianh5jibxw/640?wx_fmt=svg "")  
  
  
  
  
**漏洞描****述**  
  
    泛微协同管理应用平台(e-cology)是一套兼具企业信息门户、知识文档管理、工作流程管理、人力资源管理、客户关系管理、项目管理、财务管理、资产管理、供应链管理、数据中心功能的企业大型协同管理平台，形成了一系列的通用解决方案和行业解决方案。  
      
  
      
赛博昆仑CERT监测到泛微E-cology9 存在SQL注入漏洞，未经过身份认证的攻击者可以利用该漏洞获取到数据库的敏感信息，可能造成信息泄露或权限提升，结合后台远程代码执行漏洞可以完全控制服务器。泛微已经发布新补丁v10.76修复了该前台sql注入漏洞。  
<table><tbody><tr style="height:39px;"><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;word-break: break-all;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">漏洞名称</span></strong></span></p></td><td colspan="3" data-colwidth="144,144,144"><p><span leaf="" style="color: rgb(0, 122, 170);"><span textstyle="" style="font-size: 13px;">泛微Ecology前台sql注入漏洞</span></span></p></td></tr><tr style="height:39px;"><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">漏洞公开编号</span></strong></span></p></td><td colspan="3" data-colwidth="144,144,144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">暂无</span></span></p></td></tr><tr style="height:39px;"><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">昆仑漏洞库编号</span></strong></span></p></td><td colspan="3" data-colwidth="144,144,144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">CYKL-2025-017104</span></span></p></td></tr><tr style="height:39px;"><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">漏洞类型</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">SQL注入</span><span leaf=""><br/></span></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">公开时间</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">2025年7月</span></span></p></td></tr><tr style="height:39px;"><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">漏洞等级</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">高危</span></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">评分</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">暂无</span></span></p></td></tr><tr style="height:39px;"><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">漏洞所需权限</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">无权限要求</span></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">漏洞利用难度</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">低</span></span></p></td></tr><tr style="height:39px;"><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">PoC</span></strong><strong><span leaf="">状态</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">未知</span></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">EXP</span></strong><strong><span leaf="">状态</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">未知</span></span></p></td></tr><tr style="height:39px;"><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">漏洞细节</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">未知</span></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">在野利用</span></strong></span></p></td><td data-colwidth="144" width="144"><p><span leaf="" style="color: rgb(0, 122, 170);"><span textstyle="" style="font-size: 13px;">已知</span></span></p></td></tr></tbody></table>  
  
**影响范围**  
  
e-cology9 并且 补丁版本 < 10.76  
  
  
**漏洞复现**  
  
  
目前，赛博昆仑CERT已成功复现  
泛微Ecology前台sql注入执行漏洞，延时8秒。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaZ7t7b9DodsFVkuzNUGGmFexrmhVGUMa3rEXgaIa8fwMib4KqFaErErebfevibtibcl7TY7s4iaT2bLEO0ZZtnwJMg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaZ7t7b9DodsFVkuzNUGGmFexrmhVGUManHsaIMdRM1twaCwZJp1eQKEfLsK2N9MoSAiaYSIpBublxqekszZOgug/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**防护措施**  
- **修复建议**  
  
目前，官方已发布安全补丁，建议受影响的用户尽快联系厂商获取安全补丁。  
  
- **技术业务咨询**  
  
  
  
赛博昆仑支持对用户提供轻量级的检测规则或热补方式，可提供定制化服务适配多种产品及规则，帮助用户进行漏洞检测和修复。  
  
赛博昆仑CERT已开启年订阅服务，付费客户(可申请试用)将获取更多技术详情，并支持适配客户的需求。  
  
联系邮箱：  
cert@cyberkl.com  
  
公众号：赛博昆仑CERT  
  
  
****  
**时间线**  
  
    2025年7月，官方发布补丁v10.76修复漏洞  
  
    2025年7月9日，赛博昆仑CERT发布漏洞风险通告  
  
  
  
**技术业务咨询**  
  
邮箱：cert@cyberkl.com  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iaZ7t7b9Dodvib7ddpGMC6vx4COAy4sBoGLJ1DKwHPSc2JX7FQat3De8XiaajuAHkJzOY9ic9bnaHiaLJqVHIe0E2wg/640?wx_fmt=gif "")  
  
  
  
  
  
