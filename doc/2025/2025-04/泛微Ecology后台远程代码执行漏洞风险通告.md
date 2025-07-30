#  泛微Ecology后台远程代码执行漏洞风险通告   
 赛博昆仑CERT   2025-04-14 11:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iaZ7t7b9Dodvib7ddpGMC6vx4COAy4sBoGbGCkwVUIJSHBPI0z1Utrp1h5ys6ygT3albl3PgjejJcRRRiaDFFbMBA/640?wx_fmt=gif "")  
  
  
-  
赛博昆仑漏洞  
安全风险通告  
-  
  
泛微Ecology后台远程代码执行漏洞风险通告  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/7j1UQofaR9fsNXgsOXHVKZMJ1PCicm8s4RHQVjCJEjX63AsNibMx3So4wSMAvubEOoU2vLqYY7hIibIJbkEaPIDs5A4ianh5jibxw/640?wx_fmt=svg "")  
  
  
  
  
**漏洞描****述**  
  
    泛微协同管理应用平台(e-cology)是一套兼具企业信息门户、知识文档管理、工作流程管理、人力资源管理、客户关系管理、项目管理、财务管理、资产管理、供应链管理、数据中心功能的企业大型协同管理平台，形成了一系列的通用解决方案和行业解决方案。  
  
    近日，赛博昆仑CERT监测到泛微官方发布了10.74补丁版本，经过身份认证的远程攻击者可通过该漏洞执行任意代码，最终可导致攻击者获取远程服务器上系统权限。  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 39px;visibility: visible;"><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span leaf="">漏洞名称</span></strong></span></p></td><td colspan="3" style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span leaf="">泛微Ecology后台远程代码执行漏洞</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 39px;visibility: visible;"><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span leaf="">漏洞公开编号</span></strong></span></p></td><td colspan="3" style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span leaf="">暂无</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 39px;"><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">昆仑漏洞库编号</span></strong></span></p></td><td colspan="3" style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">CYKL-2025-013425</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 39px;"><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">漏洞类型</span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">代码执行</span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">公开时间</span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">2025-04-10</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 39px;"><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">漏洞等级</span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">高危</span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">评分</span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">8.8</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 39px;"><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">漏洞所需权限</span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">普通用户权限</span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">漏洞利用难度</span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">低</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 39px;"><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">PoC</span></strong></span><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">状态</span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">未知</span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">EXP</span></strong></span><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">状态</span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><span leaf="">未知</span></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 39px;"><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">漏洞细节</span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">未知</span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">在野利用</span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf="">未知</span></p></td></tr></tbody></table>  
  
  
**影响范围**  
  
e-cology9 并且 补丁版本 < 10.74  
  
**漏洞复现**  
  
  
目前，赛博昆仑CERT已成功复现  
泛微Ecology后台远程代码执行漏洞  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaZ7t7b9DoduUotW3RIlE2xFSBicFvvrxqz3htaUODjxnTKLa0wtlUxrMQibDIUUXIOZU0icPTRVo9Micz2Ia7iaRHeA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaZ7t7b9DoduUotW3RIlE2xFSBicFvvrxqvXYbbUwqgnE9a4qemayia39Ut8okOpOLELOtZmpl6R2Hywr70yOHotg/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**防护措施**  
- **修复建议**  
  
    目前，官方已发布安全补丁，建议受影响的用户尽快安装最新版本补丁。  
  
    下载地址：  
  
https://www.weaver.com.cn/cs/securityDownload.html?src=cn  
  
- **技术业务咨询**  
  
  
  
赛博昆仑支持对用户提供轻量级的检测规则或热补方式，可提供定制化服务适配多种产品及规则，帮助用户进行漏洞检测和修复。  
  
赛博昆仑CERT已开启年订阅服务，付费客户(可申请试用)将获取更多技术详情，并支持适配客户的需求。  
  
联系邮箱：  
cert@cyberkl.com  
  
公众号：赛博昆仑CERT  
  
  
****  
**时间线**  
  
    2025年4月10  
日，官方发布补丁  
  
    2025年4月14日，赛博昆仑CERT发布漏洞风险通告  
  
  
  
**技术业务咨询**  
  
邮箱：cert@cyberkl.com  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iaZ7t7b9Dodvib7ddpGMC6vx4COAy4sBoGLJ1DKwHPSc2JX7FQat3De8XiaajuAHkJzOY9ic9bnaHiaLJqVHIe0E2wg/640?wx_fmt=gif "")  
  
  
  
  
  
  
  
  
  
  
