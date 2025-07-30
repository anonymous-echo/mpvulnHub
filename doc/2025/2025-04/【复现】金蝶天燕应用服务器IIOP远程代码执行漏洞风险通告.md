#  【复现】金蝶天燕应用服务器IIOP远程代码执行漏洞风险通告   
 赛博昆仑CERT   2025-04-25 14:38  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iaZ7t7b9Dodvib7ddpGMC6vx4COAy4sBoGbGCkwVUIJSHBPI0z1Utrp1h5ys6ygT3albl3PgjejJcRRRiaDFFbMBA/640?wx_fmt=gif "")  
  
  
-  
赛博昆仑漏洞  
安全风险通告  
-  
  
金蝶天燕应用服务器IIOP远程代码执行漏洞风险通告  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/7j1UQofaR9fsNXgsOXHVKZMJ1PCicm8s4RHQVjCJEjX63AsNibMx3So4wSMAvubEOoU2vLqYY7hIibIJbkEaPIDs5A4ianh5jibxw/640?wx_fmt=svg "")  
  
  
  
  
**漏洞描****述**  
  
  
    金蝶Apusic应用服务器（Apusic Application Server，AAS）是一款企业级中间件，全面支持JakartaEE规范，提供Web、EJB、WebService容器，适配国产软硬件，用于支撑企业级应用运行。  
  
    赛博昆仑CERT监测到  
金蝶Apusic应用服务器IIOP远程代码执行漏洞的漏洞情报，Apusic V10.0应用服务器部分功能时使用了IIOP协议，未经过身份认证的攻击者可以通过构造恶意的反序列化数据在服务器上执行任意代码，从而进一步控制服务器。  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 39px;visibility: visible;"><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">漏洞名称</span></span></strong></span></p></td><td colspan="3" style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;visibility: visible;"><section><span leaf="" style="font-size:10pt;"><span textstyle="" style="color: rgb(0, 122, 170);">金蝶天燕应用服务器IIOP远程代码执行漏洞</span></span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 39px;visibility: visible;"><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">漏洞公开编号</span></span></strong></span></p></td><td colspan="3" style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">未知</span></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 39px;"><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">昆仑漏洞库编号</span></span></strong></span></p></td><td colspan="3" style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">CYKL-2025-014655</span></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 39px;"><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">漏洞类型</span></span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">代码执行</span></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">公开时间</span></span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">2025-04-01</span></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 39px;"><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">漏洞等级</span></span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">高危</span></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">评分</span></span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">9.8</span></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 39px;"><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">漏洞所需权限</span></span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">无</span></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">漏洞利用难度</span></span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">低</span></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 39px;"><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">PoC</span></span></strong></span><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">状态</span></span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">未知</span></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">EXP</span></span></strong></span><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">状态</span></span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">未知</span></span></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 39px;"><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">漏洞细节</span></span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">未知</span></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(31, 35, 41);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">在野利用</span></span></strong></span></p></td><td style="-webkit-tap-highlight-color: transparent;padding: 8px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(222, 224, 227);font-size: 10pt;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span leaf=""><span textstyle="" style="color: rgb(0, 122, 170);">未知</span></span></p></td></tr></tbody></table>  
  
  
  
  
**影响范围**  
  
Apusic 应用服务器软件 V10.0 企业版 SP1-SP8  
  
  
**漏洞复现**  
  
  
目前，赛博昆仑CERT已成功复现  
金蝶天燕应用服务器IIOP远程代码执行漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaZ7t7b9DodtoibfzIWb72nBmPnGqmxWeQuRgYxJlicicM5E6uiaia2Fh9Mbj316yH5WJ70oOqA6bh4ImmCiaB1ZLchXQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
****  
**防护措施**  
- **修复建议**  
  
目前，官方已发布安全补丁，建议受影响的用户尽快安装最新版本补丁。  
  
      下载地址：  
  
https://www.apusic.com/view-477-120.html  
  
- **技术业务咨询**  
  
  
  
赛博昆仑支持对用户提供轻量级的检测规则或热补方式，可提供定制化服务适配多种产品及规则，帮助用户进行漏洞检测和修复。  
  
赛博昆仑CERT已开启年订阅服务，付费客户(可申请试用)将获取更多技术详情，并支持适配客户的需求。  
  
联系邮箱：  
cert@cyberkl.com  
  
公众号：赛博昆仑CERT  
  
  
**参考链接**  
  
https://www.apusic.com/view-477-120.html  
  
  
****  
**时间线**  
  
    2025年4月1日，官方发布补丁  
  
    2025年4月25日，赛博昆仑CERT发布漏洞风险通告  
  
  
**技术业务咨询**  
  
邮箱：cert@cyberkl.com  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iaZ7t7b9Dodvib7ddpGMC6vx4COAy4sBoGLJ1DKwHPSc2JX7FQat3De8XiaajuAHkJzOY9ic9bnaHiaLJqVHIe0E2wg/640?wx_fmt=gif "")  
  
  
  
  
  
  
  
  
  
  
