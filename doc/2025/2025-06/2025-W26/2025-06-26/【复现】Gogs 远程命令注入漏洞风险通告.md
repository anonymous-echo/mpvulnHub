> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMDQyMTIzMA==&mid=2247484900&idx=1&sn=987e33d854d2403c3a6e423aa4282b73

#  【复现】Gogs 远程命令注入漏洞风险通告  
 赛博昆仑CERT   2025-06-26 09:55  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iaZ7t7b9Dodvib7ddpGMC6vx4COAy4sBoGbGCkwVUIJSHBPI0z1Utrp1h5ys6ygT3albl3PgjejJcRRRiaDFFbMBA/640?wx_fmt=gif "")  
  
  
-  
赛博昆仑漏洞  
安全风险通告  
-  
  
Gogs 远程命令注入漏洞风险通告  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/7j1UQofaR9fsNXgsOXHVKZMJ1PCicm8s4RHQVjCJEjX63AsNibMx3So4wSMAvubEOoU2vLqYY7hIibIJbkEaPIDs5A4ianh5jibxw/640?wx_fmt=svg "")  
  
  
  
  
**漏洞描****述**  
  
  
    Gogs 是一款开源的自托管 Git 服务，它提供了简单易用的 Web 界面，帮助用户轻松管理代码仓库，支持多种认证方式和权限管理，适用于个人开发者及团队协作。  
  
    赛博昆仑CERT监测到Gogs 远程命令注入漏洞(CVE-2024-56731)， CVE-2024-39931 的补丁中仅添加了对路径是否为 .git 目录的检查可以通过创建符号链接进行绕过，经过身份认证的攻击者可通过创建符号链接，进而重写 .git 目录下的任意文件，最终实现远程命令执行  
<table><tbody><tr style="height:39px;"><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;word-break: break-all;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">漏洞名称</span></strong></span></p></td><td colspan="3" data-colwidth="144,144,144"><section><span leaf="" style="color: rgb(0, 122, 170);"><span textstyle="" style="font-size: 13px;">Gogs 远程命令执行漏洞</span></span></section></td></tr><tr style="height:39px;"><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">漏洞公开编号</span></strong></span></p></td><td colspan="3" data-colwidth="144,144,144"><p><span leaf="" style="color: rgb(0, 122, 170);"><span textstyle="" style="font-size: 13px;">CVE-2024-56731</span></span></p></td></tr><tr style="height:39px;"><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">昆仑漏洞库编号</span></strong></span></p></td><td colspan="3" data-colwidth="144,144,144"><span data-v-4471a619="" data-pm-slice="0 0 []"><span leaf="" style="color: rgb(0, 122, 170);"><span textstyle="" style="font-size: 13px;">CYKL-2024-038130</span></span></span></td></tr><tr style="height:39px;"><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">漏洞类型</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">命令</span><span leaf="" style="color: rgb(0, 122, 170);">执行</span><span leaf=""><br/></span></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">公开时间</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">2025年6月24日</span></span></p></td></tr><tr style="height:39px;"><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">漏洞等级</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">高危</span></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">评分</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">9.9</span></span></p></td></tr><tr style="height:39px;"><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">漏洞所需权限</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">普通用户权限</span></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">漏洞利用难度</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">低</span></span></p></td></tr><tr style="height:39px;"><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">PoC</span></strong><strong><span leaf="">状态</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">未知</span></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">EXP</span></strong><strong><span leaf="">状态</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">未知</span></span></p></td></tr><tr style="height:39px;"><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">漏洞细节</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">未知</span></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><strong><span leaf="">在野利用</span></strong></span></p></td><td data-colwidth="144" width="144" style="font-size: 10pt;text-align: left;"><p><span style="color: rgb(0, 122, 170);"><span leaf="">未知</span></span></p></td></tr></tbody></table>  
  
**影响范围**  
  
Gogs < 0.13.3  
  
  
**漏洞复现**  
  
  
目前，赛博昆仑CERT已复现  
Gogs 远程命令注入漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaZ7t7b9DodvLhzDULyUjMOGtgFzoibPfonxXHibJo5IN8pcUdsu4XvYqvicwznicdToSnNICauK7bCgysv0NEWNcng/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**防护措施**  
- 缓  
解措  
施  
  
在 Gogs 配置文  
件 app.ini 中关闭用户注册功能  
，修改后重启 Gogs 服务  
  
[auth]  
  
DISABLE_REGISTRATION = true  
  
- **修复建议**  
  
    目前官方  
已有  
可更新  
版本，  
建议受  
影响  
用  
户升级至最  
新版本：  
  
    Gogs >= 0.13.3  
  
    官方补丁下载地址：  
  
    https://github.com/gogs/gogs/releases/tag/v0.13.3  
  
  
  
- **技术业务咨询**  
  
  
  
赛博昆仑支持对用户提供轻量级的检测规则或热补方式，可提供定制化服务适配多种产品及规则，帮助用户进行漏洞检测和修复。  
  
赛博昆仑CERT已开启年订阅服务，付费客户(可申请试用)将获取更多技术详情，并支持适配客户的需求。  
  
联系邮箱：  
cert@cyberkl.com  
  
公众号：赛博昆仑CERT  
  
  
****  
**时间线**  
  
    2025年06月26日，赛博昆仑CERT发布漏洞风险通告  
  
  
**技术业务咨询**  
  
邮箱：cert@cyberkl.com  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iaZ7t7b9Dodvib7ddpGMC6vx4COAy4sBoGLJ1DKwHPSc2JX7FQat3De8XiaajuAHkJzOY9ic9bnaHiaLJqVHIe0E2wg/640?wx_fmt=gif "")  
  
  
  
  
  
  
  
  
  
  
  
  
