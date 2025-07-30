#  立即更新！GitLab曝满分零点击账户劫持漏洞   
看雪学苑  看雪学苑   2024-01-15 17:59  
  
1月11日，GitLab发布了一个紧急安全更新，以修复一个CVSS评分10分的零点击账户劫持漏洞。攻击者能够通过密码重置接管受害者账户，并且无需任何用户交互。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GtV2rqHTkEjRzdjSP7yIH8vEArTVtskwrvDK4fqusibuMP6bV4ia9Cg28NzaQQIrDeDeMsZEibW8KIg/640?wx_fmt=png&from=appmsg "")  
  
  
  
据了解，这是  
GitLab CE/EE中的一个认证问题，影响从16.1到16.1.6、16.2到16.2.9、16.3到16.3.7、16.4到16.4.5、16.5到16.5.6、16.6到16.6.4和16.7到16.7.2的所有版本，允许将用户账户重置密码请求发送到任意未经验证的电子邮件地址，从而导致账户劫持。  
  
  
GitLab在公告中解释说，该漏洞是在2023年5月1日的16.1.0版本中引入的。GitLab在16.1.0版本中进行了更改，允许用户通过辅助电子邮件地址重置其密码。该漏洞由电子邮件验证过程中的错误导致，GitLab在最新的补丁中修复了该错误，并实施了一些安全措施来保护客户。  
  
  
GitLab强烈建议自托管GitLab实例的管理员立即将所有受影响的版本更新到最新发布的修补版本，并且建议用户为所有的GitLab账户（特别是管理员账户）启用双因素身份验证。  
  
  
好消息是GitLab表示目前尚未在由GitLab管理的平台上检测到CVE-2023-7028的任何滥用行为。有所担心的用户可通过以下方式进行自查：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GtV2rqHTkEjRzdjSP7yIH8o6vQyevtIcsHWRL8TwdUa8FmtHcGXgk1aoSL5SqNpVichc3fA5ke4qA/640?wx_fmt=png&from=appmsg "")  
  
  
  
除此之外，GitLab还在这次更新中修补了另一个CVSS评分9.6的严重漏洞（CVE-2023-5356），该漏洞允许攻击者利用Slack/Mattermost集成以其他用户身份执行斜杠命令。  
  
  
GitLab公告链接：  
https://about.gitlab.com/releases/2024/01/11/critical-security-release-gitlab-16-7-2-released/  
  
  
  
编辑：左右里  
  
资讯来源：GitLab  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
code repository（代码仓库）  
  
软件开发需要共同努力，大型软件项目需要开发团队可以同时承担代码不同部分的工作。  
代码仓库是开发人员放置源代码的中心存储点。  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球在看**  
  
****  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1UG7KPNHN8FxuBNT7e2ZEfQZgBuH2GkFjvK4tzErD5Q56kwaEL0N099icLfx1ZvVvqzcRG3oMtIXqUz5T9HYKicA/640?wx_fmt=gif "")  
  
戳  
“阅读原文  
”  
一起来充电吧！  
  
