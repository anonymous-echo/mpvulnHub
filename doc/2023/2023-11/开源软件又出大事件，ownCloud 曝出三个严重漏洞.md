#  开源软件又出大事件，ownCloud 曝出三个严重漏洞   
小薯条  FreeBuf   2023-11-27 19:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38eicIsZAZQ7zQBWryx1YBLLuHSwzgvMU3wdgRImCwFUw1NxXh6LSgOeoicfwEJRJzDDMwiclkcnY2dA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
开源文件共享软件 ownCloud 近日警告称存在三个严重安全漏洞，其中一个漏洞可能会暴漏管理员密码和邮件服务器凭证。  
  
  
ownCloud 是一款开源文件同步和共享解决方案，个人和组织均可通过这个自托管平台管理和共享文件。  
  
  
其用户包括企业、教育机构、政府机构和注重隐私的个人，他们希望数据自主可控，而不是将数据托管给第三方云存储提供商。据 OwnCloud 网站报告，其安装量达 20 万次，拥有 600 家企业客户和 2 亿用户。  
  
  
该软件由多个库和组件组成，共同为云存储平台提供一系列功能。  
  
  
******严重的数据泄露风险**  
  
## 上周早些时候，该项目的开发团队发布了三个安全公告，警告称 ownCloud 的组件中存在三个不同的漏洞，可能会严重影响其完整性。  
  
  
第一个漏洞被追踪为 CVE-2023-49103，CVSS v3 最高分为 10 分。该漏洞可用于在容器化部署中窃取凭证和配置信息，影响网络服务器的所有环境变量。  
  
  
该漏洞影响了 graphapi 0.2.0 至 0.3.0，问题源于该应用程序对第三方库的依赖，该库通过 URL 公开了 PHP 环境详细信息，从而暴露了 ownCloud 管理员密码、邮件服务器凭据和许可证密钥。  
  
  
官方建议的修复方法是删除 "owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php "文件，禁用 Docker 容器中的 "phpinfo "函数，并更改可能暴露的机密，如 ownCloud 管理员密码、邮件服务器、数据库凭据和对象存储/S3 访问密钥。  
  
  
安全公告警告中强调称，仅仅禁用 graphapi 应用程序并不能消除漏洞。  
  
  
此外，phpinfo 还暴露了其他各种潜在的敏感配置细节，攻击者可利用这些细节收集系统信息。因此，即使 ownCloud 没有在容器化环境中运行，这个漏洞仍应引起关注。  
  
  
第二个漏洞的 CVSS v3 得分为 9.8，该漏洞可能影响 ownCloud 核心库 10.6.0 至 10.13.0 版本，涉及到身份验证旁路问题。  
  
  
如果用户的用户名已知且未配置签名密钥（默认设置），攻击者就有可能在未经身份验证的情况下访问、修改或删除任何文件。  
  
  
已公布的解决方案是，如果没有为文件所有者配置签名密钥，则拒绝使用预签名 URL。  
  
  
第三个不太严重的漏洞（CVSS v3 得分：9），涉及到子域验证绕过问题，影响 0.6.1 以下所有版本的 oauth2 库。  
  
  
在 oauth2 应用程序中，攻击者可以输入特制的重定向 URL，绕过验证码，将回调重定向到攻击者控制的域。  
  
  
官方建议采取的缓解措施是加固 Oauth2 应用程序中的验证代码。公告中分享的临时解决方法是禁用 "允许子域 "选项。  
  
  
公告中描述的三个安全漏洞严重影响了 ownCloud 环境的安全性和完整性，可能导致敏感信息暴露、隐蔽数据盗窃、网络钓鱼攻击等。  
  
  
文件共享平台的安全漏洞一直受到攻击，CLOP 等勒索软件组织利用这些漏洞对全球数千家公司进行数据盗窃攻击。  
  
  
官方建议ownCloud 的管理员立即应用建议的修复程序，以降低风险。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7VjpicfRmENW5Jzf1ec8Vub5ibnEQjSlchNRoD5fZNeib09msyqNeZjbWQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
https://www.bleepingcomputer.com/news/security/critical-bug-in-owncloud-file-sharing-app-exposes-admin-passwords/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7rv5uiamoibTdp9P2ia0swfbiaV4uicHc9icqdtbRUlvMtLfRyDXHqJkQqfBg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247491509&idx=1&sn=358062ec395fbcbe7b15c7c582631a5c&chksm=ce1ce52af96b6c3c9327439b4a74887b00d10c169601c2e26e79ac4105725a9559a908f64390&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247491523&idx=1&sn=ec31589bf31dbe9fdc2b9e4db5321dcc&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247491509&idx=1&sn=358062ec395fbcbe7b15c7c582631a5c&chksm=ce1ce52af96b6c3c9327439b4a74887b00d10c169601c2e26e79ac4105725a9559a908f64390&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247491480&idx=1&sn=3c9a9f6f543968ad3c6d2fc02dc8bafb&chksm=ce1ce507f96b6c11aa34e03870dda998756564845ddeaf43bc200ea581bfad34ca73cfc77d12&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247491456&idx=1&sn=8ad8dd55c50dd968a01b23a2fb1449b7&chksm=ce1ce51ff96b6c09d007b798eef16dd316d497c30502f0dda71124ce4284b7fa3b8dffaa77b6&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
