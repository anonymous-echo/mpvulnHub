#  ownCloud披露三个严重安全漏洞，可能暴露管理员密码和邮件服务器凭据   
看雪学苑  看雪学苑   2023-11-27 17:59  
  
近日，知名开源文件共享软件ownCloud披露了三个严重安全漏洞，这些漏洞可能会暴露管理员密码和邮件服务器凭据。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EpYVbPparKx99eMEpb5OGT2jLIorTV93pGdOtpMy0aHt6DDXJElcoIlxXD3m8ia6ib2wqz7qL7D8Sg/640?wx_fmt=png&from=appmsg "")  
  
  
  
据了解，ownCloud建立于2010年，最初是一个托管和同步文件的开源项目，用于在不同设备或地点轻松便捷地共享和处理文件。其免费好用的特性，使其很快发展为最大最受欢迎的开源项目之一。ownCloud公司于2011年成立，在全球范围拥有2亿用户和600多企业客户。  
  
  
ownCloud由多个库和组件组成，这些库和组件共同为该云存储平台提供各种功能。该项目的开发团队前不久发布了三份安全公告，警告ownCloud组件中存在三个安全漏洞，可能会严重影响到其安全性。  
  
  
第一个漏洞（CVE-2023-49103）的CVSS v3分数为满分10分。ownCloud表示：graphapi应用程序依赖于一个提供URL的第三方库。当访问此URL时，它会显示PHP环境的配置详细信息（phpinfo）。这些信息包括Web服务器的所有环境变量。在容器化部署中，这些环境变量可能包括诸如ownCloud管理员密码、邮件服务器凭据和许可证密钥等敏感数据。  
  
  
解决方法是删除'owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php'文件，禁用Docker容器中的'phpinfo'函数，并更改可能泄露的秘钥（如ownCloud管理员密码、邮件服务器和数据库凭据以及Object-Store/S3访问密钥）。安全公告中强调，仅仅禁用graphapi应用程序并不能解决问题。  
  
  
第二个漏洞CVSS v3分数为9.8，影响ownCloud核心库版本10.6.0至10.13.0，是一个身份验证绕过问题。该漏洞使得攻击者如果知道受害者的用户名并且受害者没有配置签名密钥（这是默认设置），便无需身份验证即可访问、修改或删除任何文件。对此的解决方案是，如果文件所有者未配置签名密钥，则拒绝使用预签名URL。  
  
  
第三个漏洞（CVSS v3分数：9）是一个影响版本低于0.6.1的oauth2库的子域验证绕过问题。在oauth2应用程序中，攻击者可以输入一个特制的重定向URL，绕过验证代码，从而允许攻击者将回调重定向到其控制的域。官方建议在Oauth2应用程序的验证代码中添加加固措施，临时解决方法可以禁用“允许子域”选项。  
  
  
上述三个安全漏洞可能导致敏感信息泄露、数据窃取、钓鱼攻击等问题。文件共享平台中的安全漏洞通常利用价值较高，因此，ownCloud建议用户尽快应用相对应的修复措施并进行库更新，以减轻影响。  
  
  
  
编辑：左右里  
  
资讯来源：ownCloud官网、bleepingcomputer  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
隐写术（Steganography）  
  
一种加密数据，将其隐藏在文本或图像中的方法，通常是出于恶意目的。  
  
  
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
  
