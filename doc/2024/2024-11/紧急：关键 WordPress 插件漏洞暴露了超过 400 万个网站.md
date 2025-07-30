#  紧急：关键 WordPress 插件漏洞暴露了超过 400 万个网站   
 船山信安   2024-11-18 16:34  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30npPb8DgklcHKDp0ZH5ibzPXT8FkWcFvFxSGgFmo6o1S2Vj9M8lVpVTug/640?wx_fmt=other&from=appmsg "WordPress Plugin Vulnerability")  
  
WordPress 的 Really Simple Security（以前称为 Really Simple SSL）插件中披露了一个严重的身份验证绕过漏洞，如果成功利用该漏洞，可以授予攻击者远程获得对易受攻击站点的完全管理访问权限。  
  
该漏洞被跟踪为 CVE-2024-10924（CVSS 评分：9.8），影响该插件的免费和高级版本。该软件安装在超过 400 万个 WordPress 网站上。  
  
“该漏洞是可编写脚本的，这意味着它可以变成针对 WordPress 网站的大规模自动化攻击，”Wordfence 安全研究员 István Márton 说。  
  
继 2024 年 11 月 6 日负责任披露后，该缺点已在一周后发布的 9.1.2 版本中得到修补。这种可能的滥用风险促使插件维护者与 WordPress 合作，在公开披露之前强制更新所有运行此插件的网站。  
  
根据 Wordfence 的说法，在 9.0.0 到 9.1.1.1 版本中发现的身份验证绕过漏洞是由于在名为“check_login_and_get_user”的函数中处理不当的用户检查错误而引起的，从而允许未经身份验证的攻击者在启用双因素身份验证时以任意用户（包括管理员）身份登录。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30nxWWrBjHfm8sX0Z1SqnzttK8RK7xEGgbot9icWF4ZAeFlsj8TZlpsl4g/640?wx_fmt=png&from=appmsg "")  
  
“不幸的是，添加双因素身份验证的功能之一实施不安全，这使得未经身份验证的攻击者可以在启用双因素身份验证时通过简单的请求访问任何用户帐户，包括管理员帐户，”Márton 说。  
  
成功利用该漏洞可能会产生严重后果，因为它可能允许恶意行为者劫持 WordPress 网站并进一步将其用于犯罪目的。  
  
该披露是在 Wordfence 揭示了适用于 WordPress 的 WPLMS 学习管理系统 WordPress LMS（CVE-2024-10470，CVSS 评分：9.8）的另一个严重缺陷几天后披露的，该缺陷可能使未经身份验证的威胁行为者能够读取和删除任意文件，从而可能导致代码执行。  
  
具体来说，4.963 版本之前的主题“由于文件路径验证和权限检查不足，容易受到任意文件读取和删除”，允许未经身份验证的攻击者删除服务器上的任意文件。  
  
“这使得未经身份验证的攻击者可以读取和删除服务器上的任意文件，包括网站的wp-config.php文件，”它说。“删除wp-config.php会强制站点进入设置状态，允许攻击者通过将站点连接到其控制下的数据库来启动站点接管。”  
  
来源：【黑客新闻网】  
  
