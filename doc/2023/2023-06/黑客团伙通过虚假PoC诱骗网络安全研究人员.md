#  黑客团伙通过虚假PoC诱骗网络安全研究人员   
看雪学苑  看雪学苑   2023-06-15 18:03  
  
漏洞情报公司VulnCheck最近发现，在GitHub和Twitter上有黑客团伙假冒网络安全研究人员发布虚假的PoC漏洞利用，借此针对Windows和Linux设备植入恶意软件。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Hf3NGQeOrI7t7fKFiaF7LhhTC0vIdjwhYgoOn5z6ficZQmj6Dclnq9Xe04H65PSYYInpWxzicC1Q1Vg/640?wx_fmt=png "")  
  
  
在个人资料页面，这些人自称是“High Sierra Cyber Security”网络安全公司的研究人员，为增加可信度，甚至还盗用了Rapid7等安全公司的真实安全研究人员的头像。他们在Twitter上宣传其看似正规的GitHub代码库，潜在攻击目标很可能是参与漏洞研究的网络安全研究人员及公司。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Hf3NGQeOrI7t7fKFiaF7Lhhx1jnMKFU1icBGibAS3EEYVpXEhUM8GXXxLukibLX3aia9wbgorFmtsFqLA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Hf3NGQeOrI7t7fKFiaF7LhhUUIp5g33Xh3Vc3zM76N8k1ZeEX23mRaXBJSWaIgg4UKcethibCgwpNA/640?wx_fmt=png "")  
  
  
6月14日，VulnCheck漏洞情报公司撰写了一篇博文阐述此事，他们报告称这个活动自2023年5月以来一直在进行，该团伙推广针对Chrome、Discord、Signal、WhatsApp和Microsoft Exchange等流行软件的0day漏洞利用。但所有这些恶意代码库都包含一个名为“poc.py”的Python脚本（包含用于下载并执行恶意二进制文件的代码），将根据受害者的主机操作系统下载不同的有效负载。  
  
  
该脚本会根据受害者的操作系统从外部URL下载一个ZIP文件到受害者的计算机上，Linux用户是“cveslinux.zip”，Windows用户则是“cveswindows.zip”。恶意软件会被保存到Windows的%Temp%目录或Linux的/home/<username>/.local/share文件夹中，然后被解压并执行。  
  
  
VulnCheck报告称，该ZIP文件中的Windows可执行文件（'cves_windows.exe'）在VirusTotal上被超过60%的杀毒引擎标记，Linux可执行文件（'cves_linux'）则要隐蔽得多。尽管每次发现新的类似活动VulnCheck都在第一时间联系平台进行删除，但VulnCheck指出，这些黑客团伙似乎很有毅力，在现有账户和代码库被举报并删除后，他们总会创建新的账户和代码库。  
  
  
VulnCheck针对此类事件提醒网络安全研究人员及爱好者，在从未知代码库下载内容时需要注意仔细审查代码。通过针对漏洞研究和网络安全社区，恶意软件可能会为攻击者提供网络安全公司的网络初始访问权限，导致进一步的数据窃取和勒索攻击。由于网络安全公司往往拥有关于客户的敏感信息，如漏洞评估、远程访问凭据甚至未公开的零日漏洞，对于不法分子来说是非常有价值的攻击目标。  
  
  
  
编辑：左右里  
  
资讯来源：vulncheck  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
抓鸡  
  
即设法控制电脑，将其沦为肉鸡。  
  
  
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
  
