#  SSRF漏洞简单练习   
 sec0nd安全   2025-01-23 14:31  
  
**点击标题下「蓝色微信名」可快速关注**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ick6R1E3YokGicVeM3swHEZaM8cfEGLUB8QRicTAicIKyLaicmlicUGLv7XQP56vvc8dxVNSjYerVCHON8n1dlajco1w/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Sg02xflJ62rdxefX9thdaL8hxJWicY1vPlEmzNIWcBy2ypXTggHXX9e0kFDEVicficwTDdlLHLNrh6ica1SEvMqKeQ/640?wx_fmt=gif "")  
  
免责声明：本文仅用于合法范围的学习交流，若使用者将本文用于非法目的或违反相关法律法规的行为，一切责任由使用者自行承担。请遵守相关法律法规，勿做违法行为！本公众号尊重知识产权，如有侵权请联系我们删除。  
  
  
01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JklNicn4RoOYselcxR3KCEWzc5XxKBV6dHxicYwheES56YJiczBO0ticvSn4pXR7hibHXW2Rpfr6027LhnCurzjwibXg/640?wx_fmt=png "")  
  
  
  
SSRF介绍  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rrbZLC2ibIgtgV382cFCwmibpHFT7jndu1ibEDpFia0dzsjETHdt0HFzYlVRnHIaumpf3QyVos7giadDicqSku9zOEibw/640?wx_fmt=jpeg "金属质感分割线")  
  
  
## 1、概念简介  
  
  
SSRF（Server - Side Request Forgery），服务器端请求伪造漏洞，攻击者利用该漏洞，通过目标服务器发起对其他服务器或服务的恶意请求 。  
  
## 2、漏洞原理  
  
  
**服务端发起请求**  
：在正常的 Web 应用程序中，服务器端经常需要根据用户的输入或业务逻辑，发起对其他服务器资源的请求，如获取图片、数据文件，调用其他 API 等。  
  
**恶意构造请求**  
：攻击者通过精心构造恶意的请求参数，欺骗服务器端应用程序，使其发起对攻击者指定的目标服务器或服务的请求。这些目标可能是内部网络中的敏感服务器、外部的恶意站点等。  
  
  
## 3、漏洞危害  
  
  
**（1）内网资源探测**  
  
攻击者可以利用 SSRF 漏洞对内网进行端口扫描，发现内网中开放的服务和端口。例如，确定内部数据库服务器、文件服务器等的位置和端口信息，为进一步的攻击做准备。  
  
**（2）敏感数据泄露**  
  
如果内网中的某些服务器存储了敏感数据，攻击者可以通过构造特定的请求，让存在 SSRF 漏洞的服务器去访问这些内部服务器，从而获取敏感数据。比如获取数据库中的用户账号、密码信息等。  
  
**（3）利用第三方服务发起攻击**  
  
有些 Web 应用程序会调用第三方服务，如云存储服务、社交媒体 API 等。攻击者可以利用 SSRF 漏洞，让目标服务器以其自身的身份访问这些第三方服务，并执行恶意操作。  
  
  
  
02  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JklNicn4RoOYselcxR3KCEWzc5XxKBV6dHxicYwheES56YJiczBO0ticvSn4pXR7hibHXW2Rpfr6027LhnCurzjwibXg/640?wx_fmt=png "")  
  
  
  
SSRF漏洞简单练习  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rrbZLC2ibIgtgV382cFCwmibpHFT7jndu1ibEDpFia0dzsjETHdt0HFzYlVRnHIaumpf3QyVos7giadDicqSku9zOEibw/640?wx_fmt=jpeg "金属质感分割线")  
  
本次练习使用的靶场是portswigger，需要注册登录才能使用。实验不难，主要实际操作体会一下SSRF漏洞的简单利用和危害。  
  
靶场链接：  
https://portswigger.net/web-security/ssrf  
  
每个关卡都有参考的解题步骤（Solution）！  
  
## 1、Lab: Basic SSRF against the local server  
  
  
Lab链接：  
https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost  
  
（1）访问/admin，发现做了限制，不能直接访问  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokE2GIGsGjW51yOb8Yia81vokzPEZA6fdTXhvSn53Ba5E64NhibMBYJLcgwqrldyTAW2ZmIJlFpJ2qsg/640?wx_fmt=png&from=appmsg "")  
  
（2）访问商品页面，点击Check stock并抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokE2GIGsGjW51yOb8Yia81voktMXNMJgbX3Hxx8yv0EUIgeg9D7ap2zbllmzs52ddH84sq9picSAbmjw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokE2GIGsGjW51yOb8Yia81vokkobnLlLslS6JBdxak2vrYyqEFALjm26HRpiazCVaUEWlcUpfrP9mLdg/640?wx_fmt=png&from=appmsg "")  
  
（3）将stockApi后的URL替换为http://localhost/admin  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokE2GIGsGjW51yOb8Yia81voklIDibD3TXeFZrj7ysqKHEV780nAK68K8UItNaS7fKiaEcnJbnHmCFaow/640?wx_fmt=png&from=appmsg "")  
  
（4）把stockApi后的URL替换为http://localhost/admin/delete?username=carlos  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokE2GIGsGjW51yOb8Yia81vokv5uslsgdq8Kib6MuXzDbYpjibmFuq7sFoV0XDqDnjZsV3Xw0bX9c1aUw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokE2GIGsGjW51yOb8Yia81voktVpVK4mVYqy7HaPLPfUT3dsCCwXEicUrPxC1UUWZ0MAQ2r2AMNmFkuw/640?wx_fmt=png&from=appmsg "")  
  
（5）实验通过  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokE2GIGsGjW51yOb8Yia81vokOaWIMIIU0QYdMmvgZ7ibJfx4AGqv6PXd14BbcRv6gxTUia1iat6tVqLYA/640?wx_fmt=png&from=appmsg "")  
  
  
THE END  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokFvoM6PLd2g5R9ZyvTVYQhyosDWxvJP5DSfU2zuS01w7sRwGM8y8FPkADsZgW9OzB1fkoEcrsDxmA/640?&wx_fmt=png "")  
  
亲爱的朋友，若你觉得文章不错，请点击关注。你的关注是笔者创作的最大动力，感谢有你  
！  
  
  
