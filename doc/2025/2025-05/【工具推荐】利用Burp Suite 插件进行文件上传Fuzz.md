#  【工具推荐】利用Burp Suite 插件进行文件上传Fuzz   
 小白爱学习Sec   2025-05-08 00:00  
  
**免责声明**  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=wxpic&random=0.18042352401019524&random=0.49301784938611526&random=0.7409665131631742 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7L4WY53VhUO2spBG8TGAPF8o98Ac6Y3EPLSEFGmKXeZyQCOGkqFWbeMibTfC1wZLjJTDmLb4Z0P9VCAV3RLDbbQ/640?random=0.11828586430527777&random=0.3266770581654057&random=0.7229092426155448 "")  
  
本文旨在提供有关特定漏洞工具或安全风险的详细信息，以帮助安全研究人员、系统管理员和开发人员更好地理解和修复潜在的安全威胁，协助提高网络安全意识并推动技术进步，而非出于任何恶意目的。利用本文提到的漏洞信息或进行相关测试可能会违反法律法规或服务协议。  
作者不对读者基于本文内容而产生的任何行为或后果承担责任。  
如有任何侵权问题，请联系作者删除。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**简单介绍**  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
资源获取跳转至文末  
  
Burp Suite插件专为文件上传漏洞检测设计，提供自动化Fuzz测试，共500+条payload，利用burp快速进行Fuzz。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/x095A8xUTuWohf2jaqRLJ44WHEZreKkcJVm2ewvhhg2x0S1ap8xVhnXcicGSSqVWqT0IYoEP13WIBmP6FgqsmIw/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**功能介绍**  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
1、 WAF绕过技术  
- **后缀变异**  
：ASP/ASPX/PHP/JSP后缀混淆（空字节、双扩展名、特殊字符等）  
  
- **内容编码**  
：MIME编码、Base64编码、RFC 2047规范绕过  
  
- **协议攻击**  
：HTTP头拆分、分块传输编码、协议走私  
  
- **字符变异**  
：引号混淆、特殊字符插入、换行截断技术  
  
- **数据溢出**  
：超长文件名、边界溢出测试、重复参数定义  
  
2、系统特性利用  
  
Windows特性：  
- NTFS数据流（::$DATA）  
  
- 保留设备名（CON, AUX）  
  
- 长文件名截断  
  
Linux特性：  
- Apache多级扩展解析  
  
- 路径遍历尝试  
  
- 点号截断攻击  
  
内容欺骗  
- 魔术字节注入（GIF/PNG/PDF头）  
  
- SVG+XSS组合攻击  
  
- 文件内容混淆（注释插入、编码变异）  
  
- .user.ini和.htaccess利用  
  
### 云环境绕过  
- **对象存储绕过**  
：S3/Azure元数据标头注入  
  
- **容器化环境**  
：Docker/Kubernetes路径遍历技术  
  
- **Serverless绕过**  
：云函数临时存储利用  
  
- **容器逃逸**  
：特权路径访问尝试  
  
等等  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**安装方法**  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
1. 确保已安装Burp Suite Professional  
  
1. 在Burp Extender中点击"Add"  
  
1. 选择下载的Upload_Auto_Fuzz.py  
文件  
  
1. 点击"Next"直到安装完成  
  
## 使用指南  
1. 拦截文件上传请求  
  
1. 右键请求内容 → "Send to Intruder"  
  
1. Positions内将Content-Disposition开始，到文件内容结束的数据作为fuzz对象，如图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/x095A8xUTuWohf2jaqRLJ44WHEZreKkcII3EE00Ikg1CA5EP7GFaSlYibqLe0POdQXCsvwuARxiaBjN3ebs0OaFg/640?wx_fmt=png&from=appmsg "")  
  
4. 在Intruder的"Payloads"标签中选择：  
```
Payload type: Extension-generatedSelect generator: upload_auto_fuzz
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/x095A8xUTuWohf2jaqRLJ44WHEZreKkcl9kqyBI1w3CoCW6pwRNNhBauGtZQtpfJaibOiciblJFWibG2Jm4dqFT4wQ/640?wx_fmt=png&from=appmsg "")  
  
5. 取消Payload encoding选择框，如图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/x095A8xUTuWohf2jaqRLJ44WHEZreKkcMEqLPULyYic3dkCaBIBkqARM0CMicwphmZCmwxD8jQlOZczw1giaiazNaQ/640?wx_fmt=png&from=appmsg "")  
  
6. 开始攻击并分析响应  
  
  
**资源下载**  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=wxpic&random=0.18042352401019524&random=0.49301784938611526&random=0.7409665131631742 "")  
  
  
  
点击下方名片后台回复【  
upload  
】获取资源信息  
  
  
