#  联达动力OA UpLoadFile.aspx 任意文件上传漏洞   
Superhero  Nday Poc   2024-10-21 20:08  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
联达动力OA是PHPOA推出的新一代OA系统,系统支持性好、安全、数据高速缓存化；支持100+应用自行安装与定义,应用表单自定义,支持应用无代码开发,支持多语言。  
  
  
**01******  
  
**漏洞概述**  
  
  
联达动力OA UpLoadFile.aspx 接口处存在任意文件上传漏洞，未经身份攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:   
```
(body="/LKSys_WindowControlScript.js" || body="onload=\"LKSYS_PubMaxWin()" || body="id=\"lkbLogin\" href=\"javascript:__doPostBack('lkbLogin','')" || (body="IdentityValidator" && body="HHCtrlMax"))
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIC3mUXMFicFwqqmFY3MyzvSeYPB1LIveia4Yzwo1icNUSnkM3GuuYy4ABhHmYxNpefhpOhs6QqAzWcw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIC3mUXMFicFwqqmFY3MyzvSN5y8Lu22dlR0kWz7hS9gV8DYiaVbpQU4iayauylGAsKewNMqq9Nia2utQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIC3mUXMFicFwqqmFY3MyzvSK6ibgpPqPAnv8vDkOM4xaoGGeITgGu7wrsRia64qCL3RjicnOGjpTgovQ/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIC3mUXMFicFwqqmFY3MyzvSuN3HXQiaEzu0MsZ5xUMQb6bRLPCiaecfBFD7iaIGq15svaLhtVv1icBXQQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIC3mUXMFicFwqqmFY3MyzvSlrDgJxs9hiccZJIbT3Ybj4WQrIaRia54mfagXHuFuLQnJAVRxeIL83BQ/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIC3mUXMFicFwqqmFY3MyzvSRrgVibXgJsd09OuYvtUFI6ic65887PhnWXOegBvlqqvFicJcmXkTibS7YA/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、 升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。   
  
2、三款工具都支持内置poc+自写poc目录一起扫描。   
  
3、保证每周更新10-15个poc。   
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
