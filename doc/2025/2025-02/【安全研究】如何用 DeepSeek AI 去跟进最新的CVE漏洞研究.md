#  【安全研究】如何用 DeepSeek AI 去跟进最新的CVE漏洞研究   
原创 Mstir  星悦安全   2025-02-18 06:22  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
    众所周知，CVE的最新漏洞往往是安全研究人员的一大乐趣，而CVE最新的漏洞的Github是发布在下方链接中的，每日都会更新最新漏洞及全部的CVE漏洞压缩包.```
https://github.com/CVEProject/cvelistV5/releases
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5d9wLAkqga29CepWDZo7PmcT8k0e2AhzLuvuxql3iaypeoKnvDVkeYicQSFMgiadelIkyQdovOWIWObw/640?wx_fmt=png&from=appmsg "")  
  
    而我们的目的是将今日最新的CVE漏洞文件全部解析并导入到html中，并翻译成中文，以供查看  
## 0x01 Prompt 提示词  
  
我们直接用DeepSeek 去生成一段Python代码，需要tk图形化，并且有能够导出为html的功能，就这些已经足够完成跟新研究的目的了.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5d9wLAkqga29CepWDZo7Pmc2u1zgnk2uzVzCNhaRBdTHK4yRT2JOdzdBsdDSfydhLx8jDRib6ZAibjg/640?wx_fmt=png&from=appmsg "")  
  
当然，这段 Prompt 生成的程序还是太简陋了，需要自行往里添加亿点点细节，然后我们再独立生成一个方便查看的html界面，如我下图提示词即可生成.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5d9wLAkqga29CepWDZo7PmcZLCsVHEG8fI4CTXpj7IxnEhicdKMJUvxlTibDIZCXrxiaQlhwH8Kh7tFw/640?wx_fmt=png&from=appmsg "")  
  
生成出来的界面是这样的，比较简约  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5d9wLAkqga29CepWDZo7PmcibYw9QygeZn1ibI90Rb5icBCpESNIocYvGLDk47pSzQMkeq7W0LyLbEQw/640?wx_fmt=png&from=appmsg "")  
  
但我个人更喜欢黑色一点的，所以给他换成了黑色风格的界面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5d9wLAkqga29CepWDZo7PmcE9lvktbByEIeYBrDWIRbg2liaoMdah1ffH4Cnd9GYQQ5tCZXmGNc5dQ/640?wx_fmt=png&from=appmsg "")  
  
之后肯定还需要自己修改一下代码，让其能够解析文件夹中的json文件，并生成html导入其中，方便查看.  
  
以下是我编写的CVE小工具演示:  
  
  
之后直接用浏览器的翻译插件翻译成中文即可舒服地阅读了.  
  
现在已经是AI 时代了，大家自己随便就能用ai写一个趁手的工具，甚至都不需要开发基础，当然，想写的好肯定是需要懂编程的.  
## 0x02 工具下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**PS : 报告模板关注公众号发送 250218 获取!**  
  
  
****  
**开了个星悦安全公开交流群，🈲发公众号，纯粹研究技术，还会拉一些大佬，希望大家多多交流.**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AkuT8liaHT74r6flTrjvRkw1VNgbtP6SOMric3VmMh70u6Oicg3HiaEvRfibicENBHFovyBC6PGTYJn02A/640?wx_fmt=png&from=appmsg "")  
  
下方二维码添加好友 回复关键词   
**星悦安全**  
进群  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AOzYX7kxefGbGGZg3g1ltkN30q9hceg23PiczgUqMT0EE9w0fLK9uw1eKWwQX9TljXQe1OQeHRZ2Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
