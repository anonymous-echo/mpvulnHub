#  同学，XXE漏洞了解一下   
原创 Caigensec  菜根网络安全杂谈   2025-02-06 04:09  
  
**点击标题下「蓝色微信名」可快速关注**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ick6R1E3YokGicVeM3swHEZaM8cfEGLUB8QRicTAicIKyLaicmlicUGLv7XQP56vvc8dxVNSjYerVCHON8n1dlajco1w/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Sg02xflJ62rdxefX9thdaL8hxJWicY1vPlEmzNIWcBy2ypXTggHXX9e0kFDEVicficwTDdlLHLNrh6ica1SEvMqKeQ/640?wx_fmt=gif "")  
  
免责声明：本文仅用于合法范围的学习交流，若使用者将本文用于非法目的或违反相关法律法规的行为，一切责任由使用者自行承担。请遵守相关法律法规，勿做违法行为！本公众号尊重知识产权，如有侵权请联系我们删除。  
  
  
01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JklNicn4RoOYselcxR3KCEWzc5XxKBV6dHxicYwheES56YJiczBO0ticvSn4pXR7hibHXW2Rpfr6027LhnCurzjwibXg/640?wx_fmt=png "")  
  
  
  
漏洞介绍  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rrbZLC2ibIgtgV382cFCwmibpHFT7jndu1ibEDpFia0dzsjETHdt0HFzYlVRnHIaumpf3QyVos7giadDicqSku9zOEibw/640?wx_fmt=jpeg "金属质感分割线")  
  
  
## 1、XXE概念  
  
  
XXE（XML External Entity，XML外部实体）漏洞，是一种因XML解析器不当处理外部实体而引发的安全漏洞。攻击者通过构造恶意XML数据，利用外部实体功能读取服务器本地文件、探测内网服务或发起拒绝服务攻击甚至实现远程代码执行等。  
  
## 2、漏洞利用原理  
  
### （1）外部实体引用  
  
XML允许定义**外部实体**  
，这些实体可以从外部资源（如本地文件、远程URL）加载数据。攻击者通过在XML中插入恶意外部实体，利用解析器的功能读取敏感信息。  
### （2）漏洞触发条件  
- XML解析器默认启用外部实体解析（如旧版PHP的libxml库、Java的SAXParser等）。  
- 用户可控的XML输入未被过滤（如上传XML文件、提交XML格式的API请求）。  
- 解析结果被直接返回或错误信息泄露敏感数据。  
  
## 3、常见的漏洞利用场景  
  
  
**文件上传功能**  
  
**用户上传XML格式的文件（如SVG图片、配置文件），解析时触发XXE。**  
  
API接口  
  
REST/SOAP API接收XML格式的请求体，未校验外部实体。  
  
**单点登录（SSO）**  
  
**SAML协议使用XML进行身份断言，若解析不当可能被利用。**  
  
XXE漏洞的本质是XML解析器过度信任用户输入。防御需从禁用外部实体、严格过滤输入、更新依赖库三方面入手。开发人员应始终对XML数据保持警惕，尤其是在处理用户可控内容时。  
  
  
02  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JklNicn4RoOYselcxR3KCEWzc5XxKBV6dHxicYwheES56YJiczBO0ticvSn4pXR7hibHXW2Rpfr6027LhnCurzjwibXg/640?wx_fmt=png "")  
  
  
  
XML简单了解  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rrbZLC2ibIgtgV382cFCwmibpHFT7jndu1ibEDpFia0dzsjETHdt0HFzYlVRnHIaumpf3QyVos7giadDicqSku9zOEibw/640?wx_fmt=jpeg "金属质感分割线")  
  
XML学习参考链接：  
https://www.w3school.com.cn/xml/index.asp  
  
## 1、XML简介  
  
  
XML 指可扩展标记语言（EXtensible Markup Language）  
  
XML 是一种  
标记语言  
，很类似 HTML  
  
XML 的设计宗旨是  
传输数据  
，而非显示数据  
  
XML 标签没有被预定义。需要  
自行定义标签  
。  
  
XML 被设计为具有  
自我描述性  
。  
  
XML 是   
W3C 的推荐标准  
  
XML 被设计为传输和存储数据，其焦点是数据的内容。  
  
HTML 被设计用来显示数据，其焦点是数据的外观。  
  
## 2、XML结构  
  
```
<?xml version="1.0" encoding="ISO-8859-1"?><note><to>George</to><from>John</from><heading>Reminder</heading><body>Don't forget the meeting!</body></note>
```  
  
第一行是 XML 声明。它定义 XML 的版本 (1.0) 和所使用的编码   
  
下一行描述文档的根元素  
  
接下来 4 行描述根的 4 个子元素（to, from, heading 以及 body）  
  
最后一行定义根元素的结尾  
  
## 3、XML外部实体  
  
  
外部实体是一种特殊的实体，它指向外部资源（如文件、URL 等），允许在 XML 文档中引用外部的文本数据。外部实体的主要作用是实现数据的复用和模块化，使得 XML 文档可以引用外部的文件内容，避免在多个 XML 文档中重复相同的数据。  
### （1）读取系统文件  
```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE readFile [    <!ENTITY ff SYSTEM "file:///etc/passwd">]>    <message>&ff;</message>
```  
### （2）执行系统命令  
```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE aa [    <!ENTITY ff SYSTEM "expect://id">]>    <message>&ff;</message>
```  
  
  
02  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JklNicn4RoOYselcxR3KCEWzc5XxKBV6dHxicYwheES56YJiczBO0ticvSn4pXR7hibHXW2Rpfr6027LhnCurzjwibXg/640?wx_fmt=png "")  
  
  
  
XML简单了解  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rrbZLC2ibIgtgV382cFCwmibpHFT7jndu1ibEDpFia0dzsjETHdt0HFzYlVRnHIaumpf3QyVos7giadDicqSku9zOEibw/640?wx_fmt=jpeg "金属质感分割线")  
  
靶场地址：  
https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files  
  
Lab: Exploiting XXE using external entities to retrieve files  
  
利用XXE外部实体读取文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokEnnNSgJy1u4vARxFMrau0emPficjXKLEME9L00ZXQoLP7HUiaYZO2VmWwKvUHwQ6JlPPam0DfZCVicw/640?wx_fmt=png&from=appmsg "")  
  
（1）在商品页面Check stock，抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokEnnNSgJy1u4vARxFMrau0ebXcBtO9llrLzqgGRZeA1A7j33dW98Km0eRtolEJibic4zfTNAZRcClyQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokEnnNSgJy1u4vARxFMrau0ebXcBtO9llrLzqgGRZeA1A7j33dW98Km0eRtolEJibic4zfTNAZRcClyQ/640?wx_fmt=png&from=appmsg "")  
  
（2）发现数据包里有XML文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokEnnNSgJy1u4vARxFMrau0eKWBmZpT4YLcnNtbYgSDGNdUFsoUibDr2Kd2IMwyOiaRADVxXU1lvPOvg/640?wx_fmt=png&from=appmsg "")  
  
（3）修改XML文件内容，访问/etc/passwd目录  
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE readFile [
    <!ENTITY ff SYSTEM "file:///etc/passwd">
]>
 <stockCheck><productId>&ff;</productId><storeId>3</storeId></stockCheck>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokEnnNSgJy1u4vARxFMrau0ePymeFZsCGULv0fBviayvbyAAg8ZNW280UlWeGggC2miavHxnkPOj24AA/640?wx_fmt=png&from=appmsg "")  
  
（4）访问文件成功，实验解决  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokEnnNSgJy1u4vARxFMrau0eepsKDbDPDbk4nzEOlsKIYutZscerLYKuJjxDiaBadFwk5He3nTV3LyQ/640?wx_fmt=png&from=appmsg "")  
  
  
THE END  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokFvoM6PLd2g5R9ZyvTVYQhyosDWxvJP5DSfU2zuS01w7sRwGM8y8FPkADsZgW9OzB1fkoEcrsDxmA/640?&wx_fmt=png "")  
  
亲爱的朋友，若你觉得文章不错，请点击关注。你的关注是笔者创作的最大动力，感谢有你  
！  
  
  
