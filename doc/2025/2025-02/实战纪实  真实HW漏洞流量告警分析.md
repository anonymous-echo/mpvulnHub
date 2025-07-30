#  实战纪实 | 真实HW漏洞流量告警分析   
 实战安全研究   2025-02-27 02:01  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -   满心欢喜 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
今年七月，我去到了北京某大厂参加HW行动，因为是重点领域—-jr，所以每天态势感知设备上都有大量的告警，当时非常累，感觉每天睡醒就是盯屏幕。现在给大家分享一下我碰见的部分告警流量以及一些其他友厂当时分享的流量，并教大家我是如何分辨其为什么漏洞引起的告警。  
  
涉及保密协议，以下所有内容都会厚码  
#### 一、web.xml 文件泄露  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrGOicrNPkrd9dyZ1OQcDWlZlZE4QwRGibfOJgDu3ACr8fAfbqjqjftmOa9iabygvseUI2fv8aicb5Bvw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
web.xml文件是Web应用程序中的核心配置文件，它位于Web应用程序的WEB-INF目录下，这个文件定义了Web应用程序的配置信息：  
  
Servlet定义：声明Web应用程序中的Servlet及其对应的URL模式。  
  
Servlet映射：将URL模式映射到特定的Servlet。  
  
初始化参数：为Servlet提供初始化参数。  
  
欢迎文件列表：定义访问Web应用程序根目录时默认显示的页面。  
  
错误页面：定义错误发生时显示的页面。  
  
安全约束：定义访问控制和用户认证机制。  
  
会话配置：设置会话超时等会话管理参数。  
  
MIME类型：定义文件扩展名与MIME类型的映射。  
  
JSP配置：JSP页面的配置信息。  
  
**这次泄露的原因正是因为客户服务器没有正确设置访问权限，使得WEB-INF目录可以被外部访问，在系统开放时间段攻击队是由目录扫描工具直接扫出来了，当时是及时响应，杜绝了攻击。**  
  
web.xml文件泄露可能会造成以下危害：暴露敏感信息：如果web.xml中包含了敏感的初始化参数，如数据库密码、API密钥等，泄露后可能会被攻击者利用。  
  
理解应用结构：攻击者可以通过web.xml了解应用程序的URL结构和Servlet映射，这有助于他们发现潜在的攻击点。  
  
绕过安全控制：如果web.xml中定义了安全约束，泄露后攻击者可能会找到绕过这些安全控制的方法。  
  
配置弱点利用：攻击者可能会利用web.xml中的配置弱点，比如会话管理不当，来发起会话劫持攻击。  
  
信息泄露：错误页面和欢迎文件列表的配置可能会泄露关于应用程序内部结构的信息。  
  
MIME类型滥用：如果MIME类型配置不当，攻击者可能会利用这一点来执行恶意文件上传攻击。  
  
JSP配置泄露：JSP页面的配置信息泄露可能会导致攻击者利用JSP页面的特定功能进行攻击。  
#### 二、Fastjson 远程代码执行漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrGOicrNPkrd9dyZ1OQcDWlZXv7K35upL4SNgubpx6WZBSZRpK8SJkb9mB1WYvOXxQZ6MmkCSd7reA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
fastjson反序列化漏洞原理：  
  
只要我们传入一个json类型数据包含@type，程序在调用JSON.parseObject这个方法处理json对象时，程序就会反序列化生成一个对象。因此，了解了Fastjson处理json的机制，攻击者只需要将@type值设为Templateslmpl，构造一个恶意类，而这个类还有一个字段是_bytecodes，程序根据_bytecodes生成了一个java实例。问题在于java实例生成的同时，会自动调用构造函数。那么攻击者只要把恶意代码赋值给_bytecodes字段，恶意代码就会执行。  
  
如何判断反序列化漏洞是否攻击成功：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrGOicrNPkrd9dyZ1OQcDWlZErAQChRib8VCrQreuLJLr0mUZcKaTicXsI8FNmyLKVgwndIUXcyfu3Gg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
该图片来自我的面经  
  
**当时在waf上看见这个告警顿感天都塌了，JSON类型，@type，状态码400，想着都执行成功了准备收拾行李被开除了，幸好当时有另一个驻场大佬，直接在防火墙把策略关了，外网访问不了，杜绝危害。**  
#### 三、hydra工具爆破  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrGOicrNPkrd9dyZ1OQcDWlZpiaZrMFnJdIGNQQIrRXS1KpXMNjibtxibatd4swuPVJ2nhb10MQyrQnTA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
Hydra，也被称为“九头蛇”，是一款由著名黑客组织THC开发的开源暴力破解工具 。它主要用于通过暴力破解的方式尝试登录到目标服务器或服务，以测试和评估网络的安全性。Hydra支持多种协议，包括但不限于SSH、FTP、Telnet、SMTP、HTTP(S)、MySQL、PostgreSQL、SMB等。它能够自动化地进行暴力破解过程，使用预先准备好的用户名和密码字典，尝试所有可能的组合来登录到目标服务器或服务上。  
  
**这里它爆破的ua头居然直接有hydra这个字符特征，Hydra在进行攻击时，可以自定义HTTP请求中的UA头，以模仿常见的浏览器或其他客户端的请求，这样做的目的是为了减少被目标服务器识别为攻击流量的可能性，但这里居然直接暴露自己，我也是没看懂攻击队要干嘛。**  
#### 四、绕过验证，SQL攻击成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrGOicrNPkrd9dyZ1OQcDWlZjruFAPpjFJ3NuvOkDiaLH2pfdKLXdIHe4r0yECRbVgG28JQXr5S4THw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
其Payload为 /**/UNION/**/SELECT/**/20NULL,CONCAT(‘~,’version(),%20’~’)  
  
**内联注释：原理：在SQL关键词中插入内联注释（如/**/），可以改变关键词的外观，绕过基于文本匹配的过滤器。大小写变种：原理：SQL是不区分大小写的，所以可以混合使用大小写字母来绕过对特定关键字（如SELECT, FROM）的过滤。**  
  
成功绕过了验证机制执行了version()函数获得了数据库版本 这条SQL注入语句的目的是在不改变原始查询结构的前提下，通过UNION操作符将一个查询数据库版本的SELECT语句插入到原始查询中。这样，当这条注入语句被执行时，它不仅会执行原始的查询，还会执行攻击者添加的查询数据库版本的语句，并将结果输出在页面上  
#### 五、Struts2代码执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrGOicrNPkrd9dyZ1OQcDWlZ89SwbVib154hnoMJt77JkA0ic8be13ibz9yXEiaxRdX7PAJ52C8mjtW7cA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
st2-062 rce原理：开发人员使用%{. . .}语法进行强制OGNL解析，有一些特殊的TAG属性可以执行二次解析。对不受信任的用户输入使用强制OGNL解析可能会导致远程代码执行。  
  
**com.ooensymphony.xwork2.ActionContext.container特征**  
  
如何在流量层面分析st2命令执行是否成功：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrGOicrNPkrd9dyZ1OQcDWlZHs1RbqAd6gjibfxFw7jlibAb3ZDMOtH5qESur9ekkPA2EsWsZEDf3GXQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
分享就到这了 一点浅薄的知识，大佬勿喷大佬勿喷  
  
  
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，  
  
所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**没看够~？欢迎关注！**  
  
  
  
**分享本文到朋友圈，可以凭截图找老师领取**  
  
上千**教程+工具+交流群+靶场账号**哦  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
******分享后扫码加我！**  
  
  
**回顾往期内容**  
  
[零基础学黑客，该怎么学？](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247487576&idx=1&sn=3852f2221f6d1a492b94939f5f398034&chksm=fa686929cd1fe03fcb6d14a5a9d86c2ed750b3617bd55ad73134bd6d1397cc3ccf4a1b822bd4&scene=21#wechat_redirect)  
  
  
[网络安全人员必考的几本证书！](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247520349&idx=1&sn=41b1bcd357e4178ba478e164ae531626&chksm=fa6be92ccd1c603af2d9100348600db5ed5a2284e82fd2b370e00b1138731b3cac5f83a3a542&scene=21#wechat_redirect)  
  
  
[文库｜内网神器cs4.0使用说明书](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247519540&idx=1&sn=e8246a12895a32b4fc2909a0874faac2&chksm=fa6bf445cd1c7d53a207200289fe15a8518cd1eb0cc18535222ea01ac51c3e22706f63f20251&scene=21#wechat_redirect)  
  
  
[记某地级市护网的攻防演练行动](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247543747&idx=1&sn=c7745ecb8b33401ae317c295bed41cc8&token=74838194&lang=zh_CN&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247542576&idx=1&sn=d9f419d7a632390d52591ec0a5f4ba01&scene=21#wechat_redirect)  
[手把手教你CNVD漏洞挖掘 + 资产收集](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247542576&idx=1&sn=d9f419d7a632390d52591ec0a5f4ba01&token=74838194&lang=zh_CN&scene=21#wechat_redirect)  
  
  
[【精选】SRC快速入门+上分小秘籍+实战指南](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247512593&idx=1&sn=24c8e51745added4f81aa1e337fc8a1a&chksm=fa6bcb60cd1c4276d9d21ebaa7cb4c0c8c562e54fe8742c87e62343c00a1283c9eb3ea1c67dc&scene=21#wechat_redirect)  
  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
  
  
  
