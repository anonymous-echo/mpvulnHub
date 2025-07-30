#  【海外SRC赏金挖掘】Microsoft微软高危漏洞 403ByPass (二)-- 协议降级实现403绕过   
原创 abbas_heybati  fkalis   2024-10-02 16:09  
  
# 海外SRC赏金挖掘专栏  
> **在学习SRC，漏洞挖掘，外网打点，渗透测试，攻防打点等的过程中，我很喜欢看一些国外的漏洞报告，总能通过国外的赏金大牛，黑客分享中学习到很多东西，有的是一些新的信息收集方式，又或者是一些骚思路,骚姿势，又或者是苛刻环境的漏洞利用。于是我打算开启这个专栏，将我认为优秀的文章进行翻译，加入我的理解和笔记，方便我自己学习和各位师傅共同进步，我争取做到日更，如果各位师傅觉得有用的话，可以给我点个关注~~ 如果师傅们有什么好的建议也欢迎联系我~~ 感谢各位师傅的支持~~**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicdYMrcDj1IM8qV6I0rkpibO7pTY4CibicHmG6uHuL0eiasl9l6xI2MDRZaKhicsPUAdzslV95G055uvHibw/640?wx_fmt=png&from=appmsg "")  
# 正文部分  
> 原文作者: https://twitter.com/abbas_heybati  
  
  
## 总结  
> **当遇到403页面的时候，可以尝试将该请求的协议从HTTP/1.1 降级为 HTTP/1.0 并删除所有标头，尝试进行403bypass**  
  
## 漏洞复现  
### 漏洞资产  
```
lyncdiscover.microsoft.com
```  
### 发现403  
  
在 lyncdiscover.microsoft.com 域上做 FUZZ，发现几个路径是 403 Forbidden。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicem2aibX5PpKA0kXyNY7zHz4u1D8S8ibbNvFmVqkcLUPT6srARxDh1XZpmHPPqW1yGyLH5gYGmu6okQ/640?wx_fmt=png&from=appmsg "null")  
### 通过协议降级实现403绕过  
#### 1. 将 HTTP 协议版本更改为 1.0。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicem2aibX5PpKA0kXyNY7zHz46Sns5ChlbtqVj5PkTickiacsnmeyzBB8S3buu7ARBibuwh8Vv6aLia8m1Q/640?wx_fmt=png&from=appmsg "null")  
#### 2. 删除全部的请求头  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicem2aibX5PpKA0kXyNY7zHz4hxzcvicuKIfElO1W9bchO7exz2ZNo0j6DBNJz2SxcxJxwibEr5iaDdP3g/640?wx_fmt=png&from=appmsg "null")  
#### 3. 成功绕过403  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicem2aibX5PpKA0kXyNY7zHz4Stzl86oZQbDicplia9kYQFJJicTEWqS56n7ZCEaRjoDfr5PG8p19f6Tkg/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicem2aibX5PpKA0kXyNY7zHz4hCmCETmkHyWuCsmdYH4X6oqKgZFSHzDyE4zQq3Oic5iaWM3RTQvGKPlQ/640?wx_fmt=png&from=appmsg "null")  
  
用相同方法尝试另一个路径  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicem2aibX5PpKA0kXyNY7zHz42yxib0ia0uXqOLNXQPpfFJw41E81I2dykq8uhcvxLIwAo4o3kiaonpNrg/640?wx_fmt=png&from=appmsg "null")  
  
成功绕过  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicem2aibX5PpKA0kXyNY7zHz4WxEibAOkXOJzbukb1IStSanpg8CwRB8p3ZRS95o0TwzsqWz0Au1xBAg/640?wx_fmt=png&from=appmsg "null")  
### 补充（举一反三）  
  
使用此方法不仅可以用来绕过403bypass，也可以绕过 （CDN） 并获取服务器 IP。  
1. 1. 正常的请求，存在CDN  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicem2aibX5PpKA0kXyNY7zHz4LBPBmYS03LLCZSJJBZroVcBlfds2IbxS3V4tQZI3IwfPCicQxZqAXOA/640?wx_fmt=png&from=appmsg "null")  
1. 2. 我们再次使用相同的方法并发送请求，这次它将向我们显示服务器的主地址。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicem2aibX5PpKA0kXyNY7zHz4teyBzzz6GDNI80MPlpibC4oBf6RRZc7RpwNegmNO9FYXoTydRGCdWJg/640?wx_fmt=png&from=appmsg "null")  
# 知识星球  
  
**具体的星球介绍可以看一下这里~~**  
  
[WingBy小密圈，他来了！](https://mp.weixin.qq.com/s?__biz=MzkyODcwOTA4NA==&mid=2247484765&idx=1&sn=01366a5d13fb4be7f9c0e69e565d64ff&chksm=c215e5eef5626cf8c87fcca7d784068772d364a12aa4b4a224aebd1e69bddf52fec0f791d000&token=276602823&lang=zh_CN&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicdYMrcDj1IM8qV6I0rkpibO7lPF38IqibU9Az906W6RHJBQhf2OR32Ks7sd8Xh4ric0VFRNR2lXmFwKA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicdCvkAftp00C0F9g6uLYXGnpAWQmOBwrqRUI6V26tvWqFJib6PmZO9fiaY0nia2An9JmtL5mMibqIAH5w/640?wx_fmt=jpeg&from=appmsg "null")  
  
**注意：帮会和星球是为了考虑大家的方便习惯，福利和内容是一致的，后续更新也是一致的~~~只需要进行一次付费就可以啦~~（建议还是使用帮会）**![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicf197vbRopEgYNZjbmJ00wHzicThAsLt7xehsSWC5JKY3NSEMkWbGolb0oSJmLlQlqHTic5bVyFgeBg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
# 项目合作  
  
  
**有甲方大大，或者厂商师傅，或者其他的项目，欢迎咨询，我以及团队始终将客户的需求放在首位，确保客户满意度~~**  
  
****  
**目前主要的服务范围：**  
****  
> **1. 渗透测试、漏洞扫描**  
  
**2. 代码审计**  
  
**3. 红蓝攻防**  
  
**4. 重保以及其他攻防类项目**  
  
**5. 红队武器化开发以及蓝队工具开发**  
  
**6. CTF相关赛事的培训等**  
  
**7. cnvd，cnnvd，edu，cve等证书**  
  
**8. nisp，cisp等证书**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicdYMrcDj1IM8qV6I0rkpibO7ZJRQaUkzj4SdzlE2LemzRDG7yrl4rP4cFunhhibibX3CzGEPwFQzqIkw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
