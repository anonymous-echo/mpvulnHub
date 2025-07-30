#  实战分享｜Autorize如何让我躺赚接口越权漏洞赏金   
原创 zangcc  Eureka安全   2025-04-22 12:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BictawU0A1NPmibPmwrMnlL4Gadw4ibwrvtRsBy8K8ZfSqK9jlcOcY8YNwpuiaLTR7fKcXWl7iauRhoo5HfKH0buFYA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
年初我接了个外网系统的渗透项目，漏洞其实不是很多，但是高危也有几个，因为实战技巧专栏好久没更新了，所以趁着今天比较有时间，分享一个价值3k💰的  
接口越权漏洞实战细节。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN7JXAJc6gP9LLqWHzyUAntnoSEMzC6wy0Y16ibiabSBWjgdlNyOcCWRQFGRKjCbVDYVQ33BFJibrOJQ/640?wx_fmt=png&from=appmsg "")  
  
我总感觉漏洞是有共性的，万变不离其宗。越权也是我的“福洞”，无论是cvnd证书还是edusrc证书，又或者是这种有钱的渗透项目，越权都是我最爱挖的漏洞。大家如果有闲暇时间，可以抽几分钟看看Eureka安全-实战技巧专栏的其他文章，看完之后你肯定会有收获的。  
  
  
❕文章末尾有抽奖送书，感兴趣的可以参与一下🍻  
  
## 0x01 前言  
  
工具很简单，就是BurpSuite加插件Autorize，Autorize的官方Github仓库：  
```
https://github.com/Quitten/Autorize
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN7JXAJc6gP9LLqWHzyUAnt6XxVIicWjlRAOefp1rvzI8RcCUCiarVXURFy9FalA30x6Bkv7gPtx58g/640?wx_fmt=png&from=appmsg "")  
  
也可以直接在BApp Store搜索下载，评分还蛮高的：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN7JXAJc6gP9LLqWHzyUAntFzGfIGn8ptIce78Lgw1oy59UrxM9qR3cmlTgMxB9icH4gMh80Z834Kg/640?wx_fmt=png&from=appmsg "")  
  
  
因为这是一个python写的工具，所以在安装这个插件之前，需要在BurpSuite配置一下Jython，由于配置的部分跟本文无关，我就不在这里再写怎么配置Jython环境了🙏，第一次配置的话，可以参考下面这篇文章，大概1-2分钟就能完成配置✅。  
  
```
https://blog.csdn.net/weixin_43847838/article/details/139232217
```  
  
  
需要提一下，就是我用的  
Autorize是二开过的，跟原版的比其实就多了个水平越权的配置，简单来说就是原版只支持两种权限（高权限+低权限）的用户进行越权测试，我这个增强版是三种权限（高权限+低权限+高权限的水平用户）的用户进行越权测试。正常情况下，用原版的功能也足够了，只需要在  
Autorize配置低权限用户的用户凭证请求头，然后在BurpSuite的浏览器中用高权限用户进行各个功能的正常操作就能测出来哪个接口存在越权。  
  
  
说了那么多看得云里雾里很正常，下面就用我实际项目中的案例来演示一下具体的操作⬇️。  
  
  
## 0x02 实战细节  
  
在写这篇文章的时候，系统漏洞已经修复了，为了保护系统和用户隐私，关键信息和细节我会进行打码。先来看看Autorize的核心功能和配置项：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN7JXAJc6gP9LLqWHzyUAntFJcq2BApJWUIkAZd4cYvQchydiaN8XDK9dZYpYXJsgZjv0lIF3ZNTWQ/640?wx_fmt=png&from=appmsg "")  
  
  
在上图中，V和H的含义就是垂直和水平，下面的文本框有初始文本：  
  
```
Cookie: Insert=injected; cookie=or;
Header: V
```  
  
这里代表什么意思呢？其实指的是系统的用户凭证信息，这里需要灵活变通，大部分的系统都是用Cookie请求头来代表用户凭证，但是有些系统则不是使用Cookie请求头，比如我这次项目的这个目标系统，用的就是  
Access-Token请求头加上请求体里面的  
auth_id和  
uId。  
  
以下面这个接口为例：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN7JXAJc6gP9LLqWHzyUAntO5Rz7aOZfopd4fmLGLbTXXqq2Wewr54zSicjm27Y3ztpU3IXLOfg3SA/640?wx_fmt=png&from=appmsg "")  
  
三者一一对应，如果有一个被篡改，后端就会校验不过，返回用户未登录的错误码和事件信息。所以在配置  
Autorize插件时，一定要保证三个信息填对，  
避免出现未登录的报错：  
```
"event":"po_logout",
"code":-1
```  
  
看  
到这里相信大家对权限的验证有了初步了解，再回过头来看看Autorize的配置，测接口垂直  
越权，选V。既然是垂直越权，那肯定是高低权限用户之间的关系，提前准备好2个账号，1个是高权限账号，1个是低权限账号。  
  
  
先给大家看看高权限账号和低权限账号的区别，系统必须实名认证（KYC注册），未实名认证的用户什么功能都操作不了，强制要求先完成KYC注册。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN7JXAJc6gP9LLqWHzyUAnt3fvRJicSd4ibPeCN5U4mYLdR7SzPf94n6wic4ib9NvHIyefrXseAMia8nQA/640?wx_fmt=png&from=appmsg "")  
  
高权限用户顾名思义就是完成了  
实名认证，并且所有功能都是能跑通的：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN7JXAJc6gP9LLqWHzyUAntr5IEQXcIyQ8XyyZ5cgjiaCyVWQiaWNGaKBAr61CDJGGEtWOObBkS60Zw/640?wx_fmt=png&from=appmsg "")  
  
那么我们测试的时候，提前在  
Autorize上面填上低权限的账号的用户凭证就行了，也就是用户Cookie或者独特的请求体等等。这里还有一个很重要的点，一定要切记❗️两个账号都必须同时在线，避免测试时低权限用户凭证实效导致测试异常。  
  
  
如何保证两个账号都在线呢？这里又有一个BurpSuite的技巧，只需要在设置，Burp's browser中把browser的缓存功能取消勾选，就能同时多开多个浏览器，并且在各个浏览器登陆不同的账号而不冲突之前登陆的账号了。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN7JXAJc6gP9LLqWHzyUAnticPMZMrh77XzEBTYZJmiadJrCs3KKu7xu5O4ullpGROsIPrsMNxhteBw/640?wx_fmt=png&from=appmsg "")  
  
这是我的个人习惯问题，我喜欢用BurpSuite自带的浏览器，原生且安全，还能防蜜罐获取个人信息，还不用那么麻烦的去配置证书就能抓包。这段是废话，与本文无关，可以不看。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN7JXAJc6gP9LLqWHzyUAnt4s9F8YdslicItr49Kb52Eu8YGfSlfEuIuBY9EtdbFWVejKEbaEEEMYw/640?wx_fmt=png&from=appmsg "")  
  
把低权限用户的请求头  
Access-Token  
填在文本框中，因为这次的目标系统比  
  
较特殊，用户凭证还包括请求体的内容，所以我们还需要替换一下请求体的参数，将高权限的请求体参数替换成低权限的请求体参数。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN7JXAJc6gP9LLqWHzyUAntqMb2lFORGyW1PIMATAH5kVhENNnQ9GadriaCQwt2vtiaB8k2vc6rbW3Q/640?wx_fmt=png&from=appmsg "")  
  
配置完成之后，这  
样我们在用高权限用户去点击测试系统功能时，  
Autorize就会自动的请求相同的接口，但是用户凭证字段会全部替换成低权限的用户去请求了。最后，一定要记得点  
击保存（Update）！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN7JXAJc6gP9LLqWHzyUAntt99TjLjvwTVVZedj6302ctfzIt4EOib9gmBZGcDMppYbI8N5aOpnBew/640?wx_fmt=png&from=appmsg "")  
  
然后，我们用高权限的用户在系统内过一遍核心功能，都过一遍。就会发现很多借口都存在越权，但是我们只关心核心的业务接口：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN7JXAJc6gP9LLqWHzyUAntboH9rsToOibLdqCf80FoahO1KG9M7XXj2ib0x08DJSDo0ZstcoxXzhZg/640?wx_fmt=png&from=appmsg "")  
  
我们就以这个xxxx_list接口为例，插件内能看到越权的请求和原始请求：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN7JXAJc6gP9LLqWHzyUAntRfnEpftK8ofeyIMYJhM3C8cLiaje8gZNvl5HUBR0phoN2VmMTdY1gZQ/640?wx_fmt=png&from=appmsg "")  
  
能看到两个不同权限的用户对相同接口的响应包：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN7JXAJc6gP9LLqWHzyUAntanh633oxsGk2y61Amm4lBwfWib8U6TViaxCKv1arkKH1joco3bQNXCXg/640?wx_fmt=png&from=appmsg "")  
  
上图就能很明显的看到，这个接口高低两个权限的用户都能请求成功，并且能正常返回，但是低权限用户（未完成实名验证的用户）在业务系统上是明确不允许执行任何操作的，所以可以得出结论，这个接口的权限校验不合格，存在越权。  
  
  
因为这个接口危害性并不是很大，也不是很核心的业务接口，所以当时提交报告时备注了一下，正常能达到高危级别的是另一个功能接口，查询订单详情。只要攻击者猜解出订单id，就可以用任意的账号去请求这个接口，并返回真实客户的银行、身份等敏感信息。因为已经修复了，我就不贴截图了，最后加上各种非核心的接口整理一下，最后客户认可了这个越权漏洞，积极修复👍，值得点赞。  
  
  
## 0x03 总结  
  
      
Autorize有其他问题可以私信问我。很早之前我就关注到BurpSuite开始支持原生的API安全扫描功能，但是我一直使用不成功，可能是文档导入有问题，这个功能我觉得还蛮有意思的，等我研究透彻了看看能不能实战运用一波。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN7JXAJc6gP9LLqWHzyUAntPOzNzY9H2xDfhpWzsvcrPVpZZjT4NVA96OzxvF9JhIAadyVURSszkw/640?wx_fmt=png&from=appmsg "")  
  
  
## 0x04 本期抽奖🎟️  
  
一等奖🥇：Python区块链应用开发从入门到精通  
  
Python零基础入门→区块链技术详解→区块链项目开发，从0到1就这么简单！  
  
知识讲解+学习问答+实训练习+实战开发，体例丰富，活学活用！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BictawU0A1NN7JXAJc6gP9LLqWHzyUAntdsdib7Pjr6ribAia3Sibyr2iaZuaqqPQyPw2xKsbEjyNEB6X1QaWFaooxUw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
二等奖🥈：Power BI商业智能数据分析与可视化  
  
本书的主要内容包括数据分析和数据可视化基础知识，  
Power Query  
数据获取、转换与加载，  
Power BI  
数据模型，  
DAX  
基础和进阶知识、  
DAX  
的实践案例、  
DAX  
驱动数据可视化交互，仪表板开发实践、仪表板多场景应用，以及  
AI  
辅助学习等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BictawU0A1NN7JXAJc6gP9LLqWHzyUAnt7NZvv4icUdCANl087DNhxicODXukkAIPiabgicnLMMUwTvvYByJqdGIJOA/640?wx_fmt=jpeg&from=appmsg "")  
  
参与方式（2025年4月26日星期六开奖）：需要点赞或推荐公众号任意一篇文章  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BictawU0A1NN7JXAJc6gP9LLqWHzyUAntcu5ibic5S4cfmbBX3vmcGAIr8xb4nfFiaDYWYoROyaibTOtbguy9WF7RFw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWfiaAtUngV8rgLh0bIibv9SumD1Y9ZmphGxK9lKiakkOWDp2gRsLjZInPg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
更多 >>  技术分享  
  
欢迎大家关注EureKaSec，无论是技术交流还是有兴趣加入我们团队，都欢迎随时联络沟通。如果有好的技术文章想投稿，审核通过后会有稿费报酬🎟️。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NPmibPmwrMnlL4Gadw4ibwrvtTnnX1Z9oJJjfGdN70P4zwbBCwldVYEq3YlJHicOK9iatVd3LdOIkiamxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
点个   
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BictawU0A1NN6aytu0hPxHz3C9vpIQIBTOjyvsXKPVQEPqdHQCXWfVGoTaGXyABSUL3HBgjPHHYlnqJE4LzRUTQ/640?wx_fmt=jpeg&from=appmsg "")  
，挖洞必高危！  
  
人划线  
  
  
