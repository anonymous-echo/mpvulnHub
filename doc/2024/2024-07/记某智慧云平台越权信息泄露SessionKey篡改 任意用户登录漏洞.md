#  记某智慧云平台越权信息泄露SessionKey篡改 任意用户登录漏洞   
routing  Z2O安全攻防   2024-07-21 20:34  
  
点击上方[蓝字]，关注我们  
  
  
**建议大家把公众号“Z2O安全攻防”设为星标，否则可能就看不到啦！**  
因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuao3T9EnGbUIqxgDhEVicCV8NbH4FiaZ3YIbpXNEr6qFicGkAelnQHKGHsVlfapMGgO3DHA68iaiac0n4Q/640?wx_fmt=png "")  
  
  
# 免责声明  
  
  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号团队不为此承担任何责任。  
  
# 文章正文  
  
  
本篇文章是记录最近给一所大学做渗透测试时该学校存在的漏洞（目前已经修复）。我是先找该学校的微信小程序的资产，因为各位佬们也知道，微信小程序相对于web应用服务端来讲维护较少，所有漏洞存在多，好挖点。嘿嘿嘿，下面就来讲讲我是怎么从这个小程序端渗透到web应用端。  
## 知识点讲解  
#### 微信小程序的session_key有什么用？  
  
官方文档说是用session_key来生成登录态，让前端每次请求的时候加上登录态来请求接口。**session_key 功能说明：**  
1. 1. 微信客户端通过wx.getUserInfo()获取用户的信息  
  
1. 2. 后台有时候也需要获取微信客户端的用户信息，因此，就需要利用session_key这个秘钥来从微信平台中获取  
  
1. 3. 后台如果想要获取用户的信息，就一定要知道session_key，如果session_key 过期，就需要客户端完成一次登录的流程  
  
**图文参考：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZicHiaaSH1Z9FQl3Ds41Ria2M7A1ujcvagA036wicy2FIblz6ZxvCPibhmV7SERdskRnaFE5oYlsBXicEw/640?wx_fmt=png&from=appmsg "null")  
## 渗透测试  
  
我是有目的性的针对这个大学的小程序进行渗透测试的，所以直接在微信小程序检索该大学，然后挨个进行测试，发现该学校有智慧云平台（这个我还是蛮感兴趣的，因为之前我挖到蛮多的这类平台的漏洞）瞬间就比较兴奋。  
#### 一、弱口令爆破  
  
直接进入该小程序，然后通过bp抓包，一般的思路就是拿到小程序的数据包，然后进行访问下该host，尝试下是否存在弱口令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZicHiaaSH1Z9FQl3Ds41Ria2M7nGbRwCZ7LlwVNPUu2vgeegVW1sOSrsFicmTQurh086hG4ydnwY6IsA/640?wx_fmt=png&from=appmsg "null")  
  
  
一访问该host，然后跳转网站也没，中间是这个动态，一看就是若依系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZicHiaaSH1Z9FQl3Ds41Ria2MbLKmbXiaf8LjZSpvsNUVnLv6MoULJg2ZelxfJpvTeIuwMa0WiaPUVib0g/640?wx_fmt=png&from=appmsg "null")  
  
  
看到若依，那么就得优先尝试下弱口令了  
  
```
admin:admin123
ry:admin123
```  
  
  
但是这个web端是需要使用手机号和密码进行登录的，所以平常使用的那两个弱口令也就没用了，但是经常碰若依系统的就知道，进入后台以后，里面一般会经常留有一个测试账号和测试手机号，可以给师傅们看看若依系统的后台用户管理界面：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZicHiaaSH1Z9FQl3Ds41Ria2MjkyusjUdx0XQkj3mlVfkaibCqZlBINP7LfO2icKrRBiaLqfjFXJFawDgA/640?wx_fmt=png&from=appmsg "null")  
  
  
可以看到该测试账号使用的手机号，都是很弱的也就是容易爆破的手机号。下面我们回到小程序端，然后可以看到这里存在用户登录的地方，且比webduan爆破更加方便，没用验证码什么东西。  
  
然后抓包，通过bp的爆破功能模块进行尝试爆破他的用户名，密码我们这里直接使用123456，因为这种学校网站存在这样的123456的弱口令很正常，目前要做的就是爆破用户名也就是手机号了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZicHiaaSH1Z9FQl3Ds41Ria2MfN7aniccyic5VyibDFIzOsFah9840ZqXCr315XxoOL0LqqCxxQuT9M1ag/640?wx_fmt=png&from=appmsg "null")  
  
  
下面是我自己准备的常用的测试手机号，然后导入bp中进行爆破。  
  
比如师傅们也是可以收集一些常用的测试手机号，有需要的可以私信我，可以给大家发一下。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZicHiaaSH1Z9FQl3Ds41Ria2MYW4425gRhxDGJCic3HuruUhKXWSGArtyDxLZ9FmFNPQlttpOKeicrAUw/640?wx_fmt=png&from=appmsg "null")  
  
  
可以看到00000000000:123456爆破成功了，且成功登录进了web页面端  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZicHiaaSH1Z9FQl3Ds41Ria2MAPiaJ8kmTeibvrgEmCEWjkvQd6AHbOm7RSDDQwxF6sBpdtzRyFXzictoA/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZicHiaaSH1Z9FQl3Ds41Ria2M7PymqdAvib0x7m6vZRSMKXBtwvDUbJ0UT52RpyKuNHMhibLJtVsF5ERQ/640?wx_fmt=png&from=appmsg "null")  
#### 二、越权漏洞  
  
  
在这里进行测试，发现 getteachers参数 ，这个应该可有查到很多老师的信息的（这里就是查询的性王的老师信息）  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZicHiaaSH1Z9FQl3Ds41Ria2Mar53OkACxsLL4mMxmnJIZHmZiaHJkTMJ0icJTT9JyBEFtHZw1zCKkmibw/640?wx_fmt=png&from=appmsg "null")  
  
  
这里也可以尝试删除下这个参数，就可以获取所有老师的信息了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZicHiaaSH1Z9FQl3Ds41Ria2MibSUVicKTFe1VmhMvc7BZsWHkKiaCibBZWSC3vQFRJc84eg9d5CjZEiaTwA/640?wx_fmt=png&from=appmsg "null")  
  
  
这里可以看到我们开始爆破出来的测试账号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZicHiaaSH1Z9FQl3Ds41Ria2MMng8GaNy7P8zjJfUupoFsceibeqEibLF2iaMU7UWymUZt7JXgA3yia13Sg/640?wx_fmt=png&from=appmsg "null")  
  
  
我们开始知道了账号就是手机号，那么我们目前获取到了那多的手机号，我们就可以尝试获取有权限的账户了  
  
尝试发现这个性王的老师，应该是学校管理员账号，可以看到全年级的考勤信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZicHiaaSH1Z9FQl3Ds41Ria2M8fVFuR1eVnhWqhzZicrbxCceMfxUKcX3JbEFiaLf7uaSG70K3cMCeYWA/640?wx_fmt=png&from=appmsg "null")  
#### 三、Wx_SessionKey篡改 任意用户登录  
#### Wx_SessionKey_crypt工具下载链接：  
  
https://github.com/mrknow001/BurpAppletPentester  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZicHiaaSH1Z9FQl3Ds41Ria2McnnCMY7UNq4Mz1M1F17IpTZCZ4jaOJib4EgYkd1EfW4ibcxnbCl1mxZQ/640?wx_fmt=png&from=appmsg "null")  
  
收集该数据包中的SessionKey、iv以及加密字段三个部分，然后再利用Wx_SessionKey_crypt这个工具，我们就可以通过篡改手机号，从而可以任意用户登录危害漏洞。  
  
可以利用这个Wx_SessionKey_crypt工具，进行解密，可以看到确实是我自己的手机号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZicHiaaSH1Z9FQl3Ds41Ria2MtRhqksYke3fM6ZpqD49BPrRL8pFdFG4QQfgVLE4UXEPhy5ezxxM1xQ/640?wx_fmt=png&from=appmsg "")  
  
我这里前面进行信息收集到了好多个老师的手机号，一个17开头的朱老师的手机号开始尝试123456弱口令没有成功登录后台，  
  
那么现在尝试把Wx_SessionKey_crypt里面我的手机号改成17开头朱老师的手机号，然后再利用上面的工具进行加密，再替换上面bp里面的数据包，就可以成功登录了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZicHiaaSH1Z9FQl3Ds41Ria2MVQxaMbeJaX7ibpuoJDs6DrOtyrQjNnrGMSlib0aXItsUSPSWYMk8PYnA/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZicHiaaSH1Z9FQl3Ds41Ria2MXl1UW6JHn0AXhlAYaicVib9qI6sic1WM4bboTdFK8wLwEaHrHLtdjaOJA/640?wx_fmt=png&from=appmsg "null")  
  
  
到目前为止，任意用户登录也就复现完毕了！  
## 总结  
  
这次的渗透测试来讲还是很有收获的，特别是第三个Wx_SessionKey篡改 任意用户登录，大家可以去小程序尝试下，大家首先得找到SessionKey、iv以及加密字段三个部分，然后才可以利用这个工具进行篡改，然后任意用户登录。然后其次就是大家如果第一次挖漏洞还是渗透测试什么的，一定不要小瞧弱口令，因为只有登录进去了，里面后台的很多功能点你才有机会进行测试。最后希望这篇文章对漏洞挖掘和渗透测试师傅们有帮助！！！  
  
文章原文：https://xz.aliyun.com/t/14956  
  
# 技术交流  
  
  
### 学习圈子  
  
  
  
一个引导大家一起成长，系统化学习的圈子。  
  
  
如果看到这里的师傅是基础不够扎实/技术不够全面/入行安全不久/有充足时间的初学者...其中之一，那么欢迎加入我们的圈子，圈子提供以下内容：  
  
  
**1、每周发布学习任务，由浅入深，循序渐进，从常见的Web漏洞原理与利用、业务逻辑漏洞与挖掘，到WAF绕过、代码审计、钓鱼与免杀，再到Linux/Windows内网、提权、权限维持、隧道代理、域渗透，层层递进。会发布相应的参考资料及建议，成员自行学习实践，并会根据每周任务选取1-3位完成优秀的成员，返还入圈费用。**  
  
2、日常分享优质学习资源与攻防渗透技巧，包括但不限于渗透tips、教程、手册、学习路线等。  
  
3、  
一个学习氛围浓厚的社区，遇到问题可以快速提问、交流讨论，共同学习。  
- 目前已经规划了几个月的内容：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYHyEqA6pDb8VLMp8HsIicKjI8JbTjQ6Qv5fib5NL1mUqWgkHF130FUezb0uwppCQTOnuHrw5fpLHog/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
欢迎加入我们，一起学习！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZ9O4iae49hDfCW7hmqiaYclNdZyaia683iaEkabOCRQeXcd8TP3TUWx3wtDllnJb5f4ic8hVL69OhwDaw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
### 交流群  
  
  
关注公众号回复“**加群**”，添加Z2OBot好友，自动拉你加入**Z2O安全攻防交流群(微信群)**分享更多好东西。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h8P1KUHOKuYMO5aHRB3TbIy3xezlTAkbFzqIRfZNnicxSC23h1UmemDu9Jq38xrleA6NyoWBu1nAj0nmE6YXEHg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
### 关注我们  
  
  
  
**关注福利：**  
  
**回复“**  
**app****" 获取  app渗透和app抓包教程**  
  
**回复“**  
**渗透字典****" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。**  
  
**回复“漏洞库" 获取 最新漏洞POC库(**  
**1.2W+****)******  
  
**回复“资料" 获取 网络安全、渗透测试相关资料文档**  
  
****  
点个【 在看 】，你最好看  
  
  
  
