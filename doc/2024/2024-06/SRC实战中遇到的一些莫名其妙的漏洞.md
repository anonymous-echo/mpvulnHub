#  SRC实战中遇到的一些莫名其妙的漏洞   
1572282084220041  Z2O安全攻防   2024-06-02 21:03  
  
点击上方[蓝字]，关注我们  
  
  
**建议大家把公众号“Z2O安全攻防”设为星标，否则可能就看不到啦！**  
因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuao3T9EnGbUIqxgDhEVicCV8NbH4FiaZ3YIbpXNEr6qFicGkAelnQHKGHsVlfapMGgO3DHA68iaiac0n4Q/640?wx_fmt=png "")  
  
  
# 免责声明  
  
  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号团队不为此承担任何责任。  
  
# 文章正文  
  
  
# 前言  
  
真实案例，文中所写漏洞现已经被修复，厚码分享也是安全起见，请各位大佬见谅哈！  
# 案例一：奇怪的找回密码方式  
  
某次漏洞挖掘的过程中，遇到某单位的登录框，按以往的流程测试了一下发现并没有挖掘出漏洞，在我悻悻地点开找回密码的功能并填入了基础信息之后，我发现他的业务流程与常见的安全的找回密码的方式并没有什么区别，都是需要接收到手机验证码或者邮箱验证码或者回答正确安全问题才能进行下一步重置密码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshpdPIDrSgDkXCzZsxnwksUfXyeISdjxiazjKwdqXLkRgYwCtSSnwxteA/640?wx_fmt=png&from=appmsg "null")  
  
但是敏锐的我，发现了右上角存在一个验证方式不可用？的功能，我点开发现竟然直接跳到重置认证方式里面去了：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshkxYNyyZgNbVZxuV5wWazzV8Gk0lLvzOPPNFAPDGMWs9vFjJCbAPfwg/640?wx_fmt=png&from=appmsg "null")  
  
然后我把原号主的安全问题重置之后，更令我意外的是直接跳转到重置密码的步骤了（令人哭笑不得2333）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshCe2JkmLkzegKgWPEmdia8OjicCWNMf70GcdkFaLPNBaRA3icQmtSm4zaQ/640?wx_fmt=png&from=appmsg "null")  
  
就这样我就修改了原号主的密码成功进入了系统进行后续安全测试：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshPniazt0z0S84iaX8wNbLshvsiaTe6usBDLHJ3IkWDf5etnwhbwqc3NGyA/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshBWoT8qwvq9oEicA3mb9w0I3otnrpK2rWK6Lg5icEwFhWiaribuV1oEcAMQ/640?wx_fmt=png&from=appmsg "null")  
# 案例二：且丘世专  
  
在某次SRC挖掘过程中，我发现了一个站点可以进行任意用户注册，在往下继续挖掘的过程中，发现了一个比较有趣的越权。  
  
当我成功登录的时候，我抓到了一个数据包大致如下(已脱敏)：  
```
GET /XXX?id=%E4%B8%94%E4%B8%98%E4%B8%96%E4%B8%93 HTTP/1.1
Host: XXX
Accept: /
......
Connection: close
```  
  
我敏锐的直觉告诉我这里很有可能存在越权的漏洞，但是这个id看起来实在确实很抽象，经验丰富的师傅可能一眼就看出来是URL编码，我们拿去解码一番：  
  
发现解码出来我们的id居然是：且丘世专  
  
有趣，经过我的一番FUZZ后我发现有下面的对应规则：  
  
<table><thead style="line-height: 1.75;background: rgba(0, 0, 0, 0.05);font-weight: bold;color: rgb(63, 63, 63);"><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;">序号</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;">汉字</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;">URL 编码</td></tr></thead><tbody><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">0</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">丐</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">%E4%B8%90</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">1</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">丑</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">%E4%B8%91</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">2</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">丒</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">%E4%B8%92</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">3</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">专</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">%E4%B8%93</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">4</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">且</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">%E4%B8%94</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">5</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">丕</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">%E4%B8%95</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">6</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">世</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">%E4%B8%96</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">7</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">丗</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">%E4%B8%97</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">8</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">丘</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">%E4%B8%98</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">9</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">丙</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">%E4%B8%99</td></tr></tbody></table>  
  
所以且丘世专对应着我的id也就是4863。  
  
然后我将对应的id值进行遍历一下就越权查看了大量用户的信息：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshVwPicgJA5ic834QFzS8UMtgm7ns0cCVoKQPliaRgWLCbUAKk4ib3sdbOaQ/640?wx_fmt=png&from=appmsg "null")  
# 案例三：1 + 1 + 1 ？  
  
在另外一次SRC挖掘中，同样是找回密码功能处，我选择直接重置admin账户的密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshvJR66yA0ZibWH0kUQZ7ImEFsXKrIwMqa3z4GPcRFax1TdVCic7AX9blg/640?wx_fmt=png&from=appmsg "null")  
  
该找回密码的逻辑是输入正确的密保问题，于是我随便输入了三个2来测试：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshVuHQpk6SgDjUTtwOhQGEiabSrfBV3icNqibxSnF4ukMicuJDGw8c0HIXjA/640?wx_fmt=png&from=appmsg "null")  
  
确实很安全，那么3个1呢？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshF5ic80boztSr5hkBhgJ8qvIMYgu8XQlTaE6sTKLGzTfA5D2SSUEjxuw/640?wx_fmt=png&from=appmsg "null")  
  
居然直接进入了重置密码的界面。。。。。。  
  
由于是admin账户，我没有贸然去修改密码，后续厂商也是承认了该漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshh8tozJN2icseyGtWVVnWsmGIVvbaH8f5sm3ZCsaJVgZWgOyqialOY35Q/640?wx_fmt=png&from=appmsg "null")  
# 总结  
  
有些时候有些漏洞确实非常莫名其妙，本文其实并没有太深的技术支持，但是也算是一种思路的补充吧！  
```
文章来源：https://xz.aliyun.com/t/13790
如有侵权，联系删除
```  
  
  
  
### 考证咨询  
  
  
最优惠报考  
各类安全证书(NISP/CISP/CISSP/PTE/PTS/PMP/IRE等....)，后台回复"  
好友位"咨询。  
  
  
### hvv招募  
  
  
厂商直推，大量初中高级需求，扫码投递简历  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ3bSnXfdDnF8ePdwj8LO6eDY9ibxxTQhdAK7DkVC9GTKY4BgFExTW3GXrSt7ksb5S8YS41LgtpaUg/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
  
