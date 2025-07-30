#  SRC逻辑漏洞合集   
ming9  Z2O安全攻防   2024-06-06 23:57  
  
点击上方[蓝字]，关注我们  
  
  
**建议大家把公众号“Z2O安全攻防”设为星标，否则可能就看不到啦！**  
因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuao3T9EnGbUIqxgDhEVicCV8NbH4FiaZ3YIbpXNEr6qFicGkAelnQHKGHsVlfapMGgO3DHA68iaiac0n4Q/640?wx_fmt=png "")  
  
  
# 免责声明  
  
  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号团队不为此承担任何责任。  
  
# 文章正文  
  
  
### 0x01 未授权  
  
未授权问题为普通用户登录或没有登录后，拼接js接口，构造报文，越权实现管理员的权限操作。原因：后端没有校验Cookie/Session的身份信息，以至于普通用户的权限可以实现管理员权限的功能。  
#### First  
  
webpack打包会泄露很多js接口，本人在这里演示一下Vue3+Webpack接口泄露的创建过程  
使用Vue3-cli创建项目  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshSLoHBy1ydyxBhxiapJ6LkHY5b5SEk5icZHAvxoTeYQPn9hHqOKI8tcfg/640?wx_fmt=png&from=appmsg "null")  
  
  
修改两个文件，一个是router目录下的index.js，一个是views目录下的ming.vue  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshkxUj7e6pcES6EbaeFEeunlvlyFCO6YmQW7f1ePehjyKjrQLDfWIw6Q/640?wx_fmt=png&from=appmsg "null")  
  
  
npm run build打包webpack生成dist文件夹，将这个文件夹中所有内容放在宝塔面板上展现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnsha6EVMHxXicic2xJMNEnlfOXTdqyor0mIOdzd3Jgib6kIfR4FmNUtlCO7g/640?wx_fmt=png&from=appmsg "null")  
  
  
修改网站配置文件Vue Router进行路由管理，需要配置服务器以处理单页应用的路由，这意味着无论用户在浏览器中输入什么路径，都应该返回index.html文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshtIzJ5Ns0jibZE41PyIib8KKMZvX1WqNH4IuQ3OAVIXPX78rDicshsy6yQ/640?wx_fmt=png&from=appmsg "null")  
  
  
浏览器打开url查看js文件就可以发现泄露的js接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshwYCQ4GiaqN1Ap7iaSZ7mIpKz7uUvdyMdvf47UIk5saZ7vRiaG7nKC4ocw/640?wx_fmt=png&from=appmsg "null")  
  
  
拼接接口就可以查看内容  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshwohHczg1LVnByl8EN4Vw6yKa6y4zBKn3jYDFoibgBnibgPjOzN7ib3MZQ/640?wx_fmt=png&from=appmsg "null")  
#### Second  
  
使用普通用户权限登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshyQh7ZDBgUfbttdXNga1yY2adFTNevCre0X8pMouVIxziaic6XUuT9szA/640?wx_fmt=png&from=appmsg "null")  
  
  
查看这个网站目录下的js文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnsh1GJXhYCMVMO0xYKfjolxY31sUanjTpibI3BFSsabZ2ibcLfiaibXL7mmlg/640?wx_fmt=png&from=appmsg "null")  
  
  
拼接js接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnsh7gtEicdMY4WTNp2R5PkeVTTET9hgLGaicibwE4wo9JF3Qqh5oSh5QMFxQ/640?wx_fmt=png&from=appmsg "null")  
#### Third  
  
同样使用普通用户权限登录找js接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnsh1GkwVn7FKW1aptTfibNtzuFGPHM0zmy6X3Mtu8PSxS4dLa5pbXQMxFw/640?wx_fmt=png&from=appmsg "null")  
  
  
拼接js进入后台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshhKbJY14sK29Ih84IlLRmjkDYria7ALzicXsQTsgAibZrpEoRPYvWDLBLQ/640?wx_fmt=png&from=appmsg "null")  
### 0x02 越权  
  
越权也属于未授权的一种，因为漏洞出现的次数比较多，所以我单独写了出来。水平越权：一个用户可以查看其他用户的信息，比如一个招聘网站，每个人可以查看自己的信息，例如身份证号、姓名、头像等，但是一个用户能查看其它用户的信息，这就属于水平越权，同样修改其他人信息，删除也为水平越权。  
#### First  
  
水平越权查看其它用户的信息  
一个招聘系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshiax40nibdiaRF1aGvKicd9kgGmGwT9QoTlicIXYvDTJjjgpUxTy7DQye6jw/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshibRP0gjriaXQWxElslbgcH6XSySgYxLmq6U8XmRdP8DbByfEf8ftFXWw/640?wx_fmt=png&from=appmsg "null")  
  
  
burp拦截报文  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshb4e4AoRq6xzIauuB5lBHGcGHAp30ukiaTzBvAIa7TOronjOg6sQrcOg/640?wx_fmt=png&from=appmsg "null")  
  
  
是不是对12354有点感觉呀，burp重发包测试一下12352  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshgv3E8CGCffyV6hvDs2E2EH4ese8Fof2CjEYNv8nAcpcpiaeN9HISTCg/640?wx_fmt=png&from=appmsg "null")  
  
  
12353  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshKwhPj2yNhdUyARIczic9usXrpHUSdy1tZ8AKbp0iaRoNcnLyC8icBKXgw/640?wx_fmt=png&from=appmsg "null")  
  
  
水平越权也有sql注入的可能，详情可看上篇文章  
#### Second  
  
越权修改其他用户的信息  
系统上我注册了两个账号，一个为ming4，一个为ming5  
登录ming5账户，修改信息点击保存  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshVbHNSGPwsDSktxIoP6ZukcHyPGdDZB3J8HUpyyYorRCJd9z5gTtn7g/640?wx_fmt=png&from=appmsg "null")  
  
  
burp拦截报文  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshaaXGkEp7L5Uev75BtCvblQnTzsIO1AKDPiavIvLYicESEDCfp4V9QOuQ/640?wx_fmt=png&from=appmsg "null")  
  
  
修改id为2177(ming4用户的id)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnsh06xKVnkvC5qZiaGpvofxWdiaIO0gLCCH36BqKIRAibyJCicN29PKiaiaAXvA/640?wx_fmt=png&from=appmsg "null")  
  
  
刷新ming4用户的信息，信息修改，密码也修改了  
后续碎碎念：其实这里怀疑是update sql语句，当时比较菜，没有测试，如果现在这个站点还能让我测试的话，我会测试  
2177 and sleep('5') 这种看看会不会产生延时注入  
#### Third  
  
OA系统越权登录，这里的逻辑为使用学生的学号登录统一认证，统一认证有跳转OA系统的链接点，学生用户是进入不了OA系统的，但是老师的工号可以进入  
统一认证界面点击OA系统的链接，burp拦截报文  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshHKy3f5TklZDzicJEpuvLcmicO3TsURJWG1yECcSv8PgvzCTMutmicQGYQ/640?wx_fmt=png&from=appmsg "null")  
  
  
ticket修改为老师的工号，进入OA系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnsh9f9szQicgzkhFIlFN7DdAjoBFTZOmU4MKnKfJnoRwefRTfVwicuZpia8w/640?wx_fmt=png&from=appmsg "null")  
### 0x03 Cookie  
  
后端开发人员编写代码使得服务器使用cookie识别用户信息  
#### First  
  
修改cookie中的内容就可以直接为管理员权限  
登录之后，web系统回复了以下内容，cookie中cookieusername以及cookieid，我们可以修改为cookieusername=admin以及cookieid=1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnsh8gcSpaBMiaotvNAG8yulxpubmOcIMJlvCDLA8eV6vKo7DQSHQFHxpsA/640?wx_fmt=png&from=appmsg "null")  
#### Second  
  
cookie修改信息触发水平越权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshIIicwKABqx6QyIiaKK4UA1rcN3Sl6ytwRiad8uicsKgxz9vJdPPhJoEW0Q/640?wx_fmt=png&from=appmsg "null")  
  
  
修改cookie中userid内容产生越权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshdCmx6ZoNt8h9LbWv2jG3to68qdOa57jn2MqKwZNBZtnQAuNItHETkg/640?wx_fmt=png&from=appmsg "null")  
### 0x04 任意密码重置  
  
网站使用手机发验证码修改密码，但验证码的作用仅为展示前端界面，没有与后端的校验交互  
#### First  
  
一个系统重置密码框  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshVxvab8YQkHsxibhh8ibQNtcJqjJDr1TzfQZibjg8eyKAYhbwia6b5o0FJw/640?wx_fmt=png&from=appmsg "null")  
  
  
输入手机号输入验证码发送报文  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshc04LZzAGJ2SZ9dH8sEqG1SvjZQF5WKWXVubO6b5jL6XYiceZMoQl44A/640?wx_fmt=png&from=appmsg "null")  
  
  
修改status值为1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshCzqut2MZYPbUL8oFNWFWicoGjwSa2UASgJXPAcDsiaKc1yE0KBuCcuww/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshYvAibOODB6Fsp11HzoQZXNZMa5Luw8L4fUv3YeG90wFPj2FwHBfVu3g/640?wx_fmt=png&from=appmsg "null")  
  
  
输入密码点击下一步  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnsh21hvdicvXf9bSib85gtPmDgrLvJcEKiaAHdWWJetfI3vK8sjoOOWuKaGQ/640?wx_fmt=png&from=appmsg "null")  
  
  
绕过  
漏洞修复后的判定方式为在输入密码点击下一步的发送报文中携带验证码信息  
#### Second  
  
还是一个重置密码的地方，随便写入验证码点击下一步  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshLwjYx5tmC6ncwxCw5rNWu78CEWQtl3xR3OpiaGqoLWMBeutKtJiaDJNw/640?wx_fmt=png&from=appmsg "null")  
  
  
回显报文情况  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshThBNPBSDsmfpic3uPy0td2dhEJUibXUnshnKlkmDEHfDw6VPM0sia3FxA/640?wx_fmt=png&from=appmsg "null")  
  
  
这里改为True呗  
再点击一下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshibsuAVO5R1FHEyPbRPoTxesXRscqDTicqL6iaxyXRhoXMJU37Yhzjgh1w/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnshzEB7rA5qwvOO2H8ywAEjUIkyhuzguWFtNUUpeiclL3Gu489zQIv1GFg/640?wx_fmt=png&from=appmsg "null")  
  
  
返回为True，成功重置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaUagJwBLzv9zFStqhcDnsh5TUHpHQMcLuw3oMCL0gB2p7PgnmSftp16MpiaZqrTIkxia1RuJEmT2nw/640?wx_fmt=png&from=appmsg "null")  
### 末尾  
  
逻辑漏洞覆盖面很广，并发问题，支付漏洞在本文中均没有提及。  
```
文章来源：https://xz.aliyun.com/t/12655 ，ming9
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
  
  
