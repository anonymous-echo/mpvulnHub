#  记某src通过越权拿下高危漏洞   
小*咔  Z2O安全攻防   2024-05-20 20:35  
  
点击上方[蓝字]，关注我们  
  
  
**建议大家把公众号“Z2O安全攻防”设为星标，否则可能就看不到啦！**  
因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuao3T9EnGbUIqxgDhEVicCV8NbH4FiaZ3YIbpXNEr6qFicGkAelnQHKGHsVlfapMGgO3DHA68iaiac0n4Q/640?wx_fmt=png "")  
  
  
# 免责声明  
  
  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号团队不为此承担任何责任。  
  
# 文章正文  
  
  
  
在挖掘某SRC时，遇到了一个社区网站，社区站点是我在挖掘SRC时比较愿意遇到的，因为它们可探索的内容是较多的，幸运地，通过两个接口构造参数可进行越权，从而获得整个网站用户的信息。  
- • 图片以进行脱敏处理。  
  
• 在登录网站后，查看产生的数据包，发现了一个特定的API接口：/gateway/nuims/nuims?Action=GetUser  
  
• 通过返回包的内容判断该接口用于获取当前用户的登录信息，包括用户名（UserName）、加密后的密码（Password）、绑定的邮箱信息、绑定的电话信息以及用户的IP地址等敏感数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ3bSnXfdDnF8ePdwj8LO6eEiceiaJQLUHrKfomMVGaq8wzYWyhmibAj9K6rIp8ZNjc5lOGt31eBXrhQ/640?wx_fmt=png&from=appmsg "")  
  
- • 此时看到返回包的信息十分激动，这接口要是能越权，就可以看到这个站点其他用户的个人信息了，漏洞这不就来了吗。  
  
- • 可回头去看请求包头，发现是get请求包，参数只有Version可以修改，但是修改后没有任何效果，尽管接口返回了敏感信息，但目前看来它并不能越权到其他用户。  
  
- • 会不会存在其他的参数可以进行修改，回去翻了js文件，想查看下有没有泄露的参数信息，查看后js的一些参数并不能进行构造。  
  
- • 再次查看返回包时，想到该网站会不会通过userId进行权限校验的，然后在接口构造userId进行测试。  
  
- • 构造参数接口，在接口/gateway/nuims/nuims?Action=GetUser&Version=2020-06-01加上UserId参数的值，UserId参数填上其他用户即可越权查看其他用户的个人账户敏感信息。  
  
- • 构造后的接口：/gateway/nuims/nuims?Action=GetUser&Version=2020-06-01&UserId=xxxxxxxxxxxxx。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ3bSnXfdDnF8ePdwj8LO6emT8da0gkwbRNZ447XspeVsovibaZuJkRasW8WGiciadXZMfRplMr4sW1A/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ3bSnXfdDnF8ePdwj8LO6ettPvIlpNrJg6sicRMAfHsF5e6vQGdicrDIqoGFTdFEDQuAtm254WGdiaQ/640?wx_fmt=png&from=appmsg "null")  
  
• 此时我们可以看到，替换了userId参数后，可以查看到其他用户的个人信息，成功进行了越权  
  
• 继续对该站点进行测试，看看还能不能发现其他漏洞。  
  
• 通过插件findsomething获取到了另一处接口：/gw/nuims/api/v1/nuims/LcpGetUser，该接口和上一个接口返回的内容相同  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ3bSnXfdDnF8ePdwj8LO6eHbvwSEyM3G7fxkyibofWibCtwb2aP6FtZTLNSr21Ccxb9L4cQNL8MpVQ/640?wx_fmt=png&from=appmsg "null")  
  
• 那会不会和上一个接口存在同一个参数越权呢，继续构造参数进行测试，成功越权查看用户信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ3bSnXfdDnF8ePdwj8LO6eZH1SaEdYVh3dkfa54ro9rWrjfYibibcgbawDzEfUicOGyiciavGNPbFHXEA/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ3bSnXfdDnF8ePdwj8LO6e2P003rw35ZE0gJgtDcW2pia3pSrKFXuLZZOicbibJj0Fv3JvVjoFZ35CQ/640?wx_fmt=png&from=appmsg "null")  
  
• 已经成功找到可以越权的漏洞，但是此时又出现了问题，userId参数并不是可以遍历的，不可遍历的参数，一般审核是不认可的，有可能都不给通过，更别想拿到高危了。  
  
• 所以还需要进一步挖掘，看能否获取到其他用户的userId信息，如果能拿到其他用户的userId参数，那我们不就可以拿到更多的用户信息了。  
  
• 返回首页，查看论坛界面。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ3bSnXfdDnF8ePdwj8LO6eojbwrqH9pEfWIibicYJ9M1gIGJpWBe39JVQn8ELJCWme2eW5WXasP6XA/640?wx_fmt=png&from=appmsg "null")  
  
• 查看数据包，可以发现数据包中出现的communityUserId和之前的userId的值是一样的。  
  
• 但是communityUserId是如何获取的呢，通过点击论坛里面的帖子，可以获取不同作者的communityUserId信息，这时我们就可以获取到其他用户的userId值了，再将该值进行替换，可以越权看到他人的个人账户信息了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ3bSnXfdDnF8ePdwj8LO6egl840NRWtxSNciaDRql5FlRGFSJE6U0K2b79vicic1Gorj2MPBqm9RsRg/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ3bSnXfdDnF8ePdwj8LO6e2d3JI1DfG2F5P1lpwCDuWVueyxYZDZPyYRVttnuoZB9AEguG27aPDA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ3bSnXfdDnF8ePdwj8LO6evOibN8r98JY8M6YyzJicMvXQEExiayNj3C5Ieq6LGFgBWEFlpj32bViaYQ/640?wx_fmt=png&from=appmsg "")  
  
- 测试完，就可以去写报告提交了，坐等高危的到来。  
文章来源：https://xz.aliyun.com/t/14493  
  
  
### hvv招募  
  
  
厂商直推，大量初中高级需求，扫码投递简历  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ3bSnXfdDnF8ePdwj8LO6eDY9ibxxTQhdAK7DkVC9GTKY4BgFExTW3GXrSt7ksb5S8YS41LgtpaUg/640?wx_fmt=png&from=appmsg "")  
  
  
# 技术交流  
  
  
### 知识星球  
  
  
**欢迎加入知识星球****，星球致力于红蓝对抗，实战攻防，星球不定时更新内外网攻防渗透技巧，以及最新学习研究成果等。常态化更新最新安全动态。针对网络安全成员的普遍水平，为星友提供了教程、工具、POC&EXP以及各种学习笔记等等。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYl1eHu25UAxhOZEBXZpSmXPg6kVsggaWKZsh0ab2kh6icbbkBgOH8icuV0x2IPGGRMiaU2hNBErstcA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYl1eHu25UAxhOZEBXZpSmX8Pjria4EK9ib8PPUAxiaMaSqUZibdxNoqqmmVHqGwXkYdzziaZNDLOwCGQw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkRgdNbBQdOZibtbt7oibUpdUIl55vlmiaibqInxXG1Z9tfo52jF8onER5R4U2mCM5RpZia6rwEHnlMAg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYItiapGtLIq3gAQYGfE5nictnkFeBicm7brKdibz4Va1hRf2dKZT0IyRRXYboE1lbZ6ZquDGnzqKibGGw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZKYf6lyR0eMFiaJpyiaflOO7cFrTsWAxOO3sibJNhtGdqoAH5OlE8nzKRPduf7HspsKab3OZTBiaa9aw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
  
  
