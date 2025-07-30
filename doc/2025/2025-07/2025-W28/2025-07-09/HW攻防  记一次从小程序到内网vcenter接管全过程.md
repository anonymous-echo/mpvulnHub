> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247519641&idx=2&sn=8510368cd30e6d362c3f0e85461e8755

#  HW攻防 | 记一次从小程序到内网vcenter接管全过程  
 渗透安全团队   2025-07-09 02:30  
  
   
  
   
  
> 由于数据较为敏感，前方有大量厚码，各位看官见谅！  
  
  
   
# 一.前言  
  
本文涉及的相关漏洞均已修复、本文中技术和方法仅用于教育目的；文中讨论的所有案例和技术均旨在帮助读者更好地理解相关安全问题，并采取适当的防护措施来保护自身系统免受攻击。  
# 二.大概流程  
### 1. 外网突破（小程序漏洞利用）  
- • 发现小程序存在 **SQL注入**  
，但利用价值有限。  
  
- • 利用 **Shiro反序列化漏洞**  
 获取Web服务器权限，尝试写入内存马失败（EDR拦截）。  
  
- • 覆盖**404.jsp**  
,写入WebShell，成功进入内网。  
  
### 2. 内网横向渗透  
- • 发现 **Todesk**  
 远程控制软件，通过内存抓取获取凭证，连接内网机器。  
  
- • 使用 **fscan**  
 扫描内网，发现大量漏洞：  
  
- • **Nacos默认密码**  
 → 获取敏感配置  
  
- • **Druid未授权访问**  
 → 登录后台  
  
- • **Spring Env信息泄露**  
 → 获取数据库账号密码  
  
- • 利用数据库服务器作为跳板，发现 **vCenter**  
 目标。  
  
### 3. vCenter接管（最终目标）  
- • 利用 **CVE-2021-22005**  
 漏洞上传WebShell，获取 **root权限**  
。  
  
- • 提取 **vCenter数据库**  
，解密管理员密码。（**行不通**  
）  
  
- • 通过 **生成Cookie**  
 绕过认证，成功登录 **vSphere Web控制台**  
，接管整个虚拟化环境。  
  
### 4.最终成果  
- • 控制 **外网入口服务器**  
、**内网数据库服务器**  
、**vCenter**  
。  
  
- • 获取 **数十台核心服务器权限**  
 及大量敏感数据（数据库、支付密钥等）。  
  
# 三.正片开始  
# 1.小程序  
### 1.1.sql注入  
  
查询处拿到两个注入，mysql，用处不大  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaViaHoZ75WHN00pB88iblHt1emvBG0VSrnmS2TBLejqsmBfibnDP3pzMlAw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVcn8ftUEM5R3xcrq0G5YE7EJJLhAviazjh3gj5ua0N8NOCTibcpv9YZ1A/640?wx_fmt=png&from=appmsg "")  
  
### 1.2.shiro反序列化  
  
在同接口发现shiro，工具梭哈拿下，终于也是让我碰上了哈哈哈哈  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVKiaTQbXvQ11Tqg9SShzsxdlfLu7TCt7CfiaGKx7M0lcpr3KG47iciaGB5A/640?wx_fmt=png&from=appmsg "")  
  
  
然后准备打内存马，然后直接上哥斯拉进内网。但是一直打不上去，手动也不行，看了下进程列表，发现了问题，存在edr  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVNPAuMBUE6yI8Aoorj2NJuXLo9ehydlkwdNtxP7ibHRicwnyMIxs7EUpQ/640?wx_fmt=png&from=appmsg "")  
  
  
打不了内存马，只能手动去写webshell，这里卡了很久，因为一直没有找到路径，加上前后端分离，在当前执行命令的路径下，找不到对应的静态文件，一度怀疑此处是别的站开的进程，因为上层目录存在多个tomcat。  
  
只能通过搜索静态文件，一开始等了很久，没有回显，以为是没有找到，就又卡住了。结果找着找着，结果突然回显回来，应该是find了很久。找到了绝对路径，但是写马发现此目录是纯静态，前后端分离的，没有执行权，又找不到后端，没法了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVXgZ17tuyTJFob6cDfuWYbFvscL0t1bJeibYdIXdgXPibwyIs94CMjdyA/640?wx_fmt=png&from=appmsg "")  
  
  
上马直接下载  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVqOV3Q82F5MsBVwZPCXibcHfTibibZTNqhMJoicvhtYthXjIUsDTVKwJ6ibA/640?wx_fmt=png&from=appmsg "null")  
  
### 1.3.迂回拿下todesk  
  
其实一开始就看到有todesk，然后想要上传proceedump抓取内存，但是发现本地读取没法下载，然后二合一的工具又会被edr拦截。本来是卡住的，但是上面找了前端，就可以通过前端去下载。  
  
下载后工具读不出来，二合一直接抓取后在服务器读取的工具又会被拦截。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVrnGPpMYmibBqvSyfXIVs0zyPBZWfjdqq7W3G9xJaXKdwtuviaz0Q8Jog/640?wx_fmt=png&from=appmsg "null")  
  
  
查阅相关信息后，把dump的内存文件copy到前端目录，通过静态目录，去下载读取的内存文件。拉到本地手工读取，搜索字符串dump的日期，上下文寻找，看到数据或字符串大概率就是，尝试几个  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaV09DVdUMMQvCPjf3RTicuLGJQAUpm7et4NWnQhaSIE8fE2WG4NKTsVhw/640?wx_fmt=png&from=appmsg "")  
  
  
成功连接上  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaViaHDfARJl6AJbAJo7zh0sfAtibXibFDXk6eYhatcGXR4QpPVKJUxNwJjw/640?wx_fmt=png&from=appmsg "")  
  
  
但是特别卡，根本点不动，而且发现有运维在操作。没有办法，只能再次迂回回去找目录。接下来就到了非常逆天的一段，一台服务器里开了七八个tomcat，开始翻目录，找真实路径，加上这个服务端全部是通过这种路由，去构造参数访问不同的功能，前后端不在一个目录，逆天开发。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVfxCjandakhB9A9HSorYISmIyzuGJicmWs8jjHTQukd3icVibuqUL0VRcg/640?wx_fmt=png&from=appmsg "")  
  
  
死活是找不到后端所在的对应路径，而静态文件，和图片之类的，全部在上面那个前端文件夹里  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVnicWojzxzlgwpIIWicDYA5NYb8zScCFxYADWjUzLeibFBHgALOXjibNib0Q/640?wx_fmt=png&from=appmsg "")  
  
  
最后发现，include了404页面，在扫路径的时候发现访问/api/xxx一个不存在的页面，都会直接跳转的404.jsp页面，索性直接找到404.jsp这个文件，通过下载服务器上的免杀webshell来覆盖这个文件。别问为什么既然找到404.jsp了，不直接写马，因为写上去了，也找不到访问地址......而404这个文件则是全局include的  
  
好在没有杀软，powershell下载是能用的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVwzLRteEWrdib6aicAFwVfAOJB95rW5W39aQmZw8bpruWEiaswDjqv9N5w/640?wx_fmt=png&from=appmsg "")  
  
# 2.内网  
  
终于，拿下，由此进入内网  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaV1JibuJXNajoNPMx3ibAKW7DKdpUB0OV4ElUzmx3ymxxnyMylqoC0BC5g/640?wx_fmt=png&from=appmsg "")  
  
  
找到配置文件拿下数据库  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVicfrkaYUmtB7D1SWgStPzVI1Ua88jM1bGSAIEhLr8ibg9oymYhZung1Q/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVWiaKAH1AFoZqCj3iaVwxDPIe60MvOYxIxG5OWTB0vZxjwjnEiajViceuMA/640?wx_fmt=png&from=appmsg "")  
  
  
接管小程序，和一大堆数据库，加上支付key  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVFfT6mwm9gJiam4d41PrwDjFF6ygcuAm2d3Qf8zic8AASn8ricHak11GxQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVqPZJdaYc8FlhfdwpZialKCibktDXCWZ7bJ2ianzMPNtTIzHia7QrQdaNew/640?wx_fmt=png&from=appmsg "")  
  
  
进了内网挂上frp， 丢上免杀的fscan，低速率开始扫描。  
  
通过多个nacos默认密码，大量未授权敏感信息泄露，又拿到一批数据库密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaV0OibarJzkHMwCofE6BDfBl153opySibSco2BMvOVccvichpwIrSl8pslg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVaRCQLS3WodgNpFbXKBfOhe53F2zpVvvUZDPBrOeIq5BNdOqQEA7vuQ/640?wx_fmt=png&from=appmsg "")  
  
  
druid未授权，通过session直接登陆后台，拿到web管理权  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVySBjiclNTe7rXQNJpreF16uudlqxEDzugAYiblIwAD4mSh8rUibksn2dA/640?wx_fmt=png&from=appmsg "")  
  
  
大量spring env未授权，通过heapdump 文件，拿到大量敏感信息，账号密码等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaV96pDQzKbJF8sSQzsAficc8dH0vJpopRoibw2OicEfclA6VF4KBRxAnnkw/640?wx_fmt=png&from=appmsg "")  
  
  
通过泄露的账号密码，进行密码喷洒，拿到大量数据库，大部分可以执行命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaV0PBTTqLiczdlAKsxJHxFqELwzTsOEj8ziaGkt1l7hzCHGyzzWbBpx3bg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVamiczn2kuJiaIKlfwAzDac1LSzFCWH75ypiahAWpggyFqlrE3c4MFGcmA/640?wx_fmt=png&from=appmsg "")  
  
  
挨个查看，选了一台双网卡主机，上线cs做个维权，查看arp发现还有三个网段 。1.1.1.1/2/3  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaV2TDJVmRJRV9UvnjeDbmZe91x49ibuhsBz3iaGqFTrUdOicmnGwf69PQibQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVIGic3Z8j5bxNSEgga3kdmTLGjRYWZywQb0bQLsqJet4NMesiadib7NU6g/640?wx_fmt=png&from=appmsg "")  
  
  
上fscan扫着扫着发现，被应急了，外网webshell和隧道直接掉了。  
  
还好上了一台数据库服务器到cs做了维权，这台数据库服务器，存在两张内网网卡，同时出网，比较隐蔽。  
  
但是版本较低，需要重新起隧道，2008r2系统要低版本frp，此处使用  
v0.51.2  
 版本，高低版本配置文件兼容，一样可以使用.toml不需要改。  
# 3.拿下vcenter  
  
通过fscan扫描找到了vcenter，人称小域控，打到这里基本摸清了内网结构，是没有域环境的，只有一台vcenter，那么大概率这台就是集权控制中心了。  
  
试了好几个github上的高star工具都打不动，手工paylaod打完了一遍，都没结果。  
  
突然想起来，内网试试goby。这里不得不提，内网goby是真的好用，挂上代理，指定单扫poc，防止流量过大  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVMEJwOgfA0KCRMdm2iaQuIJlfAg3Er9tt426tD2mwNIgTVpHAEEiaGWpg/640?wx_fmt=png&from=appmsg "")  
  
  
最后通过cve-2021-22005上传拿下，goby yyds！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaViaRxbzuFa9Tu2onklibn6fK5RqVToHtWF81W9adQzW8vj4fOIML1EtcQ/640?wx_fmt=png&from=appmsg "null")  
  
  
拿到webshell，是台linux，默认root，权限拉满，省去了提权。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVOX82D4iaUzI1U4iacEYXyo6yjEGOQQkExUQvK5Ga7cFLpQ84DtS8QnWQ/640?wx_fmt=png&from=appmsg "")  
  
  
但是只是拿到服务器还不够，我们还控制不了里面的虚拟机还需要拿到vcenter的web端的管理权限。  
  
准备dump数据库下来解密登陆，但是一直dump不下来，因为哥斯拉的shell是半交互式，输入不了密码，索性加了个用户直接ssh去dump数据库的表  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVmz1qQyJ1vQeHFggsktn1UL9JWCDzlZibqjRFSpwNC5DQicYhWqLlMmaA/640?wx_fmt=png&from=appmsg "")  
  
  
读取密钥  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVQw4fibmhTrsFoOhd9AwtQHSsgBRLXCbBBU7YYr2uKAGeG5ZwSLmwibug/640?wx_fmt=png&from=appmsg "")  
  
  
然后用脚本解密出密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaV6HWN30eia15Ikd0dPcialD1FVgEpjSLBra0wLiaP48HnbjExGwVIHnrMw/640?wx_fmt=png&from=appmsg "")  
  
  
账密为 
```
vpxuser/password.txt里的密码
```

  
 有文章说这是web端的，有的说是服务器的。但是解密出来发现都无法登陆  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVnicCyws20LKfK1gFsboM3wLfiawt4muBFURuLuB2QmhS8tNj1tXTjV3A/640?wx_fmt=png&from=appmsg "")  
  
  
最后换了种办法，把data.mdb拉下来生成cookie  
  
先通过data.mdb生成三个txt文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVNJISPNrExqicx8eBHtkZg7V0y36S2Kqbib7uGqjFMyiaQvVNHE7HwqxGQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVZQhpkng1YTSDmHJa53B5uicUM7AwzSVK99kibv0nFCJXYicVc1iayDDXdA/640?wx_fmt=png&from=appmsg "")  
  
  
此处ip为目标ip，如果在内网记得挂上代理，要去请求才能生成cookie。vsphere.local为上面脚本跑出的doamin  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVL1hNziaG52Wc5tu9m4TOnt4bRZQTMxYEnHDxPrcLiaDwAt3AepLEeSSg/640?wx_fmt=png&from=appmsg "")  
  
  
打码处为vcenter ip，本地执行记得挂上代理，需要发送http请求才能生成  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVQ6vjLae8NfAial8TzI2992JdPHjGBSkEgS0Liau1pk5UzscaG2GKuhiaA/640?wx_fmt=png&from=appmsg "")  
  
  
添加cookie后直接访问ip/ui，不要点刷新。  
  
成功登陆。到这里基本上内网已经穿了，再打下去也没什么意义了，主要服务器都在vcenter集权管理了，后面就是生成快照，抓密码，就可以拿到服务器密码进行登录了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVia3nfESkOPicABic7dEoCQOFS61dXrSaicdUWzJpWBSnDsvPskZaQs4rZg/640?wx_fmt=png&from=appmsg "")  
  
# 四.成果展示  
  
数据库  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVYuCOUubG2SVM8JXNYhhOpaLsWDuacQulic1Ribu20QJVwgMWoKs4jiaGA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVJicjVdaePGwzwh6BxgW68nCsjibYYJBY5ZmbMAiaZI89LL5u4mmWcWpwQ/640?wx_fmt=png&from=appmsg "")  
  
  
外网入口一台，vcenter一台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVZbgjWBGZAvxLp3Og4gJIzOocF0cddl2LKaFpnokzuqZlupRQpKmOqw/640?wx_fmt=png&from=appmsg "")  
  
  
内网一台数据库服务器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVVZ3tIPPy0ic3dHcs3cGuhHemiaYa9e79OMoo42d9POnPqNsU9dcibXeJg/640?wx_fmt=png&from=appmsg "null")  
  
  
vcenter集权平台外加核心服务器几十台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaVfoJTSSZRgAYfmMffuD3vw68LXNgyHE07JRPOpM9yfESQSbBWN0ZUJQ/640?wx_fmt=png&from=appmsg "")  
  
  
还有大量web端未授权敏感信息弱口令等等，不一一展示了  
# 五.参考文章  

```
https://blog.csdn.net/qq_63855540/article/details/142085758
https://mp.weixin.qq.com/s/PrZQo6IOJqzQ8nOmxtDx9Q
https://forum.butian.net/share/1893
```

  
  
   
  
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，  
  
所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BwqHlJ29vcrDwktUPiazia5Prfc5FSe0iaV4PNqdGrTU7WFGEzlgvkLZI1zk3xTEky4XkzKUyzvabIzFIE9mg3enw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**★**  
  
**付费圈子**  
  
  
**欢 迎 加 入 星 球 ！**  
  
**代码审计+免杀+渗透学习资源+各种资料文档+各种工具+付费会员**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**进成员内部群**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8AQHAyOTgM5sLrvP6qiboXljGWG0uOdvcNR8Qw5QJLxSVrbFds2j7MxExOz1ozb9ZoYwR68leoLdAg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.09738205945672873&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**星球的最近主题和星球内部工具一些展示******  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8Doq0iczyRiaBfhTQyfzqSGuia4lfHfazabEKr2EDe7sGVoxUhLrNRA4FbI1yef6IkWdmzxvZrTiaJncg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BmE6FAA8Bq7H9GZIRt1xYZpmYNWxrrzolt71FtX5HyM03H0cxkiaYelv7ZSajLtibEdBXUpCibdItXw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8ADSxxicsBmvhX9yBIPibyJTWnDpqropKaIKtZQE3B9ZpgttJuibibCht1jXkNY7tUhLxJRdU6gibnrn0w/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DAc8LkYEjnluf7oQaBR9CR7oAqnjIIbLZqCxwQtBk833sLbiagicscEic0LSVfOnbianSv11PxzJdcicQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8B96heXWOIseicx7lYZcN8KRN8xTiaOibRiaHVP4weL4mxd0gyaWSuTIVJhBRdBmWXjibmcfes6qR1w49w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DAc8LkYEjnluf7oQaBR9CRBgpPoexbIY7eBAnR7sWS1BlBAQX51QhcOOOz06Ct2x1cMD25nA6mJQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AqNwoQuOBy9yePOpO5Kr6aHIxj7d0ibfAuPx9fAempAoH9JfIgX4nKzCwDyhQzPrRIx4upyw5yT4Q/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**加入安全交流群**  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247513602&idx=1&sn=98045772ff9aebe8792552e32523bf83&chksm=c1764badf601c2bbcc199da519611ac8c36c17e5a0554fe32ab9d9769403a495187058f19f3d&scene=21#wechat_redirect)  
  
 			                  
  
  
**信 安 考 证**  
  
  
  
需要考以下各类安全证书的可以联系我，下方扫码回复  
**考证**  
进交流群，价格优惠、组团更便宜，还送【  
渗透安全团队  
】知识星球**1**  
年！  
<table><tbody><tr style="outline: 0px;"><td data-colwidth="557" width="557" valign="top" style="outline: 0px;word-break: break-all;hyphens: auto;"><p style="outline: 0px;"><span style="outline: 0px;font-size: 14px;letter-spacing: 0.51px;"><span leaf="">CISP、PTE、PTS、DSG、IRE、IRS、</span></span><span style="outline: 0px;font-size: 14px;letter-spacing: 0.51px;"><span leaf="">NISP、</span></span><span style="outline: 0px;font-size: 14px;letter-spacing: 0.51px;"><span leaf="">PMP、CCSK、CISSP、ISO27001...</span></span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AOzYX7kxefGbGGZg3g1ltkN30q9hceg23PiczgUqMT0EE9w0fLK9uw1eKWwQX9TljXQe1OQeHRZ2Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**教程如下图**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8C3Gu1libJC0muV1WmOFa3XM3fTyOiaOJYPgCiaHV6gkJJBia6Fjeds9w9pxxyyPNJhbcfK3I1tcGueTg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
  
**推荐阅读**  
  
  
  
**干货｜史上最全一句话木马**  
  
  
**干货 | CS绕过vultr特征检测修改算法**  
  
  
**实战 | 用中国人写的红队服务器搞一次内网穿透练习**  
  
  
**实战 | 渗透某培训平台经历**  
  
  
**实战 | 一次曲折的钓鱼溯源反制**  
  
  
**免责声明**  
  
由于传播、利用本公众号渗透安全团队所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号渗透安全团队及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  
  
  
  
