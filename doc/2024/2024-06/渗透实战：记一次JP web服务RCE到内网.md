#  渗透实战：记一次JP web服务RCE到内网   
 迪哥讲事   2024-06-02 22:29  
  
注：本文仅做技术假设分享，禁止对外非法渗透，违者后果自负  
  
# 1.信息收集  
  
前段时间很火的东正洗衣机rce漏洞  
  
语法  
```
```  
  
页面长这样  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkDgntsAe2xqZSQ2ny0FiadrZdpZfjk8cGseN1j7Z7h61WTpkFGicmibTxA/640?wx_fmt=png&from=appmsg "")  
  
poc如下  
  
后台常规的测试功能管道符绕过  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0Xczk0YqChAsziaNVWYmMZ7AgkdzQA7590QLPwWnTbmTRLvrjLyAYUFY58sw/640?wx_fmt=png&from=appmsg "")  
  
成功RCE  
  
  
  
  
  
  
# 2.打点  
  
这里复习一下常见的命令注入绕过方式  
```
```  
  
这里处理一下上传webshell的问题  
```
```  
  
没处理成功，对面系统无法执行  
  
折腾了半天的下载，发现机子不出网，无ping和curl  
  
无权限写目录，tmp对应目录了也无法写  
  
干到这了，不写个shell怪可惜的  
  
开始信息收集！  
  
## 1.本机信息收集  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkC1giaLEkkYOFKVCrtribozeJDzPicmD1AHr1en4pwpkIatghKOSaLsAcg/640?wx_fmt=png&from=appmsg "")  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkWjH0NlDIg3Ofibn6pREianGSGzDdicJlEHvu98ZAq5mic0kMPhiasicChYCA/640?wx_fmt=png&from=appmsg "")  
```
```  
  
都无写入权限  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkEwCGIiatdTQWaMwfvjc9fJ5qu3fwkjgYl9KfCozzfBj3pXogc5KczicA/640?wx_fmt=png&from=appmsg "")  
  
tmp也不能下载文件，只能touch一个文件  
  
web目录也没权限写  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0Xczkvr7lYDWCMs9Nw1m1JicAk0T7mjbib3icmx8Y8j7nZD5j31kHFqSp815Sg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkfFVSDmfamAgOt9PkjkmGdsUD8elVESTpKaSZlPCg3Re7XHRRhmkowA/640?wx_fmt=png&from=appmsg "")  
  
难道就要就此放弃了吗  
  
  
## 2.破解密码  
  
cat一下/etc/passwd  
  
发现了惊喜  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkNgmxwFA6hHfMdHLhhcpGUrKwKMxuhK3ibHsb2iaqtZWDBt41N5LOMNCQ/640?wx_fmt=png&from=appmsg "")  
  
/etc/passwd一般存的是一般的用户信息  
  
/etc/shadow存储用户密码信息  
  
前者格式  
```
```  
  
后者格式  
```
```  
  
这里密码直接泄露在etc/passwd里，我们可以尝试来破解  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkqNyoBp3vJ6TbokJBQlVy9r0RnvyiasahWqt9gVIWqYz8BUdEf8p0TWw/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0Xczkh7uPsWpZn3d60GE8ncgrtiajQTwDyycn73a46CKFPjcdFBz0icIYoHqQ/640?wx_fmt=png&from=appmsg "")  
  
成功破解两个账户  
  
但对方22端口拒绝连接  
  
g  
  
## 3.发现htaccess文件  
  
发现精彩东西  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkLiaicEHkq8dUkkCH5wuWvibhK0Dmagcz5MgZMxlFP758Oogd8vwXmEdSA/640?wx_fmt=png&from=appmsg "")  
  
  
chatgpt一下就行了  
  
这个配置文件直接暴露了权限控制要求的目标用户  
  
且对应的文件在  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkhTTjfdyibSvO8VWQyiclHrSGcF7L4Vc19qgJzPJkB5P6vsN53ZDEvUZA/640?wx_fmt=png&from=appmsg "")  
  
那还等什么，我们直接  
```
```  
  
发现好东西  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkiaZYoYLRj41YqM5iajiaTiawfW3lt2RSm1o38mIUesicq8JDkLHwyEkqHEA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczklemmTbXSIaezldUlhfxBWWuvj0vWvjBr5838spqyYQKq6EsCiagWVSw/640?wx_fmt=png&from=appmsg "")  
  
再次破解成功  
  
其他的也可以拿去破解破解  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkkEmLZOu6WqaKvL6skBqG2frm1Wovp8bup2ODq8Y3OewxQmKJIjMMFg/640?wx_fmt=png&from=appmsg "")  
  
左边是密码，右边是账号  
  
非常完美  
  
  
# 3.登录测试  
  
## 1.进入管理页面输入账号密码  
  
成功打入  
  
然后翻阅  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkiaiaEGvmRU5YagVylBsnDmhWA2UIntp002gTpgdppBkflko0nhwiaubVQ/640?wx_fmt=png&from=appmsg "")  
  
抓重点文件进行测试  
### 1.之前的命令注入由此产生  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkicdWVZ4hocH8cEn224mjHL4RhKrxI8R4oias9iczonichaZBHpRibgOG6yA/640?wx_fmt=png&from=appmsg "")  
### 2.ftp服务器发现好东西  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0Xczk3O4b3ZFmR92g5efr2XicSohia6r7NQnR1Xz0mZICWJKu1oDO0mCicUpKw/640?wx_fmt=png&from=appmsg "")  
  
发现ftp的ip，密码，端口，还有域名信息  
  
  
账号密码端口  
  
密码的话直接f12明文查看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkG7ibNaexaRSa860SfNgpMTtj3MrxGvUNmTWFbf1PBzr8CAlzaTgMBJQ/640?wx_fmt=png&from=appmsg "")  
  
  
直接ftp  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkD4icn84hpM3FSKNuLyYukTLqy3zvOKSXdJBX7YaqeBdT4t72X6ibylmw/640?wx_fmt=png&from=appmsg "")  
  
成功进入  
  
### 3.put lcd上传下载东西姿势  
  
这是最简单的ftp操作  
  
成功种入一句话木马  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkTFOiat9q8DVzzwhNtnUpg3x77NFb3MYMhXJZoRhCLjSQ64nHJrSg17Q/640?wx_fmt=png&from=appmsg "")  
  
# 4.上免杀木马  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW1xQA1iaZxTFaenOS6N0XczkGZxHLPWoarPtJIGsQIxWyRr3EwSoD2ia7loUq6xFhDMfiaQcpiaG2FHkg/640?wx_fmt=png&from=appmsg "")  
  
成功上线  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款前面有同学问我有没优惠券，这里发放100张100元的优惠券,用完今年不再发放  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7N5nMaJbtnMPVw96ZcVbWfp6SGDicUaGZyrWOM67xP8Ot3ftyqOybMqbj1005WvMNbDJO0hOWkCaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
# 5.后记  
```
```  
  
  
  
  
