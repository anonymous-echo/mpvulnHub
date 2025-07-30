#  ATK&CK红日靶场二，Weblogic漏洞利用，域渗透攻略   
原创 仙草里没有草噜丶  泷羽Sec   2024-11-22 23:40  
  
##### ~ 不辞青山，相随与共~  
  
‍  
  
[‍开箱即用！265种windows渗透工具合集--灵兔宝盒](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247492994&idx=1&sn=ca2ba6fe86b4172e3e6d3cbb3791c05f&chksm=ceb17e8ff9c6f7993d49ebab74c400cff9ffb9e2010a8af69ff4197b5a289af53a595e03e5a2&scene=21#wechat_redirect)  
[渗透测试中新手必练的15个靶场](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247491804&idx=1&sn=551c8b898f5e932ba993d11e5a050eab&chksm=ceb17bd1f9c6f2c75ac926d476aeb58c2e1c42903ed2ac8f8761f50957b7bf1a3a328362578f&scene=21#wechat_redirect)  
  
‍  
  
‍### 靶场搭建  
#### 靶机下载  
  
靶场一套下来共20多G，夸克下载（新用户只要三块）官网的百度不行新用户贵。。：  
```
https://pan.quark.cn/s/4299d63eac02

```  
  
红日官网：//vulnstack.qiyuanxuetang.net  
#### 环境说明  
  
内网网段：10.10.10.1/24  
  
DMZ网段：192.168.111.1/24  
  
**DC**  
  
IP：10.10.10.10 OS：Windows 2012(64)  
  
应用：AD域  
  
**WEB**  
  
IP1：10.10.10.80IP2：192.168.111.80OS：Windows 2008(64)  
  
应用：Weblogic 10.3.6 MSSQL 2008  
  
**PC**  
  
IP1：10.10.10.201IP2：192.168.111.201OS：Windows 7(32)  
  
**攻击机**  
  
IP：192.168.111.128 OS：kali10  
  
**拓补图**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJ8uBOic3JzbwhlHDPbNsry8s3AsbuxYaEAeoqWOv8IWh201bGFI2I25Q/640?wx_fmt=png&from=appmsg "")  
  
image-20241122200910839  
  
配置好虚拟网络编辑器仅主机的网段，为域网段  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJBCFcvDK7dH40TpzfG3vYEKwXSTXh4HDNicufknCININjncVJ9Aa5Jag/640?wx_fmt=png&from=appmsg "")  
  
image-20241118211249297  
  
修改nat网卡为192.168.111.0（内网网段）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJeStPcibRCGQAGGicytVOfMF3omibTMm3brQzcfia495AtDJbvM2pmuLoMA/640?wx_fmt=png&from=appmsg "")  
  
image-20241118213302276  
  
把已有的三个靶机仅主机网卡都设置为刚刚添加的vm2仅主机网卡（10.10.10.0/24）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJLnKShYNnoSkYaZBzWwNXqX1GSmn01QgCNWHMgBmdPCfdvHU5Bjn5FQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241122201418790  
  
启动靶机  
  
三台虚拟主机默认开机密码都是：1qaz@WSX  
  
但是web这台，需要注意一下，点击切换用户后重新输入如下内容  
  
账号：de1ay，密码：1qaz@WSX  
  
域控服务器，administrator/1qaz@WSX  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJibxv0ncujyic2l4EXr2yJkmpZ1YWHfn1uP9E4QfnRCkOTtCU7hL1kbxA/640?wx_fmt=png&from=appmsg "")  
  
image-20241118212617032  
  
开启web服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJesc2GKVc86zAMj6kZkq7rIyDZAF13aYVkwsxSt5HlBU9qddAsSRYDw/640?wx_fmt=png&from=appmsg "")  
  
image-20241118221137187  
  
开启成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJmSiclCKsNZABhUXf9ibjDSOtX3UqZK3vuCtNHCXygslj8JrFGsww7otw/640?wx_fmt=png&from=appmsg "")  
  
image-20241118221205047  
  
访问7001端口，看到这个报错页面即启动成功，靶场搭建完成  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJl3EkVFwZpU1VwtEDQFX4OGPT4uvy7xoMrgDutWe0VJSlibibpsFxprdg/640?wx_fmt=png&from=appmsg "")  
  
image-20241118221253618  
### 靶机渗透  
  
nmap主机探测 -sP  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJuvR2qTBPia2egG4Hnib5MrKm7hwy8K0iaHT43NovCkxPa9KQu5HKUYXAw/640?wx_fmt=png&from=appmsg "")  
  
image-20241118221900622  
  
查看所有的服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJyg43AykUSR5KGthAmHs0oibcbGB5aDr6qXbpk4icC4SgeMico5XzBXhfQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241118221846507  
  
使用searchsploit检索漏洞，发现一个java反序列化漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJuat6Zt05y7MTdiaChSptUT2h4Y8lWB0hAZTUjPwCLOibRfX3tcY2VLFw/640?wx_fmt=png&from=appmsg "")  
  
image-20241118222104588  
  
找到exp文件路径  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJzoibMtW2ia9oTV2Iibl2JVrVDOicjzldOicK7c99eZQ9o47bHTPIredD9Nw/640?wx_fmt=png&from=appmsg "")  
  
image-20241118222305660  
  
利用，提示了怎么使用，需要在后买你加两个参数，分别是IP和端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJJVFxCt2FFiaOLoVaicntiaaotgXYejib5SwmqplBJy4oLGSwUxDJDbd4cg/640?wx_fmt=png&from=appmsg "")  
  
image-20241118222253499  
  
看样子不存在这个反序列化漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJbzOiaceDcsbPrPicRrdrbUAPNNmKAXXO0n0e1AQkKRAZ9PcIEYb53ZfQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241118223855384  
  
试试刚刚检索出来的漏洞库，其他的exp  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJDBiaMPbuv73lNsZWGL5jo25dpuKS4Q4YlNLD1IlKggPeo0K8rCs0TkA/640?wx_fmt=png&from=appmsg "")  
  
image-20241118223922389  
  
WebLogicTool，直接漏扫，存在CVE_2016_0638_ECHO，漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJAPMqcOriae8sF4mxOrzdLpwaGEXZ9gNTmjfKc7vmkIKlRebiaGiakkibow/640?wx_fmt=png&from=appmsg "")  
  
image-20241118224424182  
  
命令执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJj9ZibdiaLSI1xpHLAz6bicoX4QHxZQJIiaRDe0ETAArMFfD0XEwggTYuEA/640?wx_fmt=png&from=appmsg "")  
  
image-20241118224600641  
  
我测试了一下，shell上传，内存马注入，蚁剑连接，都获取不到shell，可能我太菜了  
  
这里有一个工具WeblogicScan，是一个专为检测Oracle WebLogic服务器安全漏洞设计的开源工具  
  
https://github.com/rabbitmask/WeblogicScan  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJSwRgoRat4WBAWEOzOH87iarVXPrichqQqrwriaiaCPWUMB5mqvmYTg5KicQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241122153609634  
  
扫到了两个漏洞  
1. CVE-2017-3506：wls-wsat组件远程命令执行  
  
1. CVE-2019-2725：一个Oracle weblogic反序列化远程命令执行漏洞  
  
#### msf漏洞利用  
  
放行指定端口，不然会出现创建会话失败  
```
ufw allow 4444/tcp

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJhTBvTspBNqyicvRfVRKaIlCtf31KlovcSYUQ5poH5xiaDPTUZWNwpLKg/640?wx_fmt=png&from=appmsg "")  
  
image-20241122184401392  
  
先搜第一个2017那个，但是没有结果，搜搜第二个2019的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJFEicV65r2qljeMdzzyQdcL7UvTv3WKRiaDeZKkdbyulGJIaGShSy9AxA/640?wx_fmt=png&from=appmsg "")  
  
image-20241122182353958  
  
msf配置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJiaTj2G9BUjEPDXH0EXUETlVKGTQ2CNrueCWpYw4j6SFxSrhiaQZHwMAA/640?wx_fmt=png&from=appmsg "")  
  
image-20241122185506430  
  
上线成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJby86OdFrYDVh2O0QPvZkopM3cH33agxtIibg2Q4fqJoYwGknvruAEfg/640?wx_fmt=png&from=appmsg "")  
  
image-20241122202959008  
  
msf派生shell到cs，search payload_inject  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJe1cQZFVhadtvakZgffl9ogibwicUHsLnfVoCqrGspm4pWdFJX6KwqxIw/640?wx_fmt=png&from=appmsg "")  
  
image-20241122191401368  
  
开启cs服务器  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJyknKW9JxuXMAXhapD80z3477ncfd5dE2cUQKZcWXqLrap64AQoW8KQ/640?wx_fmt=png&from=appmsg "")  
  
创建监听器  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJXdJL5CUNLVYGBJ2BhTo428BckHHZgCEGZchlbPckZ8wOibK5ce4cslA/640?wx_fmt=png&from=appmsg "")  
  
image-20241122190426593  
  
上线  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJZOmyxUXaNf3abKA0I7NDg3jYTLeqj9cGCLHqmKBAu5NDyrREMljpUg/640?wx_fmt=png&from=appmsg "")  
  
image-20241122191418997  
#### 域内信息收集  
  
找到IP信息  
```
shell ipconfig

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJdE5yPw1kJDUkRWzVDbWqV7fj9CT9e9m5FxINKQVnHBJFKjMIgqxiaRQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241122191554366  
  
portscan可以识别目标主机上运行的服务类型，通常用于内网中  
```
portscan 10.10.10.0/24

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJTNmkqlpXW2tmmBhdl3xib9FD4fibkicEFwG5JH7XiaKJa9eMmHlibtxLAnw/640?wx_fmt=png&from=appmsg "")  
  
image-20241122192253700  
  
看到了DC这个名称的主机，基本可以确定10.10.10.10是域控主机了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJlRAQFY8pMXAzz3taLXRUnhSbyDJ1P8ibHbB1afMoh4eudRibWZ0JHepg/640?wx_fmt=png&from=appmsg "")  
  
image-20241122193208750  
  
抓取hash密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJHIdLicHcqEMGy8hgic7fP8EsnCYvKrhFF7qwU0lLfTv1zupicnw6TR5mw/640?wx_fmt=png&from=appmsg "")  
  
image-20241122195238064  
  
创建一个smb监听器  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJaJBLUoHwRtlwOqs9pLZrmrekuyDWt2vXeiaUibD7PsRPqloRYIqib9D7w/640?wx_fmt=png&from=appmsg "")  
  
image-20241122195940951  
  
查看所有主机，找到域控服务器  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJLQ2SwNicUzu79HPBJ3As7BBbQyEzVnfVs8JmcmHO3wdVC0qk25lDOiag/640?wx_fmt=png&from=appmsg "")  
  
image-20241122193354757  
  
利用psexec获取主机权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJzjQ8aBSjGTbjFlCpyhayaicstDBUD45DspwO6cCdNyBdbBahXjU42icw/640?wx_fmt=png&from=appmsg "")  
  
image-20241122200052181  
  
上线成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJZGlu8tX05wJ1D5ibqM0xxTHpgj30LpwBYibpkMbq04dAbRIGXibmHAGKA/640?wx_fmt=png&from=appmsg "")  
  
image-20241122200311652  
#### 痕迹清除  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJCeDQqX04GtQUJ9ZOldSXrZ3UC3Mzr1ArP5mJYlmF8bNTG1B2sdGAuA/640?wx_fmt=png&from=appmsg "")  
  
image-20241122203616132  
  
清除日志即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGww61vbdNvl4rGRuvshtpJ3tqe3kaMcWYDGmIrSc5dwcnEwRYwCicteWNfbnbVp8ITtefzvuicwEDw/640?wx_fmt=png&from=appmsg "")  
  
image-20241122203723809  
#### 往期推荐  
  
[【渗透测试】DC-8提权靶机综合渗透教程](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247493402&idx=1&sn=f82fd09a24fc8a0ca2ea5a8b657378aa&chksm=ceb17c17f9c6f5015ca07a2c4791b4a899f249e6d971f83ceff8331f83f0b924088665662120&scene=21#wechat_redirect)  
  
  
[【渗透测试】DC-3提权靶机综合渗透教程](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247492685&idx=1&sn=7414dd06518e8303e077e072b064bca9&chksm=ceb17f40f9c6f65610fd4427fa37e1f21434a9301f900a47b1ca2dd83762b7703a9eb86700ef&scene=21#wechat_redirect)  
  
  
[CISP-PTE 综合靶场1 图文解析，msf综合利用MS14-058提权漏洞【附靶场环境】](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247488126&idx=1&sn=40c4c171c0ab69f74ae6831ff479930b&chksm=ceb28973f9c50065b39dfa255f4ebbb3ada9183a25c70d8acb90751ccef301a7e53caf0f39c8&scene=21#wechat_redirect)  
  
  
[24年6月版本AWVS激活，AWVS漏洞扫描工具安装以及基本使用教程](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247493143&idx=1&sn=451a5ee39bbf8109362bbbc5c540f4cc&chksm=ceb17d1af9c6f40cfe0ff9d94ed1c3cd085af8368cd9a35b811638322a31ccb91ff9c397caff&scene=21#wechat_redirect)  
  
  
[利用MySQL特性，WAF绕过技巧](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247492213&idx=1&sn=930589375081c5dc497f7c4c4be69b00&chksm=ceb17978f9c6f06eb0e3f6b0d2e073f2b83919f10eca804fb304ea88f3ee52050c9b94a5c539&scene=21#wechat_redirect)  
  
  
