> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2MzkwNDU1Mw==&mid=2247485850&idx=1&sn=f495ab99b95b02c18a410789c7a25244

#  nacos漏洞利用工具  
信安路漫漫  信安路漫漫   2025-07-18 23:01  
  
github地址：  
https://github.com/charonlight/NacosExploitGUI/releases  
###   
###   
### 0x01 前言  
  
在攻防演练中，Nacos一直是红队攻击的重点目标之一，红队通常需要快速打点，尽快发现系统中的漏洞，并利用它们获取权限。在NacosExploitGUI_v7.0版本中，更新了UI及其各种友好的提示、新增空间测绘功能让打点资产更迅速、修复derby sql注入漏洞在在特殊场景下的编码问题、新增derby sql注入不出网RCE的检测及其利用、 修复配置文件提取接口上限的问题、Jraft Hessian 反序列化漏洞新增自定义group攻击链路、新增自定义注入内存马密码及其路径、新增注入蚁剑内存马、新增命令执行可反弹shell功能等等。  
  
###   
### 0x02 工具简介  
  
工具支持检测Nacos多种常见漏洞，并且支持多种利用方式，如添加用户、删除用户、重置密码、sql注入、内存马注入、命令执行、配置文件提取等等。工具提供直观友好的图像化界面，用户能够轻松进行操作和管理。支持空间测绘、批量扫描功能，用户可以同时对多个目标进行漏洞检测，极大地提高了扫描效率。还支持暂停扫描、终止扫描、自定义多线程扫描、自定义请求头、内置随机User-Agent头、http代理、socks代理、扫描结果导出为表格等等功能。  
###   
### 0x03 工具检查能力  
  
工具目前支持如下漏洞的检测，我们也会持续添加poc和各种漏洞利用方式。漏洞检测支持非常规路径的检查，比如Nacos的路径为   
http://xxx.xxx.xxx.xxx/home/nacos  
 , 只需在目标中填入Nacos的路径即可，指纹识别功能就会去扫描三个路径(" "、"/nacos" 、"/home/nacos")，识别了Nacos才会开启漏洞扫描  

```
Nacos Console 默认口令漏洞
Nacos Derby SQL 注入漏洞(CNVD-2020-67618)
Nacos User-Agent 权限绕过漏洞(CVE-2021-29441)
Nacos serverIdentity 权限绕过漏洞
Nacos token.secret.key 默认配置漏洞(QVD-2023-6271)
Nacos-Client Yaml 反序列化漏洞
Nacos Jraft Hessian 反序列化漏洞(CNVD-2023-45001)
```

  
  
### 0x04 漏洞利用  
  
新增了空间测绘功能，支持Fofa、Quake、Hunter查询，可一键将查询结果发送至批量扫描  
  
![0](https://mmbiz.qpic.cn/sz_mmbiz_png/Rzo6rPw2nBxZpRveeibaJITliatoJ5gJicYp3icibqO4ZYnOgtUzPHPF52W7r2GHvkVRpHwypibgXmktYAGafeESVeFQ/640?wx_fmt=png&from=appmsg "")  
  
批量检测自动识别版本，多线程扫描速度极快  
  
![0](https://mmbiz.qpic.cn/sz_mmbiz_png/Rzo6rPw2nBxZpRveeibaJITliatoJ5gJicYVmG1Xta1ct9SWXWRoBhhwXvU2oWcI3tg0JTGR6cPibjEvRJnCIGeibeg/640?wx_fmt=png&from=appmsg "")  
  
SQL注入功能，内置各种Derby注入查询语句，一键查询即可  
  
![0](https://mmbiz.qpic.cn/sz_mmbiz_png/Rzo6rPw2nBxZpRveeibaJITliatoJ5gJicYwYtjGAlRIRpoGicXmLfWHZiaeKMHUkiaX1VfJw5WNPZsLeIvNicX2ItF4Q/640?wx_fmt=png&from=appmsg "")  
  
  
针对近期暴露出Derby SQL注入漏洞新的利用方式，该工具也已经集成，支持不出网命令执行、反弹shell及其注入冰蝎、蚁剑、哥斯拉内存马，具体使用如下  
  
![0](https://mmbiz.qpic.cn/sz_mmbiz_png/Rzo6rPw2nBxZpRveeibaJITliatoJ5gJicYxNcaXqNXpgqRWIcp7RGKTILrHbBvUxx2VxWsiclvJ1l0rGWSlPcicozw/640?wx_fmt=png&from=appmsg "")  
  
Hessian反序列化漏洞，我们都知道一共有三条可攻击的链路，7.0版本已将其他两条链路添加至工具，拓展了可攻击面，一条链路被打崩溃了可以更换其他两条链路继续尝试。新增了一键注入蚁剑的内存马、新增了自定义注入内存马的密码和路径，先打的点再也不用害怕被别人连接了，内存马可以多次注入不同路径，不会导致链路崩溃。  
  
![0](https://mmbiz.qpic.cn/sz_mmbiz_png/Rzo6rPw2nBxZpRveeibaJITliatoJ5gJicYKyL06Sx6UuicUib7iap3wP7eFXaiatJtHVkJclOWPCztB8rJ6RRFwQwrAQ/640?wx_fmt=png&from=appmsg "")  
  
  
当然，如果目标被别人先打了全部路径，不知道连接密码还能利用吗？当然能，只要链路未崩溃，可以使用命令执行（无回显）进行反弹shell，首先可以借助dnslog使用代码执行功能探测链路的可用性。  
  
![0](https://mmbiz.qpic.cn/sz_mmbiz_png/Rzo6rPw2nBxZpRveeibaJITliatoJ5gJicYhicFRXMoI6Zib5xhKFpnX7saShBSCVLRWIWHpQ7wKHSGWibBg7NscQYKw/640?wx_fmt=png&from=appmsg "")  
  
  
当发现链路可用时，直接使用该链路进行反弹shell，同样不会导致链路崩溃，可多次执行  
  
![0](https://mmbiz.qpic.cn/sz_mmbiz_png/Rzo6rPw2nBxZpRveeibaJITliatoJ5gJicY0ibibDa1Sicd4UrRble3YcpJAOskO6KbGsJaYBl4ibLcY4hBVibJwC1ToYA/640?wx_fmt=png&from=appmsg "")  
  
权限绕过漏洞利用功能，支持添加用户、删除用户、重置密码、以及支持获取账号的accessToken  
  
![0](https://mmbiz.qpic.cn/sz_mmbiz_png/Rzo6rPw2nBxZpRveeibaJITliatoJ5gJicY1guJx3khL3bcJqQib3S4Tt2GqlRibBgdRhObXaD6yzJzPN2rK1DkKE3A/640?wx_fmt=png&from=appmsg "")  
  
  
Yaml反序列化功能，支持一键去检测Nacos-Client低版本存在的Yaml反序列化漏洞，需要配置accessToken，打法可参考：  
[https://mp.weixin.qq.com/s/SfAFMiraMKafcISo5IDEAg](https://mp.weixin.qq.com/s?__biz=MzkyNDYwNTcyNA==&mid=2247483790&idx=1&sn=5c022bacc63ef8e8fadd37fae4544306&scene=21#wechat_redirect)  
  
 。  
  
![0](https://mmbiz.qpic.cn/sz_mmbiz_png/Rzo6rPw2nBxZpRveeibaJITliatoJ5gJicYH7LbJBNUxeJtWlkVZJF6iaDMQfOJz5TWMOebOujDQkjwCSQCZic7Z5TA/640?wx_fmt=png&from=appmsg "")  
  
  
配置提取功能，可以一键获取所有命名空间的配置信息，若目标Nacos不存在未授权漏洞，则需要手动配置accessToken，支持导出结果为表格，方便持久化存储以及搜索，7.0版本修复导出上限的问题  
  
  
![0](https://mmbiz.qpic.cn/sz_mmbiz_png/Rzo6rPw2nBxZpRveeibaJITliatoJ5gJicYiagFoDUbJy0pWcUpGrPiarA8ibDYpkvzuKNk9r3rhPIZLjFSEngCF5DWg/640?wx_fmt=png&from=appmsg "")  
  
  
  
