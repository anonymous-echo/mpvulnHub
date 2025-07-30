#  安卓app抓包总结   
北海  沃克学安全   2024-11-29 01:02  
  
## 申明：文章仅供技术交流，请自觉遵守网络安全相关法律法规，切勿利用文章内的相关技术从事非法活动，如因此产生的一切不良后果与文章作者无关。  
  
本文由北海师傅发表在先知社区  
  
文章地址：https://xz.aliyun.com/t/16315  
# 前言  
  
这里简单记录一下相关抓包工具证书的安装  
### burp证书安装  
  
安装证书到移动设备导出证书![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIRHnGSa2K1cGPsoOvIFn0lU7FIyXvdDA5k2grKZhd72PYX1JZQuoljQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIUTzFCNukicNTS5wvibsT93qBnichSia7CsFLGgoFelSl43micPuTmgOvicPQ/640?wx_fmt=png&from=appmsg "")  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIJShsl5MhmXib1fPZ6d8iba67Z2Z5MN15dRTpibmKYIiaA6ZMO0CO3jBDmA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIiatDOibWcFjg4kRxCzPODGqP5517nKKsTWmib4le25gd4FSY2OXK8lXFA/640?wx_fmt=png&from=appmsg "")  
把bp.pem改成727ceb75.0  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIp1MicTiaTM0wHAbkTE0uBRjMOxpr2e8Hiav48wPKgcckNsyNrgFpzsC4w/640?wx_fmt=png&from=appmsg "")  
  
adb上传至设备这里以雷电模拟器为例  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIw6icg7K1h3DareBFOn3HmQkS0AovFE62vlDgov6PSAvRneibg31q5v9Q/640?wx_fmt=png&from=appmsg "")  
  
使用mt管理器把证书从sdcard文件夹下转移到/system/etc/security/cacerts下![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tItZsopw46CAyHLRKXMUTK9hpFPVe0OnFlCkRiaLLcpdDajib1mOA7At9g/640?wx_fmt=png&from=appmsg "")  
  
  
添加读写权限![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tICkTqCpAQjShPHic5hxH4pSoJVibynjQRgM2Xk1PstBms6NIplOlDCqoQ/640?wx_fmt=png&from=appmsg "")  
  
  
重启后即可  
### charles证书安装  
  
charles-proxy-4.6.4-win64.msi链接: https://pan.baidu.com/s/1ZNm71DIZNbjXN5eXwv6TSA?pwd=m79v 提取码: m79vcharles激活码计算器：https://www.zzzmode.com/mytools/charles/  
  
安装证书到移动设备保存根证书  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIjznicQ4SDK9d2L9vAOzm4OTk26u4PC3CpE1CsXmLfNXHuSylcPFH1Tw/640?wx_fmt=png&from=appmsg "")  
  
可以保存为pem格式或者cer格式![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIN5n2DjdStv9bruhqgNfm7hoW9hSPBiaEvAZCMLq1hA2z60icbX4iaAd8A/640?wx_fmt=png&from=appmsg "")  
接着后续可以参考前面的burp证书安装步骤  
### filder证书安装  
  
导出证书![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIJRWR3ZGHZICIw7lOFS1Qu25qtqblFFT86RxsYw1jGdV7hqEkEE7V7g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIuleMh40BwzzDd4UyBtSaViab0GauhicaUd5CcFyN7FSEicNHA7fAPXxfw/640?wx_fmt=png&from=appmsg "")  
  
之后参考burp证书的操作即可，包括：使用openssl计算格式，转换hash，重命名，上传到模拟器，移动到系统证书目录  
### 补充说明  
  
1.实际上，像是bp,花瓶以及fd这些抓包工具，证书的安装除了导出证书再上传的方式外，还有访问代理服务器下载的方式，网上有很多教程，本文重点在总结抓包思路，就不一一赘述了  
  
2.安装证书的目的是拦截和分析HTTPS流量。而从Android7(API24)开始，系统不再信任用户级别的CA证书，只信任系统级别的证书。所以如果抓包安卓7以上系统的设备，安装证书的时候还要将证书移动到系统级别的证书目录  
  
例如前面burp证书导入雷电9(android9)模拟器时，我们把证书从sdcard文件夹下移动到/system/etc/security/cacerts目录中。而/system/etc/security/cacerts目录正是用来存放系统级别的CA(证书颁发机构)证书的  
  
3.对于装了高版本安卓系统的真机，可能无法通过命令行或者mt管理器将证书移动到/system/etc/security/cacerts目录（我这里试过，发现安卓10不行）。此时可以通过Magisk中的Move Certificates模块将用户证书转化为系统证书。Move_Certificates-v1.9.zip链接: https://pan.baidu.com/s/1nqZxuptJIftppEQdPOSl_Q?pwd=5qd5 提取码: 5qd5然后在magisk的模块栏中选择从本地安装成功后就会出现Move_Certificates模块  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIE8JicibKXS35PJkA80rfwoTyUtRDnkCib7aOnXV9g53Kjibic3qdOpE596A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIGyMpMlhBWm5bh2toUjibewrBUNj4AXeJ838QVO6X5ABJ3vKzt596dzQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIQXamJCckF9GiaXXhPiba8vWptYrn4ibeEFgZmFGOXUqAe7I9bupohBFdA/640?wx_fmt=png&from=appmsg "")  
  
进入设置，找到安全，然后进入凭据相关的一栏，选择从存储中安装  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIyUu2iaZcSH9A9hiaYRemFAib6XgO6GZXV3p05Jh946F818cGeKUaOWfpg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIJuicde5k7iaKSWBicPBPsRiaKu9KpojcZmNeNZdurPgN0WUkPiczt4PLpLg/640?wx_fmt=png&from=appmsg "")  
  
然后在用户中就可以看到该证书  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIDJftsZUdNgTdZ7roiawQSibvm1CaKicWCBq2qXnZTvBxPpj5Xhwqxd4NQ/640?wx_fmt=png&from=appmsg "")  
  
重启后它就移动到系统证书下了  
# 抓包  
### burpsuite直接抓包  
  
条件：  
- pc和移动端设备能相互ping通  
  
- bp证书导入移动端设备  
  
- 无检测  
  
下面以雷电模拟器为例：  
  
burp设置代理![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tI228ox2v5s1CtdmNzoOOkTMxv0Cz40qLx4tiatpZg3wgexwTicub93CZQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIu6iblML1YgNcj1SLVRibXJ6iaVEqxOADAC5ibLDhYc62ibIiaG6FjZHLMic5A/640?wx_fmt=png&from=appmsg "")  
  
雷电模拟器配置wifi代理![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tILKnn7lv7v1KLR4r6Q87Pu8BicTHKQ2y0d5jF5Th5XZ77ib7rhZ8TMrjA/640?wx_fmt=png&from=appmsg "")  
  
  
随便选一个app抓登录的包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tI8ZC0SYKPsYiaAEcBLA5HT8Y51nnpxic6c5ZwdXiaEnmJl4biaib4SNSATqw/640?wx_fmt=png&from=appmsg "")  
### burpsuite+postern抓包  
  
条件：  
- pc和移动端设备互通  
  
- bp证书导入移动端设备  
  
- 无vpn流量检测  
  
如果app做了系统代理检测（wifi），而没做vpn代理检测的话，我们可以在Android等设备上启动一个VPN服务，让APP 的所有流量都先经过VPN服务，再抓取APP的网络数据包  
  
而postern就是安卓的vpn全局代理工具https://pan.baidu.com/s/1ChA4svJIshOlAMcY0efZFA?pwd=zkea  
  
postern设置代理服务器（服务器地址和端口号与bp的监听地址一致）![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tITdxEib3z0epNSvNncuQvooOJwBjUM7lVaD7SHdaUj9KednVHCibMYOSA/640?wx_fmt=png&from=appmsg "")  
点击保存  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIIrMjNUlicEicgy97x6mHPXy2SjgyrRU4THO36fAfIv52wXgiaC6oy6e1A/640?wx_fmt=png&from=appmsg "")  
  
设置代理规则![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tId2RqnR1QibPaw24WnftzWiaVlrMEOdAslSmIsW5DKzibO9JwMfIfvBbAQ/640?wx_fmt=png&from=appmsg "")  
选择刚添加的burp代理组  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIlDdbGYdanu3fo8Th4ialtHTBuxjR49EFINGmnMU6fT9ics6Rib5ToxReQ/640?wx_fmt=png&from=appmsg "")  
  
点击保存![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIe8bKuSpia0x76oviaxLzqibiacS10ZCZDtyndUkEAewhJW5cM7cQgWGR3w/640?wx_fmt=png&from=appmsg "")  
  
  
点击打开vpn（若显示关闭vpn，则表明已经开启了vpn）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIgQc4RJxxJct3xNwUPPsE8Equ17weHvnjxXwUu7GKeibIQqVwMjpwUUA/640?wx_fmt=png&from=appmsg "")  
  
再次打开app,发现抓包成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIVDm5Cjj8EZibXqawRR2cjNGsSPVqyJn2wpFEw7d6CPrxXnMAe9s80Kw/640?wx_fmt=png&from=appmsg "")  
### burpsuite结合proxifer（限于模拟器）  
  
条件：  
- 模拟器  
  
- 模拟器导入burpsuite证书Proxifier是一款强大的网络工具，允许用户将不支持代理的应用程序通过代理服务器进行连接。我们可以使用proxifer代理模拟器进程的流量  
  
链接: https://pan.baidu.com/s/1caU29yXbAMKYn5HRQ52Qvw?pwd=81u1 提取码: 81u1  
  
proxifer设置代理服务器（服务器地址和端口号与BurpSuite的监听地址一致）![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIpjYHOGSxuAoeZxEauJ4ocMS3ZIIlL1JicHicbg64UJmEhPEiad5jKgpow/640?wx_fmt=png&from=appmsg "")  
选择HTTP/HTTPS即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIxYNHaU7qxZLdLaDmjRw7TjhSK2mjaNVUfXM0dFzfiaPX2zqhCSQD6EQ/640?wx_fmt=png&from=appmsg "")  
  
设置代理规则![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIkK1qsMLYX2mQBlZvy1uPYARia9jPchuTWMicMuYicYrHlBPT6PdacrBug/640?wx_fmt=png&from=appmsg "")  
  
  
目标程序设置为Ld9BoxHeadless.exe(LdBoxHeadless.exe负责模拟器的运行,雷电9的则是Ld9BoxHeadless.exe)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIzbF63p9kB5rjrArnXyMRbOARX3INqiad7Q6U4v3yIag4db5Ya6cdbDw/640?wx_fmt=png&from=appmsg "")  
将代理规则优先级提前  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIREjlnhMiac2N5BSm5icetoGIKujdsMbWncYEpvYwniaVicqhJvIu5dUtzQ/640?wx_fmt=png&from=appmsg "")  
  
burp配置代理设置，跟proxifer的符合![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIxibsDQicWuCef4lodJbgqdNpGj0sc8tLptxNCKqnN3KC3w49LZlQ8aIw/640?wx_fmt=png&from=appmsg "")  
  
  
即可抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIWeBaWToBLTvkgelnibCT2PWfpJGGIADYSCdwwylMODtMn8w9UMIMZYw/640?wx_fmt=png&from=appmsg "")  
### adb联合burpsuite  
  
条件：设备安装了burpsuite证书  
  
有时候，移动设备和测试主机不处于同一网段，且没有设置路由规则，或者所在的无线局域网设置了ap隔离，导致两设备无法互通。对于这种场景，可以采用adb端口转发的方式联合burp抓包  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIcVEE54cEicrQFnW4K2xy6HibNLhnuF34QEOHYdGx7X7bEibLJPnoxoxSQ/640?wx_fmt=png&from=appmsg "")  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIWjXKwibuFfGpk8QvfOC1BA0icKRCPJt1lay9meqQy8K1ZbBWILk7fvqQ/640?wx_fmt=png&from=appmsg "")  
然后配置burp代理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIT3BibAWq590eErtAlYITvRXsanticaT2ibjJ1jj0VfGJkwZQFoichFjJfg/640?wx_fmt=png&from=appmsg "")  
  
成功抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIZqVnNmgC3hTqsOia7c2HPGpRLFmjyFk3hvibVGwqRuwSCN2Hpd4jCdww/640?wx_fmt=png&from=appmsg "")  
  
adb reverse --remove tcp:6789settings put global http_proxy :0  
  
补充：安卓高版本进行上述操作后连接wifi会出现一个x，这是由于原生安卓系统验证wifi是否有效，是去访问谷歌的服务器  
  
运行以下命令：adb shell settings put global captive_portal_https_url https://connect.rom.miui.com/generate_204，（改为访问小米服务器）开启飞行模式，再关闭飞行模式即可解决！  
### postern+charles+burpsuite  
###### postern设置  
  
添加代理服务器![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIbeHvCvOAbia16xPM90Btn3cl4xp4FDpxPr9ZRg0pbicMOzYaudYjKMVw/640?wx_fmt=png&from=appmsg "")  
  
  
配置好信息后下拉点击保存  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIE5hT96SndcftQBVxxictXe5cqhEr13YTdiaYdeY74mYrldyjXsRJr0Rw/640?wx_fmt=png&from=appmsg "")  
  
添加代理规则  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIqPGgqj8n5YyBYMC1FQOcJjWNZUNAYRMQDd9LsB4O7t7D77R1Julq5w/640?wx_fmt=png&from=appmsg "")  
  
配置好信息后点击保存  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIwWibE6ZEfAicMKms7kNHqC6vXO6n5kAtGZdZEsVRmLIvpYMYbic0D46dA/640?wx_fmt=png&from=appmsg "")  
然后打开vpn即可  
###### charles设置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIPJiaiaceR80rcDRUlyq1lOpkJcXEGkqkKDOtR7icL8GT3FAXKvg0ibyaZQ/640?wx_fmt=png&from=appmsg "")  
设置SSL代理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIwUXLUCIEsiaCakCYtEqxyw9umcR6SaNkpbZ4XW5OtJdmsDRT5eCLxnA/640?wx_fmt=png&from=appmsg "")  
代理设置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIXll17odIia5QhlfdUX2S734iaicVVEYFY55x9bWD1JJHI1RFEtSIppk6Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIIq1weoXMgDfhSBDaWgcUhrNoHgk3glB9915sGvdj8l6EA7XLmqiafeg/640?wx_fmt=png&from=appmsg "")  
然后启动SSL代理，就可以抓包了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIsichY30y0kUBELPia4zrHRxxv6RGCSbYzFLBsTm2M7yMo3KqregCmbNQ/640?wx_fmt=png&from=appmsg "")  
###### 联动burpsuite  
  
charles在之前的基础上设置外部代理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIF8ibt9jiaq2dGklzDicN3btmBlmqEefKuxpCk70Uc9LL2z183npVqic3cA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIyk0V8hMx7oRqZCkdibSYaCGqolop3IgIegX4emnEXDo1S8msiavM0UOA/640?wx_fmt=png&from=appmsg "")  
### 小黄鸟  
  
HttpCanary是直接在安卓设备上操作的抓包工具HttpCanary_9.9.9.9.apk链接: https://pan.baidu.com/s/16lH8rqZHJW43LRDR5eNCwA?pwd=k692 提取码: k692  
  
导入证书![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIWjTBeEHQR28PVA2E3IOfvWFm8HI7OG70Drm0THohJ5oPFibITSJuiaNQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIP4LicNpnlLsw5s5ykciccryCe4oL3odljSsTcfV3uExbOUe0Lq7TqRPA/640?wx_fmt=png&from=appmsg "")  
  
尝试抓包，如下图![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIWMvxPeVjTicPJCn7Hn0VKMxeE0rZR64o0CYV5auLTIv92j5ialrM5waA/640?wx_fmt=png&from=appmsg "")  
  
  
开启bp，监听8080即可联动  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIgDq9AMNJDXhHEzsoapA5ofMbQCm3mxBLCYbxuggPnabGmn5Q0gzPicA/640?wx_fmt=png&from=appmsg "")  
### fiddler+wifi代理  
  
条件：  
- 设备安装fiddler证书  
  
- 移动设备和PC互通  
  
fiddler抓包在进行逻辑漏洞挖掘时具有一定的优势，因为相比于bp，它更容易观察流量的整体逻辑。并且fiddler的并发机制比bp优秀  
  
这里以雷电模拟器为例fiddler配置 导航栏点击Tools,然后选择Options监听端口默认是8888  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tILP6dnAy0Po1SCJTdTz6cMOAowzdrIgJXUZCO34PqWgHOr3CbKtbDibg/640?wx_fmt=png&from=appmsg "")  
  
设备设置wifi代理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIKribce3ydkia2e1R8Cricmx6wibwo7LSk9kQ8K8ADcvqabkPQM5vVts3BQ/640?wx_fmt=png&from=appmsg "")  
  
抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIakNKZeSApOyGwGyUVsfnaQnCr1SptP2S6bEabQ1tYJCbA2q6mkTZQw/640?wx_fmt=png&from=appmsg "")  
### fiddler结合postern  
  
条件：  
- 设备安装fiddler证书  
  
- 移动设备和PC互通fiddler也可与postern之类的vpn软件联合，来绕过wifi代理检测，操作与burpsuite相似,这里就不赘述了  
  
### r0capture（hook抓包）  
  
条件： 安卓7，8，9，10，11  
  
https://github.com/r0ysue/r0capture  
  
r0capture仅限安卓平台7、8、9、10、11 可用，能通杀TCP/IP四层模型中的应用层中的全部协议，包括Http, WebSocket, Ftp, Xmpp, Imap, Smtp, Protobuf等协议，并且能够绕过默认库的证书校验r0capture通过Hook Android系统中的SSL/TLS库的关键函数，如SSL_read和SSL_write，来拦截和捕获应用层的数据包。这些操作发生在SSL层，因此在数据被应用层的代码处理之前，r0capture已经获取了明文数据，从而绕过了应用层的证书校验机制不过也因此无法解密自研的SSL框架  
```
```  
  
Spawn模式，比如向抓包大众点评，先找到大众点评app的包名  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIcohfwMSvNM97l02vnyVmSujBFadtHnX8sl0hWWOT8tbjyvNEQvm8Ng/640?wx_fmt=png&from=appmsg "")  
  
开启frida服务端，然后在r0capture项目文件夹下运行r0capture脚本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIj19MqwgCUOGaWAia5JO9XX5zIDibxa9WcNsBseU9C3sMIwiajre2WpF4Q/640?wx_fmt=png&from=appmsg "")  
  
可以在项目文件夹下看到打印的流量日志  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIicFwgnQGnqoFrtDNwDChjiatokHgnicViaBwlAbDRHysQp2nAxfDPWSqXg/640?wx_fmt=png&from=appmsg "")  
  
Attach模式，再以抓包大众点评为例，先找到大众点评的进程名  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tI2J8CP5QXhyicWd0n41l3RaT7JSR1icSKzGXb8w7AIvTbtxDW0zamV21g/640?wx_fmt=png&from=appmsg "")  
  
开启frida-server  
  
然后在r0capture项目文件夹下运行r0capture脚本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIC2x3MWCk5Guu645y8aFMEGHuoyTpPs5qFzx0BFjYtXhlHlKEpcFmPQ/640?wx_fmt=png&from=appmsg "")  
  
Ctrl+C停止抓包后，然后就可以在项目文件夹下看到抓到的pcap流量包了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tItQMJBicDdAjSUQdicNYYww9PqqVv6DwrQxPHtUzh3PTVzvbx0PpNyMqQ/640?wx_fmt=png&from=appmsg "")  
  
wireshark打开  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIIm85gaxqlv2SPpn7ib02B7PywMcIUfHQXeTfuCy015Wg6kAqEADL72A/640?wx_fmt=png&from=appmsg "")  
追踪第一条流看看，发现抓包成功了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIgeW9t2Gb3SCOwjMBwEiaK9z3HwwzeKygsX9oWen0DvWIgFEJqEOLQPg/640?wx_fmt=png&from=appmsg "")  
### tcpdump + wireshark  
  
tcpdump 是一款功能强大的网络抓包工具，它可以抓取涵盖整个TCP/IP协议族的数据包，但是tcpdump本身无法解密 SSL加密过的数据，所以对于https没有办法  
  
在安卓设备上运行  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIHQnJFzwC9yllnfXZk64WkLHc60VRXKFfxBg050PrZA8Da5xExmKtcw/640?wx_fmt=png&from=appmsg "")  
  
这样子做更多的是分析tcp层的通信流程，包括密钥传输等  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tI6icuuKBA8gGicnHFprfGFhaxID2XiaJvxZJgibbEdhJRjz0PQ4ZINosoaQ/640?wx_fmt=png&from=appmsg "")  
### Lsposed+TrustMeAlready +bp/fd/charles（突破单向认证）  
  
条件：  
- root设备（模拟器也行）   
  
- 安装了Magisk  
  
- 设备安装了抓包工具的证书  
  
Lsposed:https://github.com/LSPosed/LSPosedTrustMeALready:https://github.com/ViRb3/TrustMeAlready  
  
LSPosed是基于Xposed开发的一个框架，支持android8.0以上的高版本，可以在不修改 APK 文件的情况下，通过模块改变系统和应用程序的行为  
###### 安装Lsposed  
  
进入magisk设置![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIoXqnmtFUiaqCdiaicQe1KukWu2ezHlO7FvILicKTIA71hCgIu2hibHNTiaGA/640?wx_fmt=png&from=appmsg "")  
打开zygisk  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIAn2en9EsKkNHwaV7LN7YWia2DjGM4BGPxtzxKLCvreOslJXkQAr8vqA/640?wx_fmt=png&from=appmsg "")  
  
将下载好的Lsposed包上传到设备,例如：  
```
```  
  
选择从本地安装（我这里已经安装了，所以显示有了）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIdQibBC1vrsvAVUuTeIZyKibT7Niae8dGC691w8iajp4MYrx9aNB0W6QkIw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIJqsI8YMtiaibbaSNj2Sj9WwYAVqxHicVpHhicAHRS5eMEcia3KORvJqCQJg/640?wx_fmt=png&from=appmsg "")  
  
开启Lsposed  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIyqYUgXCeWtJwLOb1HNYicL2HDN32VOEibOwptCnyDo00ibV72jVtVvb6A/640?wx_fmt=png&from=appmsg "")  
  
在Lsposed的zip包中找到manager.apk，安装到设备即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIH33mOShEHOsdFicz2AicQzSJwQc1MJic5wK53TuuwGVYuA1o0gwAuHKaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tI8r7pDYiavfHQVYspz45LegNfehicXg1myJ52vom2pOxGicdynOLWaRGzg/640?wx_fmt=png&from=appmsg "")  
打开发现已经激活  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIDPFYqdeicwo0GkA5yQOoiaSEILomXHGs6Ra6EWetzkhuLX6ezYibQdQdw/640?wx_fmt=png&from=appmsg "")  
###### 安装TrustMeAlready  
  
使用adb将TrustMeAlready.apk安装到设备上  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIC82rsrIoUibg2xqsv4kyS0RVcba4rA4klJOQHB4hAt8wm6NMd1D70gA/640?wx_fmt=png&from=appmsg "")  
  
打开Lsposed![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCMca57cwVlUlt2AgtkI15tIsAWLYYZPUjOFuONibbCLUfWWaIIYQQXMrj1VqmJ4kuMg4HooyAh3Zvw/640?wx_fmt=png&from=appmsg "")  
选择给某个app启用即可  
  
接着就可以用抓包工具抓包了  
# 总结  
  
抓包工具有burpsuite,fiddler,charles等burpsuite适合渗透测试，charles适合开发者分析调试app，fiddler个人认为适合app的逻辑功能的测试（逻辑漏洞挖掘）  
  
如果没有任何检测，我们通过wifi代理就可以结合抓包工具抓包了。如果存在系统代理检测，可以尝试使用vpn软件（postern等）绕过，或者使用proxifer抓取模拟器进程在模拟器外部实现流量代理  
  
对于移动设备和PC无法互通的场景，可以尝试在usb连接后使用adb进行流量转发  
  
如果存在SSLpining（单向证书校验），可以考虑Lsposed框架+TrustMeAlready进行绕过（低版本：xposed+JustTrustMe），如果存在双向证书校验，就得考虑逆向，找到apk中保存的证书了。不过也可以尝试使用肉丝大佬的r0capture脚本把加密前解密后的流量dump出来（如果app没有存在自研SSL框架的话）  
  
  
  
如果喜欢小编的文章，记得多多转发，点赞+关注支持一下哦~，您的点赞和支持是我最大的动力~  
  
   
  
