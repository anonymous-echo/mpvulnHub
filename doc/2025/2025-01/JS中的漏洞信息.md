#  JS中的漏洞信息   
 船山信安   2025-01-23 16:00  
  
# 声明  
  
本文章所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法. 此文章不允许未经授权转发至除先知社区以外的其它平台！！！  
# 前言  
  
当我们拿到网站，但是又不知道密码，目录扫描也扫不出有效的信息时，我们可以从前端JS源码入手，找找是否有可以利用的点，或者未授权的接口从而一步一步扩大危害，拿到系统源码或者用户信息等。  
# SQL注入  
  
登录框开局必出货，hhh  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3niao7EUdVm0E6Xmy4Kh0qe9mkYuSouARuWsybVcznrbe8dCs0juJxDWg/640?wx_fmt=png&from=appmsg "")  
  
查看前端源码，发现Identity_Get接口，且存在userid和researchid参数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3n5AqdLPHB1Q6MzwfVDr142JaBuQic38SkOwn7S4NAeolcaMNmTVfUx5Q/640?wx_fmt=png&from=appmsg "")  
  
访问该接口抓包，使用burp进行测试，通过单引号重放发生报错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3nnoicBblLAeLTIlicsTB4aSsLcXMd0qewQBsniac8GWp09vReriaUG5CxJQ/640?wx_fmt=png&from=appmsg "")  
  
SQLMAP直接一键梭哈  
```
```  
  
Oracle数据库  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3nZ8NY0LtPnvS04gTykaOOT6vr6mNVSibZp9ibdjy9mINWiby51UibPKVJBw/640?wx_fmt=png&from=appmsg "")  
  
查询当前数据库用户  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3nOYmO7Z1l2yENmqicenszXvPHKExsdrzsdu0NmDdTticcWRPiaTAY9Yxhg/640?wx_fmt=png&from=appmsg "")  
# 地图key泄露  
  
这个KEY泄露虽然很常见，但是能用的不多，这个能够利用的我还是第一次遇见  
高德地图key  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3nhv72E429ad2WV8yibYSZQ46oowVCMp8RNibjjCEjgDtPhuyfibrN81Vew/640?wx_fmt=png&from=appmsg "")  
  
此key有效，hhh  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3nv2ibP2NM8HuBac6lnzfuIduSc4Otc3Klc0ZVD2doBOyTSK4lfDXw6Og/640?wx_fmt=png&from=appmsg "")  
# 文件下载一  
  
访问网站打开插件查看接口信息，发现/xxx/xxx/zipDownload，以看这种就有戏啊  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3nB7rBWohW8cXAJovSfgCYGfPaBlwP3pQo7rGfpmRdicNPPzQkdb4ibAicg/640?wx_fmt=png&from=appmsg "")  
  
访问连接，通过提示信息输入path和type参数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3nhIb0NBSzic1nuInbh5OGXQoEKKpARqAibSFh5iacyhgWFj4VibvLO7l5gg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3nShzqnj2sK89BYZf03rajJq1JnR4P1eZNF1Ha3w3ztnoqPjdf7qmzMQ/640?wx_fmt=png&from=appmsg "")  
  
直接目录遍历下载  
```
https://ip/xxx/xxx/zipDownload?type=1&path=/../../../../../../..//etc/passwd
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3nbYibRXvyyXNnhvzx1WoiazGrbharQZqDBcsiaDYgjgOWew6WdOqLQtKuA/640?wx_fmt=png&from=appmsg "")  
  
发现shadow密码文件也可以进行下载，猜测网站用户为root权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3nHV6vKc1fBzFd4DLOdCZJDA9m4166WlA4iax2PBkNJxJ4nb72bpQeSaw/640?wx_fmt=png&from=appmsg "")  
  
后面就是FUZZ下源码，或者SSH私钥登录，直接拿下shell，美滋滋  
# 文件下载二  
  
访问网站，打开熊猫插件发现一个export的接口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3n4iafV2hEgmHDps4HwYoUvVeUNVAk94YU6D8rITBgtTttb7hccFAurxQ/640?wx_fmt=png&from=appmsg "")  
  
直接使用目录穿越，可把整个网站打包下来，包括数据库备份信息，源码甚至是中间件  
```
http://ip/xxx/Opt/export?path=../../
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3nUmeAdkk9hHdUld24z331udOFwtjiauvyHtPVHFB6cEVbapbl2O8qSmg/640?wx_fmt=png&from=appmsg "")  
# 信息泄露  
  
这个其实危害感觉不大，只泄露了用户名，手机号等一些信息，但是这个网站SRC的，所以还有20元子赏金，hhh  
查看前端const.js文件，发现两个管理员用户信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3nAXFF0GHcEZpY8rhyFPeUejJLogLkCpGUnU9JaQJ40FJ3W3JicJDcxzw/640?wx_fmt=png&from=appmsg "")  
  
直接在找回密码处输入用户名密码，获取到手机号信息  
如下图1：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3nQibRkl25ooq1oWlYHvk9WF0vVKyDIdK0jYvRyXFyP63q0Xo1zQDN4MQ/640?wx_fmt=png&from=appmsg "")  
  
如下图2：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOPS7zfM3Q4lPYmwLlDaq3nuzhpJh0ZavPExDTCZ6yibhXZ7oIBoAibmSRGlAAsZ2KqdHQbGPDaXkXA/640?wx_fmt=png&from=appmsg "")  
  
只有两个账号，泄露的东西也不多，所以赏金不高，hhh  
  
作者：【bcloud】  
  
