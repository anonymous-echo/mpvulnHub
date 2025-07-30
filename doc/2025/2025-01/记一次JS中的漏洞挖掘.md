#  记一次JS中的漏洞挖掘   
bcloud  亿人安全   2025-01-02 08:17  
  
# 声明  
  
本文章所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法. 此文章不允许未经授权转发至除先知社区以外的其它平台！！！  
# 前言  
  
当我们拿到网站，但是又不知道密码，目录扫描也扫不出有效的信息时，我们可以从前端JS源码入手，找找是否有可以利用的点，或者未授权的接口从而一步一步扩大危害，拿到系统源码或者用户信息等。  
# SQL注入  
  
登录框开局必出货，hhh  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x9zFRBSODFwB9dsZ0Uyrz8kUic59WApyiaXbJqakAz1L8mUQHQNhPBpuJA/640?wx_fmt=png&from=appmsg "")  
  
查看前端源码，发现Identity_Get接口，且存在userid和researchid参数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x9IZgjd5xvsRGZ3s51pkBsfGPlHwVdcnU6jTNZxz81UyrvGJo5ub8oOQ/640?wx_fmt=png&from=appmsg "")  
  
访问该接口抓包，使用burp进行测试，通过单引号重放发生报错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x9X95zA39jBLX6ybfO4WNNqg9XPn51yFbAaaoibscuicyASuGicoZ2NYAjQ/640?wx_fmt=png&from=appmsg "")  
  
SQLMAP直接一键梭哈  
```
```  
  
Oracle数据库  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x9Vbu0EjhGvV0K5XtibYAproibzicEhuwdhViaNnm3cAHPPtPfeMJg0aNa0Q/640?wx_fmt=png&from=appmsg "")  
  
查询当前数据库用户  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x9xM8A5jAbOu9CmjqlMWcwMZQ8zHy0yRj1CfAbvblq9Obiba9rib8LicE4A/640?wx_fmt=png&from=appmsg "")  
# 地图key泄露  
  
这个KEY泄露虽然很常见，但是能用的不多，这个能够利用的我还是第一次遇见高德地图key  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x9N1Phh9quiad5X7MZa3A7Ktk05fpwZGwxicypxVTZ452F1T4Z1hMlXwicg/640?wx_fmt=png&from=appmsg "")  
  
此key有效，hhh  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x96osZiaaYNXdDhXEH7l03aMAic4MWicAgmrfmmlR1whH8SibsO3VbXYDFKA/640?wx_fmt=png&from=appmsg "")  
# 文件下载一  
  
访问网站打开插件查看接口信息，发现/xxx/xxx/zipDownload，以看这种就有戏啊  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x9F5lCPzL4XXXAVDAV4qgeHGiabCKlaAasQTufXMMt1JxYHzFQBrK4Z8A/640?wx_fmt=png&from=appmsg "")  
  
访问连接，通过提示信息输入path和type参数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x96XoDu0vUlYp7zPp0sOKpHibw5eAumEbyAVHoJayaWVnEdvFXPMf4iaGA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x9f8NoEehXdXX0ffCOcB5saAItOYxk47oOfRPDHOJy8JDW19X6HXnEOQ/640?wx_fmt=png&from=appmsg "")  
  
直接目录遍历下载  
```
https://ip/xxx/xxx/zipDownload?type=1&path=/../../../../../../..//etc/passwd
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x9tpn35mAJQZiaJDSgZhfSwkJOgYBcEKZatnQy2GpVMibyoXxkfHWZKKeQ/640?wx_fmt=png&from=appmsg "")  
  
发现shadow密码文件也可以进行下载，猜测网站用户为root权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x9XZYr3RxicHQAh4WwmXG0vLibCc02NfFDNtZamjRpTAGhzHQXPHl4VOng/640?wx_fmt=png&from=appmsg "")  
  
后面就是FUZZ下源码，或者SSH私钥登录，直接拿下shell，美滋滋  
# 文件下载二  
  
访问网站，打开熊猫插件发现一个export的接口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x9OKL1sZGiaVdKUibLnU5I4mru6WV4EITDn1TXHk4N45ibk3oeiaXczrriczw/640?wx_fmt=png&from=appmsg "")  
  
直接使用目录穿越，可把整个网站打包下来，包括数据库备份信息，源码甚至是中间件  
```
http://ip/xxx/Opt/export?path=../../
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x9fBVibsEy2fE7wjFMnfK2PLibRwpaS5uvWeianvfpzIlntwxUsabKGSs0w/640?wx_fmt=png&from=appmsg "")  
# 信息泄露  
  
这个其实危害感觉不大，只泄露了用户名，手机号等一些信息，但是这个网站SRC的，所以还有20元子赏金，hhh查看前端const.js文件，发现两个管理员用户信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x96IXAEEO8MdiaAN3nYWxMT2tnf9UmzhbWYU9Ct1BhuSggP1bQnYcZQhw/640?wx_fmt=png&from=appmsg "")  
  
直接在找回密码处输入用户名密码，获取到手机号信息如下图1：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x9LZopy46zJSLZrm3rbtsIx9d9p8yrSkRZFhPpqw7mkibP5dzbEynVGOA/640?wx_fmt=png&from=appmsg "")  
  
如下图2：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqKtFPNDxSuZNYRGkGQU0x9Yuu6y4DXbbevq1CLWvAsMEhfOm1ic8C0FwibrO0H8zuXXp1SqlIwuic9Q/640?wx_fmt=png&from=appmsg "")  
  
只有两个账号，泄露的东西也不多，所以赏金不高，hhh  
  
  
