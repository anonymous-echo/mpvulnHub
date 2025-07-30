#  仅靠JS审计就能捡到的漏洞 前端代码中的隐藏利用点|挖洞技巧  
bcloud  渗透安全HackTwo   2025-06-08 16:01  
  
**0x01 前言**  
   
  
       前端JS源码往往隐藏着未授权接口、敏感信息泄露等漏洞。本文结合实际案例，系统讲解如何通过审计JS文件挖掘高价值漏洞，从SQL注入到地图Key泄露，再到文件下载，探索手工渗透的魅力与技巧。  
  
参考文章：  
https://xz.aliyun.com/news/16886  
  
现在只对常读和星标的公众号才展示大图推送，建议大家把**渗透安全HackTwo“设为星标”，否则可能就看不到了啦！**  
  
**末尾可领取挖洞资料文件 #渗透安全HackTwo**  
  
**0x02 漏洞详情**  
  
当拿到网站，但是又不知道密码，目录扫描也扫不出有效的信息时，我们可以从前端JS源码入手，找找是否有可以利用的点，或者未授权的接口从而一步一步扩大危害，拿到系统源码或者用户信息等。  
# SQL注入  
  
登录框开局必出货  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5cU4xu8nmQaZOjXovKYhmsObhRJUQIBkb1axtufic0niaJN8KIRKIFsI5TOsgMuvv5Z5f22jzzKK1A/640?wx_fmt=png "")  
  
  
查看前端源码，发现Identity_Get接口，且存在userid和researchid参数![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5cU4xu8nmQaZOjXovKYhms2qlwCIV2PhT1mNmkeYahRXqeuiaWeLhibEe34Uk26oYAGicwFzcIDb1FA/640?wx_fmt=png "")  
  
访问该接口抓包，使用burp进行测试，通过单引号重放发生报错![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5cU4xu8nmQaZOjXovKYhmsC8fJ6NKctYKB7AHmA542QwW5hsYYz0raleGic8iaeTEz9HgRE8jhwfoA/640?wx_fmt=png "")  
  
  
SQLMAP直接一键梭哈命令  
  
```
python sqlmap.py -u "http://ip/Api/xxx/xxx/xxx/Identity_Get?USERID=1&RESEARCHID=1" --batch --risk 3
```  
  
  
Oracle数据库  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5cU4xu8nmQaZOjXovKYhms4cAO4MHas5x0s83ezNrwXNohWyM6UxCbyXw5ib4gAgDFgTlmG6rZPDw/640?wx_fmt=png "")  
  
查询当前数据库用户  
```
python sqlmap.py -u "http://ip/Api/xxx/xxx/xxx/Identity_Get?USERID=1&RESEARCHID=1" --batch --risk 3 --current-user
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5cU4xu8nmQaZOjXovKYhmsyObFFvricQUB6SpqIuAIY7yFhOgdyxk0waP0eicGiaWhgr9zpIeNiamNbw/640?wx_fmt=png "")  
# 地图key泄露  
  
这个KEY泄露虽然很常见，能够直接被API接口调用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5cU4xu8nmQaZOjXovKYhmsH9UO2UMVib50KdYVqMqqkHsrCfTU1BSmF7Kwf2XiaicKYRTdsTKRkaEug/640?wx_fmt=png "")  
  
  
此key有效  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5cU4xu8nmQaZOjXovKYhmsbNsJ3K2Go5RDHocsPchxO1kQPhl6iam8lP5w7UOSMdFwTzAE1KibHf9Q/640?wx_fmt=png "")  
# 文件下载一  
  
访问网站打开插件查看接口信息，发现/xxx/xxx/zipDownload，以看这种就有戏啊  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5cU4xu8nmQaZOjXovKYhmsecv3whFVIMeYIhOsRNCZTbibfeOdw0LhWryaMvNez4k1JEibNPKicTCaA/640?wx_fmt=png "")  
  
访问连接，通过提示信息输入path和type参数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5cU4xu8nmQaZOjXovKYhms4V3bouyEonGujTd10Dtt9wiaDzMLuGTRRictbV19Rib7iazUEaxAdHqKAg/640?wx_fmt=png "")  
  
直接目录遍历下载  
```
https://ip/xxx/xxx/zipDownload?type=1&path=/../../../../../../..//etc/passwd
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5cU4xu8nmQaZOjXovKYhmsqSKN9zeVfVEoo9XU4CE9bhOiceD1ImkNAIhNrmVPWQ72pJlt7YzW5nA/640?wx_fmt=png "")  
  
发现shadow密码文件也可以进行下载，猜测网站用户为root权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5cU4xu8nmQaZOjXovKYhmsHq6xATseLGjd4HpEvGQsYDv529d0XYcD4ribkibM69ibMDb5UibiadYAgoA/640?wx_fmt=png "")  
  
后面就是FUZZ下源码，或者SSH私钥登录，直接拿下shell，美滋滋  
# 文件下载二  
  
访问网站，打开熊猫插件发现一个export的接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5cU4xu8nmQaZOjXovKYhms6ZVsp3kduNCT9Hv9gVyNR5LvDmVic1YSRicCqjVzLfmqQw10IMDEUy1A/640?wx_fmt=png "")  
  
直接使用目录穿越，可把整个网站打包下来，包括数据库备份信息，源码甚至是中间件  
```
http://ip/xxx/Opt/export?path=../../
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5cU4xu8nmQaZOjXovKYhms5cv14dZ5mvEDhDNfmVEL4AcAxDAWD50VaGNOHNdn6L9brCHsicGMf6g/640?wx_fmt=png "")  
# 信息泄露  
  
这个其实危害感觉不大，只泄露了用户名，手机号等一些信息，  
但是这个网站SRC的，所以有赏金  
  
  
查看前端const.js文件，发现两个管理员用户信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5cU4xu8nmQaZOjXovKYhmstj8vjGVzibxKz6tkOhsZicvrFVAX0Up6ibmyhiadfTXL9Oia8UHhmVTkRag/640?wx_fmt=png "")  
  
直接在找回密码处输入用户名密码，获取到手机号信息  
  
如下图1：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5cU4xu8nmQaZOjXovKYhmsNGo6QAwtic91Z6ueQ5LUygqicx1yCNQ44QzCTvuRX6wpQ9ODwa2X3rkQ/640?wx_fmt=png "")  
  
如下图2：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5cU4xu8nmQaZOjXovKYhmsnEbiaMqOHCzMXQLZ4r2VgibIia8VvuvnoOR1ibg3S10SVvMJibFjQ9rpsTg/640?wx_fmt=png "")  
只有两个账号，泄露的东西也不多不借助抓包工具如何挖到漏洞渗透工具是这场网络安全探险不可或缺的“飞船”与“武器”，然而，无需借助工具，直接对网站进行渗透还是比较有挑战性的，最近一个星期基本都是这样，拿手机渗透，或者打开电脑一个浏览器打遍天下。手工测试打开网站，发现图片直接右键新建连接直接把png文件图片取消进行访问，目录浏览直接拿下像上述这种存在目录浏览，一般情况下网站还有，这里直接通过搜索相关接口，直接发现另一个接口image_data，直接访问发现同样进行目录浏览，就是这么容易这里另一个网站，同样是如上述一样试了一下目录浏览，但是没有成功，那么这里直接就搜索相关接口如/api，/upload啥的，基本都可能存在漏洞，这里直接搜索/api，发现还是比较多接口的这里挨个进行查看，发现一个_Get接口直接访问发现需要传入两个参数，像这种情况直接提示的你可以直接传参就可以了，如果没有传参的话你可以去找找js文件里面有没有相应的代码，再不济就借助工具爆破一下接口也行这里传入接口直接添加单引号发现保存了那再添加一个单引号，发现直接进行闭合，哈哈哈，注入不就来了这里直接用sqlmap测试，也不管工不工具了，测试出漏洞才是真的，哎嘿。直接验证成功，数据为Oracle再跑下用户名也是没有问题的，这个完全就是没有防护嘛这里还有另外的接口同样存在Sql注入，就不一一测试了这个如果不借助工具的情况运气也得有，不然还真发现不了，我直接在网站后面任意拼接几个常用的参数，发现upload成功了，而且直接回显hhh更神奇的是后面还有一个.svn文件泄露而且通过测试发现这个网站系统还是一个通用型漏洞，捡到了，hhh这个还是目录浏览并且也是通用型，不过需要登录进去才能发现那个网站，这里先登录进去后发现有一个可能点可以下载xls文件，而且鼠标悬浮上去发现是跳转至另一个网站进行下载。直接复制xls连接，另外打开一个窗口进行访问，发现成功访问，又是目录浏览了且xls连接文件也是直接下载这个也是一个通用型漏洞，只要使用这个系统都有，直接打开网站源码查看即可发现存在key网上直接找payload，访问成功回显位置，说明key是正确的restapi.amap.com/v3/geocode/regeo?key=55208xxxxxxxxx1271&s=rsv3&location=116.434446,39.90816&callback=jsonp_258885_&platform=JS  
**0x03 总结**  
  
徒手渗透测试通过审计前端JS源码、接口测试和参数拼接挖掘高价值漏洞，包括SQL注入、目录遍历、文件下载、地图Key泄露以及信息泄露等。直接审计JS访问API接口发现未授权漏洞，利用路径穿越下载敏感文件，从JS文件中提取敏感信息，结合业务逻辑和通用漏洞特性，逐步扩大攻击面挖到高危漏洞。  
喜欢的师傅可以点赞转发支持一下谢谢！  
  
  
**0x04 内部星球VIP介绍V1.4（更多未公开挖洞技术欢迎加入星球）**  
  
  
**如果你想学习更多另类渗透SRC挖洞技术/攻防/免杀/应急溯源/赏金赚取/工作内推/欢迎加入我们内部星球可获得内部工具字典和享受内部资源/内部群。**  
  
1.每周更新1day/0day漏洞刷分上分，目前已更新至4000+  
  
2.包含网上一些付费工具/各种插件BurpSuite漏洞检测插件/  
fuzz字典  
等等  
  
3.Fofa会员Ctfshow各种账号会员共享等等  
  
4.最新SRC挖掘/红队/代审视频资源等等  
  
5. .....  
  
6.详情直接点击下方链接进入了解，后台回复"   
星球  
 "获取优惠先到先得！后续资源会更丰富在加入还是低价！（即将涨价）以上仅介绍部分内容还没完！**点击下方地址全面了解👇🏻**  
  
  
**👉****点击了解加入-->>2025内部VIP星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
回复“**app**  
" 获取  app渗透和app抓包教程  
  
回复“**渗透字典**  
" 获取 一些字典已重新划分处理**（需要内部专属fuzz字典可加入星球获取，内部字典多年积累整理好用！持续整理中！）**  
  
回复“**书籍**  
" 获取 网络安全相关经典书籍电子版pdf  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.4版本0day推送**  
  
**2.最新Nessus2025.01.06版本主机漏洞工具**  
  
**3.最新BurpSuite2024.11.2专业稳定版**  
  
**4.最新xray1.9.11高级版下载Windows/Linux**  
  
**5.最新HCL AppScan_Standard_10.8.0.28408特别版下载**  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜欢的师傅可以点赞转发支持一下  
  
  
  
  
  
  
  
  
  
  
