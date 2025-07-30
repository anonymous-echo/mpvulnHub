#  综合后渗透工具e0e1-config|漏洞探测   
eeeeeeeeee-code  渗透安全HackTwo   2025-04-16 16:01  
  
0x01 工具介绍 e0e1-config 是一款后渗透工具，主要用于提取浏览器、数据库连接、远程桌面工具等的敏感信息。它支持提取 Firefox 和 Chromium 内核浏览器的浏览记录、下载记录、书签、cookie 和用户密码，同时可以获取 Windows 系统中 Notepad++ 和记事本的内容。工具还支持获取各种远程管理工具的配置信息，如向日葵、ToDesk、Navicat、DBeaver、Xshell、FileZilla、WinSCP 等。此外，它还具有敏感信息文件搜索功能。注意：现在只对常读和星标的公众号才展示大图推送，建议大家把渗透安全HackTwo"设为星标⭐️"否则可能就看不到了啦！  
**下载地址在末尾**  
  
0x02 功能简介  
## 该工具主要用于后渗透方面，包含：  
  
firefox和chromium内核浏览器，提取浏览记录、下载记录、书签、cookie、用户密码  
  
Windows记事本和Notepad++ 保存与未保存内容提取  
  
向日葵（支持最新版本） 获取id、密码、配置信息  
  
ToDesk 获取id、密码、配置信息  
  
Navicat 获取数据库连接信息  
  
DBeaver 获取数据库连接信息  
  
FinalShell 获取连接信息  
  
Xshell和Xftp 获取连接信息  
  
FileZilla 获取连接信息  
  
winscp 获取连接信息  
  
敏感信息文件搜索  
## 效果展示  
## 浏览器信息获取  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7PXVicXHicD18cY12UhS8dR6ibHjKGicr32Sxjpic0XN6annZ0GOWqxH2VxGsyfhIEX1Ed8CaibT0JoFxg/640?wx_fmt=png&from=appmsg "")  
 ![image](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7PXVicXHicD18cY12UhS8dR6EAZErYic0TzwW8W7BIgBg641howk5gGYXSBFER0A6RhQp8sJVvQxnOg/640?wx_fmt=png&from=appmsg "")  
  
  
敏感信息文件搜集功能  
  
![QQ_1744284336027](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7PXVicXHicD18cY12UhS8dR6Xs36woVCXNZzVQN4mrg6XyZPTff0xkWecxQqicvRHwUGo9PKiarZQn1A/640?wx_fmt=png&from=appmsg "")  
  
notepad功能  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7PXVicXHicD18cY12UhS8dR6y1DexdKiaWrv5pGR7GYr21gTjZojoJGetUY1v1oAWXUzZnvEpjeDqYg/640?wx_fmt=png&from=appmsg "")  
  
向日葵功能（支持最新版本）  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7PXVicXHicD18cY12UhS8dR6dxNgkNgjpGPm3MwyHuOu4SM1hUjhDXuIdBrnlvgYUsn39CqGIsiaXMw/640?wx_fmt=png&from=appmsg "")  
  
todesk功能  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7PXVicXHicD18cY12UhS8dR6fDURQcgdmDdWxk6r8jYhlLmicM7OdsIq4Ukns7kAAILooSOTF8KvYkQ/640?wx_fmt=png&from=appmsg "")  
  
navicat功能  
  
![QQ_1744283637007](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7PXVicXHicD18cY12UhS8dR6ZrZDsAupTJeZG0lQxicHYLnPhYdBtHP632IJxI5kxjdKr7tG1ictBLLA/640?wx_fmt=png&from=appmsg "")  
  
dbeaver功能  
  
![QQ_1744283684310](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7PXVicXHicD18cY12UhS8dR6AtmOHtgGuJ9MUib3C4OZm0mq5SOXmdx4IN38twnZ7Pvohl4PJHVzOMQ/640?wx_fmt=png&from=appmsg "")  
  
finalshell功能  
  
![QQ_1744283820508](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7PXVicXHicD18cY12UhS8dR6acficNKxlJjojwoBHXTGC44343onaYXn993iabNgxgvqPaBKzanKBiaXQ/640?wx_fmt=png&from=appmsg "")  
  
xshell功能  
  
![QQ_1744283871974](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7PXVicXHicD18cY12UhS8dR6mXmtZXTkF4iahd3gXPibJAxibBzwdtdGaiar6yLTvKLNQMuEQEerd3LsfA/640?wx_fmt=png&from=appmsg "")  
  
xftp功能  
  
![QQ_1744283915688](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7PXVicXHicD18cY12UhS8dR63W6ARcLQBkVeFhLicbQYcIia10MvI9zoKpYryhdT3B5kNtUSZFwrfoRw/640?wx_fmt=png&from=appmsg "")  
  
filezilla功能  
  
![QQ_1744283962054](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7PXVicXHicD18cY12UhS8dR6Xo8pad9AVvrqdc1Kib0m4LkSQuxvwKVanCSJjGpXLc8PdojhWQSG3Dw/640?wx_fmt=png&from=appmsg "")  
  
winscp功能  
  
![QQ_1744284044686](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7PXVicXHicD18cY12UhS8dR6lYvFkwAsD1paia7licDOdtXD8Upg0M0eygXlnjiazK8VsSgyib9Hopgujw/640?wx_fmt=png&from=appmsg "")  
## 0x03更新说明添加firefox和chromium内核浏览器，提取浏览记录、下载记录、书签、cookie、用户密码0x04 使用介绍  
## 工具使用示例go build -ldflags "-w -s" ./  
## 微步沙盒分析  
```
e0e1-config -winscp #获取winscp连接信息，通过默认配置文件和注册表
e0e1-config -winscp -winscp-path "C:\path\winscp.ini" #自定义配置文件路径
e0e1-config -all #执行所有功能
e0e1-config -all -output "result.txt" #执行所有功能，并将输出 输入到result.txt文件中
e0e1-config -bromium all -output "result.txt"
e0e1-config -all -browser-format csv -output "result.txt"
```  
## 微步沙盒分析  
## 因为添加了浏览器方面的东西，所以会有一些敏感的东西，会有一点检出，不过效果还好。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7PXVicXHicD18cY12UhS8dR6NDkpVplOq3cib8k4ASiaDnpv3dIibYFvTHBHNHwLXtXPibglDibnqXSJTOw/640?wx_fmt=png&from=appmsg "")  
##   
0x05 内部VIP星球介绍-V1.4（福利）        如果你想学习更多渗透测试技术/应急溯源/免杀/挖洞赚取漏洞赏金/红队打点欢迎加入我们内部星球可获得内部工具字典和享受内部资源和内部交流群，每1-2天更新1day/0day漏洞刷分上分(2025POC更新至3700+)，包含网上一些付费工具及BurpSuite自动化漏洞探测插件，AI代审工具等等。shadon\Quake\Fofa高级会员，CTFshow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复" 星球 "有优惠券名额有限先到先得！全网资源最新最丰富！（🤙截止目前已有1700多位师傅选择加入❗️早加入早享受）  
**👉****点击了解加入-->>内部VIP知识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250417获取下载**  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
# 往期推荐  
  
  
**1. 内部VIP星球福利介绍V1.4星球介绍(0day推送)**  
  
**2. 最新BurpSuite2025.2.1专业版（新增AI模块）**  
  
**3. 最新Nessus2025.02.10版下载**  
  
**4. 最新xray1.9.11高级版下载Windows/Linux**  
  
**5. 最新HCL AppScan Standard 10.2.128273破解版下载**  
  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜欢的朋友可以点赞转发支持一下  
  
