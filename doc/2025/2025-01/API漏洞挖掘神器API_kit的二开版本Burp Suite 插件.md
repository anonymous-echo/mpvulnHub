#  API漏洞挖掘神器API_kit的二开版本|Burp Suite 插件   
漏洞挖掘  渗透安全HackTwo   2025-01-15 16:01  
  
0x01 工具介绍   
APIKit二开版本是基于Burp Suite的API接口扫描插件，改进自APIKit1.0。新增扫描开关以防止无意扫描，优化页面性能，增强界面交互体验。该插件可主动/被动扫描API泄露文档并生成请求包用于安全测试，支持自定义扫描与自动发送请求功能。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5rELkSstFT3dibawBnOmB8vSDeOXiaHdRLAic8PSkNJyvqa6zkRxwv6r8VuhiaibHia3LysnCWplR5QvJg/640?wx_fmt=png&from=appmsg "")  
  
**下载地址在末尾****（昨日文章回复日期未更新，已在01月15日更新重新获取即可）**  
  
0x02 功能简介功能该版本APIKit是对API-Security项目的APIKit1.0进行的二开，增加了扫描开关，避免直接打开burp乱扫被抓起来。修复了输出页面卡死的问题。Do Target API Scan页面将cookie的输入框变大了一些，更美观的输入。APIKit是基于BurpSuite提供的JavaAPI开发的插件。APIKit可以主动/被动扫描发现应用泄露的API文档，并将API文档解析成BurpSuite中的数据包用于API安全测试。界面如下  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5rELkSstFT3dibawBnOmB8v4gMrbMSlkfS2Yia4olmKlr2uM8lqV0lbkiczQ1ibxRjb1t6ia4bwFx1vzQ/640?wx_fmt=png&from=appmsg "")  
0x03更新说明1.增加了一下表格的排序，方便更快筛选到不同响应2.修改名字为APIKit_pro，方便和原版共存0x04 使用介绍Scanner Enabled开启扫描就打开Scanner Enabled按钮Send with Cookie开启Cookie，可以把包的Cookie存下来，生成请求的时候保留Cookie。Auto Request Sending扫描所有API泄露中的所有接口。Do Auto API scanDo Auto API scan可以指定任意一个请求进行API指纹探测。在任何一个Burpsuite可以右键打开更多选项的页面中，都可以点击右键，选择Do Auto API scan来发起一次主动扫描，进行API指纹探测。Do Target API ScanDo Target API scan可以指定任意API技术、任意BasePath、任意API文档Path、和任意Header进行API请求的生成和探测。在任何一个Burpsuite可以右键打开更多选项的页面中，都可以点击右键，选择Do Target API scan来打开选项框。  
0x05 内部星球VIP介绍-V1.3（福利）        如果你想学习更多渗透挖洞技术/技巧欢迎加入我们内部星球可获得内部工具/字典/内部Fuzz字典和享受内部资源，每周一至五周更新1day/0day漏洞刷分上分(2025POC更新至3500+)，包含网上一些付费工具BurpSuite漏洞检测插件，Fofa高级会员、商业会员、CTFshow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复" 星球 "有优惠券名额有限先到先得！后续资源会更丰富在加入还是低价！（价格随资源人数进行上涨早加入早享受）👉点击了解加入-->>内部VIP知识星球福利介绍V1.3版本-1day/0day漏洞及内部资源每日更新  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250116获取下载地址**  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
> **彩蛋🌟昨日内部星球新增0day/1day漏洞及资源:(已连续更新600天+星球涵盖全网90%资源)**  
  
  
```
#内部星球资源更新
如何发现导致账户接管的参数篡改漏洞
针对前端加密爆破的方法及实战案例
百度技术培训中心存在越权取消订单漏洞
记录第一次尝试小程序支付漏洞挖掘
某小程序高危漏洞
广州华镒智能科技有限公司Jeewms存在SQL注入漏洞
0day移动应用getPicServlet存在任意文件的读取漏洞
内训宝企业培训平台 scorm 任意文件上传导致RCE漏洞
1dayPHPCMS演示站index存在SQL注入漏洞
CS_CounterStrike1.6.1最新版
CS/Webshell等免杀工具分享
全网最全的SRC资产表更新2025
POC漏洞库3000+的0day/1day漏洞更新
SRC漏洞挖掘培训视频更新
```  
  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.3版本-‍星球介绍(新增推送0day)**  
  
**2. 最新Nessus2024.10.7版本主机漏洞扫描下载**  
  
**3. 最新BurpSuite2024.7.3专业版中英文版下载**  
  
[4. 最新xray1.9.11高级版下载Windows/Linux](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483882&idx=1&sn=e1bf597eb73ee7881ae132cc99ac0c8e&chksm=cf16a75af8612e4c73eda9f52218ccfc6de72725eb37aff59e181435de095b71e653b446c521&scene=21#wechat_redirect)  
  
  
[5. 最新HCL AppScan Standard 10.2.128273破解版下载](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483850&idx=1&sn=8fad4ed1e05443dce28f6ee6d89ab920&chksm=cf16a77af8612e6c688c55f7a899fe123b0f71735eb15988321d0bd4d14363690c96537bc1fb&scene=21#wechat_redirect)  
  
  
  
###### 渗透安全HackTwo  
  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜欢的朋友可以点赞转发支持一下  
  
  
