#  BurpAPI越权漏洞检测工具|漏洞探测   
shuanx  渗透安全HackTwo   2025-05-20 16:00  
  
0x01 工具介绍 BurpAPIFinder 是一款用于攻防演练的Burp Suite插件，旨在帮助安全研究人员发现网站中未授权访问、敏感信息泄露和越权漏洞。它可以提取网站的URL，解析JS文件中的链接，识别敏感信息，如账户、密码、私钥等。支持自定义敏感关键词和路径，集成多种敏感信息指纹库。此工具可自动探测并识别敏感信息，帮助提高漏洞检测效率。注意：现在只对常读和星标的公众号才展示大图推送，建议大家把渗透安全HackTwo"设为星标⭐️"否则可能就看不到了啦！#渗透安全HackTwo  
**下载地址在末尾**  
  
0x02 功能简介  
## 🚀攻防演练过程中，我们通常会用浏览器访问一些资产，但很多未授权/敏感信息/越权隐匿在已访问接口过html、JS文件等，通过该BurpAPIFinder插件我们可以：1、发现通过某接口可以进行未授权/越权获取到所有的账号密码、私钥、凭证2、发现通过某接口可以枚举用户信息、密码修改、用户创建接口3、发现登陆后台网址4、发现在html、JS中泄漏账号密码或者云主机的Access Key和SecretKey5、自动提取js、html中路径进行访问，也支持自定义父路径访问 ...  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7OuEB2v6Ca1ymc8GQlbGMh5WWK7dIr5hN2Wrj4YB5soa0bwsaMWpTSbOibSdW99ELVOamtmSlBG3g/640?wx_fmt=png&from=appmsg "")  
> 如果有更好的建议或者期待使用的，点个免费的Star  
> 提取网站的URL链接和解析JS文件中的URL链接(不单单正则、支持多种模式提取)  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7OuEB2v6Ca1ymc8GQlbGMhZDfonBYialVPdXtO1v1hCKQC1z567qAQGAPSnsgIqZ1yWKmGiaZLR0fg/640?wx_fmt=png&from=appmsg "")  
  
前段界面可自行定义敏感关键词、敏感url匹配  
  
界面可配置的开启主动接口探测、敏感信息获取  
  
支持用户自定义父路径重新开发扫描任务  
  
集成主流攻防场景敏感信息泄漏的指纹库  
  
集成HaE的敏感信息识别指纹  
  
集成APIKit的敏感信息识别指纹  
  
集成sweetPotato的敏感信息识别指纹  
  
0x03更新说明 优化从JS中提取url路径，方式一：从单双引号中提取出包含/的路径 优化从JS中提取url路径，方式二：优化提取js中concat的场景，补全父路径 优化从JS中提取url路径，方式三：针对404场景，通过匹配已经访问过的路径，来寻找对应的父路径 匹配内容标高亮显示，有价值标蓝色，敏感信息标红色 前端展示js提取出来的url结果 新增右键"提取url"功能，支持对某一个具体路径提取出url出来 新建右键"自定义凭证"，支持对URL下返回状态码3xx且重要无敏感指纹场景的补充上自定义凭证进行识别 新增右键"自定义路径扫描", 支持该URL对下面目录进行扫描且支持自定义凭证扫描 新增右键"用户自定义父路径"， 支持该URL下返回状态码3xx或4xx且无敏感指纹场景的补充上自定义父路径后进行识别 新增右键"复制"，快速对PATH复制 优化结果输出，默认输出匹配到末尾40个字符出来0x04 使用介绍  
## 📦jar包二选一下载加载即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7OuEB2v6Ca1ymc8GQlbGMhkUpDyB2cIVCI0NYapN0pOEOWUAKtKib210diccrkwCoZVEf2ibiaiatqMKA/640?wx_fmt=png&from=appmsg "")  
```
BurpAPIFinder-high-v2.0.2.jar为高性能版本：对大js会提取前500w出来作识别
BurpAPIFinder-lower-v2.0.2.jar为普通性能版本：对大js会提取前50w出来作识别
```  
  
0x05 内部VIP星球介绍-V1.4（福利）        如果你想学习更多渗透测试技术/应急溯源/免杀/挖洞赚取漏洞赏金/红队打点欢迎加入我们内部星球可获得内部工具字典和享受内部资源和内部交流群，每1-2天更新1day/0day漏洞刷分上分(2025POC更新至3800+)，包含网上一些付费工具及BurpSuite自动化漏洞探测插件，AI代审工具等等。shadon\Quake\Fofa高级会员，CTFshow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复" 星球 "有优惠券名额有限先到先得！全网资源最新最丰富！（🤙截止目前已有1800多位师傅选择加入❗️早加入早享受）  
**👉****点击了解加入-->>内部VIP知识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250521获取下载**  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
# 往期推荐  
  
  
****  
**1.内部VIP知识星球福利介绍V1.4（AI自动化工具）**  
  
**2.CS4.8-CobaltStrike4.8汉化+插件版**  
  
**3.最新BurpSuite2025.2.1专业版（新增AI模块）**  
  
**4. 最新xray1.9.11高级版下载Windows/Linux**  
  
**5. 最新HCL AppScan Standard**  
  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
一款快速识别网站指纹3W+的Google插件|「指纹猎手」=  
  
