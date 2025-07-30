#  最新Nacos 综合漏洞利用检测工具12月更新|漏洞探测   
漏洞挖掘  渗透安全HackTwo   2024-12-26 16:00  
  
0x01 工具介绍   
NacosExploit是一款用于检测Nacos服务中已知漏洞的工具，支持自定义内存马功能，使渗透测试更加灵活。通过简单的FOFA查询语法，可以快速识别目标Nacos实例的认证绕过等问题。  
  
**下载地址在末尾**  
  
0x02 功能简介支持漏洞| PoC | Exploit | Vulnerability Name                   | Vulnerability Identifier || :-: | :-----: | :----------------------------------- | :----------------------- || YES |   YES   | Nacos Default Auth Disabled          | /                        || YES |   YES   | Nacos Default Password (nacos/nacos) | AVD-2021-896025          || YES |   YES   | Nacos Default server.identity        | /                        || YES |   YES   | Nacos Default token.secret.key       | AVD-2023-1655789         || YES |   YES   | Nacos Default User-Agent             | AVD-2021-29441           || YES |   YES   | Nacos Derby SQL Injection            | AVD-2021-897468          || NO  |   YES   | Nacos Client Yaml Deserialization    | /                        || NO  |   YES   | Nacos Jraft Hessian Deserialization  | AVD-2023-1700159         || NO  |   YES   | Nacos Jraft Services File Operations | AVD-2024-1743586         |功能展示漏洞检测：认证绕过：Derby SQL 注入：Jraft 反序例化漏洞：0x03更新说明优化代码修复部分已知问题添加 Nacos Hessian 反序列化内存马（AVD-2023-1700159）添加 Nacos 任意文件读取（AVD-2024-1743586）0x04 使用介绍java8、jdk1.8一键启动java8 -jar .\NacosExploit-v2.0.0.jar  
0x05 内部星球VIP介绍-V1.3（福利）        如果你想学习更多渗透挖洞技术/技巧欢迎加入我们内部星球可获得内部工具字典和享受内部资源，每周一至五周更新1day/0day漏洞(2024POC更新至2500+)，包含网上一些付费工具BurpSuite漏洞检测插件，Fofa高级会员，CTFshow等各种账号会员共享。详情直接点击下方链接进入了解，需要加入的直接点击下方链接了解即可，觉得价格高的师傅可后台回复" 星球 "有优惠券名额有限先到先得！内部包含了网上需付费的0day/1day漏洞库，后续资源会更丰富在加入还是低价！👉点击了解加入-->>内部VIP知识星球福利介绍V1.3版本-星球介绍-1day/0day漏洞库每日更新  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20241227获取下载地址**  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
> **彩蛋🌟内部星球新增1day/0day漏洞及资源:(每日更新中...)**  
  
  
```
博斯外贸管理软件V6.0 logined.jsp存在SQL注入漏洞
快云服务器小助手 getdetail 存在任意文件文件读取漏洞
赛诸葛数字化智能中台系统 login 存在SQL注入漏洞
中犇科技有限公司数字化智能中台系统存在sql注入漏洞
网神SecFox运维安全管理与审计系统存在 FastJson反序列化RCE漏洞
西联软件移动门店管理系统 StreamToFile 存在文件上传致RCE漏洞
用友-友数聚科技CPAS审计管理系统V4 getCurserIfAllowLogin 存sql注入漏洞
最新Webshell CS等免杀工具分享
Webshell免杀的应用思路
NucleiPoc15W+
新增Xray最新企业版
SRC资产表
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
  
  
