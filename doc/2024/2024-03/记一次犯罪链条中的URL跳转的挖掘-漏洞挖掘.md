#  记一次犯罪链条中的URL跳转的挖掘-漏洞挖掘   
漏洞挖掘  渗透安全HackTwo   2024-03-12 00:02  
  
0x01 前言   
         
2023年  
12  
月，接到朋友求助，他的母亲被诈骗5万元，诈骗人使用的是他哥哥的微信号，找到我寻求帮助。  
经过研判，对方盗取了被害人亲戚的微信号，以老套的诈骗方式“是我是我诈骗”进行作案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7tTg7hkmjcEFIyCFeqT6mEtN7Kjw46V5xt08dMPMFO5bRI2syticgM4hp7WSm0KkZvsC48Sibq96UQ/640?wx_fmt=png&from=appmsg "")  
  
**末尾可领取字典等资源文件**  
  
0x02 漏洞分析        利用钓鱼链接，让被害人帮忙微信投票，在投票时提示需要登入微信，需要微信的账号密码以及验证码。漏洞点这里已经是别的站点了在盗取微信号后，伪装成本人向亲朋好友借钱0x03 挖掘犯罪链条中的URL跳转        在拿到盗号的二维码后第一时间对URL进行分析，套路其实很老套，就是我上面说的那些，在挖掘过程中，犯罪链条中的一环跳转了某个大厂的URL。        犯罪链条经过了一层某大厂URL跳转，使得诈骗网站可以逃过QQ/微信等聊天工具的URL检测，成功混进了白名单，没有提示危险。若跳转的链接非白名单URL，则出现拦截，显示是否确认跳转，如下图：若链接是白名单，则直接跳转0x04 URL跳转绕过综上所述，如果非白名单就会出现拦截如http://127.0.0.1/?url=http://www.HackTwo.cn尝试白名单，已知该厂商的白名单有 baidu.com qq.com等白名单成功跳转，无任何提示直接跳转犯罪链条中的利用已知 http://127.0.0.1/?url=http://baidu.com是直接跳转的白名单绕过 http://127.0.0.1/?url=http://baidu.commxxx.cn 利用二级域名绕过检测规则绕过方法2 http://127.0.0.1/?url=http://baidu.com.xxxxx.cn案子已经过去几个月了，也已经结案了，但是该漏洞还是没有修复0x05 内部福利介绍-V1.3更新啦！        👇详情直接点击下方链接进入了解星球👇需要加入的直接点击下方链接了解即可，觉得价格贵的师傅后台回复" 星球 "有优惠券使用名额有限先到先得！点击了解-->>内部VIP知识星球福利介绍V1.3版本-星球介绍  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
回复“**app**  
" 获取  app渗透和app抓包教程  
  
回复“**渗透字典**" 获取 针对一些字典重新划分处理（需要更多完整字典可加入星球获取）  
  
回复“**书籍**" 获取 网络安全相关经典书籍电子版pdf  
  
********  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
  
  
# 往期推荐  
  
  
**1. 内部VIP知识星球福利介绍V1.2版本-元旦优惠**  
  
**2. 最新BurpSuite2023.12.1专业版中英文版下载**  
  
[3. 最新Nessus2023下载Windows/Linux](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247484713&idx=1&sn=0fdab59445d9e0849843077365607b18&chksm=cf16a399f8612a8f6feb8362b1d946ea15ce4ff8a4a4cf0ce2c21f433185c622136b3c5725f3&scene=21#wechat_redirect)  
  
  
[4. 最新xray1.9.11高级版下载Windows/Linux](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483882&idx=1&sn=e1bf597eb73ee7881ae132cc99ac0c8e&chksm=cf16a75af8612e4c73eda9f52218ccfc6de72725eb37aff59e181435de095b71e653b446c521&scene=21#wechat_redirect)  
  
  
[5. 最新HCL AppScan Standard 10.2.128273破解版下载](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483850&idx=1&sn=8fad4ed1e05443dce28f6ee6d89ab920&chksm=cf16a77af8612e6c688c55f7a899fe123b0f71735eb15988321d0bd4d14363690c96537bc1fb&scene=21#wechat_redirect)  
  
  
  
###### 渗透安全HackTwo  
  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜欢的朋友可以点赞转发支持一下  
  
  
