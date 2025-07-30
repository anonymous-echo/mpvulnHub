#  用友CRM存在日志信息泄露-附上POC   
原创 漏洞挖掘  渗透安全HackTwo   2024-01-07 10:28  
  
###   
#   
0x01 产品简介  
          
CRM首先是一种管理理念，核心是将企业的客户作为企业最重要的资源，通过完善的客户服务和深入的客户分析来满足客户的需求，在向客户不断提供最大价值的同时，实现企业的价值，实现“双赢”  
。  
  
**TIPS: 批量检测POC在末尾领取**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6ShSyTK8mqTtCGHh97UupdCU89qU06n0tcajhOmKlc9nQ19cEhQSCWSLdPKkbtlt7QdTjt7dbxPQ/640?wx_fmt=png&from=appmsg "")  
#   
  
**今日星球新增1day/0day未公开漏洞-公告******  
  
> ****  
> 1.id_cv_ew在线文档预览系统文件上传和读取漏洞  
  
> 2.  
SemCms外贸网站商城系统SEMCMS-SQL注入漏洞  
  
>   
>   
> **未公开漏洞1day、0day的POC及批量利用脚本后台回复"星球"加入内部获取！！**  
>   
>         声明，请自行搭建环境进行漏洞测试，该公众号分享的工具、项目、漏洞仅供安全研究与学习之用请勿用于非法行为，如用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
>   
  
  
  
0x02 漏洞描述        日志信息泄露是一种漏洞，该漏洞可导致应用将敏感数据输出到设备日志中。如果这类敏感信息被泄露给恶意攻击者，就可能是非常有价值的信息（例如用户的凭据或个人身份信息），也可能会造成进一步的攻击。‍0x03 ZoomEye语法ZoomEye语法: title:"用友U8CRM"0x04 漏洞复现POC1 批量检测POC在末尾领取http://xx.xxx.xxx.xx:8072/datacache/solr.logPOC2http://xxx.xxx.xxx.xxx:8072/datacache/crmdebug.log0x05 修复建议鉴权0x06 内部福利介绍        需要加入内部知识星球可点击下方链接，资源包含但不限于网上未公开的1day/0day，2024最新企业SRC/CNVD/Edu实战挖掘技巧报告，红队内网横向渗透，代码审计，JS逆向，SRC培训等课程。内部干货多及渗透思路很多，对新人友好，实战报告赏金几百到几千不等，加入圈子拥有FOFA、shadan、360Quake、ZoomEye、Hunter、CTFshow、Tide等等高级会员账号，SRC文档，武器库。圈子里面资料价值至少在10K以上，目前星球内部主题300+，资源2000+，其他和网盘资源1w+覆盖全网星球、纷传90%以上内容并持续更新中，越早加入价格越低。(详情点击下方地址了解-->>还是觉得价格贵的师傅后台回复" 星球 "有优惠券使用名额有限先到先得)点击了解-->>内部VIP知识星球福利介绍V1.2版本-元旦优惠  
  
****  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回**  
**复20240107获****取批量检测POC**  
  
  
**压缩包解压密码：HackTwo**  
  
****  
需要更多未公开或不公开通用漏洞1day/0day，POC师傅可以加入星球获取支持一下！****  
  
  
# 最后必看  
  
  
    本工具或文章仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，如果你学习了该文章内容需要测试请自行搭建靶机环境，勿用于非法行为。  
  
  
    为避免被恶意使用，本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。  
  
  
      
  
文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担。  
  
  
    在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行扫描。  
  
  
    如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
****  
  
  
  
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
  
  
