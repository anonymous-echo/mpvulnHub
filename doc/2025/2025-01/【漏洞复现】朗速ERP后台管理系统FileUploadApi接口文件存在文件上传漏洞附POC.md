#  【漏洞复现】朗速ERP后台管理系统FileUploadApi接口文件存在文件上传漏洞||附POC   
FL_Clover  网络安全007   2025-01-03 00:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=png&from=appmsg "")  
  
漏洞介绍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocOR11vNUnAVxK5mEnib7ZCOaKtwzk3S5jDX3ZUeLMTKibUm95GBoSQk3pEg/640?wx_fmt=png&from=appmsg "")  
  
  
      
在当今复杂多变的网络安全环境中，朗速ERP后台管理系统中的FileUploadApi接口文件存在文件上传漏洞，攻击者可利用该漏洞上传恶意文件，进而控制服务器或窃取企业敏感信息。为保障系统安全，请尽快对该接口进行修复，并加强文件上传功能的权限验证和文件类型检查，以防患于未然。同时，建议对现有系统进行全面的安全检查，确保企业信息安全不受威胁。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDq1yNv813Qhtc598qAh11wesgxPn5RsWZXbE7daMb9ptClZEJMMVxXly6fu6vcRmbfkNCzA767Ctg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=png&from=appmsg "")  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocOR11vNUnAVxK5mEnib7ZCOaKtwzk3S5jDX3ZUeLMTKibUm95GBoSQk3pEg/640?wx_fmt=png&from=appmsg "")  
  
  
1.资源探测  
```
fofa:body="/Resource/Scripts/Yw/Yw_Bootstrap.js"
```  
  
2.漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDq1yNv813Qhtc598qAh11wePHMa4vYUahqiabdykQyYsW7Uvy7qLRXHsnmkAvWVQGoQZWYEb9puUXg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=png&from=appmsg "")  
  
漏洞POC  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocOR11vNUnAVxK5mEnib7ZCOaKtwzk3S5jDX3ZUeLMTKibUm95GBoSQk3pEg/640?wx_fmt=png&from=appmsg "")  
  
```
已收录到圈子网盘！需要的自取！
链接：https://wiki.freebuf.com/front/societyFront?society_id=291
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=png&from=appmsg "")  
  
最近1个月的漏洞复现文档  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocOR11vNUnAVxK5mEnib7ZCOaKtwzk3S5jDX3ZUeLMTKibUm95GBoSQk3pEg/640?wx_fmt=png&from=appmsg "")  
  
```
最近1个月的漏洞复现文档，有你需要的可以直接去圈子网盘下载：
 WordPress插件ElementorPageBuilder存在文件读取漏洞(CVE-2024-9935).docx 
 锁群管理系统存在任意后台管理泄露漏洞.docx 
 九思OA系统upload_l文件存在任意文件上传漏洞.docx 
 用友GRP-U8系统taskmanager_login存在SQL注入漏洞.docx 
 博斯外贸管理软件V6.0中的logined文件接口存在SQL注入漏洞.docx 
 博斯外贸管理软件V6.0中的loginednew文件接口存在SQL注入漏洞.docx 
 灵当CRM系统接口uploadfile文件上传漏洞.docx 
 灵当CRM系统接口getMyAmbassador存在SQL注入漏洞.docx 
 时空WMS-仓储精细化管理系统SaveCrash文件上传漏洞.docx 
 时空WMS-仓储精细化管理系统 ImageAdd 接口存在文件上传漏洞.docx 
 Zabbix存在SQL注入漏洞(CVE-2024-42327).docx 
 WordPress插件Tutor_LMS存在SQL注入漏洞(CVE-2024-10400).docx 
 WordPress插件FileUpload任意文件读取漏洞(CVE-2024-9047).docx 
 WordPress插件rtw_pdf_file任意文件读取漏洞.docx 
 中科网威anysec安全网关arping存在后台远程命令执行漏洞.docx 
 Yapi存在远程命令执行漏洞.docx 
 金和JC6协同管理平台oaplusrangedownloadfile存在文件下载漏洞.docx 
 北京友数CPAS审计管理系统V4 getCurserIfAllowLogin 接口存在SQL注入.docx 
 北京友数CPAS审计管理系统存在任意文件读取漏洞.docx 
 云连POS-ERP管理系统downloadFile存在任意文件读取漏洞.docx 
 云连POS-ERP管理系统ZksrService存在SQL注入漏洞.docx 
 协众OA系统接口checkLoginQrCode存在SQL注入漏洞.docx 
 Cloudlog系统接口request_form存在SQL注入漏洞.docx 
 国威HB1910数字程控电话交换机generate文件未授权命令执行漏洞.docx 
 JeecgBoot系统接口passwordChange任意用户密码重置漏洞.docx 
 泛微e-cology9系统接口FileDownloadLocation接口存在SQL注入漏洞.docx 
 泛微云桥e-Bridge系统checkMobile存在SQL注入漏洞.docx 
 泛微-云桥e-Bridge addTasteJsonp 接口存在SQL注入漏洞.docx 
 TOTOLINK远程代码执行漏洞(CVE-2024-51228).docx 
 蓝凌EKP系统接口sysFormMainDataInsystemWebservice存在任意文件读取漏洞.docx 
 神州数码DCN系统接口online_list存在任意文件读取漏洞.docx 
 杜特网上订单管理系统getUserImage存在SQL注入漏洞.docx 
 秒优科技-供应链管理系统doAction存在SQL注入漏洞.docx 
 昂捷CRM系统cwsupload任意文件读取漏洞.txt 
 昂捷CRM系统cwsuploadpicture任意文件读取漏洞.docx 
 圣乔ERP系统 downloadFile.action 存在任意文件读取漏洞.docx 
 用友U8-Cloud系统接口ReleaseRepMngAction存在SQL注入漏洞.docx 
 飞鱼星路由器存在敏感信息泄露漏洞.docx 
 上海汉塔上网行为管理系统存在远程命令执行漏洞.docx 
 Apache-Tomcat条件竞争致远程代码执行漏洞.docx 
 方正畅享全媒体新闻采编系统screen.do存在SQL注入漏洞.docx 
 方正畅享全媒体新闻采编系统reportCenter.do存在SQL注入漏洞.docx 
 蓝凌EKP系统接口thirdImSyncForKKWebService存在任意文件读取漏洞.docx 
 海康威视运行管理中心applyST远程代码执行漏洞.docx 
 大华DSS数字监控系统 attachment_downloadByUrlAtt.action接口存在任意文件读取漏洞.docx 
 顺景ERP系统FullGuidFileName任意文件读取漏洞.docx 
 用友NC系统接口yerfile_down存在SQL注入漏洞.docx 
 用友U8-CRM系统getDeptName存在SQL注入漏洞.docx 
 卓软计量业务管理平台image任意文件读取漏洞.docx 
 SecFox运维安全管理与审计系统FastJson反序列化漏洞.zip
 勤云远程稿件处理系统存在SQL注入漏洞.docx
 赛诸葛数字化智能中台系统login存在SQL注入漏洞.docx
 用友GRP-U8系统taskmanager_login存在SQL注入漏洞.docx
 安科瑞环保用电监管云平台etEnterpriseInfoY存在SQL注入漏洞.docx
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=png&from=appmsg "")  
  
帮会介绍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocOR11vNUnAVxK5mEnib7ZCOaKtwzk3S5jDX3ZUeLMTKibUm95GBoSQk3pEg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORY46W37hdIib0UibY4EBBNU8JF9KLZDzB64MiasA4iaWwuMdqtZn3HXpdsA/640?wx_fmt=png&from=appmsg "")  
  
  
【帮会服务】  
  
1.最新漏洞库（目前已1000+poc，定期更新，包含部分未公开漏洞）  
  
2.应急响应资料库（热门病毒应急响应手册，应急工具）  
  
3.安全书籍库（市面上热门安全书籍电子版）  
  
4.字典库（攻防实战字典合集，字典生成工具）  
  
5.安全制度库（100+篇安全管理制度汇编）  
  
6.攻防演练红蓝队实战经验库  
  
7.工具库（攻防实战工具，日常渗透工具，免杀工具，代码审计工具等）  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=png&from=appmsg "")  
  
加入方式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocOR11vNUnAVxK5mEnib7ZCOaKtwzk3S5jDX3ZUeLMTKibUm95GBoSQk3pEg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  帮会刚建立，现在加入可享早鸟价：  
  
原价  
19.9月卡  
  
现在  
29.9元享永久会员！  
  
限时两周！！！  
限时两周！！！  
  
随着资源的积累后续会直接涨价至  
99.9！  
  
PC链接：https://wiki.freebuf.com/front/societyFront?society_id=291  
  
微信扫码加入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDrP5Ku16BK5Bl1AmveJZicdUJnc3fD7iaubFnH9sJiaNCVDico4GmGUlibWGM7PabbhLlqzFPXZqrXpJLg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
<table><tbody><tr><td data-colwidth="576" width="576" valign="top"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;color: rgb(34, 34, 34);background-color: rgb(255, 255, 255);"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;color: red;"><span leaf="">免责声明：</span></span></strong></p><p style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;background-color: rgb(255, 255, 255);"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;"><span leaf=""> </span></span><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 14px;"><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;">本文章仅做网络安全技术研究使用！另利用网络安全007公众号所提供的所有信息进行违法犯罪或造成任何后果及损失，均由</span><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;">使用者自身承担负责</span></span></strong><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;">，与网络安全007公众号</span><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;">无任何关系</span></span></strong><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;">，也不为其负任何责任，</span><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;">请各位自重！</span></span></strong><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;">公众号发表的一切文章如有侵权烦请私信联系告知，我们会立即删除并对您表达最诚挚的歉意！感谢您的理解！</span><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;">让我们一起为我国网络安全事业尽一份自己的绵薄之力！</span></span></strong></span></p></td></tr></tbody></table>  
**●****推荐阅读●**  
  
**日常实战渗透小技巧，掌握就无需担心漏洞产出为零！**  
  
**红队如何在攻防演练中一夜暴富？**  
  
**全方位揭秘：50多种横向渗透提权终极技巧，一篇文章彻底掌握！**  
  
**未授权访问漏洞系列**  
  
**应急响应系列**  
# 浅谈Nacos漏洞之超管权限后续利用  
  
**记某APP服务端渗透测试实战GetShell**  
  
**实战|某网站未授权访问=》数据库权限=》服务器权限**  
  
**Nessus漏扫神器之攻防两用**  
  
**超级弱口令工具+超级字典，攻防必备！**  
  
写作不易，分享快乐  
  
期待你的 **分享**  
●**点赞●在看●关注●收藏**  
  
