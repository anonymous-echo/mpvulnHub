#  【漏洞复现】快云服务器助手GetDetail接口文件任意文件读取漏洞   
FL_Clover  网络安全007   2025-01-06 01:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=png&from=appmsg "")  
  
漏洞介绍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocOR11vNUnAVxK5mEnib7ZCOaKtwzk3S5jDX3ZUeLMTKibUm95GBoSQk3pEg/640?wx_fmt=png&from=appmsg "")  
  
  
    在当今复杂多变的网络安全环境中，  
快云服务器助手存在的 GetDetail 任意文件读取漏洞，是一个具有较高安全风险的隐患。该漏洞使得不法分子有可能利用其机制上的缺陷，通过构造特定的请求等方式，突破正常的权限限制，实现对服务器上任意文件进行读取操作。这意味着服务器中存储的敏感信息，比如配置文件、用户数据等，都有被泄露的风险。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDpUMX12ocmKfoqhj0icCvUwPGUoI58ftOhSdRFm3FibKcs23VXlfDHgYicKLXzyQ41kMyUtQPxa0mia3g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=png&from=appmsg "")  
  
漏洞修复措施  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocOR11vNUnAVxK5mEnib7ZCOaKtwzk3S5jDX3ZUeLMTKibUm95GBoSQk3pEg/640?wx_fmt=png&from=appmsg "")  
  
- 输入验证  
：加强对服务器访问权限的精细管理，严格限制不必要的访问请求，对文件读取操作进行严格的身份验证和授权把控。  
  
- 安全服务  
：定期开展安全自查与漏洞扫描工作，以便能尽早发现类似潜在的安全漏洞。  
  
- 权限配置  
：为文件和目录设置合理的权限，遵循最小权限原则。只赋予应用程序必要的文件读取权限，限制可访问的目录范围。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=png&from=appmsg "")  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocOR11vNUnAVxK5mEnib7ZCOaKtwzk3S5jDX3ZUeLMTKibUm95GBoSQk3pEg/640?wx_fmt=png&from=appmsg "")  
  
  
1.资源探测  
```
fofa:title="快云服务器助手"
```  
  
2.漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDpUMX12ocmKfoqhj0icCvUwPLBRNF5UnoibBjnUrHtR9TbWDbKEGGcFzSAf12qKU3Ijvk2mfKgwvHjQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=png&from=appmsg "")  
  
漏洞POC  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocOR11vNUnAVxK5mEnib7ZCOaKtwzk3S5jDX3ZUeLMTKibUm95GBoSQk3pEg/640?wx_fmt=png&from=appmsg "")  
  
```
已收录到圈子网盘！需要的自取！
链接：https://wiki.freebuf.com/front/societyFront?invitation_code=2e710439&society_id=291&source_data=2
切记：
1.不可用于非授权渗透测试以及网络安全攻防演习！！！
2.可以用于自身资产漏洞风险排查！
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
近1个月的漏洞复现文档展示  
```
注：
1.公众号这里展示近1个月的漏洞复现文档，需要的可以直接去圈子网盘下载；
2.目前圈子已更新1000+漏洞（包含复现文档，exp脚本，yaml文件等）
例如复现笔记展示如下：
月子会所ERP管理云平台GetData接口文件存在SQL注入漏洞.docx 
赛诸葛数字化智能中台系统login存在SQL注入漏洞.docx 
勤云远程稿件处理系统存在SQL注入漏洞.docx 
安科瑞环保用电监管云平台etEnterpriseInfoY存在SQL注入漏洞.docx 
SecFox运维安全管理与审计系统FastJson反序列化漏洞.zip 
锁群管理系统存在任意后台管理泄露漏洞.docx 
博斯外贸管理软件V6.0中的logined文件接口存在SQL注入漏洞.docx 
博斯外贸管理软件V6.0中的loginednew文件接口存在SQL注入漏洞.docx 
WordPress插件ElementorPageBuilder存在文件读取漏洞(CVE-2024-9935).docx 
九思OA系统upload_l文件存在任意文件上传漏洞.docx 
用友GRP-U8系统taskmanager_login存在SQL注入漏洞.docx 
内训宝scorm存在任意文件上传漏洞.docx 
时空物流运输管理系统存在敏感信息泄露漏洞.docx 
大华智能物联综合管理平台GetClassValue远程代码执行漏洞.docx 
朗速ERP系统FileUploadApi接口文件存在文件上传漏洞.docx 
蓝凌EKP系统fsscCommonPortlet接口文件存在未授权SQL注入漏洞.docx 
虹安Heimdall DLP数据泄漏防护系统 pushSetup接口文件存在SQL注入漏洞.docx 
科汛新职教网校系统CheckOrder存在SQL注入漏洞.docx 
用友U8-Cloud系统接口ReleaseRepMngAction存在SQL注入漏洞.docx 
飞鱼星路由器存在敏感信息泄露漏洞.docx 
上海汉塔上网行为管理系统存在远程命令执行漏洞.docx 
Apache-Tomcat条件竞争致远程代码执行漏洞.docx 
方正畅享全媒体新闻采编系统screen.do存在SQL注入漏洞.docx 
方正畅享全媒体新闻采编系统reportCenter.do存在SQL注入漏洞.docx 
用友NC系统接口yerfile_down存在SQL注入漏洞.docx 
用友U8-CRM系统getDeptName存在SQL注入漏洞.docx 
卓软计量业务管理平台image任意文件读取漏洞.docx 
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
昂捷CRM系统cwsuploadpicture任意文件读取漏洞.docx 
圣乔ERP系统 downloadFile.action 存在任意文件读取漏洞.docx 
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=png&from=appmsg "")  
  
圈子介绍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocOR11vNUnAVxK5mEnib7ZCOaKtwzk3S5jDX3ZUeLMTKibUm95GBoSQk3pEg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORY46W37hdIib0UibY4EBBNU8JF9KLZDzB64MiasA4iaWwuMdqtZn3HXpdsA/640?wx_fmt=png&from=appmsg "")  
  
  
【圈子服务】  
  
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
  
PC链接：https://wiki.freebuf.com/front/societyFront?invitation_code=2e710439&society_id=291&source_data=2  
  
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
  
