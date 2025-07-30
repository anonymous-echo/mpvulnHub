#  (1day)iDocView在线文档预览系统某接口存在任意文件读取   
websec  WK安全   2023-12-10 09:58  
  
声明  
：  
未经授权，严禁转载，如需转载，联系作者。请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。  
  
  
  
0x00.漏洞描述  
  
(一)漏洞描述  
  
I Doc View在线文档预览系统是一套用于在Web环境中展示和预览各种文档类型的系统，如文本文档、电子表格、演示文稿、PDF文件等。此系统某接口存在任意文件上传读取漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCVxJkQJB9ClVkjr1U5KqemnPI4nBZdegAicibDKdP2yicpWnQuX2eeC01tiaaE7Slm7ibgSb1LgY7iaiap7Q/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
(二)资产测绘  
```
Hunter语法：
app.name="I Doc View"
Fofa语法：
title="I Doc View"
```  
  
(三)漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCVhII438gNMQyoR5qVaodkzBx2OoN2hwH7ciaRgQfiaDpcw6a904LjvpicnNYcqlLUdJ09fFWuSJLFgw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCVhII438gNMQyoR5qVaodkzk7VVF3zpFtXc61wMkJ2aNRIlxufibx4VI4zvjWkXT9xtTnWerboRACA/640?wx_fmt=png&from=appmsg "")  
  
  
```
目前更新漏洞列表如下：
(1day)iDocView在线文档预览系统某接口存在任意文件读取
(1day)spon世邦ip网络广播系统-rce 
(0day)某智能终端操作平台后台存在通用SQL注入漏洞   
NETGEAR DGND3700v2 路由器 setup.cgi 接口身份认证绕过 
(1day)maxView Storage Manager系统RCE 
(在野0day)某户协同OA平台某接口存在任意文件读取漏洞 
(1day)易宝OA系统UploadFile接口存在文件上传  
(1day)易宝OA系统BasicService.asmx接口存在文件上传 
(1day)奥威亚教育视频云平台前台某接口文件上传漏洞 
WeiPHP 微信开发平台某接口SQL注入
(1day)spon世邦ip网络广播系统-任意文件读取
(1day)蓝凌OA某接口存在敏感信息泄露漏洞
任子行等多个产商安全产品存在命令执行
(1day)三汇网络管理设备任意文件读取
(1day)iDocView在线文档预览系统doc/upload存在任意文件上传
Tenda 路由器 uploadWewifiPic后台RCE
万户OA-iWebPDF-DocumentEdit注入
致远互联FE协作办公平台editflow_manager.js%70 SQL注入
时空智友企业流程化管控系统wc.db数据库文件泄露
用友畅捷通App_Code.ashx文件上传
致远互联FE协作办公平台uploadFile.jsp文件上传
锐捷RG-UAC应用网关nmc_sync.php前台RCE
FH Admin Shiro反序列化
Zkteco百傲瑞达安防管理系统平台 Shiro反序列化
金和OA SAP_B1Config.aspx未授权访问
用友时空KSOA UploadImage文件上传
通达oa-moare-反序列化rce漏洞
用友ufida-getFileLocal任意文件读取
华天动力-OA8000 MyHttpServlet 文件上传
北京九思协同软件有限公司九思OA wap.do 任意文件读取
润申信息企业标准化管理系统CommentStandardHandler.ashx、DefaultHandler.ashx SQL注入
金石工程项目管理系统TianBaoJiLu.aspx SQL注入
建文工程项目管理软件BusinessManger.ashx、Desktop.ashxSQL 注入
致远A6-m系统管理软件doUpload.jsp任意文件上传
FLIR-FLIR-AX8/res.php 命令执行
云时空社会化商业ERP系统/slogin/service SQL注入
云时空社会化商业ERP系统fileupload/gpy文件上传
pkpmbs 建设工程质量监督系统FileUpOrDown.ashx文件上传
好视通-云会议upLoad2.jsp文件上传
F22服装管理软件系统 前台UploadHandler.ashx文件上传
时空智友workflow.sqlResult SQL注入
东胜物流软件TCodeVoynoAdapter.aspx、GetDataList、SaveUserQuerySetting SQL注入
海翔云平台 getylist_login.do SQL 注入
BYTEVALUE 智能流控路由器webRead/open/命令执行
海康运行管理中心/api/session命令执行
Supabase /default/query SQL注入命令执行
用友GRP /U8AppProxy 文件上传
智跃人力资源管理系统GenerateEntityFromTable.aspx? SQL注入
水务通onlyOffice-edit任意文件读取

等等...............
```  
  
进技术交流群可加下方wx  
  
****  
****  
**|**  
**知识星球的介绍**  
  
  
湘安无事星球部分内容预览在线链接  
```
https://docs.qq.com/doc/DUEVsVWhaUk51VUlr
```  
  
不好意思，兄弟们，这里给湘安无事星球打个广告，不喜欢的可以直接滑走哦。添加下面wx加星球可享优惠  
  
1.群主为什么要建知识星球？  
```
很简单为了恰饭哈哈哈，然后也是为了建立一个圈子进行交流学习和共享资源嘛
相应的也收取费用嘛，毕竟维持星球也需要精力
```  
  
2.知识星球有哪些资源？  
```
群里面联系群主是可以要一些免费的学习资料的，因为群里面大部分是大学生嘛
大学生不就是喜欢白嫖，所以大家会共享一些资料
没有的群主wk也有,wk除了不会pc,其他都能嫖hhh
```  
  
  
知识星球一次付费，后期都是永久免费续费的！！！  
  
加入知识星球之后，可享受其他永久两大圈子"知识大陆+纷传"  
  
一些共享的资源  
```
1.刀客源码的高级会员
2.FOFA在线查询与下载，key使用、360quake、shodan等
3.专属漏洞库
5.专属内部it免费课程
6.不定期直播分享（星球有录屏）
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYuCJm1WAIhc9XAa6OLI3ryvT32RpoHYTibSMVnsTh875E0Jk4XPduRqDicRQGMWHDD4RnueHudPHI3g/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYsHR6CaxF0VtiaIhM3XMm8EjWtzeq6cdnCdf0TsTF7FR6ukMZr4S9KUYDgKicicS9PIHpermh1CgYg3w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
关注下方公众号，输入"  
xaws"即可领取安全类电子书籍一份  
  
  
