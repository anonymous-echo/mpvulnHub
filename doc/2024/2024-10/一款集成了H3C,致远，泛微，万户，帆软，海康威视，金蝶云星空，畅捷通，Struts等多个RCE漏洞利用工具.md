#  一款集成了H3C,致远，泛微，万户，帆软，海康威视，金蝶云星空，畅捷通，Struts等多个RCE漏洞利用工具   
 黑白之道   2024-10-02 10:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
**01**  
  
**工具介绍**  
  
一款集成了H3C,致远，泛微，万户，帆软，海康威视，金蝶云星空，畅捷通，Struts等多个RCE的漏洞利用工具  
  
  
程序采用C#开发,首次使用请安装依赖：NET6.0 声明：仅用于授权测试，用户滥用造成的一切后果和作者无关 请遵守法律法规！  
  
  
目前已完成工具部分RCE功能，由于各种原因，目前项目尚未完善，感兴趣的朋友可以下载项目源码，手动添加其他功能  
```
H3C iMC 存在远程命令执行漏洞（RCE +批量RCE）
致远log4j2远程代码执行漏洞（RCE+MSF反弹）
致远一键检测（RCE+利用）
泛微一键漏洞检测（RCE+利用）
海康威视CVE-2021-36260 (RCE+批量RCE）
海康威视 fastjson反序列化漏洞（RCE+批量检测）
海康威视 IVMS任意文件上传漏洞（RCE getshell)
海康威视isecure center 综合安防管理平台文件上传漏洞
致远OA wpsAssistServlet 任意文件上传漏洞(getshell+批量检测)
金蝶云星空反序列化漏洞(RCE）
畅捷通T+任意文件上传(CNVD-2022-60632 )
泛微 E-Office文件上传漏洞（CVE-2023-2523)
万户OA fileUpload.controller 任意文件上传漏洞
Struts+RCE
```  
  
部分功能RCE执行效果：  
  
  
畅捷通T+任意文件上传(CNVD-2022-60632 ) 任意文件上传漏洞 内置预编译文件，工具将自动上传，可以一键getshell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2U8Er110pODvs1Udxd7MAia8nWlRpOgrGiczMBgdftSNk40rLNFnfk2PYqyicB0ibD9xJ3ow4EKLUibxbQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**02**  
  
**工具下载**  
  
****https://github.com/MInggongK/Penetration-mining-src****  
  
> **文章来源：夜组安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
