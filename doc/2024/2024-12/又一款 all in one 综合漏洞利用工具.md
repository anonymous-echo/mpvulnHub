#  又一款 all in one 综合漏洞利用工具   
永恒之锋实验室  Eonian Sharp   2024-12-02 07:40  
  
###   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hvMQKkLOqzMwIWd8s9zobcZnnqUdZabGib4E1KO7L3Br2w1GI4jgc2WW9LMWtnic039qQxmvEy7bKWiceJWscjquQ/640?wx_fmt=jpeg "")  
### 声明  
  
本公众号分享的安全工具和项目均来源于网络，仅供学术交流，请勿直接用于任何商业场合和非法用途。如用于其它用途，由使用者承担全部法律及连带责任，与工具作者和本公众号无关。  
### 介绍  
  
一款集成了H3C,致远，泛微，万户，帆软，海康威视，金蝶云星空，畅捷通，Struts等多个RCE的漏洞利用工具  
  
程序采用C#开发,首次使用请安装依赖：NET6.0 声明：仅用于授权测试，用户滥用造成的一切后果和作者无关 请遵守法律法规！  
  
目前已完成工具部分RCE功能，由于各种原因，目前项目尚未完善，感兴趣的朋友可以下载项目源码，手动添加其他功能  
  
  
该项目是C#的源码项目使用方法，需要你下载Visual Studio 2022然后使用Visual Studio 2022打开项目源码中的[渗透测试漏洞挖掘src集成版.csproj即可如果您要编写代码，进行其他模块编写，可以直接在代码中编写如果你只需要测试，你只需要点击生成解决方案，就可以生成程序了您需要安装 NET6.0 支持环境  
### 下载  
  
https://github.com/MInggongK/Penetration-mining-src[1]  
### 支持  
  
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
  
部分功能RCE执行效果：  
  
畅捷通T+任意文件上传(CNVD-2022-60632 ) 任意文件上传漏洞 内置预编译文件，工具将自动上传，可以一键getshell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hvMQKkLOqzMwIWd8s9zobcZnnqUdZabGxR3qyHlA3r4SBMXlgR2Gsd0Mle4E6AbVcoP9MU2eScouMibtSjegQXQ/640?wx_fmt=png&from=appmsg "")  
  
需要的朋友发送【  
**241202**】免费获取资源   
  
知识大陆会员直接进入帮会领取噢~  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hvMQKkLOqzMwIWd8s9zobcZnnqUdZabGthibI3Gy2kibfic2qJyg65Df2DPPsDl6wD3XPO71CWvmukdict83sRGU2w/640?wx_fmt=jpeg&from=appmsg "")  
  
### References  
  
[1]: https://github.com/MInggongK/Penetration-mining-src  
  
  
