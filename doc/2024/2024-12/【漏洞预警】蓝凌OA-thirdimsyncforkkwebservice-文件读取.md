#  【漏洞预警】蓝凌OA-thirdimsyncforkkwebservice-文件读取   
原创 马赛克安全实验室  马赛克安全实验室   2024-12-17 01:07  
  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！马赛克安全实验室情报申明（可点击查看）  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRicPjtibQUDC6OnlQyWCzfd68f5ycicia6CCgOhrqkvHfLj5ajt2SKLnWoZSh219zUS3eTcERBwhxu9Dg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
0x01漏洞描述  
蓝凌OA是由深圳市蓝凌软件股份有限公司开发，是一款针对中小企业的移动化智能办公产品 ，融合了钉钉数字化能力与蓝凌多年OA产品与服务经验，能全面满足企业日常办公在线、企业文化在线、客户管理在线、人事服务在线、行政务服务在线等需求。其接口/sys/webservice/thirdImSyncForKKWebService存在任意文件读取漏洞，攻击者可读取任意文件获取敏感信息。  
0x02产品指纹  
  
     
```
body="Com_Parameter"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McR8nnUiax5QzCV7EQVZUXObDiakanhCdXJP6jH0CN3VicAGDWtbsj2YiaKKYicxmDtFClQpdFNZLtp0Oia1Q/640?wx_fmt=png&from=appmsg "")  
  
0x03漏洞复现  
**蓝凌****OA /sys/webservice/thirdImSyncForKKWebService 接口处存在任意文件读取漏洞，解密base64即可获取读取的文件**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRibQsB9viaMfZ7ZJW9b44plKU9BwsPkhSrKmqG8NTBVwkuSv5styxZ5RdX9YeV1BqC3xkxQP9SEX1Hw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRibQsB9viaMfZ7ZJW9b44plKUQ2gQiaFYgHSzLey3k4vmpicQVAZwXSSdIzlyvls4XSWNc6PFaTK2Mibicw/640?wx_fmt=png&from=appmsg "")  
0x04扫码加入星球查看详情  
  
**扫描加入星球不迷路**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRibMUiczLZevyribRn1qUpneDyfgJROGIibTVTjgVeErEr7icQzaVX1hBUfB2c4e2lUHP7EhUia0pvKe7Lg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRicPjtibQUDC6OnlQyWCzfd68iabQ9Vb5JGMNXqnzJTc28tomdyWugPkbLp6Kgc9tECG2XXPMTiafwTAw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
0x05星球介绍  
  
**马赛克安全**  
  
**专注于漏洞情报分享，不发烂大街的东西。星球外面的兄弟欢迎进来白嫖，不满意三天退款。放心大胆的进来嫖！！！**  
  
**很多漏洞均为全网首发的0day/1day，目前星球已累计发送460个漏洞POC脚本，有没有价值，只有体会才知道！！！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McR9nTo7Az8LicJlNoGOPhaDBJjohAYibwup7U8nEBsQ2ibSSHic2fFrL8lDj7DEoQdvN3OO98R2kvhE7tw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
