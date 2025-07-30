#  【漏洞预警】 易宝OA-GetProductInv SQL注入漏洞   
 thelostworld   2024-11-16 09:10  
  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！马赛克安全实验室情报申明（可点击查看）  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRicPjtibQUDC6OnlQyWCzfd68f5ycicia6CCgOhrqkvHfLj5ajt2SKLnWoZSh219zUS3eTcERBwhxu9Dg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
0x01产品介绍  
  
**易宝OA系统是一种专门为企业和机构的日常办公工作提供服务的综合性软件平台，具有信息管理、 流程管理 、知识管理(档案和业务管理)、协同办公等多种功能。**  
  
0x02产品指纹  
****  
```
body="topvision_oaName"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McR9UIZqCptT7UFAm6LdsJcibO1Sq8WKOBnLqVxlmUXrPrTZib4ocSBorp5OLhXzmPltyBI33byhZ7oKQ/640?wx_fmt=png&from=appmsg "")  
  
0x03漏洞复现  
**易宝OA /SmartTradeScan/Inventory/GetProductInv 接口处存在SQL注入漏洞**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McR9UIZqCptT7UFAm6LdsJcibOVeHzvygwwOnn93q0nCwf1leHIQRZI5micTe9bgxp13cOdyfAhRqc2EQ/640?wx_fmt=png&from=appmsg "")  
  
****  
0x04扫码加入星球查看详情  
  
**扫描加入星球不迷路**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRibMUiczLZevyribRn1qUpneDyfgJROGIibTVTjgVeErEr7icQzaVX1hBUfB2c4e2lUHP7EhUia0pvKe7Lg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRicPjtibQUDC6OnlQyWCzfd68iabQ9Vb5JGMNXqnzJTc28tomdyWugPkbLp6Kgc9tECG2XXPMTiafwTAw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
0x05星球介绍  
  
**马赛克安全**  
  
**专注于漏洞情报分享，不发烂大街的东西。星球外面的兄弟欢迎进来白嫖，不满意三天退款。放心大胆的进来嫖！！！**  
  
**很多漏洞均为全网首发的0day/1day，目前星球已累计发送431个漏洞POC脚本，有没有价值，只有体会才知道！！！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRibaibL5lI7fXfSskibI19X9GOV7ibcyFnQGyH54BwBEhlKiaE8j536CiacuVvZGMCfhtMF5VXDW2Jp6PDw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
