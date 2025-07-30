#  【漏洞预警 】SRM智联云采系统存在多处SQL注入漏洞   
 thelostworld   2024-11-20 01:25  
  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！马赛克安全实验室情报申明（可点击查看）  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRicPjtibQUDC6OnlQyWCzfd68f5ycicia6CCgOhrqkvHfLj5ajt2SKLnWoZSh219zUS3eTcERBwhxu9Dg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
0x01产品介绍  
  
**智互联(深圳)科技有限公司的SRM智联云采系统旨在解决企业供应链管理的挑战，同时满足企业智能化转型升级的需求。该系统利用人工智能、物联网、大数据和云技术，通过一套集成的软硬件解决方案，助力企业在供应商关系管理方面实现线上、移动和智能化。这种转型有助于提高采购效率和协同作业效率，同时规避供需风险，并增强供应链整合能力，打造企业间的共赢生态。**  
  
****0x02产品指纹  
****  
```
title=="SRM 2.0"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McR8dBVVZwEU6KNePFVVibEd98jzE9q6zAcQR6Ojv1vCrcJbcY6PecNmzyzgibH1f15y5z0pWFceOBib7Q/640?wx_fmt=png&from=appmsg "")  
  
0x03漏洞复现  
**SRM智联云采系统多个接口存在多处SQL注入漏洞**  
```
/adpweb/api/srm/delivery/quickReceiptDetail?orderBy=
/adpweb/static/..;/a/sys/sysMessage/statusList?companyName=
/adpweb/a/ica/api/testService
/adpweb/static/%2e%2e;/a/srm/inquiry/getSuppliers?code=
/adpweb/api/srm/delivery/receiptDetail?orderBy=
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRicN3LXNjSdTupHW153a79nHEDmVZRn1c3XDPsZwBmGicPL6DJvxbmkRUsxoje2Y1uZ0QOQuJAjvyQA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McR8dBVVZwEU6KNePFVVibEd981L1PFdC0580TeHYURlZcNWRrLqW3nicXxalP7DtiaDiaAgBDEcmCWx0icQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McR8dBVVZwEU6KNePFVVibEd98J7uX49Yw64aiaXAPVvKq67F4BBiab3wsbt8Ha5uewuhOsuHb58hMDwtw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McR8dBVVZwEU6KNePFVVibEd98xgw9pfXibz8ELjAdC3iaTOdUiasfctuEm7yib3miaHN4wCp7fahEo7TPyEA/640?wx_fmt=png&from=appmsg "")  
  
  
0x04扫码加入星球查看详情  
  
  
  
**扫描加入星球不迷路**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRibMUiczLZevyribRn1qUpneDyfgJROGIibTVTjgVeErEr7icQzaVX1hBUfB2c4e2lUHP7EhUia0pvKe7Lg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRicPjtibQUDC6OnlQyWCzfd68iabQ9Vb5JGMNXqnzJTc28tomdyWugPkbLp6Kgc9tECG2XXPMTiafwTAw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
0x05星球介绍  
  
**马赛克安全**  
  
**专注于漏洞情报分享，不发烂大街的东西。星球外面的兄弟欢迎进来白嫖，不满意三天退款。放心大胆的进来嫖！！！**  
  
**很多漏洞均为全网首发的0day/1day，目前星球已累计发送440个漏洞POC脚本，有没有价值，只有体会才知道！！！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McR8kpbPfI7MzqMym38qXjrxZOLJCJwiadXUhF10gcSbRQXn1Zjr3IDn1EeLOtq32y3t9gsbHtpdLsaQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
  
  
  
  
  
