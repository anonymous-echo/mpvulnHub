#  【漏洞预警】 用友BIP 数据库配置信息泄露   
 thelostworld   2024-11-16 09:10  
  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！马赛克安全实验室情报申明（可点击查看）  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRicPjtibQUDC6OnlQyWCzfd68f5ycicia6CCgOhrqkvHfLj5ajt2SKLnWoZSh219zUS3eTcERBwhxu9Dg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
0x01产品介绍  
  
**YonBIP用友商业创新平台，是用友在数字经济时代面向成长型、大型企业及巨型企业，融合了先进且高可用技术平台和公共与关键商业应用与服务，支撑和运行客户的商业创新（业务创新、管理变革），并且具有数字化、智能化、高弹性、安全可信、社会化、全球化、平台化、生态化等特征的综合型服务平台**  
  
0x02产品指纹  
****  
```
body="iuap-apcom-workbench/"
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McR8kpbPfI7MzqMym38qXjrxZCMfa5CzSLrEDVcEwMPuqrSbCU0alVU9kYXhziaPHYwYnf1TLU2SbrNQ/640?wx_fmt=png&from=appmsg "")  
  
0x03漏洞复现  
**用友BIP /bi/api/SemanticModel/GetOlapConnectionList 接口处存在信息泄露**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McR8kpbPfI7MzqMym38qXjrxZz8kuksq2YTrhr0eS18X26E1k4iajPib4mbEFZuFQI1LCrTVJqHbIoJ2A/640?wx_fmt=png&from=appmsg "")  
  
0x04扫码加入星球查看详情  
  
**扫描加入星球不迷路**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRibMUiczLZevyribRn1qUpneDyfgJROGIibTVTjgVeErEr7icQzaVX1hBUfB2c4e2lUHP7EhUia0pvKe7Lg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRicPjtibQUDC6OnlQyWCzfd68iabQ9Vb5JGMNXqnzJTc28tomdyWugPkbLp6Kgc9tECG2XXPMTiafwTAw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
0x05星球介绍  
  
  
**马赛克安全**  
  
**专注于漏洞情报分享，不发烂大街的东西。星球外面的兄弟欢迎进来白嫖，不满意三天退款。放心大胆的进来嫖！！！**  
  
**很多漏洞均为全网首发的0day/1day，目前星球已累计发送440个漏洞POC脚本，有没有价值，只有体会才知道！！！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McR8kpbPfI7MzqMym38qXjrxZOLJCJwiadXUhF10gcSbRQXn1Zjr3IDn1EeLOtq32y3t9gsbHtpdLsaQ/640?wx_fmt=png&from=appmsg "")  
  
****  
  
