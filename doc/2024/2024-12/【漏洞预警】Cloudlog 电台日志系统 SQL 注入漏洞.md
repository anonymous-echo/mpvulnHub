#  【漏洞预警】Cloudlog 电台日志系统 SQL 注入漏洞   
原创 马赛克安全实验室  马赛克安全实验室   2024-12-16 02:28  
  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！马赛克安全实验室情报申明（可点击查看）  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRicPjtibQUDC6OnlQyWCzfd68f5ycicia6CCgOhrqkvHfLj5ajt2SKLnWoZSh219zUS3eTcERBwhxu9Dg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
0x01漏洞描述  
**Cloudlog 是一个自托管的 PHP 应用程序，可让您在任何地方记录您的业余无线电联系人。使用PHP和MySQL构建的基于Web的业余无线电记录应用程序支持从HF到微波的一般站记录任务。其接口/index.php/oqrs/request_form存在SQL注入漏洞，攻击者可通过该漏洞获取数据库信息。**  
0x02产品指纹  
****  
```
icon_hash="-460032467"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McR9nTo7Az8LicJlNoGOPhaDBJHva6ic2OyL7IbtZRhIPON2MMlhzdfYLUCcO2yvjkBQaZMeJsKB6yiagw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McR9nTo7Az8LicJlNoGOPhaDBJ4zsHV5MicjENWO1lT5gXR9Zib8ScxWOyw8oWqrH2ztXNkgoLkUDkbYyw/640?wx_fmt=png&from=appmsg "")  
0x03漏洞复现  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McR9nTo7Az8LicJlNoGOPhaDBJEqXhZb7WFicxTVq7kpTibKM9zp5BXv3TgEPsbTFnltRTkeVJuMJ82M7A/640?wx_fmt=png&from=appmsg "")  
0x04扫码加入星球查看详情  
  
**扫描加入星球不迷路**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRibMUiczLZevyribRn1qUpneDyfgJROGIibTVTjgVeErEr7icQzaVX1hBUfB2c4e2lUHP7EhUia0pvKe7Lg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McRicPjtibQUDC6OnlQyWCzfd68iabQ9Vb5JGMNXqnzJTc28tomdyWugPkbLp6Kgc9tECG2XXPMTiafwTAw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
0x05星球介绍  
  
**马赛克安全**  
  
**专注于漏洞情报分享，不发烂大街的东西。星球外面的兄弟欢迎进来白嫖，不满意三天退款。放心大胆的进来嫖！！！**  
  
**很多漏洞均为全网首发的0day/1day，目前星球已累计发送460个漏洞POC脚本，有没有价值，只有体会才知道！！！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wibiaOls7McR9nTo7Az8LicJlNoGOPhaDBJjohAYibwup7U8nEBsQ2ibSSHic2fFrL8lDj7DEoQdvN3OO98R2kvhE7tw/640?wx_fmt=png&from=appmsg "")  
  
****  
****  
  
