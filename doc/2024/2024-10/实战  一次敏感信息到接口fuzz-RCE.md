#  实战 | 一次敏感信息到接口fuzz-RCE   
 Z2O安全攻防   2024-10-11 22:03  
  
一次敏感信息到接口fuzz-RCE，开局一张图，一看就是高端局了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGERt3gj89m1Ww5jIOBaDib2yRDZGRricHibMIAgJL4CAUiamJRzcu1PGcSA/640?wx_fmt=png "")  
  
老规矩资产收集一遍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGRRbD92HbvWOHmgjeGiaBtNRColJgmYEslOnVgO5vZShF7NXiaE3kxR8Q/640?wx_fmt=png "")  
  
没其他子域名，多地ping下域名看下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGy0QTD8epX6nXosmDWickiaGGibVNDNoT1fWibPicwJQYCoJHhtAqcnkBPXA/640?wx_fmt=png "")  
  
难道不是cdn？国外ping也返回的是同ip  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGMCdXdJHvZqKIBABkFz3sI7BibrMc4MXEOfyhPHZDlmf7A9QgwpdOufA/640?wx_fmt=png "")  
  
除了已知的80和443  
  
还开放了8443，8466  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGaCfOCe7WcApeMAib2pSooAOcjia0tmzRNQBZXnNKZQIsicJrwnYzmBXHQ/640?wx_fmt=png "")  
  
扫下端口看下  
  
8443端口WEB端  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGxMNia3zUorP7KiaRz0UmibrHnziciajPFnoU8DDonbjBoQLI9TkVbw1B5CQ/640?wx_fmt=png "")  
  
梭哈，梭哈，梭哈  
  
扯远了，测试了许久没发现可以利用的点，尝试了下掉鱼，发现客服只想让我充钱  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGwWVkJWKFS2YHRI00hfdKGNDKuFDMJ3lbvp9PbSZoSu4Ok3FLQLkcIQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaG7y8OxlUpHo62I4gia2kb2HOQ0IQgyGcJUWC1UDoeNr2M60qLic9ICPrg/640?wx_fmt=png "")  
  
还得是晓晓，知道我没钱，还叫我去贷款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGhozuvJrKAdYGLQGquw7fj2XXOXvT9ibhZLIawK48EyEegL66n9Tx6oQ/640?wx_fmt=png "")  
  
不愧是真爱  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGfnic5KHn1LfHzRkP44D2uvJcXcxxWWREETZNmwia4yBepjsz0Dlv3QzQ/640?wx_fmt=png "")  
  
本来还想着继续跟她聊的，除了让我充钱，啥都不肯  
  
**回归正题**  
  
继续尝试深入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGic2zbeL2F52VmWbt2Gn1FVyniad9BuxDKJhLAdh9JBp8amWXJiazVx8ug/640?wx_fmt=png "")  
  
缺少访问令牌.....，本来到这里不想看了的  
  
但还是抱着试一下的心态fuzz下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGUh8icoB7b2scEf9QB5cjt0AI4ZdhMMF8icBJicjH85rr7X6gvWssVUqNg/640?wx_fmt=png "")  
  
Api/config 返回200  
  
打开看看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaG5scn4ic0qM6YHCXZhqmjUgarHM0bZAjdJHXRq3sa4XiaIeGDLXmHJpkw/640?wx_fmt=png "")  
  
激动的心颤抖的手，虽然是内网ip，但试着访问下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGBCQboQbPA9RqCK9OCLibeHHTYbgU0VApsjxzvUQhdaF6k8noeP8BoTw/640?wx_fmt=png "")  
  
令牌+1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaG5Tu1y6179JPJQsPp5w5aea7bahqEpTfVibpEJCibViatMdpZb3EWvpqicA/640?wx_fmt=png "")  
  
空白页？可调用吗，fuzz下接口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaG27V76miavicXIic0bPMPNiaKpFBDboXqic078CjPJZ0MCBtuxN57fTmZ1Ew/640?wx_fmt=png "")  
  
然后为了证实下写个脚本判断页面是不是为空，怕参数没值不返回东西就写了个默认1的值  
  
开始fuzz  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGOf1x7dEUsrwU2ibBgZv0ZGCg4zwcCqLPO3R3VknVruicEKlxk9UL3ggg/640?wx_fmt=png "")  
  
希望这不就来了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGUzS3NYKZLzSMBicMbO3M5ia0hQeo8rLdhK32ybekXQoS408TgDDahjBQ/640?wx_fmt=png "")  
  
不会是rce吧，试一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGp2DFCT9XBeBiaXwSSPdT6GFDPc4ghtZ6dNQQe4dz8iaT3w6JPHiaeLY3w/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGILylibNbsu9zzKS0xBsuKibGzpphm8VnTM6NJuBFqdk06nq8MbWhP8Mw/640?wx_fmt=png "")  
  
能获取到，再试下获取当前用户  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGGeOsiak4rsPibaicib5Fu5DmtnfjQic7k5Y1GRib2hu918oyFj9t2TLoQ1Vw/640?wx_fmt=png "")  
  
晦气下机  
  
  
### 考证咨询  
  
  
最优惠报考  
各类安全证书(NISP/CISP/CISSP/PTE/PTS/PMP/IRE等....)，后台回复"  
好友位"咨询。  
  
# 技术交流  
  
  
### SRC专项漏洞知识库  
  
  
建立了一个  
src专项圈子，内容包含**src漏洞知识库**、**src挖掘技巧**、**src视频教程**等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCOPMibnJIeBT6Yv0RwBJT9AFHKEbo3BxYkLnE00jVuoLicSOBCIzMiaJKQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuYbBtKotHSdHiakQJhjAQibJtibuWIrLXodxuZpTKwAl2zOz70DLbiaj5QTlExdjoHvvtZHufxHkuZU6g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIx3z6YtXqmOkmp18nLD3bpyy8w4daHlAWQn4HiauibfBAk0mrh2qNlY8A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugI5tZcaxhZn1icWvbgupXzkwybR5pCzxge4SKxSM5z4s9kwOmvuI3cIkQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIstia27YLJFBtC5icJO6gHLLgzRDqib6upI3BsVFfLL02w6Q8jIRRp0NJA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
### 交流群  
  
  
关注公众号回复“**加群**”，添加Z2OBot好友，自动拉你加入**Z2O安全攻防交流群(微信群)**分享更多好东西。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h8P1KUHOKuYMO5aHRB3TbIy3xezlTAkbFzqIRfZNnicxSC23h1UmemDu9Jq38xrleA6NyoWBu1nAj0nmE6YXEHg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
### 关注我们  
  
  
  
**关注福利：**  
  
**回复“**  
**app****" 获取  app渗透和app抓包教程**  
  
**回复“**  
**渗透字典****" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。**  
  
**回复“漏洞库" 获取 最新漏洞POC库(**  
**1.2W+****)******  
  
**回复“资料" 获取 网络安全、渗透测试相关资料文档**  
  
  
