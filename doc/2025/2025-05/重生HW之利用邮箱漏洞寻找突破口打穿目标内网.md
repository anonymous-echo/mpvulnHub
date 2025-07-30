#  重生HW之利用邮箱漏洞寻找突破口打穿目标内网   
 sec0nd安全   2025-05-18 15:15  
  
   
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  flysheep 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（ https://bbs.zkaq.cn）**  
  
   
  
> 小编寄语：来看看一线红队打HW的骚操作，tql佬!!!!  
  
  
由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任。  
# 前言  
  
今天，我要和大家分享一次有趣的省级HVV实战经验--某某航空公司。这次经历是我从打点到成功获取内网机器权限的完整过程，绝对让人耳目一新！如果我们不考虑近源攻击和钓鱼攻击等常见手段，那么这次的分享相较于传统漏洞攻击穿越边界的方法，充满了挑战和惊喜。  
  
为了保护演习的机密性，里面的截图会经过一定的打码处理，敬请谅解。让我们一起开始此次渗透测试之旅吧！  
# 邮箱账号密码遍历漏洞  
  
通过演习组给定的目标域名，我利用网络空间测绘平台找到一些目标资产，其中一个邮件系统引起了我的注意。通过指纹分析为exchang服务器，之所以考虑对其进行测试，主要是登录界面没有验证码机制而且没有进行限速。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWN5zTXdSwkjhB72wibz1YeAicmnK4YOv3CUVibAurHHwlmej01iazmYunZQ/640?wx_fmt=png&from=appmsg "null")  
  
  
通过常见用户名字典对exchang的枚举和爆破，最终成功获得2个账号/密码  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWTHHL0PZKlRXcibkZ3shDnCsOHFQxy1KLJicZ6ZrfICKzFevmjdVlkoFA/640?wx_fmt=png&from=appmsg "null")  
  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQW5btmzYjoIiajLWThBbMMRSNx3k1S2ic2jJ9icJzMwWWKGBWzGScnvZsvA/640?wx_fmt=png&from=appmsg "null")  
  
  
两个用户分别具有不同的权限，不断翻找邮件内容看看有没有可以利用的东东  
  
用户zhangyn  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWHSnRC0vFzOLcnJn021icCCFTh6fu61K79SNokHqjQyXTvQ2WoQeh7cA/640?wx_fmt=png&from=appmsg "null")  
  
  
用户chenjun  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWdSb6H9lOx4F1akd8ic3ucN9x4HOyWyMpJqvme92aibgN60oicMbsy8IYw/640?wx_fmt=png&from=appmsg "null")  
  
# 利用VPN突破逻辑隔离进入内网  
  
通过多次尝试发现使用账号zhangyn可以成功登录公司放置于DMZ区域的webvpn  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWT81ib4FAiaNgeTOnkfozAkvciax5vhwBWrfCTVDib97mP5sbSicUrbKrrkA/640?wx_fmt=png&from=appmsg "null")  
  
  
这样就通过VPN突破逻辑隔离顺利进入内网了  
  
点击页面上的链接还可以成功访问内网的OA办公系统  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWgPXkibc4uLzib29HAicR4Rc8fFCPaHH8wk3EIT0mQhjAwOI6ZUJxOdztQ/640?wx_fmt=png&from=appmsg "null")  
  
  
点击webvpn的链接还可以进入公司单点登录sso，10段机器，里面有挺多的功能，舒服啊。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWN41oqibQz6zgMle8BSaDO0RlxNpfCp6r0olzNgflGXcpyL0DDrsBXbQ/640?wx_fmt=png&from=appmsg "null")  
  
# 核心业务网段渗透  
  
挂上SSLVPN也同样能进入内网。继续在zhangyn的vpn中ping主站的域名，发现主站所在的内网网段是10.2.3.X网段  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWcFS6Nj69jssruuMiamU2sYqfUXmDW8JhNeGIicF3siaZple0SV0ONcdAQ/640?wx_fmt=png&from=appmsg "null")  
  
  
于是利用FSCAN扫描探测，但是奇怪的是发现该账号仅能访问4个主机地址，毕竟一个公司的内网是很大的，哪怕仅仅是办公内网也不可能仅仅只有4台机器。  
  
通过询问组里有经  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWkMwEBMsN4QcDKicbJXHpbiazm9raCXhXRBRQgdXSdx31bb1oSASnEv8A/640?wx_fmt=png&from=appmsg "null")  
  
  
验的大佬，最终我们分析该账号是乘务组人员，it权限不高，所以能够访问的内网资源极其有限。  
于是我又再次切换到之前的chenjun账号，这次发现可以访问更多10.2.3.X段的主机资源了。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWmPqGBFVGfDU7qxhGlOCCiaqqwEYfRB98ZDnfjzPMDbas7VOibLLUkPicA/640?wx_fmt=png&from=appmsg "null")  
  
  
在这些扫描到的内网资源中，我首先通过常见的weblogic 反序列化漏洞获取1台主机root权限  
  
运行控制系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQW9mQtWmK0NM5Yv7ggWnoAFNicdcWU2dVI3FeNwHkewMkXjdnmP2Dk11Q/640?wx_fmt=png&from=appmsg "")  
  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWicDbBe1WibXQwz27cgeRXAPVACMoOXsMbCuVSchyWVleRLVETUzFIjrA/640?wx_fmt=png&from=appmsg "null")  
  
### 获取域控服务器权限  
  
通过前期进入核心内网后扫描发现域控地址  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWqhicLcLzzfRpxV0p2k611vrdzdmibBa8rQzFVMhjG6WrN8WzbWEIbRjw/640?wx_fmt=png&from=appmsg "null")  
  
  
可以通过nopac域漏洞获得域控权限  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWn50PhJjaHOtpcgc5ctfmibnwgxyvw3ia09ceCyXrT9KK546fQWgcSfDA/640?wx_fmt=png&from=appmsg "null")  
  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWdd9LFJjejmhBwmpgWqzduPvsBqu4VdGtvxNb6G7JM3kicPWaNR7ictvA/640?wx_fmt=png&from=appmsg "null")  
  
  
添加域管账号后成功登录域控远程桌面  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWb6tVeRgwqe0SYU4jw2SQMibHeWGhuXibokGB8jqc1ogA2SROO2bBMrmw/640?wx_fmt=png&from=appmsg "null")  
  
### 通过资产列表锁定核心业务系统  
  
通过域内用户查询查到运维部张XX的hash，解开获得明文，登录其邮箱  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWnicWHOkPPUeabYOtqiaSjrHW0a7BMEUMicMBnJV8QdGDlSjibWKg0iaKFdw/640?wx_fmt=png&from=appmsg "null")  
  
  
获取信息资产列表，其中标注了重要系统。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQW5pKia23Vh6kINoeLS9XxLSpT2Fj25tM234wUzALKDQTU0ibibNgslib5ibw/640?wx_fmt=png&from=appmsg "null")  
  
  
在域控中可以看到对应的重要服务器  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWQSqRmxNWTax2jFTaeoot49sCfcSBonSzoJTrVsPcanmPD7wabKuGEQ/640?wx_fmt=png&from=appmsg "null")  
  
  
由于当前已有域管账号，因此可登录任意重要服务器，危害非常大。  
演示登录WQAR系统10.2.3.X，wqar是无线地面快速存取记录器，为飞机维护和可靠性提供大量基础数据，重要性不言而喻，一旦被不法分子利用，会对旅客生命财产和社会安全造成严重的安全威胁。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWh7FFibO6P6o38CqhbIqNKTSEub5ebicSEaV5tXicSBBq1kfRtAzral6Lg/640?wx_fmt=png&from=appmsg "null")  
  
### 继续邮箱爆破获得更多弱口令账号  
  
感觉有些敏感信息在邮箱里面传递，于是继续利用内网搜集到的各种信息形成新的用户字典，继续对邮箱爆破获得更多弱口令账号，下面是成功的6个  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQW04YuDibAOOFBZcRmgqrp2iaK8KN7xUZica5kuXUPHIicQd64OqudCXYXibQ/640?wx_fmt=png&from=appmsg "null")  
  
  
通过上面爆破获取的用户信息进入了若干办公后台  
  
安全管理平台：  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQW5Kd4ffGS0lh2U5stypKWtKDaLg8Xo6cngUxmztJkL3TialhibZAfmcRw/640?wx_fmt=png&from=appmsg "null")  
  
  
机组信息管理系统  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWibTicxmiaEdMPSRfzeNEsrpE5CsicQz7cRHtpfJe6YKVvJ64ibsx5OMtZrg/640?wx_fmt=png&from=appmsg "null")  
  
  
危险品培训管理系统  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWL3dAlylnBoIcsUxPkctF9Ibe5GWPS23CGrIic06BBG7Js758BoxpCOA/640?wx_fmt=png&from=appmsg "null")  
  
  
XX控制运行网  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWN32YpxY6MJ4JBAiboMRcqJZRBnFJvdlu8MnDShSW8ZLYibXLlcJ0ibibrQ/640?wx_fmt=png&from=appmsg "null")  
  
  
磐石应用服务器  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWqQyGfHYc6dBSkFjraWKtwzJ9VdHTosXApILEVVYAySkg01nyZaSRLQ/640?wx_fmt=png&from=appmsg "null")  
  
  
磐石媒体网关  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWZkV0jowqVlAwCDlLp4Wvkic5V5bAtaRjg6NLppzVmHOibdz2KxibmQ62w/640?wx_fmt=png&from=appmsg "null")  
  
### 通过弱口令爆破获得主机权限2台  
  
[+] SSH:10.2.7.42:22:admin  
  
[+] SSH:10.2.7.41:22:admin  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWUEFl2RuNjAqLR11HCmAh2ia2b83GjLSaFRFYHKMoMjA46PZuWpaicdFg/640?wx_fmt=png&from=appmsg "null")  
  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWvia19mdEibgdw8Q5iaDAEmIIaXxCfPSwm8PT0l66f7eYJeczicxkRyM4OA/640?wx_fmt=png&from=appmsg "null")  
  
  
active mq后台管理员权限  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQW1CJAQsg7B1zZPWyXdd5CbrwcMicbN3y8f8abFPoL0TJ4sZib8EUOdv6w/640?wx_fmt=png&from=appmsg "null")  
  
# 新的网段收获  
  
在该weblogic中发现主站内网地址并且可以连通。需要注意的是这里主站的内网ip地址变化到了10.0.2.X段（后面会说明该网段是核心内网段）  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQW1G1AWTywAbgMg9hpPYNhSBSGDouOmJsh24GIbJ8CgrTgQ9x4o0Fw8g/640?wx_fmt=png&from=appmsg "null")  
  
  
如图所示，通过ping命令测试发现，只有在10.2.3.33上才能访问核心内网10.0.2.0/24网段（仅仅在vpn入口是没有办法ping到核心内网网段机器的），证明已突破至内网强隔离至核心业务网段  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWnzQfLU7IfK5dxHayyHmLWHuholoYe8AQnq56JNSGdoh9RMUqoNNpqA/640?wx_fmt=png&from=appmsg "null")  
  
  
内网访问官网主站  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWUrPh6eL29PtUJjc1RwOdThuhd0Rqt4eAM8O8b3UFAicBsg06yDSzhbg/640?wx_fmt=png&from=appmsg "null")  
  
  
另一套办公系统  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWV2JYPMefJgn6myibNSHnI2ghLhia5QY0pDfFr0NEZibjxIGaLMN8QNIAg/640?wx_fmt=png&from=appmsg "null")  
  
### 通过redis未授权访问写入公钥获得主机root权限  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQW9cZFJWiaWmMqiaj5g3axdU1Ex3DhvIdIhLRUe2p4YcVJiaRXYjkvYbibqA/640?wx_fmt=png&from=appmsg "null")  
  
### 通过弱口令爆破获得主机权限 2 台  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWclBvFwYXZJSUTAOsxBYzEJFWN9t2mslYE98KqiaicJwVCIEBiaU5gryyQ/640?wx_fmt=png&from=appmsg "")  
  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWAZ4cOWbghNRXGdt60KyoNOvJsYHiaibLpxMeBXSeMb7KO30PsqhMDSfg/640?wx_fmt=png&from=appmsg "null")  
  
  
waf服务器权限  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoWcxthRLCuvYff2LHEWBQWAq9A7Re6tKRzRFIo4CymxGNjyRkIsNBApica24tFRQCTnEugIexol2w/640?wx_fmt=png&from=appmsg "null")  
  
  
又是一个小时很快过去了，但是由于该网段没有扫描出特别有价值的系统，而且目标已经连同域控等被打穿了，就没有再花费时间渗透了  
# 渗透重要成果梳理  
  
获取域控服务器权限，可控制大部分核心业务服务器  
  
通用弱口令X6  
  
办公后台X6  
  
内网redis主机X2  
  
内网弱口令主机X2  
  
内网web后台管理员X5，waf后台管理员X1  
  
这个报告怎么说也得有小1W吧。  
# 总结  
  
1.这次总的来说花了很多时间，最后还是打穿了目标内网，中间实践了很多平时练习的方法，学习到了很多的知识，但是有时候的灵光一闪，真的让人欣喜若狂。  
  
2.有一位大佬曾经说过：守需要考虑的是一个面，而攻只需要一个点。一定一定要细心。在打红队时，不要放过任何一个C段，也不要忽略任何一个很微小的信息泄露，在整个流程中每一个环节都显得尤其重要。  
  
3.类似域控服务器或者vcenter这类集权系统非常重要，一旦被锁定拿下，分数非常高的。相反，企业也应该及时对集权系统维护更新，保护资产安全。  
  
   
  
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，  
  
所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**没看够~？欢迎关注！**  
  
  
**分享本文到朋友圈，可以凭截图找老师领取**  
  
上千**教程+工具+交流群+靶场账号**  
哦  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
******分享后扫码加我！**  
  
**回顾往期内容**  
  
[零基础学黑客，该怎么学？](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247487576&idx=1&sn=3852f2221f6d1a492b94939f5f398034&chksm=fa686929cd1fe03fcb6d14a5a9d86c2ed750b3617bd55ad73134bd6d1397cc3ccf4a1b822bd4&scene=21#wechat_redirect)  
  
  
[网络安全人员必考的几本证书！](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247520349&idx=1&sn=41b1bcd357e4178ba478e164ae531626&chksm=fa6be92ccd1c603af2d9100348600db5ed5a2284e82fd2b370e00b1138731b3cac5f83a3a542&scene=21#wechat_redirect)  
  
  
[文库｜内网神器cs4.0使用说明书](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247519540&idx=1&sn=e8246a12895a32b4fc2909a0874faac2&chksm=fa6bf445cd1c7d53a207200289fe15a8518cd1eb0cc18535222ea01ac51c3e22706f63f20251&scene=21#wechat_redirect)  
  
  
[重生HW之感谢客服小姐姐带我进入内网遨游](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247549901&idx=1&sn=f7c9c17858ce86edf5679149cce9ae9a&scene=21#wechat_redirect)  
  
  
[手把手教你CNVD漏洞挖掘 + 资产收集](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247542576&idx=1&sn=d9f419d7a632390d52591ec0a5f4ba01&token=74838194&lang=zh_CN&scene=21#wechat_redirect)  
  
  
[【精选】SRC快速入门+上分小秘籍+实战指南](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247512593&idx=1&sn=24c8e51745added4f81aa1e337fc8a1a&chksm=fa6bcb60cd1c4276d9d21ebaa7cb4c0c8c562e54fe8742c87e62343c00a1283c9eb3ea1c67dc&scene=21#wechat_redirect)  
  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
  
  
