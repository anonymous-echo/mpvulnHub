> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyNjczNzgzMA==&mid=2247484597&idx=1&sn=84da85ef4d69cf4890bc6e41046a93a9

#  公益SRC平台“刷洞”技巧总结  
原创 haosha  网安日记本   2025-06-27 07:00  
  
**免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。**  
  
**前言**  
  
    自从上次发布了一篇   
“CNVD漏洞和证书挖掘经验总结” 之后好久没有发布过类似的总结文章了（回去看了一眼有的部分写的有点烂，有机会的话 “重置” 一下，重新发一遍）。加上群里有一些师傅确实问了相关问题，感觉还有有必要写一篇  
 “刷洞” 总结类的文章，至少帮助师傅们实现一下从0到1的突破。（这里也强调一下，一定要遵纪守法，不能破坏业务系统、获取敏感数据）  
  
    这里还是和之前一样总体分为了 “事件型” 和 “通用型” ，并且只总结了我 “刷” 过的平台，本人比较菜，确实没刷过  
CVE，后面有时间也会尝试刷一下，有需求的话也会总结一下发出来。  
  
一、事件型  
  
    首先盘点一下公益SRC收录事件型的平台（具体收录标准还是要以平台规则为主）：  
  
     
 1、CNVD（收录国企、央企、事业单位、政府单位）  
  
      
2、  
补天（主要看网站权重）  
  
      
3、  
漏洞盒子（全都收录）  
  
      
4、  
教育漏洞报告平台（主要收录教育系统，同时收录上海和黑龙江地区网站泄露敏感信息）  
  
      
5、CNNVD  
  
    这里我把  
CNVD、  
补天和  
漏洞盒子放在一起是因为它们  
 “刷” 洞方法是一样的，只是收录的单位不同。如果在自己本身实力达不到，挖不到漏洞的情况下就是需要去看nday、1day，可别小看nday的危害即使是过去了一两年，一样有单位因为疏忽会存在问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529c9mceLIOCOxyQfCwwe24DUEktPerGefsIJZ3HYiclctoIicSKy1gCTjwxVGdWJziajsNsGVLpFTy5vpA/640?wx_fmt=png&from=appmsg "")  
  
    同时，  
补天会不定期开放  
不限权重的活动，只要加入活动提交漏洞，它一样是不看权重都收的，这时也基本就和漏洞盒子差不太多了（但漏洞收录规则不同），并且活动奖励也还不错。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529c9mceLIOCOxyQfCwwe24DUENBt83sKibDoSz81AW0ia7GoeLVlFcG9wrPribUxWPRDp9LdyJicfjzvfLg/640?wx_fmt=png&from=appmsg "")  
  
      
教育漏洞报告平台（EDU SRC）与其他平台有所区别，虽然它一样能通过刷nday来挖掘漏洞，但是因为它有对行业的针对性，并且参与挖掘的师傅体量比较大，这么多年下来确实比较难碰到nday。  
  
    而平台本身因为只收录事件型漏洞（通用型需要拆开，分别提交目标单位归属资产，但是同一个漏洞多次提交后rank值会逐步下降），所以他的刷分技巧更需要你有能够挖掘通用漏洞的能力。个人感觉来说  
教育漏洞报告平台（EDU SRC）  
更适合前面刷洞之后的进阶，需要你拥有针对目标资产进行漏洞挖掘的能力，适合在挖掘企业SRC前的一个过渡。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529c9mceLIOCOxyQfCwwe24DUEicfGELFORXkF2amf5JevIOBhwPUVS31y59AfurcoKt0yfXt7qVa91lw/640?wx_fmt=png&from=appmsg "")  
  
      
CNNVD平台这里我没有写收录标准，原本我是以为和  
CNVD平台收录标准差不多的，但是我在3月份提交了一次漏洞，一直到文章发布的时间已经过去了3个月都压根没有审核，所以实在是摸不清楚，也就不太建议提交事件型漏洞到  
CNNVD平台。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529c9mceLIOCOxyQfCwwe24DUEVIyJP8qIUcU0QM6qMJbQn4RQibloAOs3ryeQZnZicKByFCWFnsBzYEeg/640?wx_fmt=png&from=appmsg "")  
  
  
二、通用型  
  
    同样先盘点一下公益SRC收录通用型的平台  
（具体收录标准还是要以平台规则为主）：  
  
      
1、CNVD  
  
      
2、  
漏洞盒子  
  
      
3、  
CNNVD  
  
    说到  
CNVD和  
CNNVD平台大家肯定都想要一张证书来证明自己。这里也有一个师傅们经常有的误区，认为只有满足5000W资产（实缴资金）的单位的通用产品  
CNVD才会收录，实际上通用型漏洞满足漏洞要求的话不论资产是都收录的，5000W只是颁发证书的标准，不是收录标准。  
  
    而  
CNNVD平台的颁发证书标准则要高的多，只给高危通用漏洞颁发证书，但是  
CNNVD平台的高危漏洞是需要看资产量的，有一些RCE漏洞不满足资产量级也评不到高危。  
  
    那其实通用型漏洞各家平台收录的资产标准都差不多，为什么我要留下这个三家平台呢？因为它们收本身收录漏洞的标准比较低下面我就给大家一一分享一下。  
  
    首先就是  
CNVD平台，今年也已经有好多师傅发过刷这种漏洞的方法了，就是通过FOFA、鹰图去搜集资产，找一些未授权、弱口令的漏洞，如果运气好达到5000w资产标准甚至能拿到CNVD证书（弱口令必须是设备类型的弱口令）。  
  
    设备弱口令漏洞自然不必多说，未授权漏洞是怎么刷的呢。比如打印机未授权，只要不需要登录直接控制打印机，就算未授权，同理其他设备不需要登录直接控制也能作为未授权漏洞。再比如摄像头未授权，不需要登录直接能看到监控画面同样是未授权漏洞，所以刷的方法是有很多的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529c9mceLIOCOxyQfCwwe24DUEeZdnVhX94Q2jdaeLyiar3yQYI0kxYES4icJqt6Wv8sVnZBv9XX3C3F7g/640?wx_fmt=png&from=appmsg "")  
  
    接着是  
漏洞盒子，它基本上也是什么都收的（主要是因为它收录反射型XSS），但是平台本身没有什么奖励，所以可能大家刷起来也没什么动力。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529c9mceLIOCOxyQfCwwe24DUEF8WsiabvtoibeDNocvUMpmibhx7ADwkTKy4MYI8iaTte6j87A4xwLZE0kw/640?wx_fmt=png&from=appmsg "")  
  
    最后是  
CNNVD平台，这里为什么我将这个平台我放在最后呢，因为通过刷了几次之后我发现  
CNNVD平台除了审核速度慢，几乎没有缺点，甚至没有经验的师傅都能刷，下面就是我  
推荐他有三个原因  
。  
  
    第一个就是它和前面的  
CNVD  
平台一样，可以刷未授权漏洞，不过弱口令漏洞  
CNNVD平台是不收录的。  
  
    第二个就是如果你挖掘的漏洞在  
CNVD平台重复了，可以试试提交到  
CNNVD平台，目前确实  
CNNVD平台收录的漏洞还比较少，重复率低，所以相对收录概率比较高。  
  
    第三个就是在  
CNVD不收录的反射型XSS，  
CNNVD平台也是同样收录，并且给了我中危的评级（但确实不清楚他的评级是怎么做的，因为后面跟其他师傅沟通的时候发现多数评分还是正常的，给了低危）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529c9mceLIOCOxyQfCwwe24DUEhAYQyFgsEkP1BVLqqVVEqfOqTWM0Hb1V5A7aQTnvdgwdzBHVZX4jEA/640?wx_fmt=png&from=appmsg "")  
  
结尾  
  
    最后还是要强调一下，  
一定要遵纪守法，不能破坏业务系统、获取敏感数据。祝各位师傅都能时常出洞，挖掘通杀。  
> “CNVD漏洞和证书挖掘总结”文章地址  
  
> haosha，公众号：网安日记本[CNVD漏洞和证书挖掘经验总结](http://mp.weixin.qq.com/s?__biz=MzkyNjczNzgzMA==&mid=2247484095&idx=1&sn=10701e77afd0395e4ff6810239c14919&chksm=c233f676f5447f6045a556340fc3c40ae74bd54e42af15a343e87e017ef6cf7346e84e196030#rd)  
  
  
  
