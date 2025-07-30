#  【极思】一个伪0day的抓捕实录   
 A9 Team   2025-05-05 02:10  
  
“ 文章中质量较好的，有意义的文章已经让朋友帮助备份到这里，等极思和A9关停后，还能找地方看到。五一劳动节全程在劳动，修过电灯吸过尘，陪过家人写过文。没有旅行的五一，也可以是完美的五一。  
[【极思】安全运营第6年实践总结](https://mp.weixin.qq.com/s?__biz=Mzk4ODI3MDY1Mw==&mid=2247483758&idx=1&sn=abee175cf42993c217dddcf2ccc41d22&scene=21#wechat_redirect)  
  
”  
  
##   
## 零、前言  
  
如果你问一个职场人员最6的是啥，大部分人会回答你是Boss，如果你问一个安全行业的职场人员最6的是啥，你得到答案一定不是Boss，而是Zero-day。它在信息安全人员心中，是无所不能，无所不破的，最可怕且没有之一。不过，它也无比的昂贵，一个可远程命令执行的Zero-day，能卖10万…………不是￥，是$。所以信息安全人员，如果被Zero-day攻击了，不是你倒霉，那只能证明你身价高。  
  
为啥说是伪Zero-day，因为我们响应的时候发现，几小时前POC在GitHub被公开了。看着发布时间，我在想如果再晚几时发布，我就就抓到一个Zero-day。不过转念再一想，如果不发布谁拿来打你啊，我真的天（bu）真（pei）啊。  
## 一、发现安全告警  
  
来来来，回正题。话说，2月27日下午正在开会。突然，我们的安全运营自动化系统，把TDP（微步）告警发到了企业微信群中，直接上图（不过是有码的）。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/hojPFbfiayfxdsFn0uuXG8ThJCaNSGqefohKy7flyibqkubNO5gZz7aVP3D4jV3gjiafOTgwriaibaebznAF7rjcyyw/640?wx_fmt=jpeg "")  
  
想到告警在上班时间要求30min内必须响应，要不然得贡献一小瓶酸奶（别乱想）。直接上告警响应流程图。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hojPFbfiayfyJuWibiaNC1C6dgjqqP1vhJictbqkbGfqRMWNatp3hOkmK238xoRvdMgAlTIc5Faic3V7xxccNRNIUPQ/640?wx_fmt=png "")  
  
从第一步开始，发现告警先判断真伪。源IP来自互联网，目标IP为内网，紧张度+1。Weblogic经常出漏洞，紧张度+1。远程代码执行漏洞，紧张度+1。此类漏洞攻击特征明显，且TDP平常很少误报，紧张度+2。吓得我赶紧点击超链接，1s直达告警详细页面（得瑟一下）。  
  
打开告警链接，查看包体内容，竟然是流量关键字匹配，找到自动标红的攻击代码，通过LDAP加载了class文件，紧张度+3。已经没有可能是误报了（快哭了）, 嗯嗯有可能是红队在打我们。赶紧把红队小组长叫来，确认到不是红队干的（要裂开了）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hojPFbfiayfyJuWibiaNC1C6dgjqqP1vhJicQXZtwxicn16LuvYLVTdh6ITfADb7qsaqZ9dP5wfd8jAK6LzZB1mXYZg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hojPFbfiayfyJuWibiaNC1C6dgjqqP1vhJic5RTKSLlRq8DGwhXKoic1gBMera0FkexK1OMORdTwheK6qG1Wp5BjV3g/640?wx_fmt=png "")  
  
发现告警阶段，处置原则，如果攻击是真的，且攻击影响较大，立即报告领导。想到漏洞有编号CVE-2023-21839，立即让情报小组查漏洞的详细信息。得到回复，此漏洞在1月17日公开，官方发布了补丁，一直没有公开EXP，但今天上午，此漏洞的EXP突然在网上大范围流传。  
  
## 二、攻击行为抑制  
  
立即进入安全资产管理系统查询受害服务器，同时心里一万只草泥马在奔腾，谁的主机1月17的漏洞情报工作通知，到现在还没有修？我一定要上双周会通报他。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/hojPFbfiayfxdsFn0uuXG8ThJCaNSGqefCFc4dDtymKJH9Wl5MYqe9GMtdbnLTh4Avx8ktcgJ8wGFDz6JHN9SPQ/640?wx_fmt=jpeg "")  
  
点开查询页面的时候我乐了，受害服务器是一台蜜罐，而且还是为HVV准备的。这会感觉有个蜜罐真是不错（shuang），这下只需要静静的做个观众了，等了半小时没有发现下一步攻击动作，今天又天（chu）真（chou）了。自动化发出的攻击，有谁会在意呢。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hojPFbfiayfyJuWibiaNC1C6dgjqqP1vhJic4omyppXd0jy7f2QVaK42DwDsXedTib8jePBhc0t2ZBvc18mpyJrBFFQ/640?wx_fmt=png "")  
## 三、最后的挣扎  
  
突然发现，第三阶段的攻击入口分析，第四阶段的缓解或修复措施，第五阶段的事后隐患排查，第六阶段的事后复盘改进，都不需要了？我激动的内心中竟然有些遗憾，难道我不应该开心吗？不对，我还可以加一个阶段，反击，对反击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hojPFbfiayfyJuWibiaNC1C6dgjqqP1vhJicjnk5NgkHibgabQLxlHSeht4Gkd9DD5h4IPzHG4T3r6YL0hEicicdQiaGKw/640?wx_fmt=png "")  
  
利用告警内容中的反弹链接地址，下载攻击者所用的class文件，反编译后找到了攻击者控制机，这个域名是攻击者的C&C服务器。通过查询域名注册信息，没有得到有用的信息。通过漏洞扫描，也没有找到有用的漏洞。最后通过微步的X社区和Virus Total查询域名，发现有一些关联的恶意样本，通过查看恶意样本的沙箱行为，也没有找到有用的信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hojPFbfiayfyJuWibiaNC1C6dgjqqP1vhJicojk1ZkWJqN7USE0ribgHuoVzuTu5BWaCETAa9RaLtVH5afpUEb6gPIQ/640?wx_fmt=png "")  
  
后记，找ThreatBook要了一份漏洞的详细分析报告，让红队的同学进行了复现。没想到的是，他们在去年就已经掌握了此漏洞，这就是￥的力量么。同时，也在每周一的学习会上进行了分享。[【极思】A9 Team 不负韶华](http://mp.weixin.qq.com/s?__biz=MzI2NTMwNjYyMA==&mid=2247484652&idx=1&sn=a8592cec1594492b7fd95638a9ddf3bb&chksm=ea9e2c7fdde9a569f2fb291b46b6f1b5e19540eb5cc5585077afbc3a675ded9c9a83d808fdff&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hojPFbfiayfyJuWibiaNC1C6dgjqqP1vhJicqoKJLYF24S2zeUa2eJouAB9YqjU1EFMwqFxv7iaic8DPYdPa6BoBd6qA/640?wx_fmt=png "")  
## 四、最后的礼物  
  
网络安全无小事，胆要大但心要细。看似不多的处置过程，每个动作都是经过上百次的打磨，才能做出最正确的反应。冰冻三尺，非一日之寒。铁杵成针，亦非一日之功。当然，安全运营也不是一人能行，行业安全需要国家（yeye）、监管（baba）、同行（xiongdi）、供应商共同努力，守望相助才能真正做好。告警响应流程图供参考（需要原图请后台留言+  
转发文章）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hojPFbfiayfyJuWibiaNC1C6dgjqqP1vhJicn4K3kATnmibNeLlKdkJYbbz7UKAUrCRv9lwmiabiaaOM30PicYtb3LOARQ/640?wx_fmt=png "")  
  
  
**点赞+在看+关注 - 就不会走丢了**  
  
  
