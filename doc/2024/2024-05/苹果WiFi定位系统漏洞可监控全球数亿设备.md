#  苹果WiFi定位系统漏洞可监控全球数亿设备   
安信安全  安信安全   2024-05-28 17:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/huXmkb12LiaK4J19rzVWNVvxic9tpqrWad4aon6RmYicuu94zLiaxibDn1NtoXbBriaibSUd2egTM6Z2nlOib3knFhNasA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/huXmkb12LiaKmVYiarv6fkQr9mPH9kX6a8zWmdOHsmfkrqgaE7xFCFSSSFZnmPk1rlqjNMeJhwF7Jc3M01xNw5Jw/640?wx_fmt=jpeg "")  
  
  
近日，美国马里兰大学的安全研究人员发表论文披露苹果设备的Wi-Fi定位系统（WPS）存在安全设计缺陷，可用于大规模监控全球用户（不使用苹果设备的人也会被监控），从而导致全球性隐私危机。  
  
  
研究者还在俄乌战场和以色列哈马斯加沙冲突地带实际验证了该漏洞的有效性和危险性。  
  
  
**比GPS更可怕的WPS定位：可监控全球数亿台设备**  
  
  
随着人们对  
位置服务  
的需求日益增加，移动设备也更依赖于频繁且精准的地理位置信息。这些服务包括地图导航、广告推送、游戏定位以及丢失或被盗设备追踪（例如苹果的“查找我的设备”功能）。然而，由于耗电量过高，GPS并不能满足如此频繁的定位需求。  
  
  
为解决这一难题，苹果和谷歌等科技巨头推出了基于Wi-Fi的定位系统(WPS)。该系统允许移动设备通过查询服务器上的Wi-Fi接入点信息来获取自身位置。简单来说，使用过GPS定位的移动设备会定期向WPS上报所观察到的Wi-Fi接入点的MAC地址（即BSSID）及其对应的GPS坐标。WPS服务器会存储这些上报的  
BSSID  
位置信息。  
  
  
之后，其他不使用GPS的移动设备也可以通过查询WPS服务获取位置信息。设备查询涉及发送附近BSSID及其信号强度的列表到WPS。  
  
  
总之，WPS为客户端设备提供了一种比全球定位系统（GPS）更节能的定位方式。对于移动设备，WPS的耗电量也显著低于GPS。苹果是几家运营WPS的大型科技公司之一，其他公司还包括谷歌、Skyhook等。  
  
  
由于常用的WPS系统（尤其是苹果和谷歌的系统）都是公开可访问的，并且不会要求查询数据库的设备证明其确实能看到所声称的BSSID。换句话说，任何人都可以通过查询任意MAC地址来定位跟踪个人（如果该地址存在于WPS数据库中，服务器就会返回其位置信息）。  
  
  
例如，遭受伴侣暴力的人搬到了一个未公开的地址，他们的前伴侣可以通过BSSID定期查询WPS，直到受害者的Wi-Fi接入点（或旅行调制解调器、启用Wi-Fi的电视等）的位置出现，从而泄露受害者的位置信息。  
  
  
通常来说，这种基于BSSID查询的WPS定位需要攻击者事先了解目标信息（例如MAC地址），并且攻击对象仅限单个目标。  
  
  
近日，在题为《通过Wi-Fi定位系统监视大众》的论文中，美国马里兰大学博士生ErikRye和副教授DaveLevin介绍了一种全新的苹果WPS查询方法，可被滥用于大规模监视，甚至不使用苹果手机（以及Mac电脑和iPad等苹果设备）的人也可被监控。  
  
  
这种全新的WPS查询方法能够监控全球范围内的设备，并可以详尽地跟踪设备进入和离开目标地理区域。研究者对苹果WPS提供的数据进行了系统的实证评估，发现这些数据涵盖了数亿台设备，并且允许我们监控Wi-Fi接入点和其他设备的移动情况。  
  
  
**苹果的WPS最危险**  
  
  
根据论文描述，WPS一般以两种方式之一作出响应。  
  
  
WPS定位主要又两种工作方式：要么计算客户端位置并返回这些坐标，要么返回提交的BSSID的地理位置（与AP硬件相关联），并让客户端进行计算以确定其位置。谷歌的WPS采用前者，而苹果的WPS采用后者。  
  
  
研究人员指出，谷歌和苹果的WPS系统在基本工作原理上有根本区别，苹果的系统由于其开放性，为安全研究人员和潜在的攻击者提供了进行这项研究的途径。  
  
  
研究人员指出，苹果的WPS系统特别“热情健谈”（下图）：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvalZEMIVkXibheibScSCnbGSzwlWpd3e01EWSeefE0llFBUZL5CQ4Ir9dQyY9liayVpNNTlZmWlCknrA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
论文指出：“除了客户端提交的BSSID的地理位置，苹果的API还会随机性地返回多达数百个附近BSSID的地理位置。”  
  
  
“在苹果的WPS版本中，用户提交BSSID进行地理定位，苹果WPS则会返回其认为的BSSID位置，同时返回的还包括用户未请求的多达400个附近BSSID的位置。这400个额外的BSSID对于安全研究人员/黑客的研究非常重要，因为它们允许研究人员在短时间内积累大量的地理定位BSSID。此外，苹果的WPS服务接口没有设置认证或速率限制，可以免费使用。”  
  
  
相比之下，谷歌的WPS则仅返回计算出的位置，并且经过认证、速率限制和收费，使得进行类似攻击或安全研究变得难以负担，因此比苹果的WPS要安全得多。  
  
  
**俄乌战争和以色列哈马斯冲突实战案例**  
  
  
利用苹果WPS系统的设计缺陷，Rye和Levin获取并编译了一个包含4.9亿个BSSID的全球数据库，从而可以追踪全球大量个人和人群（包括军事人员）的移动。  
  
  
论文解释道：“由于苹果WPS的精度在几米范围内，这使我们在许多情况下能够识别出AP所在的个人家庭或企业。出于对用户隐私的尊重，我们在本研究中审查的案例中不包括可能公开识别个人的例子。”  
  
  
尽管如此，研究人员表示，使用论文中描述的技术“显然有可能”确定个人或他们所属群体的身份，“可以精确到个人姓名、军事单位和基地，甚至是房车停车场。”  
  
  
为了进一步展示利用WPS进行开源情报(  
OSINT  
)潜在的攻击手法，研究者分享了几个重点案例研究，包括：  
  
- 俄乌战争：研究者首先利用苹果的WPS分析了进出乌克兰和俄罗斯的设备移动情况，从而获得了有关正在进行的战争的一些见解（这些见解尚未公开）。研究者发现疑似军用人员将个人设备带入战区，暴露了预部署地点和军事阵地。研究结果还显示了一些离开乌克兰并前往世界各地的人员信息，这验证了有关乌克兰难民重新安置地点的公开报道。  
  
- 以色列-哈马斯加沙战争：研究者使用苹果的WPS追踪加沙地带居民的离境和迁徙情况，以及整个加沙地带设备的消失情况。该案例研究表明，研究者可以利用苹果的WPS数据跟踪大规模停电和设备丢失事件。更糟糕的是，被追踪设备的用户从未选择加入苹果的WPS，在研究者进行这项研究时也没有退出机制。仅仅处于苹果设备的Wi-Fi范围内，就可能导致设备的位置和移动信息被广泛公开。事实上，研究者在苹果的WPS中识别了来自1万多家不同厂商的设备。  
  
  
  
**防御措施：IEEE不作为，马斯克遭到表扬**  
  
  
研究团队已将发现报告给苹果、  
Starlink  
和GL.iNet，并建议通过在AP的WiFi网络名称中添加“_nomap”字符串来防止BSSID进入WPS数据库。苹果已在其隐私和位置服务帮助页面中增加了对“_nomap”的支持，而谷歌和WiGLE则早在2016年就已支持这一措施。  
  
  
此外，研究人员建议实施BSSID随机化，以防止通过WPS追踪。这一措施得到了SpaceX产品安全团队的迅速响应，他们在所有Starlink设备中加快了BSSID随机化的实施步伐。然而，GL-iNet对这一建议的反应不积极，表示暂无计划部署该防御措施。  
  
  
尽管目前业界尚未意识到将BSSID随机化纳入WiFi标准工作的重要性和紧迫性，研究人员希望这项研究能引起IEEE技术专家的重视，推动这一问题的解决，就像过去推动MAC地址随机化那样。  
  
  
Rye指出：“BSSID随机化是防止通过WPS追踪的最有效的防御措施，因为每次设备启动（或移动位置）时生成一个随机标识符，将使其在WPS中看上去像是一个完全不同的设备。”  
  
  
Rye还称赞了SpaceX的产品安全团队迅速解决这一问题并在其产品中实施BSSID随机化的举措。  
  
  
Rye透露：“在我们的研究期间，一些厂商的产品已经开始实施BSSID随机化，但星链对安全的重视程度显然更高；与研究者交流后，星链加快了在所有星链设备上实施的步伐。值得注意的是，这一漏洞并非由SpaceX引起（他们无法控制苹果或谷歌的行为），但他们仍然及时且正确地解决了这一问题。”  
  
  
研究人员还通知了旅行路由器制造商GL-iNet，但该公司反应不积极。Rye表示：“他们承认了研究者的担忧以及随机化BSSID的解决方案，但告诉我们他们没有计划部署该防御措施。”  
  
  
Rye计划在8月的黑帽大会上展示这篇论文。  
  
  
论文链接：  
  
https://www.cs.umd.edu/~dml/papers/wifi-surveillance-sp24.pdf  
  
  
**END**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/huXmkb12LiaJ7eQfFyBTbBqo3wtiaia9XUsVG1mGlgvQLA2GibZoVrhgcpUPUEXRpRB3c2lKYvJt0JQbweEK0pdUww/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/huXmkb12LiaLicaBu5IHq7LKAG7mJSoU4DnXkcNSSDEvgxBfKgwfxuWoqgF5Xl3jclEFrNPUe8wmMUDU3k7dxrAA/640?wx_fmt=other&wx_co=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/huXmkb12LiaLicaBu5IHq7LKAG7mJSoU4DnXkcNSSDEvgxBfKgwfxuWoqgF5Xl3jclEFrNPUe8wmMUDU3k7dxrAA/640?wx_fmt=other&wx_co=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**往期精选**  
  
                      28     
May  
   
2024  
  
  
●[喜讯丨安信安全荣获CNAS检验机构认可证书](http://mp.weixin.qq.com/s?__biz=MzAxNTYwOTU1Mw==&mid=2650086210&idx=1&sn=6d0619e9ccac46a540b76060098dddb8&chksm=8380c0fcb4f749ea0b05eef68c9336f096803dd08131c198d07c1c59638e10db3714d1122550&scene=21#wechat_redirect)  
  
  
●[前沿 | ChatGPT——人工智能是把“双刃剑”](http://mp.weixin.qq.com/s?__biz=MzAxNTYwOTU1Mw==&mid=2650077773&idx=2&sn=d2a979a7ef0301fcadbcbb0109587be5&chksm=838121f3b4f6a8e55c545acbc68966dda860f25ebef7f722ddac015c5be9f22577ef40c59d6d&scene=21#wechat_redirect)  
  
  
●[法治 | 防范新型网络传销 守护民众财产安全](http://mp.weixin.qq.com/s?__biz=MzAxNTYwOTU1Mw==&mid=2650077685&idx=2&sn=dcffdd9a3ee608eeeb7db29a06b77161&chksm=8381224bb4f6ab5d8e3e0b79f8e4457d5c91de91cf9154cd38720773ea451206f525ce735a0f&scene=21#wechat_redirect)  
  
  
