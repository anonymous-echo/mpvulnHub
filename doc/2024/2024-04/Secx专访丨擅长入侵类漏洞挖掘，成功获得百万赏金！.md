#  Secx专访丨擅长入侵类漏洞挖掘，成功获得百万赏金！   
 Timeline Sec   2024-04-21 18:30  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Go7NSXrKWd67cvyI44KpiaSImuTeribZibA5N4A9q70DJwgVm1DmMhiaOoQXHG807k4eA2LdDYqI6Gy7eyIdtGoV9w/640?wx_fmt=jpeg&from=appmsg "")  
  
大家好，我是Secx，深耕网络安全领域多年，目前在某互联网大厂从事安全研究工作。同时，我也是知名安全团队Timeline Sec SRC组技术负责人，以专业的技术和敏锐的洞察力，为团队的安全防御提供了坚实的支撑。  
  
2021年末，我步入白帽挖洞行列，至今挖掘出多个高危漏洞，并成功获得了总计超过100W的赏金，在多家SRC（安全漏洞响应中心）排行榜中名列前茅，包括字节跳动、深信服、魅族等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bL2iaicTYdZn6Y5S74gNB1FSj30Aedia4MmLo31zbLje5zovibVQKKKYV8tA2VE5APLEZOVP5HtLBA70RsialodD20g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Go7NSXrKWd67cvyI44KpiaSImuTeribZibAjIYFg76dGPou6oCvq7fAP5ibCmECtuYsmFTHKrGsj92JZEKkGtBw1lA/640?wx_fmt=png&from=appmsg "")  
  
  
**访谈内容**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MPS72cibJRUCS4kMwwpc6Jwl0ho33q4PIia1zGricOOA5UEZD1YP55ZLg0OmVJaR5CMKCJyxx2PFVkdIxu3vicnjSA/640?wx_fmt=png&from=appmsg&wx_ "")  
  
01  
  
**成长之路：不止热爱，更要努力探索**  
  
从一个网络安全爱好者成长为挖洞达人，我的挖洞之旅可以说是充满了挑战与收获。今天，我想和大家分享一些好用的挖洞技巧与方法，希望能为同样热爱这个领域的你带来一些启发。  
  
曾经，我只是一个对网络世界充满好奇的探索者，对挖洞一无所知。但当我开始站在开发者的角度去思考，分析他们在开发功能模块时可能会遇到的风险点，仿佛打开了新世界的大门。我开始深入理解代码的逻辑，尝试找出其中的漏洞，这个过程既充满挑战又让人兴奋。  
  
然而，挖洞并不是一蹴而就的事情。每当我发现一个低危漏洞时，我并不会急于提交报告。相反，我会尽可能地举一反三，思考如何提升这个漏洞的危害程度，这种对漏洞的深入挖掘让我逐渐积累了经验，也让我在挖洞路上走得更快、更远。  
  
最后，我想说，加入一个技术氛围浓厚的安全团队，是我成为挖洞达人的重要一步。在Timeline Sec这样的团队中，我与强者们交流思想、分享经验，每一次讨论都为我带来新的启发。我们一起探讨、共同进步，这种氛围让我不断成长，也让我更加坚定了自己在网络安全领域前行的决心。  
  
如今，我已经从一个萌新小白成长为挖洞达人，但我深知，网安之路永无止境，我将继续前行，不断挑战自我，为保护网络安全贡献一份力量。  
  
02  
  
**一次刻骨铭心的挖洞经历**  
  
挖洞多年，我一直喜欢入侵类的漏洞，例如RCE、SSRF、XXE这些能拿到权限的洞，它就像一把利剑，往往能够“一招致命”。  
  
举一个让我印象最深刻的挖洞经历。有一次，我像往常一样，沉浸在代码的海洋中，分析着某公司网站的js源码。突然，一个github项目地址引起了我的注意。好奇心驱使下，我翻查了该项目的源码，意外地发现系统使用了jwt秘钥。  
  
我决定将这个项目拉到本地运行，经过一番努力后，终于成功搭建起了本地环境，并利用泄露的jwt秘钥生成了一个认证token。这个token仿佛是一把钥匙，让我能够自由地操作任意接口，我选择了新建账户的接口作为突破口，利用生成的token成功添加了一个  
未授权账户，并顺利进入系统后台。  
  
进入系统后，我并没有满足于此，继续深入分析开源系统源码，寻找可以利用的漏洞。终于，在一个可以触发python脚本的地方，我发现了突破口，通过仔细审计源码中对执行python代码的限制，成功绕过了原有的安全机制，利用执行python代码的方式拿下了该系统的shell权限。  
  
这一刻，我感受到了前所未有的兴奋与成就感，继续对该公司进行资产排查，发现这个漏洞竟然是一个通用系统漏洞，影响到了该公司互联网资产1k多条，我立即将这个漏洞上报给了相关机构，并成功获得了CVE编号。  
  
这次挖洞经历是我职业生涯中的一次重大突破，我不仅收获了挖洞以来最高的赏金，单个漏洞的赏金高达3W+。更重要的是，这次经历让我深刻体会到了网络安全的重要性，也让我更加坚定了对网络安全技术的深入研究与探索。网络安全不仅仅是技术层面的问题，更是涉及到系统安全、业务安全的综合保障。只有通过对系统的全面了解和深入剖析，才能真正发现潜在的安全风险，并采取相应的措施进行防范和应对。  
  
因此，我将继续深入研究网络安全技术，不断提升自己的技能水平，为企业的系统安全和业务安全提供更加坚实的保障。我相信，在未来的网络安全领域，我将能够发挥更大的作用，为行业的发展贡献自己的力量。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MPS72cibJRUCS4kMwwpc6Jwl0ho33q4PIOamtKDBLjzA4oKJQ9XpoOjOW57NTAEnZxmrWqIG9Aq28Y8qfJDgeUA/640?wx_fmt=png&from=appmsg&wx_ "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Go7NSXrKWd6OVeWCsBTW53hPhJicjSkzyqvTjAqdX6aUK4K6nQYcElp51HdIiaSV2amJibBL4CNRfCH95BadcB3fg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Go7NSXrKWd6OVeWCsBTW53hPhJicjSkzy4crDNo8icWRsXKlHzyFFiblcNMS368JXKlTYplQSjHzPvoaOYmgpvcCg/640?wx_fmt=jpeg&from=appmsg "")  
  
03  
  
**学习无捷径，细节是关键**  
  
多年的挖洞经历让我深刻体会到了“**勤思考、更细心、多交流**”的重要性。我意识到，网络安全的世界是如此的广阔，我不能只停留在自己擅长的领域，而是要勇敢地尝试不同类型的漏洞挖掘。同时，我也明白了代码功底的重要性，只有拥有扎实的代码基础，才能更好地理解系统的运行机制，发现潜在的安全隐患。  
  
对于那些刚刚踏入网络安全领域的新手小白们，**打牢基础是关键**。学习没有捷径可走，只有认真学好每一个技术细节，并进行实践操作来加深印象，才能在网络安全的世界中立足。同时，细心也是必不可少的品质，在挖洞的过程中，我们需要对每个数据包都进行尝试，不要放过任何一个可能存在的漏洞。当然，我们也要遵守法律法规，保护好自己和他人的利益。  
  
最后，我想说，网络安全是一个充满挑战和机遇的领域。只要我们保持对技术的热爱和追求，不断地学习和探索，就一定能够在这个领域中取得更大的成就。  
  
  
**实操平台推荐**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Go7NSXrKWd6OVeWCsBTW53hPhJicjSkzypQ0srBn9rdBwU8xrenDp7NFRsBRcL1YIopeY6Enibmc21vHPrrDgPicA/640?wx_fmt=jpeg&from=appmsg "")  
  
想要快速提升挖洞技能，一定要多进行实操训练，在众多的实操平台中，我个人推荐春秋云测，这里不仅是我多次参与众测活动的舞台，更是我在网络安全领域磨砺技艺的试炼场。对于实力出众的选手，春秋云测更是提供了定向邀请参加金融项目的机会，这无疑是对我们实战能力的一次极大提升。  
  
平台运营团队非常专业且负责任、响应速度快、对测试人员的需求都能  
及  
时给予且细致的回应。这种友好与尊重，让我深感在这里进行漏洞挖掘，不仅能够提升技能，更能够得到充分的支持与鼓励。  
  
因此，我强烈推荐那些希望深耕漏洞挖掘、提升实战能力的小伙伴们，一定要来春秋云测试试，这里不仅有丰富的众测活动等你来挑战，更有专业的运营团队为你提供全方位的支持与帮助。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Go7NSXrKWd5GUqNjDicnorYDHSvibJ9h7zm9n6r0k0F0JknV9fyOrsz08VGF8GgFjXMywUtP57xF5bgibHcPGmLoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
春秋云测会不定期上线测试项目，欢迎大家注册，随时接收最新项目动态。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgwIJ2svTmD3XNSpBFCOE6gibb1htNqzfLXzmP84LEa6mO3ia2pU4h4DcmgYqQRoaveLfHicICiaFKAsg/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
**END**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgwIJ2svTmD3XNSpBFCOE6gibb1htNqzfLXzmP84LEa6mO3ia2pU4h4DcmgYqQRoaveLfHicICiaFKAsg/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
  
  
**往/期/精/选**  
  
  
[挖洞路上，从来没有一无所获的付出！](http://mp.weixin.qq.com/s?__biz=MzUzNTkyODI0OA==&mid=2247525286&idx=1&sn=c6ad1a54a59dd7730c2bf83e8c5c4cc8&chksm=fafc2f71cd8ba6678bf21f180b697a2347354292b014872ec51c75962e4081e8f45be7c7d7a5&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzUzNTkyODI0OA==&mid=2247524369&idx=1&sn=2a6af14c3167f400e78c52f70b720199&chksm=fafc2cc6cd8ba5d0d0d8dc83f57cc64b617f5a6a77be4250a62e3eded1b52248b2b91fff2054&scene=21#wechat_redirect)  
[有关云安全漏洞挖掘的一些思考和总结](http://mp.weixin.qq.com/s?__biz=MzUzNTkyODI0OA==&mid=2247524867&idx=1&sn=ec2884e42e487b9aa4874818b76c40df&chksm=fafc2ed4cd8ba7c247f1ac48912908fd493e290708b1137950af7c9a88cc718e1cf7af2c803b&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzUzNTkyODI0OA==&mid=2247523115&idx=1&sn=af3ae1af3afb2c9e5b2263d3e55af8a6&chksm=fafcd7fccd8b5eeae46a44903ea800786896d8fd399e1fa6bd4ee247e3bc959a6526d1fc9bf0&scene=21#wechat_redirect)  
[金融门派“逻辑漏洞高手”受邀专访](http://mp.weixin.qq.com/s?__biz=MzUzNTkyODI0OA==&mid=2247524369&idx=1&sn=2a6af14c3167f400e78c52f70b720199&chksm=fafc2cc6cd8ba5d0d0d8dc83f57cc64b617f5a6a77be4250a62e3eded1b52248b2b91fff2054&scene=21#wechat_redirect)  
  
  
