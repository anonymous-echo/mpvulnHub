#  实战案例：记一次利用SpringBoot相关RCE漏洞拿下某数字化平台系统   
AlbertJay  不秃头的安全   2024-02-17 13:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWtB8XKFIXmjXwsQ1gicjDmI3bhRjPibqD3XHjdAZMgTj80WzwDcsaNCGWLeezQFyDXm52PsRPhiavJw/640?wx_fmt=png "")  
  
**实战案例：记一次利用SpringBoot相关RCE漏洞拿下某数字化平台系统**  
  
  
  
前言：本文中涉及到的相关技术或工具仅限技术研究与讨论，严禁用于非法用途，否则产生的一切后果自行承担，如有侵权请联系。  
  
由于微信公众号推送机制改变了，快来  
星标不再迷路，谢谢大家！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWtB8XKFIXmjXwsQ1gicjDmIb4ut4PbGmYf5JezQib2NwxBWAFx5JSIJ5AEsgsfibFHuiaYFjOCCzia1Zg/640?wx_fmt=png "")  
  
****  
  
****  
**前言**  
  
  
在一次众测项目中，对某大型企业的某套数字化平台系统进行测试，前端功能简单，就一个登录页面，也没有测试账号，由于给的测试时间不多，倒腾了半天没有发现有价值的漏洞，在快要结束的时候，试了几个报错，发现是Spring Boot框架的，仿佛间看到曙光，后续也顺利拿下RCE。通过本文的分享，希望能给大家获取到一些思路和帮助~~  
  
  
  
  
****  
**开局**  
  
****  
访问http://xx.xx.xx.xx/，打开就是一个某数字化平台登录页面，尝试了登录框可能存在的各类漏洞问题，如弱口令，用户名枚举，万能密码登录，登录验证绕过，任意密码重置等等，无果  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWtB8XKFIXmjXwsQ1gicjDmI7ibn4vmRfVCjJiaicZqCcMVKKI79GVUIYbxwLSubmfab6byKEsxMAysXw/640?wx_fmt=png&from=appmsg "")  
  
****  
**Spring Boot框架**  
  
****  
随后，随意构造了目录aaa看看会发生啥，结果发现是非常熟悉的404错误页面，该页面的特征确定了使用Spring Boot框架，于是看看Spring Boot是否有一些配置接口泄露，运气好还可以执行RCE  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWtB8XKFIXmjXwsQ1gicjDmItLIg7ZEbqaJ3SuJtoRxgO7vibw2ibmnhkVp493MtwjlLvtuicR3j5WskQ/640?wx_fmt=png&from=appmsg "")  
  
尝试了几个目录，确定在/gateway/一级目录下存在配置接口信息  
  
http://xx.xx.xx.xx/gateway/actuator/  
  
http://xx.xx.xx.xx/gateway/actuator/env  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWtB8XKFIXmjXwsQ1gicjDmIWygriaIWNmtrI0q23WOHWcHSmz6NvGwvBnic7IEeFsibk84rw9Y4rvo7w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWtB8XKFIXmjXwsQ1gicjDmIqj8DLw42tTZX5dIw8Ot7gQecYz70MSC1cR1oLZeDTnolMIuLzlNLag/640?wx_fmt=png&from=appmsg "")  
  
使用SpringBoot敏感目录扫描一下  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWtB8XKFIXmjXwsQ1gicjDmIJAF5ugHLOtT2IPiblpmFiaxMwyEuiaUSKibTvhOXPfVxryUYX5Elumcib9w/640?wx_fmt=png&from=appmsg "")  
  
  
扫描后发现存在蛮多接口信息，我对Spring Boot的漏洞了解不是很深，第一时间能想到rce的漏洞有两个，一个是Spring Boot Actuator jolokia 配置不当导致的RCE漏洞和Spring Cloud Gateway的应用对外暴露了 Gateway Actuator，通过Spring Cloud Gateway 远程代码执行漏洞（CVE-2022-22947）执行SpEL表达式，可远程主机上进行远程执行RCE。  
  
  
思路有了，我们先来看看是否有/jolokia或/actuator/jolokia接口，扫描发现没有，那就看看有没有/actuator/gateway/routes/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWtB8XKFIXmjXwsQ1gicjDmIoZXwxxbf0gxaE1f0LsQDH0SsVh3lID3Ooc4gLWsZ3o5rmWNicgmciblg/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**Spring Cloud Gateway 远程代码执行漏洞（CVE-2022-22947）**  
  
****  
运气还是挺好的，Spring Cloud Gateway的应用程序在Actuator端点在启用，并能获取到路由信息，  
  
http://xx.xx.xx.xx/gateway/actuator/gateway/routes/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWtB8XKFIXmjXwsQ1gicjDmIc2YxZvHWIv9hn3RrtBj4QPaGyicr86GHmS2MW94ib59ic8icagXlNKt10Q/640?wx_fmt=png&from=appmsg "")  
  
接下来构建POST请求包，在/gateway/actuator/gateway/routes/ceshiRCE 添加一个包含恶意的SpEL表达式的路由，这里我创建ceshiRCE路由,命令用的是ifconfig，这里可以也用其它的命令，注意的是Content-Type:application/json要修改为json，发包后返回201说明添加成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWtB8XKFIXmjXwsQ1gicjDmIS4NcIvfayjdGBG3oMib19CibWNhNqIvUBiapdB91TNsJY5GiaIkKq5qj8A/640?wx_fmt=png&from=appmsg "")  
  
再次刷新，  
  
http://xx.xx.xx.xx/gateway/actuator/gateway/routes/ceshiRCE，命令执行成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWtB8XKFIXmjXwsQ1gicjDmIfoIfT7J7HE4BMBmbAPFltDhaRzGvJbyO3qHVGTapETrUTGjsMn784A/640?wx_fmt=png&from=appmsg "")  
  
  
******总结**  
  
****  
本次漏洞挖掘就到这里了，感觉还有其他点可以再次深入挖掘，由于时间关系只能皆已至此了，不过没关系，还是有收获滴，但回过头来想想，如果更细心一点，信息收集面大一点会有更多的可能性。希望这次的漏洞挖掘过程，能给大家带来一些挖洞思路，谢谢大家！  
  
****  
  
  
**声明**  
  
****  
漏洞已修复，笔者初衷用于分享与普及网络安全知识，若读者因此作出任何危害网络安全行为后果自负。  
  
  
```
原文链接：https://www.freebuf.com/articles/web/388523.html
作者：AlbertJay
```  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjIKcQsgZ0q8U9MOMKkIGEGjAcDMjOXuW6eYDOur79SYFak4z5Pu5v6liaPDvuaAVGKSibvBnKiaRFiaHvBDYwsfAQ/640?wx_fmt=png "")  
  
**关于我们:**  
  
感谢各位大佬们关注-不秃头的安全，后续会坚持更新渗透漏洞思路分享、安全测试、好用工具分享以及挖挖掘SRC思路等文章，同时会组织不定期抽奖，希望能得到各位的关注与支持。  
  
  
  
  
  
**关注福利：**  
  
回复“  
google工具" 获取 google语法生成工具  
  
回复“  
burp插件" 获取 bp常用插件打包。  
  
回复“  
暴力破解字典" 获取 各种常用密码字典打包  
  
回复“  
XSS利用文件" 获取 现成XSS利用文件.pdf  
  
回复“  
蓝队工具箱  
”即可获取一款专业级应急响应的集成多种工具的工具集  
  
  
**知识星球**  
  
星球里有什么？  
  
web思路及SRC赏金，攻防演练资源分享(免杀，溯源，钓鱼等)，各种新鲜好用工具，poc定期更新  
  
**提前续费有优惠，好用不贵很实惠**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fWtB8XKFIXmjXwsQ1gicjDmIpOOws1AlTV2fDrnf9PfWtkzbn5eAI23NNibXI3p4EGHAiaiaziaTgyuGbw/640?wx_fmt=jpeg "")  
  
  
**交流群**  
  
关注公众号回复“加群”，QQ群可直接扫码添加  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWtB8XKFIXmjXwsQ1gicjDmI2N8qxDXVbEsL8bVFClp5RsqjSBquNoEWE2WJdRmCWIxB6cpknKu69w/640?wx_fmt=png "")  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjIKcQsgZ0q8U9MOMKkIGEGjAcDMjOXuW6eYDOur79SYFak4z5Pu5v6liaPDvuaAVGKSibvBnKiaRFiaHvBDYwsfAQ/640?wx_fmt=png "")  
  
**安全考证**  
  
需要考以下各类安全证书的可以联系我，价格优惠、组团更便宜，CISP、PTE、PTS、DSG、IRE、IRS、NISP、PMP、CCSK、CISSP......  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fWtB8XKFIXmjXwsQ1gicjDmIJ8JNnhQFWxklxARg422kMoKUhbdOqG7hbyWibY58TTicaqXmONg9epaQ/640?wx_fmt=jpeg "")  
  
  
****  
****  
**往期推荐**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bQv07rEoSgnASDXC53WkoCVAbC73AzGr2gJ1hkgmLJf47DcQBvKhS65n8gFR9Rfr2aeIbyMIbxguySA37OaCNA/640?wx_fmt=gif "")  
  
  
[黑客如何玩幻兽帕鲁？？？？快来学习](http://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247484897&idx=1&sn=6aa52c2b933810d47e1d3f8fc6dd8911&chksm=cf1aa7b3f86d2ea530bca736f89332414f67d3f0a2592f99e83772fb0f8f298b3692d5263058&scene=21#wechat_redirect)  
  
  
  
  
[蓝队应急响应工具箱v2024.1](http://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247484886&idx=1&sn=96736a6a72d5e44d10adc598d8c62073&chksm=cf1aa784f86d2e9257b0c7a91cf333fb1cbc938e29f8c5c4bb613fe479fcfd8aeb37c70d8025&scene=21#wechat_redirect)  
  
  
  
  
[0day | 远秋医学在线考试系统任意用户登录漏洞分析](http://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247484850&idx=1&sn=094f45925ce244a18e540ee9c6693591&chksm=cf1aa7e0f86d2ef6bd6ecff8a74f84c4e9b1e175db5521a0ad23a3aac7a40e138a4551e8e83f&scene=21#wechat_redirect)  
  
  
  
  
[攻防演练 | 柳岸花明又一村](http://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247484837&idx=1&sn=d6641d7b84530598d21d132c150393b5&chksm=cf1aa7f7f86d2ee153230d396387d66f85549bee5605e791b2f7eb797903e52d86d7a2a44f01&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/ho9ticH0FkqnaHoBXA0Q9PNJoQM7g6jw7n5iacNUsHP3vuGeTG1Vaxak2FhpRzLaUKRKGh8iaZoIia7IibkQjZn6Nrw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/ho9ticH0FkqnaHoBXA0Q9PNJoQM7g6jw7n5iacNUsHP3vuGeTG1Vaxak2FhpRzLaUKRKGh8iaZoIia7IibkQjZn6Nrw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/ho9ticH0FkqnaHoBXA0Q9PNJoQM7g6jw7n5iacNUsHP3vuGeTG1Vaxak2FhpRzLaUKRKGh8iaZoIia7IibkQjZn6Nrw/640?wx_fmt=gif "")  
  
**球在看**  
  
  
