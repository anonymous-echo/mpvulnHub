#  【1day】EduSoho配置文件泄露，获取数据库账号密码   
网络安全007  WIN哥学安全   2024-01-27 23:08  
  
    师傅们，我来啦，久等了！最近收到很多师傅们的私信我是否进去HC了，立马过来更新一波，不然真害怕你们一会乱说，不要乱传谣哦！我只是有时候学业忙不过来，实习项目太多搞不来，所以有时候没有太多时间去分享最近出的漏洞以及自己挖掘的、复现的一些漏洞，毕竟马上就要过年啦，我得回去开始大扫除啦，不知师傅们啥时候回家过年呢![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/2_02.png "")  
  
。  
  
    最近在研究EduSoho系统，该系统存在配置文件泄露，攻击者可以通过构造恶意代码，未授权直接下载或读取config/parameters.yml配置文件内容，里面包含了数据库账号密码以及secret值等敏感信息。  
  
      
**老样子，师傅们如果有用到该平台的漏洞，要记得及时找厂商进行修复以及做好防护策略，这样子就可以预防一下啦。**  
  
**一、资产搜索**  
```
zoomeye查询语法：app:"EduSoho 教培系统"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDrWoPbeNFrK8takuDpJqrOtQJlJ75M6OkBwfVDBKyrBib5F6sYQj5qy99NoZOVlQg2Iv5QrCiaWiaTMQ/640?wx_fmt=png&from=appmsg "")  
  
**二、复现过程**  
  
    该漏洞在/export/classroom-course-statistics这个接口文件中的fileNames[]，然后使用目录跳转符号进行跳转下载或读取config/parameters.yml配置文件，如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDrWoPbeNFrK8takuDpJqrOtPYzZkszhVkbvPJ9LR3uYiaZEOG41jjmlssJlnPY83vSViagRicwqU7ErA/640?wx_fmt=png&from=appmsg "")  
  
**三、POC获取方式**  
  
 文章只提供思路，如需具体POC请关注公众号并回复关键字【**240127**】即可获取POC.  
  
  
往期推荐  
  
[【渗透实战】某访客系统越权测试](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247496669&idx=1&sn=6e0030795498ab60b32023a25badd5c7&chksm=c0c85229f7bfdb3f3d788770457d4d4e779ddd091ada21104af21d3bea340443b303067efad5&scene=21#wechat_redirect)  
  
  
[【附靶场】某省信息安全管理与评估第二阶段应急响应](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247496644&idx=1&sn=bdcd7dbdedbb2a491d0168147e2d9d23&chksm=c0c85230f7bfdb26c7d411f864d7a403b8cefb919f51434aff72aa71b915f2975a949f8b7b90&scene=21#wechat_redirect)  
  
  
[CVE-2023-46226 Apache iotdb远程代码执行漏洞](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247496621&idx=2&sn=065a16a233444256e0d44969744ca292&chksm=c0c85259f7bfdb4f49a9af0c3a9fda3fd71ca311a0736f799369b55e6319726e3c1abcf0595a&scene=21#wechat_redirect)  
  
  
[【渗透实战】记一次针对某高校的渗透测试](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247496571&idx=1&sn=f805b03a741f8e42718281a787539449&chksm=c0c8528ff7bfdb9980ef84d849a5912ede5f0d2bb424e563960d5811b65556231f6b44a54034&scene=21#wechat_redirect)  
  
  
[【漏洞复现】GitLab 任意用户密码重置漏洞（CVE-2023-7028）](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247496563&idx=1&sn=abe28349e078915cb76ff878436e5513&chksm=c0c85287f7bfdb915effc064f5bc85a2797270866eaa4c85d4279674474c51aa8e5ad842906e&scene=21#wechat_redirect)  
  
  
[【攻防实战】地市红队攻防演练经验总结](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247496557&idx=1&sn=a550d9da526dd0d390b882bb10e249e4&chksm=c0c85299f7bfdb8f158a8905a46217c7913718167e91358a0c3d830b5368c0fa7266c973e80c&scene=21#wechat_redirect)  
  
  
[如何随时随地体验AWD比赛（一键启动靶机版）](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247496465&idx=1&sn=e72a117e4d831d71041ef76a90e6f25a&chksm=c0c852e5f7bfdbf3b5a4ed366e7e2badbe6b3aad58a03df619d89f41e4fd17ff0261c85d77fa&scene=21#wechat_redirect)  
  
  
[【渗透实战】手把手教你WIFI渗透](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247496431&idx=1&sn=23fd8ddbf19bf68f39d8e06b21a68c09&chksm=c0c8531bf7bfda0db58084a2f47edb398d66e05d6caac2bea490fba8a265b2be97b9ffe03cb0&scene=21#wechat_redirect)  
  
  
[【建议收藏】网络安全红队常用的攻击方法及路径](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247496396&idx=1&sn=1ee96d86aba3ad0c70baa6fea81f6c97&chksm=c0c85338f7bfda2ebb919ec5cc3cec14acb9fe9405fa849f749a0c51caacea193d441232b9e0&scene=21#wechat_redirect)  
  
  
[【红队】一款高效的企业资产收集工具](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247495909&idx=1&sn=989840c2dbf9fe8ed7a1d44028de93c8&chksm=c0c85111f7bfd807a136299c79013d3bf51eb9f5c17e664f4f8649ab5cc02be0246ecefbf6b1&scene=21#wechat_redirect)  
  
  
[记两次内网入侵溯源](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247495867&idx=1&sn=71b6524e6da6843e72dd98842fb26371&chksm=c0c8514ff7bfd8590e38649313852e7365e3d3f4f5235d615d4fb2561475ea8a9c6303d714be&scene=21#wechat_redirect)  
  
  
****  
