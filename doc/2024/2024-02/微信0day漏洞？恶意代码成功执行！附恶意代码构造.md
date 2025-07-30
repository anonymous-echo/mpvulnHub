#  微信0day漏洞？恶意代码成功执行！附恶意代码构造   
 信安404   2024-02-16 14:14  
  
- **前言**  
  
TSRC已经忽略啦，别费劲提交了，除非有师傅有思路，看看能不能扩大危害给他搞个RCE什么的，弄出来麻烦@我一下学习学习~（该漏洞无危害可以公开，不是在冲）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/68kZ08udL4Djt3NDSAblicibia0YgkXR3oMjEQSiafEtIJRHF11owvJP705gRaDm8f0Qq7XT5LAWeOiczPgn4J4icOwQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/68kZ08udL4Djt3NDSAblicibia0YgkXR3oMaSbO73xyHvkMQsiaSiaVHO0giaibKI2rYbKhLwlLlMF2Q3Su1L3pN9HZBQ/640?wx_fmt=png&from=appmsg "")  
- **事情经过**  
  
在维护ICPscan工具的过程中，与小群的师傅讨论代码逻辑优化问题的时候，突然产生了严重对话内容偏差，一段RE正则规则当中，出现了突兀的 " "，这个地方是存在随机内容的，不应该是空。这让我产生了疑惑，随即与师傅进行确认，我又重发了一遍代码，结果其他群员都看不到我发的内容，又离奇消失了。  
```
(r'<a href="/company/.*?">(.*?)</a>)')
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/68kZ08udL4Djt3NDSAblicibia0YgkXR3oM9XjvyVJB02SBRKbj0uMJfYvhmcd8AibHk31ddiap4GSOAvW5kUupuAgQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/68kZ08udL4Djt3NDSAblicibia0YgkXR3oMIR8a2tO3EmGgJBTRJS40sXPGEE6SLPeBa5aksAibXQ2qH4cyJThz18g/640?wx_fmt=png&from=appmsg "")  
  
这时候反应过来，应该是这段代码被微信解析掉了，并且存在两种情况，第一种是发送后大部分代码都在，例如变成这样  
```
(r'<a href=" ">(.*?)</a>)')
```  
  
但是当我们用复制的方式取出的时候就变成了这样  
```
(r'(.*?))')
```  
  
？？？？？怎么回事，我们的代码呢？怎么全都不见了，紧接着再多测试几个代码，最终确认，目前仅有<a>标签会产生这种情况（也有可能其他标签也可以，没测那么多而已），并且还需要进行闭合，最后代码就是这样  
```
<a href="想隐藏的内容">1</a>
```  
  
这样的代码在其他人眼里就会变成  
```
<a href=" ">1</a>
```  
  
如果我们用复制的方式，就会只留下一个“1”，其他代码全部消失了。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/68kZ08udL4BZcoY3iansjoBPReRgdJLaklNkCibhibdYhKrudDOJrtPzVD3iaBeO6XiaDEJxmuBoBgwBJyCmgoOXmuw/640?wx_fmt=jpeg&from=appmsg "")  
  
- **浅浅一谈**  
  
个人认为这个漏洞应该还是有一定利用价值的，不过会比较恶心人一点，举个例子应用在当前大事件公司裁员当中：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/68kZ08udL4Djt3NDSAblicibia0YgkXR3oMq7XmEZ6n2AEhqeljE4AF0QH4Cs3qkoZ4okPojJwgc2FCtqFKAlxPCg/640?wx_fmt=png&from=appmsg "")  
  
当这样构造了话术，在对方那显示的就是正常的沟通，会确认是经理级别的待遇，同意了这个说法，而另一头显示的却是向公司提出口头离职，由人事部门发送聊天消息记录来确认这个情况，从而实现无成本开除一名员工。  
  
甚至可以用来钓鱼或者传播不法内容能够逃避普通的监管，以下为举例，请勿进行违法犯罪活动。  
  
钓鱼域名是 dyqq.com，真实域名是 qq.com，那我就可以利用这个漏洞来进行钓鱼，构造如下恶意域名  
```
dy<a href="1">qq.com</a>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/68kZ08udL4Djt3NDSAblicibia0YgkXR3oM20f0CeqibPvK9Q5xI4LgzIRAccCGianwAnmh0yjhibEfjuTZibzxJUycAA/640?wx_fmt=jpeg&from=appmsg "")  
  
在对方视角中显示是这样的，并且由于微信自带高亮，这时候就会让被害者认为访问是正确的，登录的是 qq.com，但是当被害者复制这段信息，然后到浏览器试图登录的时候，由于这个漏洞，就会导致用户去访问钓鱼网站 dyqq.com，而不是真正的qq.com，这样就完成了一次攻击。下次护网师傅们可以构造一下话术，试试看哈哈哈。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/68kZ08udL4Djt3NDSAblicibia0YgkXR3oMiaL3ibNkLOPm2mndnXObIiavyicyUPytkakmZpCKicb99Veicy8jAvtpZqiaw/640?wx_fmt=png&from=appmsg "")  
  
由于用户对微信的信任，以及高亮代码是真正的 qq.com 从而导致用户无防备心理就进行了访问，并且输入账号密码被黑客截获。  
  
我们还可以这样构造恶意代码  
```
https://dywy.com/此处是随意命名/<a href="1">qq.com</a>/恶意网页UI.html
```  
  
效果差不多就是这样  
  
![](https://mmbiz.qpic.cn/mmbiz_png/68kZ08udL4Djt3NDSAblicibia0YgkXR3oMS4ib9mNLTFSjy7zvpQlH87n9unbvGSiaicECfV4O5GpMibKQer0KwHufhg/640?wx_fmt=png&from=appmsg "")  
  
表面看起来是qq.com，但是复制之后就会发现，其实qq.com只是一个文件夹命名，会被直接跳转到恶意构造的钓鱼网站当中去，我们只需要在访问路径上增加一个 qq.com 就可以了  
- **原理推断**  
  
这个利用过程分为三个阶段：  
  
第一阶段：构造好恶意代码发送的时候在发送者视角是能看到完整内容的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/68kZ08udL4BZcoY3iansjoBPReRgdJLak9o5Vj94V9L6rxOf5WjIloEckJUjoIntuhFyx4OZzP3yLnmhFCIVVRw/640?wx_fmt=png&from=appmsg "")  
  
第二阶段：在其他收信人视角下，href=" "里的内容全部清除了，变成一个空格  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/68kZ08udL4BZcoY3iansjoBPReRgdJLakO7keeqSsJa7ZmL6ppapCnqIyXHjMOQcftic1NdwBFOWp32m4U60yM9w/640?wx_fmt=jpeg&from=appmsg "")  
  
第三阶段：在电脑复制的时候，所有的标签代码及内容全部消失，前后文及标签夹着的内容会拼接在一起，形成完整的字符串  
  
![](https://mmbiz.qpic.cn/mmbiz_png/68kZ08udL4BZcoY3iansjoBPReRgdJLakWAFLsUB9p0k7nlXXiabjsaAMTQPrUAXibWiclVA96odBrtoD42G4aGgzw/640?wx_fmt=png&from=appmsg "")  
  
因此推断微信其实是做了两层渲染（仅指此处漏洞）的，第一层渲染掉了href中的内容（此处不知道为什么，怎么会把所有内容替换成空格），紧接着在复制的时候触发第二次渲染，将标签解析了从而导致前后拼接。那么此处就有可能进行操作，例如：钓鱼网站、XSS打cookie、甚至是用html的方式进行RCE（虽然极度困难，菜鸡的我做不到）。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/68kZ08udL4BZcoY3iansjoBPReRgdJLakM50zv3FhpBU2ia0sTvzdsVD9QU1kOdtQtPWErZQgtR0AlBYnWot35og/640?wx_fmt=jpeg&from=appmsg "")  
- **碎碎念**  
  
还是挺有意思的，虽然被认定无危害，不过感觉还是有深入的空间，有能力的师傅可以接力搞一下，说不定就来大钱呐~  
  
往期推荐  
  
[【绝对好用】黑客使用什么截图软件？](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487335&idx=1&sn=e0e27b89615299d3badee733c9e74a9d&chksm=c30415def4739cc86568b3e821536e4b3f8fa0ee401a6101605d7fc407a5f535adb1124c4efb&scene=21#wechat_redirect)  
  
  
[黑客如何玩幻兽帕鲁?](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487283&idx=1&sn=3d8054db5f3b1267cddb9f142aec5ef5&chksm=c304158af4739c9c0bccb21ffbbfec71aaed5f9a656ba6d40c7d8efe1a90f6de95d785bbed9e&scene=21#wechat_redirect)  
  
  
[假期如何优雅的远程办公/运维/测试？](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487252&idx=1&sn=48f3c4234f5921396abf83b5d4f88e4c&chksm=c30415adf4739cbbb0e1a62d8fa113b2d2ab763fc29d99634cdca07016acaa8ca6df5fbb94db&scene=21#wechat_redirect)  
  
  
[莫伸手，伸手必被抓，史上最强应急响应工具|应急溯源](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487252&idx=2&sn=eb4a7bb9a158dece580d20d595a52877&chksm=c30415adf4739cbb1d821b619b141cf5dc609eec5a27d91539c2e100a0ab4993fe6e9e94f977&scene=21#wechat_redirect)  
  
  
[人手一个的渗透神器被大佬下手了，直接二开Plus版本！](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487202&idx=1&sn=530f2eba36a8681c44c5263dc83270de&chksm=c304145bf4739d4d3000f9a36a9adec7a20853a9a78032e8b60c52f40635d0f9b887b998ef3a&scene=21#wechat_redirect)  
  
  
[【八年磨一剑】内部工具被流出后，大佬霸气公开](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487181&idx=1&sn=27ac1201e97997a32a678aa3111b8a65&chksm=c3041474f4739d626430876483cfeab53efc3b5bd6c92f2ca9f98376de11f0b93872477d819b&scene=21#wechat_redirect)  
  
  
[某大佬高危漏洞利用工具外泄，速存！](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487128&idx=1&sn=97e9df98d22a6b501c237d71e6dfdc52&chksm=c3041421f4739d37b1b72ece9bae463ad0213940aa102d6214d12b40e054ce381b7e9e6e146d&scene=21#wechat_redirect)  
  
  
[这个渗透利器都2024版了，你不会还没更新吧？](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487093&idx=1&sn=4e8192a3f2101ab1f17ad48cc46d9500&chksm=c30414ccf4739ddac8a5366ca97b3c87a25aff5330154f3fc6bdac78c08e5c06729626837f20&scene=21#wechat_redirect)  
  
  
[【神器】一键收集控股公司ICP备案、APP、小程序、微信公众号等信息](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487083&idx=1&sn=83870bd4b87647e1f1a61ed4a43dad1b&chksm=c30414d2f4739dc43922557aa48eefc31d4976d0d569329469159d5087e0320188a67c948208&scene=21#wechat_redirect)  
  
  
[红队武器库|内网渗透工具（甲方自查工具）](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247486960&idx=1&sn=376bbb02bd40a6d005c9b98ca4ef5b10&chksm=c3041749f4739e5fe1b75484989983bf72a2c16163a59a8524110fe52e79835c9a960ef12301&scene=21#wechat_redirect)  
  
  
[记攻防演练的一次溯源案例](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247486929&idx=2&sn=9be03e380266bf3d896acc9644acb047&chksm=c3041768f4739e7e13bdd0101f31b04d9ccd8108d3ba04b5c2bab59334fe9b4239995be32a22&scene=21#wechat_redirect)  
  
  
[【工具更新】Nessus 24年1月18日更新_windows 版Cracked（附下载）](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247486761&idx=2&sn=746f33e269cc484e23b8857bbe9580b8&chksm=c3041790f4739e866a0d661b05a9cd4228cf3b79806af1838b5a46bb9c4f691740313f9ea356&scene=21#wechat_redirect)  
  
  
[漏洞扫描神器AWVS又更新了，全新界面，快来下载体验吧！](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247486717&idx=2&sn=26a6ecc9fd4c4a105f2be467413dc9d8&chksm=c3041644f4739f521bb23461669b4f5e13c3674128ab4f9ecc6527785a1238b7d1a81f1696a4&scene=21#wechat_redirect)  
  
  
[【从0到精通】2024年要不要学会API安全？](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247486691&idx=1&sn=97e50f12bd735483c8ec0f15c1ac1b5e&chksm=c304165af4739f4cf834b449760035b2c27f4b7ad20cbda32804592a99c2b8ebfc32f694303c&scene=21#wechat_redirect)  
  
  
[世界第一Scanner灯塔不行？是你不行](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247486691&idx=2&sn=b585440fb5042c58ca2fe963e09b9db5&chksm=c304165af4739f4c350a425e1366d33a3f4bf190fe3c32934181fbdb91dc8d40c547b6460551&scene=21#wechat_redirect)  
  
  
  
  
