#  如何解决防火墙拉黑Nginx转发的漏洞扫描流量问题？ | 总第198周   
原创 群秘  君哥的体历   2023-07-18 22:58  
  
‍‍  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/yXsxtS2cfwYLicju4TyAeQhibftSnibn1R9dnxB7tCR0JyCicooUTh4rDmWsBv1wBniaFHVGdaNmMeJOl1hVIicPKkzg/640?wx_fmt=gif "")  
  
****  
**0x1本周话题**  
  
****  
**请教各位一个问题，漏扫扫描Nginx服务器，Nginx转发到真实服务器，中间过防火墙，防火墙把Nginx的漏扫流量拉黑了，这个有什么好的办法吗？******  
  
A1：  
我们认为扫描也是一种威胁，  
扫描流量会按照源IP生成归并告警。  
  
  
A2：Nginx是在DMZ区，其他真实服务器在内网，被中间的防护墙拦截了。  
N  
g  
inx拉黑了岂不是说明拦截到位。  
  
  
A3：  
N  
g  
inx和fw互换位置，或把XFF限时加白。  
  
Q：漏扫是你们的？还是指互联网上的常态化扫描工具。  
  
A4：漏扫已经加白了，但是拦截了  
N  
g  
inx转发的漏扫流量。  
  
A5：  
N  
g  
inx转发是有XFF IP的呀，要看你们WAF的能力。  
这个场景就是真实的应用后端在BIZ区，DMZ区只有一个  
N  
g  
inx做转发。  
  
  
A6：这个不好办，一般防火墙FW识别不了xff。  
我们这里  
全  
是  
SD-WAN。  
  
A7：只是  
N  
g  
inx转发的漏扫的流量，被内网防护墙拦截，拉黑了IP。  
拉黑的是  
N  
g  
inx IP，防火墙上加白漏扫IP没用，因为防火墙拦截的是  
N  
g  
inx IP。  
  
Q：既  
然开了，那说明达到目标了。这次封得符合预期，漏扫加白，然后解封。问题在哪呢？他只能看到Nginx ip，你希望他看到xff？理论上，七层墙，可以识别http头。  
  
  
A8：要看你的扫描器是怎么开墙的，如果是全网放白，那么直接不扫  
N  
g  
inx也没什么问题。  
如果你这个是跟着业务流量做的开墙，就只有对  
N  
g  
inx  
开白名单了。  
意思是你的漏扫又会扫  
N  
g  
inx，又会扫业务真实ip。  
  
  
A9：  
应用如果都是走的  
N  
g  
inx  
，想要漏扫直接绕过  
N  
g  
inx  
扫到应用估计也没那么简单。可以加白继续扫就行了，看你们的网络架构了。  
  
Q：漏扫上对所有Nginx加白？这个有点难，CMDB里没这么全的属性，找不到Nginx ip清单。  
  
A10：我理解从互联网  
扫描  
是攻击者视角，被拦截了没有问题。  
你在biz区应该还要部署扫描器，直接从biz扫；或者再买个扫描器的节点，放在  
N  
g  
inx后面扫，其他节点不扫带  
N  
g  
inx的区域。  
  
A11：防火墙上面给  
N  
g  
inx放白名单不去拦。  
你们如果有网络流量分析或者态感的话，应该能很容易就找出来用来转发的  
N  
g  
inx。  
  
  
A12：本来从把互联网流量转到生产区就是需要过滤，这还反过来验证了应用的防护措施到位。  
  
A13：不是互联网过来的漏扫流量，是内部的扫描器的流量。  
扫描器规则剔除了  
N  
g  
inx   
i  
p，  
不  
扫N  
G  
，  
意  
思是直接  
扫后端服务，不通过NG转发，或者漏扫放在里面扫。  
  
  
A14：  
N  
g  
inx加白了，你们FW就没意义了，因为攻击流量也是走这个路径进来的。  
感觉最方便还是漏扫放墙内扫。扫描器放在FW后面和后端Server在一个区域。要是有给所有  
N  
g  
inx list漏扫加白也行。  
  
  
A15：你的问题是防火墙老把  
N  
g  
inx封了，那么要不就是让扫描流量不过  
N  
g  
inx，要么就只有防火墙对  
N  
g  
inx开白。  
  
A16：目前掌握的应用资产应该都是通过  
N  
g  
inx转发的，上态感或者科来通过流量对资产来梳理吧，有些家的态感能直接识别出来负载均衡和流量转发的一些节点。  
  
A17：DMZ和核心层的防火墙临时给  
N  
g  
inx加白吧，扫完就停策略，或者你们fw设备支持读xff中ip，这样加白。  
FW拉黑的不是漏扫的IP，漏扫IP已经加白了，FW拉黑的是NG的ip，因为NG转发漏扫的流量到真实IP中间过了FW。建议申请点预算，多部署几个节点，dmz，生产，开发测试。  
  
  
A18：你直接扫描后端服务就好了，加不加节点都可以，前提是这一块资产要掌握清楚。  
  
A19：你是不希望fw拉黑NG的ip，而不是扫不动，是这个意思吧，那就要防火墙加白，NG资产不全，那就要NG全部加xff，防火墙识别xff。  
  
A20：防火墙估计识别不了XFF，就是SOAR上了剧本，自动化针对CVE攻击扫描触发的。  
  
A21：我们没启用FW自身的检测，用的是态感联动FW，这样就可以规避这个问题了。同时要NG上启用xff。  
  
A22：FW是怎么识别出攻击流量的，如果架构这样能拉黑的话，那就很危险了，别人一扫你业务就中断了。我理解带阻断的应该放在NG前面吧，你这样的架构别人一扫，岂不是NG来的流量都黑了，所有业务都断了。  
  
  
A23：态感负责分析，联动FW去封，不封NG，封xff（态感可以识别xff）。  
  
A24：  
我们想通过五元组对应，但发现  
用不了五元组，因为NG会改。  
  
  
  
A25：是NG转发的啊，我们是通过FW转发的，所以FW日志里面有相关信息。  
  
A26：**最开始我想的是通过时间戳来做，后来发现一旦量大了压根没办法做收敛，后来想了一下四层转发过NG只会对包头重新封装，data段不会去动，那么只需要通过对流量解析根据data段offset对包提取特征，然后根据特征匹配，这样就能解决了。之前还试过一种方案，就是在转发NG上对rpc转发的记录做留存这样记录入像端口和出像端口，也能把整个流量的链路聚合起来，但是发现不理想，因为只会记录建立完整通信的，像半开扫描这种就不会记录，目前我没看到比提取特征更好的办法了**。  
  
Q：data段特征会有大量重复的吧，特别是正常的业务请求。是只对告警进行提取么？  
  
A27：只是告警，目的就是做流量溯源，  
也可以用来解决ipv6入站转换后溯源的问题。  
  
  
A28：**比如有这么个场景，你的内网被搞穿了，中间建立了SSH进行控制，但是SSH走了NG转发，这种时候你就头大了，压根不知道是哪台机器被搞了，只是发现异常SSH链接和被搞的机器，这种只能靠其他行为分析，而不能通过这个行为本身就能定位，通过这种办法对流量进行聚合就能判断出来链路从而直接解决**。  
  
A29：这种情况，如果取了NG前面的流量给NDR也可以分析。  
其实本身能通过花钱来解决，所有的转发全通过买F5让硬件去做，F5有这种日志记录的，只是NG做四层转发的时候就不带这个东西，也算是F5故意这么做的。  
  
  
Q：刚发现服务器1/6都装了NGinx，这个是不是还得区分哪些是做转发，哪些不是做转发的？  
  
A30：应该有些应用不是很规范吧，直接在本地用NG转发业务；还  
会  
有这么一种情况，我申请了某个应用开到公网，结果本地是个NG，然后我直接开了这个NG就等于开了我的所有应用。  
  
  
A31：这个应该会检查本地NG是给一个应用使用，还是本地NG有多个服务，如果有多个服务需要单独开一台NG转发你需要开到公网对应的应用，而不是直接本地NG直接开公网，这样会存在未知问题。  
  
A32：Nginx模块很多，不一定是proxy，你要关心的是反向代理穿透网络的，运维一般的套路是NG套NG，前提得确定本地的NG是反代，是业务还是其他。  
  
  
**0x2 本周精粹**  
  
****  
[《山雨欲来风满楼？2023年上半年全球网络空间演习概览](http://mp.weixin.qq.com/s?__biz=MzI2MjQ1NTA4MA==&mid=2247489818&idx=1&sn=f31083c746f6cd7a458d3bd3db08b4d8&chksm=ea4bb35ddd3c3a4bbeb0400fa195209742b28b57c69f11055869474b38b283878707e154b639&scene=21#wechat_redirect)  
[》](http://mp.weixin.qq.com/s?__biz=MzI2MjQ1NTA4MA==&mid=2247489818&idx=1&sn=f31083c746f6cd7a458d3bd3db08b4d8&chksm=ea4bb35ddd3c3a4bbeb0400fa195209742b28b57c69f11055869474b38b283878707e154b639&scene=21#wechat_redirect)  
  
****  
  
  
[《攻防演习防守标准化的实践与思考](http://mp.weixin.qq.com/s?__biz=MzI2MjQ1NTA4MA==&mid=2247489815&idx=1&sn=545ba008c58fd7ec6a398ec7d9a709ea&chksm=ea4bb350dd3c3a46cba64a14dfd7c52fc69e30123b11114691b8e708af2012c5c334e6ab4d2e&scene=21#wechat_redirect)  
  
》  
  
  
**0x3 群友分享**  
  
# ChatGPT的六大合规风险  
  
  
[货拉拉数据加密治理实践](http://mp.weixin.qq.com/s?__biz=MzI2MjQ1NTA4MA==&mid=2247489716&idx=1&sn=758e55a2bf569afa5950f1b913a8f79e&chksm=ea4bb2f3dd3c3be55ad699dfc46910dc27bcceaadcf02ba6db081db2253618ea0d6f2e105a0b&scene=21#wechat_redirect)  
  
  
  
[【极思】外部安全事件有什么用？](http://mp.weixin.qq.com/s?__biz=MzI2NTMwNjYyMA==&mid=2247484922&idx=1&sn=a2cdfe4892f55f8024daaf15d036c0cf&chksm=ea9e2d69dde9a47f5236116670767af75d5da11ac5dfd3fa574bc791076678e56f9b88091a88&mpshare=1&scene=21&srcid=0604h23ZtRWirH2gl3zP7Pgs&sharer_sharetime=1685861087778&sharer_shareid=2f28ff6cbc3fea1dde107d1474ec1754#wechat_redirect)  
  
  
  
[CSA发布 | 《ChatGPT的安全影响》](http://mp.weixin.qq.com/s?__biz=MzA3NzM2MTQ3OA==&mid=2649818400&idx=1&sn=419c149a1289b0e56b52a67f409f6019&chksm=87569d09b021141f693e4bf9a7ace0928c854f3825f51dc79f5be99d30f1e11a31997fefc064&scene=21#wechat_redirect)  
  
  
  
[e1knot：实践之后，我们来谈谈如何建设SOAR](http://mp.weixin.qq.com/s?__biz=MzI2MjQ1NTA4MA==&mid=2247489685&idx=1&sn=467c0e1d8ec38a80faf1741719d1bf88&chksm=ea4bb2d2dd3c3bc49dd0e364c6b9d70ddfad44334e8b5909fa734dba8e2e71aa1d22c78c0c53&mpshare=1&scene=21&srcid=0523tTBoMy5IYgB91g1A7FhJ&sharer_sharetime=1684798064610&sharer_shareid=0ec826e3a7f2ff1034846a740946bd2c#wechat_redirect)  
  
  
  
[揭秘手机密码破解机制：制贩黑客工具“刷机”案背后的司法鉴定故事](http://mp.weixin.qq.com/s?__biz=MzU0NDk0NTAwMw==&mid=2247592048&idx=1&sn=8619614f14b46a6046cefa559ec56884&chksm=fb774e74cc00c762fa39efda77fc3c757e141aff11bb5f09766ac6b085f982826c0552d3575a&mpshare=1&scene=21&srcid=0531rkevM4QQjbJ1j0XresIW&sharer_sharetime=1685538524351&sharer_shareid=01f87b9596ecb8a35e75d52c8556d596#wechat_redirect)  
  
  
  
商用密码管理条例  
  
http://www.gov.cn/zhengce/zhengceku/202305/content_6875928.htm  
  
  
-------------------------------------------------------------------------------  
  
【金融业企业安全建设实践群】和【企业安全建设实践群】每周讨论的精华话题会同步在本公众号推送（每周）。**根据话题整理的群周报完整版——每个话题甲方朋友们的****展开讨论内容——每周会上传知识星球**  
，方便大家查阅。  
  
**往期群周报：**  
  
[如何看待网络安全产业内卷？数字化时代，网络安全行业还能热门多久？| 总第197周](http://mp.weixin.qq.com/s?__biz=MzI2MjQ1NTA4MA==&mid=2247489810&idx=1&sn=bf0f9b0318aa714f003e2569fa3b3f46&chksm=ea4bb355dd3c3a4355a5e2d0b5b10fb6bfb795ab8934794d7eb5a7f0f1bf7e2b869ee3d1658f&scene=21#wechat_redirect)  
  
  
[如何规范和推进企业内部的信息安全审计工作？| 总第196周](http://mp.weixin.qq.com/s?__biz=MzI2MjQ1NTA4MA==&mid=2247489798&idx=1&sn=1cad9a927686e84ea0b3b73c26e9630a&chksm=ea4bb341dd3c3a57c6060bf3a6dd432f73b1a40309e164b3a148e81d9f1222fe8bac93664d38&scene=21#wechat_redirect)  
  
  
[WAF类串联安全设备规则升级，如何验证对业务应用的影响？| 总第195周](http://mp.weixin.qq.com/s?__biz=MzI2MjQ1NTA4MA==&mid=2247489749&idx=1&sn=a4dbc4da013145ea26a12ab04f52e249&chksm=ea4bb292dd3c3b84d50df3e17d44e4dd56446d134092e4529daff5fb657befcffc0e9915c568&scene=21#wechat_redirect)  
  
## 如何进群？  
  
**如何下载群周报完整版？**  
  
**请见下图：******  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/yXsxtS2cfwbppZu5PBSictiaObD2Bnru4z5nSyfMrsqjPO0micwA8CsIDUxRb73kIPomrYtYpWuWqPwMU17LHAIpg/640?wx_fmt=jpeg "")  
  
  
  
  
  
  
  
  
  
  
