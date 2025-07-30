#  虚惊一场？curl SOCKS5 堆溢出漏洞大可不必惊慌   
原创 安全419  安全419   2023-10-12 18:08  
  
[](https://mp.weixin.qq.com/s?__biz=MzUyMDQ4OTkyMg==&mid=2247518574&idx=1&sn=55703f3667c5d3024fafb003a7b41058&chksm=f9eb57c3ce9cded57370ff25aa2637e9409dc2e52976cb54a203cdc29e51ef833e5591eed0e8&scene=21#wechat_redirect)  
  
  
  
10月4日，命令行工具curl和客户端URL传输库的主要作者Daniel Stenberg在其官方社交媒体平台中发布了一则安全公告称，即将在10月11日（本周三）发布curl的8.4.0版本，将在新版本中修复漏洞CVE-2023-38545和CVE-2023-38546。这一公告还被置顶在libcurl官网，以提醒用户关注。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9lmiax2vemgg0YdHGcAibZpaiaZrjfJVZYIw4pWWz9J2hRPV4BKyFuPXE1F6S7gpBicZyYgG9FbyJUs9BRd2Fv1kEg/640?wx_fmt=png "")  
  
  
Daniel Stenberg表示，这两个漏洞中包含的高危漏洞CVE-2023-38545“可能是curl有史以来最严重的安全漏洞”**。**并提醒各位开发者提前做好准备，排查相关联组件以在第一时间快速更新以解决安全问题。  
  
  
**来势汹汹？curl 漏洞“堪比log4j” “赶快排查”**  
  
  
  
据悉，Curl是从1998年开始开发的开源网络请求命令行工具，其具有丰富的 Api 和 Abi（应用程序二进制接口），被广泛应用于汽车、电视机、路由器、打印机、音频设备、手机、平板电脑、医疗设备、机顶盒、电脑游戏、媒体播放器等各种设备中。作为组件广泛用于应用的HTTP请求，libcurl也是一个非常流行和广泛使用的网络库，被广泛用于编写网络应用程序和客户端。  
  
  
在关注到这一漏洞情报后，业内多家安全厂商也陆续发布安全通知，提醒用户提前排查。就连行业大佬TK教主也为此发布微博，提醒大家保持关注。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9lmiax2vemgg0YdHGcAibZpaiaZrjfJVZYIUkBcQBNXFXQVHKAfGIwjRVgZHeNXRdZDskYKSqicct9ZZd7m3KaJoZA/640?wx_fmt=png "")  
  
  
安全419注意到，有人称，curl称为当今信息世界的基座之一，鉴于curl的影响面之广，预计本次的高危漏洞必然会造成另外一场轩然大波；也有人称，这一漏洞或将比拟当年的log4j漏洞，网安从业者又要熬夜加班修漏洞了，将气氛烘托得十分凝重，可以说包括开发、运维和安全团队都为此做足了动员工作，准备在新版本发布的第一时间升级更新。  
  
  
**去也匆匆？专家称不必惊慌可酌情排期修复**  
  
  
  
10月11日，curl项目的作者Daniel Stenberg正式在GitHub发布 8.4.0 版本，并公开同时影响命令行工具curl和依赖库libcurl的高危漏洞CVE-2023-38545。  
  
  
在漏洞POC信息发布后，包括赛博昆仑、奇安信、长亭科技、墨菲安全、天融信等在内的多家厂商均在第一时间确认漏洞原理，并成功复现该漏洞。  
  
  
根据奇安信CERT专家分析，CVE-2023-38545是一个由SOCKS5触发的堆溢出漏洞，当使用socks5代理时，如果主机名大于255则curl会尝试使用本地解析代替远程解析，但没有按照预期工作，导致内存损坏，攻击者可以构造恶意主机名触发漏洞，成功利用该漏洞将造成代码执行。  
  
  
奇安信CERT称，**经研判该漏洞利用条件苛刻，客户不惊慌，可酌情排期修复。**  
  
  
微步在线漏洞团队分析称，经过分析和研判，该漏洞利用条件较为苛刻，当curl配置了socks5代理、且自动follow重定向、且SOCKS5 代理必须“足够慢”等条件下，在请求恶意网站时，可能触发堆溢出，最终实现拒绝服务或代码执行，同样建议用户酌情排期修复。  
  
  
综合当前各家发布信息，除了部分厂商沿用curl作者给出的“高危”评级外，也有部分厂商根据该漏洞的实际影响情况进行了重新评级，譬如，  
阿里云应急响应中心对该漏洞给出了“中危”的评级，而微步在线对该漏洞则仅给出了“低危”的评级。  
  
  
与此同时，在向墨菲安全了解详细情况时，墨菲安全创始人章华鹏也告诉我们，经过初步分析，该漏洞利用条件较高，预估能实际造成严重危害的场景相对有限。从利用结果上看，导致拒绝服务是比较容易的，但要造成远程代码执行，需要根据具体的应用、操作系统平台进行构造，黑盒场景通常难以利用。  
  
  
但他同时也指出，虽然该漏洞并没有像curl官方最初声明的那样严重，但也不排除该漏洞还存在其他利用方式。建议企业用户升级 curl 和 libcurl 到 8.4.0 或更高版本，或参考官方发布补丁进行修复。  
  
  
截至本文发布前，安全419注意到，仍有部分「不明真相」的安全团队在持续转发“堪比Log4j”的消息，看到这里可以不必惊慌啦，参考各家厂商给出的建议，排期修复漏洞就好。  
  
  
●  
 **暂时无法升级的用户，也可以参考以下方式进行缓解：**  
  
  
1、避免在curl中使用“CURLPROXY_SOCKS5_HOSTNAME”代理  
  
  
2. 避免将代理环境变量设置为 socks5h://  
  
  
  
END  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/9lmiax2vemgg0YdHGcAibZpaiaZrjfJVZYI9TpwhYpsYibMZGzuUqYEJweWaJiaAeX37TCeiaOKZ8qOdXlB6oCgiaPERg/640?wx_fmt=gif "")  
  
  
✦  
  
**推荐阅读**  
  
✦  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzUyMDQ4OTkyMg==&mid=2247532486&idx=1&sn=9eed92eedd7fdc787e46258d2b8b3435&chksm=f9eba16bce9c287db0b73324f8edcf894c3a9b41e9ee5f15bd856fb92702df6ac772f28e9bf2&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzUyMDQ4OTkyMg==&mid=2247532446&idx=1&sn=db95163d671049bc485c596787f7dea4&chksm=f9eba133ce9c2825b2e7555b130b48791f44378ed0ad3f06803343dc618a47062bffc8d76cf1&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzUyMDQ4OTkyMg==&mid=2247532384&idx=1&sn=6e9bc75cc6548dd184400b778b796dc0&chksm=f9eba1cdce9c28db8e5107b0d3390e351cf2f7cae66be15fd8c3c081966e8fea5fd86e0045a0&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/9lmiax2vemgg0YdHGcAibZpaiaZrjfJVZYI7wt8CgBdyZYrVVVVOdzRVjLGQ2jibkputPL78qY2J7zfkicgcwHeQmCQ/640?wx_fmt=jpeg "")  
  
**粉丝福利群开放啦**  
  
加安全419好友进群  
  
红包/书籍/礼品等不定期派送  
  
