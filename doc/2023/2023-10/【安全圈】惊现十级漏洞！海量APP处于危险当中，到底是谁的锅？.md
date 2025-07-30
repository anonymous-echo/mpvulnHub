#  【安全圈】惊现十级漏洞！海量APP处于危险当中，到底是谁的锅？   
 安全圈   2023-10-12 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljgyGZIXqsjf3OxfKjANsh40oK3o56zxJQXLGM4kNQkICicoPFOPHJo7WAXcKZ6C7mErK6494U2s8g/640?wx_fmt=png "微信图片_20230927171534.png")  
  
**关键词**  
  
  
  
漏洞  
  
  
  
最近开源软件又爆出一个十级漏洞，该漏洞冲击范围巨大，涉及数百万不同的应用程序，其中也包括 iOS、Android 应用程序以及使用 Electron 构建的跨平台应用程序。  
  
这个漏洞两周前就已经被苹果和谷歌发现，但苹果和谷歌在披露漏洞时缺乏关键信息，造成了“巨大的盲点”，导致全球范围内其他开发者提供的大量应用程序未能得到修补，这些应用程序可能一直处于攻击危险之中。  
  
1为什么会产生“巨大的盲点”  
  
两周前，苹果报告称，威胁行为者正在积极利用 iOS 中的一个关键漏洞（编号为 CVE-2023-41064），以便安装世界上已知的最先进的恶意软件之一“飞马”（Pegasus）间谍软件。这些攻击使用了零点击的漏洞利用方法，也就是说攻击者不需要与目标进行任何交互，只要接收到 iPhone 上的来电或短信，就足以被“飞马”感染。  
  
四天后，谷歌报告称， Chrome 浏览器中存在一个关键漏洞。谷歌表示，该漏洞被指定为 CVE-2023-4863，由苹果安全工程和架构团队以及公民实验室报告。披露中列出的受影响供应商为“谷歌”，受影响软件则为“Chrome”，而且该漏洞已经出现在野利用。谷歌和 Mozilla 马上紧急修复了各自浏览器（分别是 Chrome 和 Firefox）中的漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhEezL9Ytzn8iapLBU7XXcKRjTzlBX3WWj3lzocLvrvWSr6Yyc7Q8aA3p1Cdd6rdbMGw8ico4VJKNHA/640?wx_fmt=png "")  
  
  
实际上，从谷歌的信息中，可以看出该漏洞源自谷歌于 2010 年开发的 libWebp 代码库，用于以 Webp 格式渲染图像。Webp 是当时的一种新兴格式，能够让文件体积比 PNG 图像再降低 26%。libwebp 几乎被整合进各种应用、操作系统及其他渲染 Webp 图像的代码库当中，**其中最知名的当数 Chrome 中使用的 Electron 框架，以及在桌面和移动设备上运行的各类应用产品**。  
  
本周一，谷歌悄悄重新提交了一项关于影响众多独立应用和软件框架的关键代码执行漏洞信息，以纠正此威胁只会影响到 Chrome 浏览器的错误印象。这份新的披露信息，编号为 CVE-2023-5129。新条目正确为 libwebp 列出了受影响的供应商和软件类别，还将漏洞的严重等级从 8.8 分（满分 10 分）提高到 10 分。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhEezL9Ytzn8iapLBU7XXcKRl4jMibVdU699LaNOsOMqO1SfqUbgH7uRva0IpsUatyNOXeC2w6SUcrA/640?wx_fmt=png "")  
  
  
安全公司 Rezillion 的研究人员认为苹果和谷歌的产品漏洞源自同一个基础漏洞，但苹果、谷歌并没有相互协调、准确报告漏洞的共同来源，反而都选择使用单独的 CVE 漏洞编号。这样一来，那些开发者用来追踪其产品中已知漏洞的自动化系统将很难检测到正在被利用的关键漏洞。  
  
Rezillion 研究人员 Ofri Ouzan 和 Yotam Perkal 写道：“由于该漏洞的影响范围包括带漏洞依赖项的软件产品，只有这些软件产品的漏洞扫描器才能识别出漏洞。那些盲目依赖漏洞扫描结果的组织将面对一个巨大的盲点。”  
  
**谷歌提交的第一条不完整 CVE 绝不是单纯的技术失误，导致在漏洞曝光两周多之后，不少软件仍未进行修复。其中最典型的例子就是 Microsoft Teams。**  
  
谷歌在新提交的漏洞描述中补充了更多细节。之前提交中的描述是：  
> 116.0.5845.176 版本之前的谷歌 Chrome 中，Webp 的堆缓冲区溢出漏洞允许远程攻击者在精心设计的 HTML 页面中执行越界内存写入。（Chromium 安全严重度：严重）  
  
  
  
现在新的描述调整为：  
> 使用特定 Webp 无损格式文件，libwebp 可能将数据越界写入堆。ReadHuffmanCodes() 函数在分配 HuffmanCode 缓冲区时，其大小来自预先计算出的 size 数组：kTableSize。color_cache_bits 值的定义需要使用此 size。kTableSize 数组仅考虑到 8-bit 一级表查找，但未考虑到二级表查找的 size。而 libwebp 最多只允许 15-bit(MAX_ALLOWED_CODE_LENGTH) 的代码大小。因此当 BuildHuffmanTable() 尝试填充二级表时，可能会写入越界数据。对尺寸不足数组的越界写入发生在 ReplicateValue 当中。  
  
  
  
无论是按 CVE-2023-4863 还是 CVE-2023-5129 的表述来看，libwebp 的这项漏洞都相当严重。因此在使用 App 之前，**用户应确保对应的 Electron 版本已经升级为 v22.3.24、v24.8.3 或者 v25.8.1**。  
  
2看似无害的工具，却造成了惊人的影响和冲击范围  
  
2010 年谷歌无意间留下的这个 bug，很可能是引发本次 iOS 零日漏洞的根本原因，并跨越 13 年精确击中了 iPhone 14。  
  
Webp 是谷歌开发的一种开源图像格式（与其他公司共享），跟 jpeg 和 png 属于同一类选手，负责提供一种新的图像压缩方法。这样文件体积更小巧，还原度也更高。没错，大家在看小尺寸 jepg 文件时，是不是经常遇到“色素块”一样的压缩痕迹？Webp 格式就是为了解决这个问题而生。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhEezL9Ytzn8iapLBU7XXcKRFHwru27ibAz8u4FUicIcib3cic4ibDKliaT6rQ5ic88514600hFJ5jic79b2icg/640?wx_fmt=png "")  
  
Jpeg 与 Web  
p 文件大小对比。  
  
因为这种格式既实用又有谷歌大佬的强力助推，Webp 自然就流行了起来。过去 12 年间，Android 和 Chrome 都默认捆绑 Webp，2 年前开始 Mac/iOS/Safari 也将其纳入自身，更不用说其他各种浏览器了。感兴趣的朋友可以参考这里的支持浏览器完整列表（  
https://caniuse.com/webp）。  
  
简单讲，Webp 库中的一个 bug 似乎会导致图像解码过程时发生堆缓冲区溢出。就是说，黑客可以向目标 iPhone 发送短信，借此实现设备入侵。对，你没有看错，黑客可以向受害者发送特制的图像来访问对方 iPhone。该图像在被接收后会由 iPhone 中捆绑的 Webp 解码器负责处理，这样黑客就能在 iPhone 上执行命令，且无需用户交互或者许可。  
  
在安全社区中，这类问题被称为零日（0-day）漏洞，即“攻击者先于厂商所发现的软件漏洞”。而这次的 bug，**存在**大概有 4 到 10 年了吧。而且之所以闹这么大，就是因为 Webp 目前存在于全球数十亿台设备之上。  
  
有很多应用程序使用 libwebp 来渲染 WebP 图像，包括 LibreOffice、Telegram、ffmpeg 以及许多许多 **Android 应用程序**以及**使用 Flutter 构建的跨平台应用程序**。  
  
还有基于 Electron 的应用程序，根据维基百科上编制的列表，包括了 1Password、Discord、Eclipse Theia、GitHub Desktop、Microsoft Teams、MongoDB Compass、Notion、QQ (for macOS)、Signal、Skype、Visual Studio Code 等等。  
  
主流浏览器、Linux 操作系统以及大量开源软件均包含 libwebp 库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhEezL9Ytzn8iapLBU7XXcKR3oG8FQYIbYsPoSQiaia05Q1VCEX6wibqUaCSPtiaY4vkwjbrz6M2l5O6IA/640?wx_fmt=png "")  
  
该图表中提到的每个产品（以及许多其他产品）都发现自己在某种程度上受到 libwebp 中的此漏洞的影响，但该漏洞的定义 CVE 是由 Google Chrome CNA 作为 Chrome 漏洞发布的，而不是针对任一上游来源。有无数的应用程序使用 Electron、Chromium 或 libwebp，它们都受到此漏洞的影响，而 CVE 则与 Chrome 相关。  
  
当谈论这个 CVE 时，它可能指的是 Chrome、Chrome 的上游，或者上游组件下游的事物。如果问你是否已经修补了这个漏洞，你能给出一个自信的答案吗？随着 Electron 的大规模扩散，可能有许多应用程序受到影响，而你甚至可能不知道究竟哪些受到影响。  
  
但在之前提交的 CVE 中，谷歌并未提及将有众多 App 受此影响。  
  
目前，Electron 修补了该漏洞（  
https://github.com/electron/electron/pull/39828）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhEezL9Ytzn8iapLBU7XXcKRKXXqKYRmgIN0NYaMGWHmJFIdcER1yib0YXTbjxKcdj3KhpcNlGqVeAg/640?wx_fmt=png "")  
  
  
1Password for Mac 已发布更新来解决该问题。Telegram Desktop 进行了更新，并且 Ubuntu、Debian、SUSE 和其他 Linux 平台也在积极更新其 libwebp 版本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhEezL9Ytzn8iapLBU7XXcKRfApQibOd8KESd31ibNvdEnahHq5O6iaOEsMFvpYSlXk5NaIrHYy8pjChQ/640?wx_fmt=png "")  
  
 Android 受不受影响？  
  
Ben Hawkes 曾经在 Google 担任零号项目的经理，他写了一篇关于他对此 CVE 的想法的完整文章（  
https://blog.isosceles.com/the-webp-0day/）。  
  
Ben 确认 Android 100% 受此影响。“与 Apple 的 ImageIO 类似，Android 有一个名为 BitmapFactory 的工具来处理图像解码，当然也支持 libwebp。截至今天，Android 尚未发布包含 CVE-2023-4863 修复程序的安全公告。”  
  
**Android 保护措施能解决这次的问题吗**？目前还不清楚，目前事情还在发酵当中。谷歌已经发布了 Webp 更新，可能会通过下个月的 Android 定期补丁推出。到时候参考发行说明，我们才能知道 Android 媒体强化有没有缓解影响，或者说在 iOS 端带来可靠的保护效果。  
  
**现在，我们能做的就是**更新所有软件。从现在开始，认真检查自动更新有没有开启。苹果已经发布了 Mac 和 iOS 端的重要更新，Chrome 也是一样。预计后续会有更多供应商快速跟进。  
  
**身为应用开发者**，如果你的应用允许用户生成图像，那请考虑提供更新的 Webp 库版本，并用它来解码用户提交的内容。这样就能主动为用户提供保护，无需等待 Android 平台的整体更新（特别是能保护那些版本太旧、已经停止更新的 Android 设备用户）。  
  
要使用特定版本，大家可以从源代码进行编译（建议包含最新修复），或在这里找到你的目标库：  
https://developers.google.com/speed/webp/docs/precompiled.  
  
如果你的应用不允许用户生成内容，那就完全无需担心。只要你的应用资产是“安全”的 Webp 文件（即未受恶意篡改的文件），就不会对用户造成任何损害。  
  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhs69mbNyEBtHfYMD4VUBzUWSC9XqQwQurtssqsoUIZYswUjS1eVREibicnShIiagmrcAYSRXxHpF6icA/640?wx_fmt=png "")  
[【安全圈】澳大利亚籍女间谍成蕾服刑期满被驱逐出境](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652046370&idx=1&sn=9fe8f067c83273fff4ed8830948f52b9&chksm=f36e2862c419a17465a01a7229aab85242c44999e15591ed89546a23895eaba21bd22105aecd&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhs69mbNyEBtHfYMD4VUBzUGIVkJUQPvG3oY7y2R1OdEnmyusjUvvaQ0Ismoo7PfkicAJZqSB9Ierw/640?wx_fmt=png "")  
[【安全圈】近2万条学员信息被泄露！黑客落网获刑，培训机构被罚](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652046370&idx=2&sn=6296d797f9af10390b39d67c11c72332&chksm=f36e2862c419a174966654861f4b7cc98260ea3bdebf47a8c22dc06100f52fea4035800db3c2&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhs69mbNyEBtHfYMD4VUBzUeTn8os0VVp97WpHepzEibHZHMg0zvhcw4nJDw66skok4enFdviczaRxg/640?wx_fmt=png "")  
[【安全圈】老同学发语音求助信以为真，大学生被“AI换声”诈骗](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652046370&idx=3&sn=95124d84c7db466e7fa944aea1396182&chksm=f36e2862c419a1748c10e21a4c06151317313bc0ef6eec8313edc6d5fc03a9416c9e986c6705&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhs69mbNyEBtHfYMD4VUBzUgzibOPF8JgibDAe9L4ib1VhIawCB0WiciamDXWEOqsDFpNrGugaIH59iaYIA/640?wx_fmt=png "")  
[【安全圈】阿里云监测：curl SOCKS5堆溢出漏洞(CVE-2023-38545)](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652046370&idx=4&sn=1eccfcdc09f13215f1f29fcb36d47209&chksm=f36e2862c419a1743c798e027034bf0a799f1c53bc7b12ef1fe4b6d05472a9cac845aa143942&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
