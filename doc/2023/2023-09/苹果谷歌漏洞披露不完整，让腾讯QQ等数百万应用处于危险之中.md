#  苹果谷歌漏洞披露不完整，让腾讯QQ等数百万应用处于危险之中   
 网络安全应急技术国家工程中心   2023-09-27 15:49  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176m1HFGWIHj2PsyHMFaUM6UeSmKsTXnxujO9DPQDB35P6P4Fp39v9UdncLC7osuQ2KBy4OeCCbLmWQ/640?wx_fmt=jpeg "")  
  
安全研究员认为，苹果和谷歌最近披露旗下产品零日漏洞缺乏关键信息，可能隐藏了一个上游开源库libwebp的漏洞，将使下游的数百万应用面临“巨大的盲点”，处于攻击危险之中。  
  
9月26日消息，研究人员日前表示，苹果和谷歌最近披露了自身产品中被积极利用的关键零日漏洞，但是他们披露信息并不完整，造成了“巨大的盲点”，导致全球范围内其他开发者提供的大量应用程序未能得到修补。  
  
两周前，苹果报告称，威胁行为者正在积极利用iOS中的一个关键漏洞，以便安装世界上已知的最先进的恶意软件之一“飞马”（Pegasus）间谍软件。这些攻击使用了零点击的漏洞利用方法，也就是说攻击者不需要与目标进行任何交互，只要接收到iPhone上的来电或短信，就足以被“飞马”感染。  
  
**“巨大的盲点”**  
  
苹果表示，这个漏洞（编号为CVE-2023-41064）源于ImageIO中的缓冲区溢出漏洞。ImageIO是一个苹果专有软件框架，允许应用程序读取、写入大多数图像文件格式，其中包括WebP格式。苹果将这个零日漏洞的发现，归功于加拿大研究机构公民实验室（Citizen Lab）。  
  
四天后，谷歌报告称， Chrome浏览器中存在一个关键漏洞。该公司表示，这个漏洞源自WebP格式处理组件的堆缓冲区溢出。谷歌进一步警告说，该漏洞已经出现在野利用。谷歌表示，这个漏洞编号是CVE-2023-4863，由苹果安全工程与架构团队和公民实验室报告。  
  
由于上述两个漏洞有诸多相似之处，很多研究人员迅速推测，二者源自同一个基础漏洞。上周四，安全公司Rezillion的研究人员发布一份证据，他们认为这份证据说明，二者源自相同漏洞的“概率极高”，漏洞源头很可能是在libwebp代码库。Libwebp常被应用程序、操作系统和其他代码库用于处理WebP图像。  
  
研究人员称，苹果、谷歌和公民实验室并没有相互协调、准确报告漏洞的共同来源。相反，三方选择使用单独的CVE漏洞编号。研究人员得出结论，漏洞将在“数百万不同的应用程序”中继续存在，直到这些程序也打上了libwebp补丁。他们表示，这样一来，那些开发者用来追踪其产品中已知漏洞的自动化系统将很难检测到正在积极利用的关键漏洞。  
  
Rezillion研究人员Ofri Ouzan和Yotam Perkal写道：“由于该漏洞的影响范围包括带漏洞依赖项的软件产品，只有这些软件产品的漏洞扫描器才能识别出漏洞。那些盲目依赖漏洞扫描结果的组织将面对一个巨大的盲点。”   
  
此外，谷歌将CVE-2023-4863范围限制在Chrome而非libwebp中，因而受到批评。谷歌官方将漏洞描述为Google Chrome中WebP的堆缓冲区溢出。  
  
谷歌代表在一封电子邮件中写道：“许多平台以不同的方式实现WebP。我们没有关于漏洞如何影响其他产品的任何详细信息。我们的重点是尽快向Chromium社区和受影响的Chromium用户提供补丁。对于软件产品来说，最好的做法是跟踪依赖的上游库，从而获取安全补丁和安全改进。”  
  
谷歌代表指出，披露信息和官方CVE页面中提到了WebP图像格式，却没有解释为什么官方CVE和谷歌的披露信息既没有提到广泛使用的libwebp库，也没有表明其他软件也可能存在漏洞。  
  
关于CVE-2023-4863和CVE-2023-41064是否源自同一个漏洞，谷歌代表没有回答。本文发布之前，公民实验室和苹果没有回复记者通过电子邮件提出的问题。  
  
**哪些对象会受到影响？**  
  
尚不清楚有多少使用了libwebp的应用程序、框架、代码库和其他软件包还没有打补丁。  
  
微软在Edge浏览器中修复了CVE-2023-4863，但该公司在上周四的一封电子邮件中表示其他受影响的产品和软件包尚未打补丁。微软代表说，受影响产品的更新“已经准备发布”，但没有提供预计发布时间。  
  
已知尚未打补丁的微软产品包括广泛使用的协作平台Teams，以及开发工具Visual Studio Code。这两个产品都使用了受CVE-2023-4863影响的Electron框架。还有很多其他应用程序也使用Electron。根据维基百科上编制的列表，它们包括：  
  
1Password，balenaEtcher，Basecamp 3，Beaker（网络浏览器），Bitwarden，CrashPlan，Cryptocat（已停用），Discord，Eclipse Theia，FreeTube，GitHub Desktop，GitKraken，Joplin，Keybase，Lbry，Light Table，Logitech Options +，LosslessCut，Mattermost，Microsoft Teams，MongoDB Compass，Mullvad，Notion，Obsidian，QQ（macOS版）。Quasar Framework，Shift，Signal，Skype，Slack，Symphony Chat，Tabby，Termius，TIDAL，Twitch。Visual Studio Code。WebTorrent。Wire。Yammer…  
  
主流浏览器、Linux操作系统以及大量开源软件均包含libwebp库。受影响的软件包数量太多，无法穷举。如果想了解未列出的产品情况，请与开发者联系。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176m1HFGWIHj2PsyHMFaUM6Ue6ZppicQWAlFpEppJLfHdKayTj1Fbg3s6XtsNDMiaF2tukVqNLwvaNmAg/640?wx_fmt=jpeg "")  
  
Rezilion在许多流行容器镜像（最新版本）中发现了易受攻击的库  
  
谨防漏报  
  
Rezillion进一步表示，对苹果ImageIO二进制文件的扫描显示，文件不仅使用了libwebp，还引用了vp8l_dec.c、vp8li_dec.h、huffman_utils.c和huffman_utils.h。与引发CVE-2023-4863的libwebp中也存在同样的文件。  
  
由于公民实验室和苹果都没有发表评论，无法确定CVE-2023-4863（由谷歌披露）与CVE-2023-41064（由苹果披露）之间的确切关系。  
  
CVE系统的整个目的是识别漏洞来源，帮助任何源代码下游软件的开发者或使用者轻松判断软件是否存在漏洞。如果不同CVE涵盖了相同的基本漏洞，那么发现这些漏洞的团队应该相互协调，明确报告这一情况。  
  
谷歌在CVE报告中省略了libwebp，加剧了信息不完整问题。Rezillion研究人员表示，这种沟通不畅将整个生态系统置于风险之中，因为许多开发人员使用自动扫描工具编译软件物料清单（SBOM），以跟踪他们维护的应用程序中任何有漏洞的组件。  
  
研究人员表示，对于开发人员来说，这些不完整的披露让确定产品是否存在漏洞变成了一项“艰巨的任务”。他们说，缺乏明晰性也会让开发人员在寻找漏洞时面临漏报的风险。研究人员写道：  
  
最初看来，漏洞似乎针对基于Chromium的应用程序。但是，现在我们有了更深入的了解。  
  
我们发现，漏洞有可能影响更多软件和应用程序，它们依赖广泛使用的libwebp软件包实现WebP编解码功能。Libwebp效率十分出色，在大小和速度方面超越了JPEG和PNG。因此，很多软件、应用程序和软件包都引用Libwebp库，甚至直接采用以Libwebp为依赖项的软件包。这样一来，想要识别存在漏洞的系统就变得特别复杂而又挑战性。libwebp的普及度显着扩大了攻击面，引发了用户和组织的严重关切。  
  
如果组织的环境中部署了SBOM解决方案，建议他们查询SBOM，查找使用存在漏洞版本的libwebp作为依赖项的软件包。最重要的是，应该确保系统的libwebp库已经打好补丁。这是因为，一些应用程序，比如Chromium，是针对系统的libwebp库构建的。  
  
苹果和谷歌的披露以及官方CVE披露中使用的英语十分简明，导致读者有充分的理由认为这些零日漏洞来源不同，且仅限于少数产品。现在，当我们有了更全面认识之后，开发者和终端用户应仔细检查软件。如果软件以任何方式与WebP图像互动，很可能需要打好补丁才能安全使用。  
  
**参考资料：**  
  
arstechnica.com  
  
  
  
原文来源：安全内参  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
