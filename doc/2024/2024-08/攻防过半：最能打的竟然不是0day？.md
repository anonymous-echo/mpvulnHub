#  攻防过半：最能打的竟然不是0day？   
原创 ThreatBook  微步在线   2024-08-22 20:04  
  
#   
  
攻防大战过半，赛博世界虽未火力全开，但依旧波诡云谲，充满刀光剑影。话不多  
说，来看看过去一个月，有哪些新的攻击手段和趋势：  
  
  
  
攻击木马  
  
**CS超90%，Linux新型特马增加**  
  
微步云沙箱S首月捕获CobaltStrike样本 6000+，红队工具样本1500+。  
攻击木马仍以CobaltStrike家族为主，占比达90%以上，也有部分攻击者技术高超，使用自写“特马”绕过检测，具备极强对抗免杀能力。  
  
微步情报局发现并命名了一款新型Linux特马——“acc特马”，主要用于攻击者渗透后远程控制，且采用C2轮询机制，用同一公钥进行远程上线以追求自动化操作。通过测绘发现在野未有样本关联C2达70多个，预计未来一个月，该特马很可能大肆攻击相关单位Linux主机。目前微步云沙箱S已支持同组特马精确检测，详情可查看：[还在Webshell？警惕Linux特马“大杀四方”](http://mp.weixin.qq.com/s?__biz=MzI5NjA0NjI5MQ==&mid=2650182016&idx=1&sn=bbf8e8d44db25920ea9cfc3e487cbab4&chksm=f4486a3cc33fe32aaff28a94dc8c64eb188e193a445f340e0eb46cf34c0512f58fe3cd907c3d&scene=21#wechat_redirect)  
。  
  
  
漏洞利用  
  
**71%为Nday利用，行业供应链需加倍关注**  
  
  
微步威胁感知平台TDP及威胁防御系统OneSIG检测到0day漏洞与Nday漏洞攻击300余个，涉及漏洞主要集中在国产OA系统、ERP系统、开发常用组件及安全设备。  
  
检测到的漏洞攻击中，“老漏洞”（Nday）由于获取成本低、广泛存在且具备更好的隐蔽性，仍是攻击者利用的主要手段，其中捕获到2022年以前的老漏洞攻击行为达到71%，且绝大部分Nday均通过工具扫描，而“新漏洞”更多是通过手工探测方式进行攻击。  
  
另外，基于微步情报局观察，也出现了行业特有的供应链系统（尤其是0day）漏洞，此类漏洞一旦被利用，将产生巨大“爆炸半径”，可能成为攻击者针对行业的“差异化”武器，影响大量终端用户及企业，值得特别关注。  
  
对于这一变化，企业不仅需要注意0day漏洞，也需提前重点盘点内部资产是否受到历史高危漏洞影响，做好日常漏洞防护，持续关注自身资产。（漏洞情报订阅通道：  
https://x.threatbook.com/v5/vulSubscribeIntro）  
  
  
红队工具  
  
**Mimikatz、fscan、Frp位列前三，需重点关注Chisel**  
  
基于微步云沙箱S捕获样本，Mimikatz、fscan和Frp排在前三，是攻击者最常用工具。排名第四则是一款新兴工具Chisel，需要企业特别关注。Chisel是一款快速的TCP/UDP 隧道工具，使用Go语言编写而成，通过HTTP进行传输，并通过SSH进行加密，由于Chisel简单易用以及跨平台等特点，备受攻击者青睐。  
  
  
木马技术  
  
**Rust与Python语言势头凶猛，多种隐秘、绕过手法并用**  
  
微步情报局发现，大部分木马仍由C/C++语言编写，紧随其后则是Rust和Python。  
木马样本执行与对抗手法上，主要涉及LOLBins的应用、ftp.exe执行相关代码、控制流平坦化混淆技术以及通过Patch正常文件执行恶意行为四种方式。  
  
其中，LOLbins是系统自带的可执行文件和工具，攻击者利用其进行恶意操作，但无需引入外部恶意软件，非常隐蔽，且工具合法，具备系统适配性。ftp.exe则是Windows自带的命令行FTP客户端程序，该程序支持运行脚本文件，因此被攻击者利用。  
  
此外，控制流平坦化混淆，通过重组代码逻辑，让分析人员在逆向工程时更难理解程序的实际流程，减少被安全软件或防病毒产品检测的概率，能有效绕过自动化分析。通过Patch正常文件执行恶意行为，是在逆向分析技术中对二进制文件或程序进行修改，从而修复软件缺陷，破解软件保护、绕过安全检查，或是更改软件行为。  
  
  
钓鱼攻击  
  
**Ink快捷方式增多，双重后缀及多加空格伪装广泛应用**  
  
社工钓鱼是0day、1day/Nday之后，排名第三的入侵源手法。文件格式上，exe后缀依旧保持领先，zip、rar后缀名紧随其后。需要注意的是，Ink快捷方式由于更具迷惑性，容易让人放松警惕，也受到了攻击者的喜爱。不过，钓鱼主题上，攻击者仍围绕政策、招聘、行政通知、社保福利等方向，与此前相比并无大异。  
  
  
攻击远控情报  
  
**攻击源IP&公有云远控地址阿里云最多**  
  
近一个月，我们从远控解析到的归属云厂商来看，公有云C2地址归于阿里云的占比最高，达到64%以上，其次则是腾讯云、联通云、华为云，来自其他公有云厂商的远控较少。  
  
另外，基于微步情报局每天自动化累计挖掘的数千个最新高可信攻击IP，我们发现攻击源IP占比最高，同样来自阿里云，其次分别来自电信云、联通云、腾讯云，这些来源访问IP行为需防守方重点关注。  
  
  
警惕  
  
**黑灰产浑水钓鱼，未知身份攻击者VPN水坑攻击**  
  
微步情报局发现，有攻击者仿冒金融、央企等20多家企业VPN站点，采用典型白加黑绕过手法，传播远控木马，窃取敏感信息和远程控制受害者终端，攻击危害极大，详情可点击：[警惕！大规模VPN水坑攻击来袭](http://mp.weixin.qq.com/s?__biz=MzI5NjA0NjI5MQ==&mid=2650181915&idx=1&sn=3dd50198c69108c066c94f952b1a5639&chksm=f4486aa7c33fe3b1d7ec4fb3e5dd2ab2ce57c7915e3ff161a3c3d69976bdbbde86a90d34aaef&scene=21#wechat_redirect)  
。  
  
此外，微步情报局还监测到，一个名叫GanbRun的高活跃黑产团伙，在钓鱼攻击中使用窃密软件，主动收集受害者信息，伪造成政府网站链接地址并诱导点击，从云存储或攻击者服务器下载恶意文件，窃取浏览器数据。具体情况可查看：[目标银行、证券、央企！黑产团伙伪造政府网站大规模钓鱼](http://mp.weixin.qq.com/s?__biz=MzI5NjA0NjI5MQ==&mid=2650181977&idx=1&sn=e6d73222a262d070eede097619203716&chksm=f4486ae5c33fe3f36db1fe67055e39f8a3d396e379f3b3c9aa6f2182ff1a91f4dddd8b1d5b7d&scene=21#wechat_redirect)  
。  
  
  
  
  
  
**漏洞情报服务**  
  
  
对微步漏洞情报服务感兴趣  
  
可扫描下方二维码  
  
↓  
↓↓  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hQl5bZ5Mx6PTAQg6tGLiciarvXajTdDnQiacxmwJFZ0D3ictBOmuYyRk99bibwZV49wbap77LibGQHdQPtA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTIdM9koHZFkrtYe5WU5rHxSDicbiaNFjEBAs1rojKGviaJGjOGd9KwKzN4aSpnNZDA5UWpY2E0JAnNg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[点此电话咨询]()  
  
  
  
  
· END ·  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSA5A4iaspRVClFku4KVwkOUriclTaohLibE2oQKMTrQ8hvSFFHevq88eibd7mstuZbeNLm5U1tPJT3xQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
