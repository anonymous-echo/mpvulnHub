#  黑客利用 ProjectSend 漏洞对暴露的服务器进行后门处理   
天唯科技  天唯信息安全   2024-12-10 06:07  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNbU68NXCNH8sw9R1wBYiaT6icvH7moZbnkDB7UPWcP57YnEr5sDNDh6pssbCmuxvzQERZeMhN6Dknw/640?wx_fmt=png "")  
  
恶意分子正在利用 ProjectSend 中的一个关键身份验证绕过漏洞的公共漏洞来上传 Webshell 并获得对服务器的远程访问。  
  
该漏洞被追踪为 CVE-2024-11680，是一个严重的身份验证错误，影响 r1720 之前的 ProjectSend 版本，允许攻击者向“options.php”发送特制的 HTTP 请求以更改应用程序的配置。  
  
成功利用该漏洞可以创建流氓帐户、植入 Webshell 以及嵌入恶意 JavaScript 代码。  
  
尽管该漏洞已于 2023 年 5 月 16 日得到修复，但直到近期才为其分配了 CVE，导致用户没有意识到其严重性以及应用安全更新的紧迫性。  
  
根据已检测到活跃利用的 VulnCheck 的说法，到目前为止，修补速度非常糟糕，99% 的 ProjectSend 实例仍在运行易受攻击的版本。  
  
**数千个实例被曝光**  
  
  
  
ProjectSend 是一款开源文件共享 Web 应用程序，旨在促进服务器管理员和客户端之间安全、私密的文件传输。它是一款颇受欢迎的应用程序，被那些更喜欢自托管解决方案而不是 Google Drive 和 Dropbox 等第三方服务的组织所使用。  
  
VulnCheck 表示，在线大约有 4,000 个面向公众的 ProjectSend 实例，其中大多数都容易受到攻击。具体来说，根据 Shodan 数据，55% 的暴露实例运行 2022 年 10 月发布的 r1605，44% 使用 2023 年 4 月的未命名版本，只有 1% 运行修补版本 r1750。   
  
VulnCheck 报告称，发现 CVE-2024-11680 的主动利用不仅限于测试，还包括更改系统设置以允许用户注册、获得未经授权的访问以及部署 Webshell 以保持对受感染服务器的控制。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibRqQo9Kkib4MBOnLKu6rZpXfAGTgJ2gXdvBPZbTxAyCqMKib9agDRz0dKgbKlueeFK1SOicKGAib8FaA/640?wx_fmt=png&from=appmsg "")  
  
启用新用户注册  
  
自 2024 年 9 月 Metasploit 和 Nuclei 发布 CVE-2024-11680 的公共漏洞以来，此活动有所增加。  
  
报告中写道：“VulnCheck 注意到面向公众的 ProjectSend 服务器已开始将其登陆页面标题更改为长的、随机的字符串。这些又长又随机的名称符合 Nuclei 和 Metasploit 实施漏洞测试逻辑的方式。”  
  
这两种漏洞利用工具都会修改受害者的配置文件，以使用随机值更改站点名称（以及 HTTP 标题）。GreyNoise 列出了与此活动相关的 121 个 IP，表明存在广泛的尝试，而不是孤立的来源。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o2ibRqQo9Kkib4MBOnLKu6rZpXibD6drZuoCvoGHkggS67cMaiaicQoiblML0BR18ialHzGSgKcGcmpjBk47g/640?wx_fmt=jpeg&from=appmsg "")  
  
Shodan 上出现的攻击受害者  
  
VulnCheck 警告称，Webshell 存储在“upload/files”目录中，名称由 POSIX 时间戳、用户名的 SHA1 哈希值以及原始文件名/扩展名生成。  
  
通过 Web 服务器直接访问这些文件表明存在积极的利用行为。基于攻击可能已经很普遍存在，研究人员建议用户尽快升级到 ProjectSend r1750 版本。  
  
参考及来源：https://www.bleepingcomputer.com/news/security/hackers-exploit-projectsend-flaw-to-backdoor-exposed-servers/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNbU68NXCNH8sw9R1wBYiaT6icvH7moZbnkDB7UPWcP57YnEr5sDNDh6pssbCmuxvzQERZeMhN6Dknw/640?wx_fmt=png "")  
  
  
天唯科技专注于大型组织信息安全领域及IT基础设施解决方案的规划、建设与持续运维服务。帮助客户提高IT基础设施及信息安全管控水平和安全运营能力，使客户在激烈的市场环境中保持竞争力。  
  
我们一直秉承“精兵强将，专业专注”的发展理念。  
先后在江门、深圳成立分公司，在武汉、长沙成立办事处以及成立广州的服务支撑中心。公司已获得高新技术企业认证、已通过IS09001、IS027001、CCRC信息安全集成服务、CCRC信息安全风险评估、CCRC信息安全应急处理等认证。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNRytkPMNOKYRW452LxR5Ez5Wee8X6KlbhoUMt9XyhhbRxHafKcCLWJic3ib0umJiaH3fl6sOx8KMBiaQ/640?wx_fmt=png "盾牌单图.png")  
  
**END**  
  
  
  
**往期推荐:**  
  
  
  
  
  
[网警提醒：警惕暗链威胁](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247503011&idx=1&sn=c7594d27cdb1e007e925f86d200dcf91&scene=21#wechat_redirect)  
  
  
  
[无补丁，I-O Data路由器0Day漏洞被利用](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247503011&idx=2&sn=86f3757c8d1f10c57e921039e6650e10&scene=21#wechat_redirect)  
  
  
  
[威努特工控主机卫士：全面守护关基设施的“中枢神经”](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247502992&idx=1&sn=3b8956abd884d299ef2f29e6878643e7&scene=21#wechat_redirect)  
  
  
  
**征文通道:**  
  
  
  
  
  
[发钱！征文！让真诚的分享更有价值](http://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247490310&idx=1&sn=db4b524d1d9f5aabb4af2184dd831de3&chksm=c25ed7a6f5295eb053d3f90e2dc8cd22a2d8ce1a62561ffa62966340ee563734cd4fd32045f3&scene=21#wechat_redirect)  
  
  
