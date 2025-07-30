#  干货！从零到一: 构建一个可靠的SCA漏洞库   
原创 todobest  SDL安全   2025-01-09 00:42  
  
**一、背景**  
> “  
> 2023 年开源安全和风险分析 (Open Source Security and Risk Analysis) 报告指出，绝大多数代码库 (84%) 至少包含一个已知的开源漏洞，相较去年增加了近 4%。其中，航空航天、航空、汽车、运输、物流，教育科技和物联网 (IoT) 三个领域的代码库中，均包含部分开源代码；物联网领域开源代码占总代码的 89%。其余的垂直行业，也有超过 92% 的代码库是开源的。在审计的 1703 个代码库中，共有 96% 包含开源代码。自 2019 年以来，OSSRA 中所有 17 个行业的高危漏洞至少增加了 42%。零售和电子商务领域的高危漏洞激增了 557%。  
  
  
近年来，由于开源组件中的安全漏洞导致的网络攻击事件频频发生，给众多企业带来了显著的经济损失和声誉危机。许多攻击者专门针对开源软件的已知漏洞，利用这些安全缺陷进行恶意攻击，进一步强调了及时感知漏洞的重要性。  
  
因此，构建一个开源组件（SCA）漏洞库，对于企业来说至关重要。通过及时更新和维护漏洞数据库，企业能够快速识别和应对潜在的安全威胁。这不仅有助于降低公司资产被攻击的风险，还能确保在软件开发生命周期中及早发现和修复漏洞，从而维护客户信任和数据安全。  
  
**二、常用漏洞库**  
  
**2.1 NVD(National Vulnerability Database）**  
  
https://nvd.nist.gov/vuln/full-listing  
  
NVD漏洞库是由美国国家漏洞数据库（National Vulnerability Database，NVD）提供的公共漏洞数据库，它是一个可搜索的、可下载的数据集，包含有关计算机系统中已知漏洞的详细信息。NVD漏洞库的目的是提供准确和完整的漏洞信息，以帮助安全专业人员预测、评估和管理计算机系统中的漏洞风险。该漏洞库收集来自多个来源的漏洞信息，包括公共漏洞披露（CVE）、共享漏洞库（OSVDB）、安全焦点漏洞数据库（SFD）等，每年发布数千个漏洞条目，可以帮助企业制定漏洞修复计划并优化安全策略。  
  
需要注意的是，虽然NVD提供了丰富的漏洞信息，但也存在一些不足之处。许多CVE（公有漏洞和暴露）数据缺乏影响版本、修复版本等重要信息。此外，2022年夏季，CVE数据格式经历了更新，发布了5.0版本（目前大多数仍为4.0）。此版本的发布添加了多个新数据字段，包括可选数据，如严重性评分、研究人员的信用、其他语言的支持、受影响产品列表、附加参考链接及社区贡献能力等。这些新增的可选数据预计将增强CVE记录的实用性，为下游用户及整个漏洞管理社区提供更多信息支持。如需了解更多详细信息，请查看官方公告：  
https://www.cve.org/Media/News/item/news/  
 。  
  
**2.2 Ghsa(GitHub Security Advisories）**  
  
漏洞地址 https://github.com/advisories  
  
该漏洞库包括CVE和GitHub的安全建议，覆盖的语言包含Java、Go、Python、Rust、Swift、Php等等，截止2024年1月7日，目前共有约21000个漏洞。该漏洞信息，会定时在https://github.com/github/advisory-database 这个仓库进行更新，每个漏洞以json  
格式展示。如下图所示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RjLIsDJd9EK5uC8ZhZWPy5PP2xMmGMiaV2DPveKicLXk0Qr25kGsyFibWqia2Ey8PAic7oJUibBV3htww9xkRk5cIrgA/640?wx_fmt=png&from=appmsg "")  
  
**2.3 Glad(Gitlab Security Advisories)**  
  
https://gitlab.com/gitlab-org/advisories-community  
  
类似上面的Github 漏洞库，该漏洞库是Gitlab官方所做的漏洞库，漏洞也支持java、go、python等多种语言  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RjLIsDJd9EK5uC8ZhZWPy5PP2xMmGMiaVSAHI48KQ8UZBH0Lb2PxX5KJ05l2Y7Z1sPaM09QdfPFTo1fniaA27icTQ/640?wx_fmt=png&from=appmsg "")  
  
该漏洞记录格式为yml格式，也包含漏洞影响版本、CVE、修复版本等  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RjLIsDJd9EK5uC8ZhZWPy5PP2xMmGMiaVFKFzYNyZanbt8lxhmLHgOichndxI8StE126C7vqDD52sIAaibXWXSs5A/640?wx_fmt=png&from=appmsg "")  
  
**2.4 Go VulnDB**  
  
https://github.com/golang/vulndb  
  
该仓库记录Go相关的安全漏洞，其数据是JSON  
，介绍了漏洞影响版本、修复版本。如果有CVE的也会介绍CVE等等  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RjLIsDJd9EK5uC8ZhZWPy5PP2xMmGMiaVNBQa5khhbq4UsbJCR7qQCYicRsUE8ibVuABXkAHT0udfRyicZxYIQNk1A/640?wx_fmt=png&from=appmsg "")  
  
**2.5 Node VulnDB**  
  
https://github.com/nodejs/security-wg  
  
该仓库主要记录Node相关的安全漏洞，其数据是JSON  
，介绍了漏洞影响版本、修复版本。这里的许多漏洞，可能并没有CVE编号。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RjLIsDJd9EK5uC8ZhZWPy5PP2xMmGMiaVnyCv44WFrQGoolP2PibB9DfnwNdqa4X8jnmh6HC39sonmicHGTAohfiag/640?wx_fmt=png&from=appmsg "")  
  
**2.6 PHP VulnDB**  
  
https://github.com/FriendsOfPHP/security-advisories  
  
PHP 项目和库中的已知安全漏洞，按照其说法，不具有权威性，可以当做参考，其漏洞格式也是yaml格式，包括漏洞影响版本等等  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RjLIsDJd9EK5uC8ZhZWPy5PP2xMmGMiaVwSn8nicR10TdwUIm7B2SmHrB2ib8CtINEic8KA5v8ttHgX9qsUlFDzwEw/640?wx_fmt=png&from=appmsg "")  
  
**2.7 Python VulnDB**  
  
访问地址https://github.com/pypa/advisory-db  
  
该仓库记录Python相关的漏洞， 漏洞格式是yaml文件，其中包含漏洞影响版本，以及修复版本。该仓库执行大量启发式方法将 CVE 与精确的 Python 包和版本进行匹配，少部分以人工进行匹配  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RjLIsDJd9EK5uC8ZhZWPy5PP2xMmGMiaVKfbVBBT65GPg0XS5weDCwHqbp8OlfPL9xyOZBOW0BoKATa8dmicTsCQ/640?wx_fmt=png&from=appmsg "")  
  
**2.8 CNNVD**  
  
访问地址：https://www.cnnvd.org.cn/home/loophole  
  
CNNVD是中国国家信息安全漏洞库，英文名称“China National Vulnerability Database of Information Security”，简称“CNNVD”，隶属于中国信息安全测评中心(一般简称国测，国测的主管单位是Security部)，是中国信息安全测评中心为切实履行漏洞分析和风险评估的职能，负责建设运维的国家级信息安全漏洞库，为我国信息安全保障提供基础服务。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RjLIsDJd9EK5uC8ZhZWPy5PP2xMmGMiaVRib0zcgiaD3rHxsN42BXopv7kxvPkTKy9wbWP1SjEULGLnpb9XIMQ7RQ/640?wx_fmt=png&from=appmsg "")  
  
CNVD是国家信息安全漏洞共享平台，是由国家互联网应急中心联合国内重要信息系统单位、基础电信运营商、网络安全厂商、软件厂商和互联网企业建立的信息安全漏洞信息共享库，目的是建立国内安全漏洞统一收集验证、预警发布及应急处置体系; CNNVD是中国信息安全漏洞库，世界各国为了更好的进行信息安全漏洞的管理和控制，均先后建立了国家信息安全漏洞库，国家漏洞库通过各种渠道在整个互联网范围内，不分国界地收集漏洞数据和补丁信息，并及时发布，让大家第一时间了解并解决自己的信息系统存在的问题。  
  
**三、系统漏洞库**  
  
上面介绍的都是一些开发语言中用到的依赖，使用到的数据库。但是一般操作系统上安装的软件，也有漏洞相关的问题。下面整理了一些操作系统常用到的漏洞库。  
  
**3.1 Redhat**  
  
https://access.redhat.com/security/security-updates/cve  
  
该漏洞链接里的CVE都是影响Redhat系统里的软件包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RjLIsDJd9EK5uC8ZhZWPy5PP2xMmGMiaVv6XgKqgicLMyxEyia7wVqCNE46ick1nmutZsgbKXQILZL507VVnibQ54ow/640?wx_fmt=png&from=appmsg "")  
  
**3.2 Ubuntu**  
  
https://git.launchpad.net/ubuntu-cve-tracker  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RjLIsDJd9EK5uC8ZhZWPy5PP2xMmGMiaVLeSfUHtnGEcLITyRYoiaL7zqtjiafyBSmZhQG70r1udIkF0sfwAGP2dA/640?wx_fmt=png&from=appmsg "")  
  
**3.3 Debian**  
  
https://salsa.debian.org/security-tracker-team/security-tracker  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RjLIsDJd9EK5uC8ZhZWPy5PP2xMmGMiaVNYL9jvWGINBBJdRG4zPiaxAicupblQHDt58Xepk2PSOiaKNVHK982xiaBA/640?wx_fmt=png&from=appmsg "")  
  
**3.4 SuSe**  
  
OpenSuse 漏洞库数据， 漏洞信息以XML 文件格式展示 https://ftp.suse.com/pub/projects/security/cvrf/  
  
**四、开源方案**  
  
**4.1 谷歌OSV**  
  
https://osv.dev/list  
  
https://github.com/google/osv.dev  
  
可以界面上搜索软件，下面会显示该软件对应的漏洞版本以及修复版本。其提供了OPEN API可供调用。另外其提供了专门的扫描工具，https://github.com/google/osv-scanner。  
  
检测工具缺点：其检测原理是检测代码中的依赖文件如pom.xml，go.mod 等等，实际类似Java语言Maven项目的间接依赖是无法检测的。  
  
漏洞库缺点：私有化部署成本较高，一方面其技术依赖于谷歌方面的glcloud，另外对配置要求极高https://github.com/google/osv.dev/tree/master/deployment  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RjLIsDJd9EK5uC8ZhZWPy5PP2xMmGMiaVwvXd1W3KHVMbWSSoibb06ibdbvuJJeWCuhIWqGnTaOeXktvjpljQM17w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RjLIsDJd9EK5uC8ZhZWPy5PP2xMmGMiaVLzslw71NOV9E7gIAHhvCibcd2EunUaQTbRns1ksCnK5B58LZDDGUQDQ/640?wx_fmt=png&from=appmsg "")  
  
**4.2 DependencyCheck**  
  
项目地址：https://github.com/jeremylong/DependencyCheck  
  
Dependency-Check 是一款软件组合分析 (SCA) 工具，可尝试检测项目依赖项中包含的公开披露的漏洞。  
  
该工具的主要工作原理是通过确定给定依赖项是否存在通用平台枚举（Common Platform Enumeration, CPE）标识符。CPE是一个标准格式，用于描述特定应用程序、操作系统或硬件的特征。通过将项目的依赖项与已知的CPE进行比对，Dependency-Check能够快速识别出存在已知漏洞的组件。  
  
**4.3 OpenSCA-cli**  
  
OpenSCA 通过解析所列编程语言和相应包管理器的配置文件。然后与漏洞库进行比对，确认组件版本是否含有漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RjLIsDJd9EK5uC8ZhZWPy5PP2xMmGMiaVRu9tIrpquKIYzLKdhmNQgBJzia2rG9jav1ibE9D7iaoK4kebAed9WOQbQ/640?wx_fmt=png&from=appmsg "")  
  
**五、总结**  
  
在本文中，我们对多个重要的漏洞库进行了详尽的介绍，包括GitHub的安全建议、NVD漏洞库、Go VulnDB等等。这些漏洞库共同构成了一个全面的安全生态系统，为开发者和企业提供了丰富的漏洞信息和安全建议。  
  
这些漏洞库涵盖多种编程语言（如Java、Go、Python、Rust、Swift和PHP)，并定期通过JSON  
、Yaml等格式更新，确保信息的时效性。且部分做了漏洞的标准化及详细分析。这些漏洞库的建设不仅显著提升了开源软件的安全性，并且为开发者和企业提供了一个集中、易于访问的资源，以有效抵御网络攻击和减少安全风险。  
  
通过整合和定期更新这些漏洞库，企业能够高效识别潜在的安全威胁，从而在软件开发生命周期中及时发现和修复漏洞，最终维护客户信任和数据安全。这一系列漏洞库的有效利用将足以满足绝大部分安全场景，为构建一个更加安全的开源环境奠定了坚实基础。  
  
  
