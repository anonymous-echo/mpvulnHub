#  DNA 测序仪漏洞标志着医疗器械行业固件存在问题   
原创 很近也很远  网络研究观   2025-01-13 06:36  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxNSGKkxONSTMVUiaD7GUZ3CMufHUu6WCAaJbIC8mEEfBeXXlzjargPICAvMQvFksCErFEvw1Xw0VZQ/640?wx_fmt=png&from=appmsg "")  
  
Eclypsium 安全研究人员发现了 Illumina iSeq 100 DNA 测序仪中的 UEFI 漏洞，但更广泛的问题涉及整个设备开发过程。  
  
在强调广泛使用的 DNA 基因测序设备中的漏洞时，安全研究人员进一步关注医疗设备行业可能存在的糟糕安全状况，该行业的硬件和固件开发通常根据可疑的支持合同外包给外部设备制造商。  
  
该设备是 Illumina 的 iSeq 100 紧凑型 DNA 测序仪，被世界各地的医学实验室广泛使用。  
  
在调查该设备时，供应链安全公司 Eclypsium 的研究人员发现了固件级别的漏洞，以及旨在防止恶意固件植入的关键安全功能缺失。  
  
研究人员在一份报告中写道：“我们发现 Illumina iSeq 100 使用的 BIOS 固件非常过时，采用 CSM 模式，没有安全启动或标准固件写保护。  
  
这将允许系统上的攻击者覆盖系统固件，从而‘破坏’设备或安装固件植入物，以实现持续的攻击者持久性。”  
  
基因工程遇上逆向工程：DNA 测序仪的易受攻击的 BIOS  
  
https://eclypsium.com/blog/genetic-engineering-meets-reverse-engineering-dna-sequencers-vulnerable-bios/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxNSGKkxONSTMVUiaD7GUZ3CMdunpibSJR6dJlYgT0iaG5UFhC9CEOjwHP9P99UtWUgO4icicHicMNLPHZbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxNSGKkxONSTMVUiaD7GUZ3CMFyyw14SlOlXLEA9k1mmPlnYnCIn2LCPNVyQXCI2G8h7fjtLlMqy7nw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxNSGKkxONSTMVUiaD7GUZ3CMr3xUJcZeKj90BIxicoIsUeTbqT1z4Mkia64O2x9eQSuicTPApKqvwCSicQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxNSGKkxONSTMVUiaD7GUZ3CMBnPYYHhIjugCblU1eKZbjsZicxl7UyZsqqOJhsiayOxgInTyWHpt0ZbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxNSGKkxONSTMVUiaD7GUZ3CM8AdOkD9dibSO31zMQicic3jjGEvrWolPBic552L15o3Ld5Q5HVvSY4SuIw/640?wx_fmt=png&from=appmsg "")  
  
但此类设备典型的开发过程性质表明，许多其他医疗设备也可能面临相同或类似问题的风险——这些问题经常出现在物联网和嵌入式设备领域，无论是医疗领域还是其他领域。  
  
典型的 x86 计算机：具有典型的遗留技术问题  
  
除了定制外壳、触摸屏界面和其他用于 DNA 测序的定制外围设备外，iSeq 100 与典型的 x86 台式电脑没有太大区别。  
  
其基本硬件包括运行 Windows 10 loT Enterprise 的 Intel Celeron J1900 2GHz 四核 CPU、8GB RAM 和 240GB SSD。  
  
这并不奇怪，因为 Illumina 与许多医疗设备供应商一样，将硬件设计和制造外包给原始设计制造商 (ODM) — 在本例中是 IEI Integration，该公司开发了各种工业和医疗计算机产品。  
  
IEI 制造了 iSeq 100 内的主板，并且是驱动该设备的统一可扩展固件接口 (UEFI) 固件的供应商。  
  
UEFI 是计算机系统中固件的标准化规范（相当于 BIOS 的现代版本），其中包含负责在加载硬盘上安装的操作系统之前初始化计算机硬件的低级代码。  
  
据 Eclypsium 的研究人员称，iSeq 100（B480AM12 – 2018 年 4 月 12 日）内的固件于 2018 年发布，存在已知漏洞。计算机和设备制造商使用由少数独立 BIOS 供应商 (IBV) 开发的 UEFI 实现，然后使用自己的代码进行配置和自定义。  
  
IBV 的基本 UEFI 实现中的漏洞可能会影响使用该 IBV 固件的所有制造商的产品。例如， 2023 年发现的一次名为 LogoFAIL 的攻击影响了所有三大 IBV（Insyde、AMI 和 Phoenix）的基本 UEFI 实现，原因是其图像解析代码中存在多个漏洞。  
  
结果，大多数 PC 制造商不得不发布 BIOS/UEFI 更新，但许多旧 PC 和主板仍然永远存在漏洞，因为尽管这些产品在现实世界中的使用时间更长，但 PC 制造商仅提供几年的软件支持。  
  
在物联网和嵌入式设备领域，这个问题更加严重，因为这些领域中专用的实时操作系统 (RTOS) 非常常见。  
  
这些设备中经常会发现数十年前由软件公司开发的固件组件，例如 TCP/IP 堆栈，这些软件公司现已不复存在，或者其知识产权多年来多次易手。  
  
工业硬件供应链也受到此问题的影响，如果不提供固件更新，固件安全将成为最终用户难以解决的问题。  
  
LogoFAIL 是 Eclypsium 在 iSeq 100 过时固件中检测到的漏洞之一，其他问题包括缺乏固件写保护、未启用安全启动以及操作系统在兼容支持模式 (CSM) 下启动。  
  
通常包含在 UEFI 中的 CPU 微码也已过时，并且容易受到影响英特尔 CPU 的已知侧信道数据泄漏漏洞的影响，例如 Spectre v2（分支目标注入）以及 Fallout 和 RIDL（微架构数据采样）。  
  
Illumina 发言人通过电子邮件称：Illumina 感谢 Eclypsium Research 的报告以及我们对协调漏洞披露原则的共同承诺。  
  
我们正在遵循标准流程，如果需要采取任何缓解措施，我们将通知受影响的客户。我们的初步评估表明这些问题并不高风险。  
  
Illumina 致力于保障我们产品的安全性和基因组数据的隐私性，我们已经建立了监督和问责流程，包括针对我们产品开发和部署的最佳安全实践。作为这一承诺的一部分，我们一直在努力改进我们为现场仪器提供安全更新的方式。  
  
需要固件保护来防止 UEFI 植入  
  
由于固件刷新未被阻止且固件缺少关键区域的写保护，因此具有操作系统本地管理员访问权限的攻击者可以轻松地将恶意代码注入固件或完全重写固件，从而导致设备无法运行。  
  
Eclypsium 研究人员在报告中写道：鉴于 Illumina 测序仪最近被发现存在严重的 RCE（远程代码执行）漏洞（CVE-2023-1968），这种情况并不罕见。  
  
该问题影响了多种 Illumina 设备，导致 FDA 二级召回以及CISA 的 ICS 医疗咨询。  
  
2023 年的 RCE 漏洞现已得到修补，但攻击者可能会找到另一个漏洞或窃取设备的凭据并利用 Windows 中的权限提升漏洞，这种情况很常见。  
  
Illumina 测序仪运行 Windows 10 2016 LTSB，版本 1607，主流支持已于 2021 年 10 月结束，但扩展支持选项将持续到 2026 年 10 月。  
  
未启用安全启动  
  
意味着负责启动操作系统的代码（无论是在 UEFI 级别还是在 Windows 引导加载程序本身）均未经过加密验证。  
  
因此，恶意代码可能会被注入到启动过程中以控制操作系统内核，这是一种称为 bootkit（启动 rootkit）的恶意软件攻击。  
  
UEFI 启动套件已在野外使用十多年。  
  
示例包括 LoJax (2018)、MosaicRegressor (2020)、FinSpy (2021)、ESPecter (2021)、MoonBounce (2022)、CosmicStrand (2022) 和 BlackLotus (2023)。  
  
更广泛问题的迹象  
  
虽然 Eclypsium 的研究仅针对 Illumina iSeq 100，但研究人员认为许多医疗设备可能都存在类似的固件安全问题，这些问题源自硬件供应链。  
  
医疗设备供应商并不总是自己制造设备硬件，而是专注于核心专业领域，将设备开发过程的其余部分外包给 ODM 和 IBV 等。  
  
许多其他制造商很可能也采用了同样的流程。一旦医疗设备制造商进入研发阶段，他们就会去 ODM 和 IBV 那里‘采购’硬件和固件解决方案，以加快上市时间。  
  
这个过程就像任何其他产品交易一样，制造商会得到 [硬件/固件] 的报价和 X 年的支持——有时包括免费安全更新，有时则不包括。  
  
据我们所知，ODM 甚至 IBV 都会在一定期限内提供更新，但一旦设备超过一定年限，发布修复程序甚至生成修复代码就会变得更加困难。  
  
请记住，工业计算机主板的设计使用寿命比我们熟悉的普通计算板要长得多。  
  
