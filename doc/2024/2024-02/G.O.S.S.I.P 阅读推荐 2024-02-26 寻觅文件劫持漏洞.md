#  G.O.S.S.I.P 阅读推荐 2024-02-26 寻觅文件劫持漏洞   
原创 G.O.S.S.I.P  安全研究GoSSIP   2024-02-26 20:26  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21F0mPgXdORs9uWOCMXRzGt9fy0eG1Uy4SoPu0m8AHiaGXEmfVCpK7jhhiaoPT9JdIC4UEdxQMO3lHFg/640?wx_fmt=png&from=appmsg "")  
  
看完上面这段话，有没有感觉到一种深深的绝望和恐惧？这里面涉及的就是我们今天要讨论的文件劫持漏洞（File Hijacking Vulnerability，FHVuln）。在今天分享的NDSS 2024论文File Hijacking Vulnerability: The Elephant in the Room中，作者对产生文件劫持漏洞的前因后果进行了系统地分析，深入调查了268个文件劫持漏洞相关的CVE，对其产生的原因进行分析，建立相关的威胁模型，并实现了一个文件劫持漏洞的动态检测工具JERRY。JERRY在438个常用程序中发现了多个文件劫持漏洞漏洞，其中有51 个获得了CVE编号。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21F0mPgXdORs9uWOCMXRzGt9ZTrIAUX6Thia3YGSLMa3BRFickiakALZU0XiaKEIRHn6hnKiaG9Ys5KJJkA/640?wx_fmt=png&from=appmsg "")  
  
什么是文件劫持漏洞呢？简单地说，就是某个应用程序所使用的文件可能会被其他人修改，如果是攻击者恶意修改了这个文件，而相关的应用程序没有意识到这种恶意修改，不加校验和防护就轻易相信并使用修改过的文件（中的内容），那么就会产生非预期的行为（通常会造成任意代码执行），安全性遭到破坏。  
  
下面这个例子（CVE-2022-24765，被本文的JERRY工具发现）是一个典型的文件劫持漏洞，漏洞原因是Git对文件路径处理不当，导致任意命令执行。该漏洞自Git项目诞生以来存在18年之久，可在所有主流操作系统中被利用。漏洞细节如下图所示。假设Bob是攻击者，Alice是受害者。 虽然Bob无权修改以下目录：C:\Users\Alice\和C:\Users\，但是所有通过身份验证的用户组中的任何人（包括Bob）都可以在路径C:\下创建目录，因此Bob创建了C:\.git\目录，并可修改目录中的任何内容。当Alice在她的主目录（C:\Users\Alice\）中调用Git命令（如git log），假设该目录中没有.git\目录，Git客户端会递归搜索其父级目录中的.git\，而在这种情况下，Git客户端会搜索到Bob创建的C:\.git\目录，并将其视为Git home目录。这时候，Bob可以通过事先部署在C:\.git\目录中的githooks来实现任意命令执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21F0mPgXdORs9uWOCMXRzGt95r5icutDJA9LMlpfgV0XzAISsEAHP7b4LsBURUTEQIhIGCzmgz5oB8A/640?wx_fmt=png&from=appmsg "")  
  
为了搞清楚文件劫持漏洞产生的原因，以及文件劫持漏洞对文件的操作能力究竟如何，作者搜集并分析了268个文件劫持漏洞CVE。首先让我们看看文件劫持漏洞产生的原因  
- 路径搜索顺序（9， 3.4%）  
  
- 当前目录优先级高于 PATH 环境变量时，如果当前目录权限较弱，攻击者可以修改当前目录文件进行攻击。例如，Github Cli 会优先搜索当前目录下的 git.exe，攻击者可以在当前目录下写入恶意可执行文件 git.exe 造成任意代码执行  
  
- 在 Windows 上使用 Linux 路径（12， 4.5%）  
  
- 例如，curl 会在 Windows 上读取 /usr/local /ssl/openssl.cnf，Windows 会将此路径解析为 C:\usr\local\ssl\openssl.cnf, 普通用户可以写入此路径，控制配置文件造成任意代码执行  
  
- 没有使用引号包裹路径（46，17.1%）  
  
- 当路径中存在空格，如果没有使用引号包裹路径将会被截断  
  
- 符号链接（52， 19.4%）  
  
- 例如 Samsung Kies 会删除一个并不存在的目录，C:\ProgramData\Samsung \DeviceProfile\Cache，如果攻击者将此目录链接到 C:\ ，Samsung Kies 在卸载时将会删除掉整个 C 盘的文件  
  
- 动态链接库（122， 45.5%）  
  
- Windows 优先搜索当前目录下的动态链接库文件，而 Linux 优先搜索环境变量中指定的目录加载动态链接库，如果在搜索路径中存在弱权限目录将导致动态链接库劫持  
  
接下来我们看看这些漏洞允许攻击者对文件的操作：  
- 移动（3， 1.1%）  
  
- 创建（22，8.2%）  
  
- 删除（27，10.1%）  
  
- 读取（19，7.1%）  
  
- 执行（76，28.4%）  
  
- 镜像加载（121，45.1%）  
  
最后作者还调查了文件劫持漏洞在哪些特定的阶段产生：  
- 安装（46，17.2%）  
  
- 卸载（12，4.5%）  
  
- 更新（5，1.9%）  
  
- 修复（10，3.7%）  
  
- 初始化（167，62.3%）  
  
- 运行（28，10.4%）  
  
在进行完调查之后，作者根据这些统计的数据，实现了JERRY动态检测工具，其架构如下图所示  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21F0mPgXdORs9uWOCMXRzGt921hLKONlkLVGsZEkSYgZUMa1jykH0fBINZLF3B25bueDytl9TmMk6A/640?wx_fmt=png&from=appmsg "")  
  
JERRY中有四个关键的组件，分别是：  
- 事件跟踪生成器（Event Trace Generator）：执行目标程序，并记录对文件的操作行为。  
  
- 使用包管理器触发目标程序的生命周期，基于 https://community.chocolatey.org/packages 实现  
  
- 对于具有 GUI 的目标程序，使用 UI Explorer 尽可能多的触发代码执行，UI Explorer 基于 https://github.com/yinkaisheng/Python-UIAutomation-for-Windows 实现  
  
- 对于命令行程序，通过输入配置文件尝试不同的参数  
  
- FHVuln 检测器（FHVuln Detector）：检查每个对文件的操作行为，如果目标程序对可劫持文件执行了危险操作，则报告漏洞。  
  
- 路径池维护程序（Path Pool Maintainer）：搜集记录中涉及的文件和目录  
  
- 路径劫持器（Path Hijacker）：尝试劫持和创建路径池中的文件，如果文件普通用户无法修改将会被跳过，然后重新回到第一步，直到不再有新文件产生  
  
下图展示了JERRY在检测前面提到的那个CVE-2022-24765（Git搜索路径相关漏洞）的流程，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21F0mPgXdORs9uWOCMXRzGt9pfichzjSpPRm6GeZibaial8AQQCeP0n5dP0xvFTMlkHGF6uqpiazib0hTWA/640?wx_fmt=png&from=appmsg "")  
  
JERRY在第五次迭代时，发现了对C:\.git\config 文件的读取操作，并且确认这个文件是普通用户就可以创建并写入的，因此报告了漏洞。  
  
通过使用已知漏洞评估JERRY并和已有工具的检测效果相比（下图），可以看出JERRY有明显的优势——仅有1例漏报（false negative），查准率和召回率（precision and recall）也明显优于现有工具。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21F0mPgXdORs9uWOCMXRzGt915EjD5ZicBef7OrwVhpCttCd9aiaSIVryQxR4vPdTn4ogznyE5KaDyDg/640?wx_fmt=png&from=appmsg "")  
  
作者用JERRY测试了663个程序，包括Chocolatry包管理器中下载次数超过10万次的软件、以及DELL、HP和联想在它们的Windows版计算机中各类预装软件，这其中有438个可以正常安装测试。JERRY发现了339个文件劫持漏洞（0day），其中84个得到了厂商的确认和修复，还获得了51个CVE编号。部分检测结果如下图所示  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21F0mPgXdORs9uWOCMXRzGt9nf79klcOBb3jlf7o7EiaSBoGW9l83Pckcibib2Q5GGZKx1rOBEK7Qpo0w/640?wx_fmt=png&from=appmsg "")  
  
作者进一步分析了报告漏洞产生的原因（起源，文件操作，生命周期阶段），如下图所示。弱权限是文件劫持漏洞的主要来源（32%），对文件读取操作造成的漏洞占比 30%，在使用阶段造成漏洞占比 60%。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21F0mPgXdORs9uWOCMXRzGt9yHaKBeh65SicWdkMbVaUbaECP0VylicpibhZzjGrNg4buiacA4FWJrMhlQ/640?wx_fmt=png&from=appmsg "")  
> 论文：https://www.ndss-symposium.org/wp-content/uploads/2024-38-paper.pdf  
  
  
  
