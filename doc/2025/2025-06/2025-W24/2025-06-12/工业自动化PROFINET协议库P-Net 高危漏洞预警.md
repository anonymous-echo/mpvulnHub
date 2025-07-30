#  工业自动化PROFINET协议库P-Net 高危漏洞预警  
原创 xubeining  山石网科安全技术研究院   2025-06-12 09:30  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxvbibNMMmxDGrTN0Z9ibYzXnSNKobTzADCPgdo1b7ukKNARFEicHqQiajWw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
****  
****  
**攻击者只需网络访问权限，即可让工业设备宕机、CPU100%满载，甚至完全失控！**  
  
****  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
工业自动化领域广泛使用的PROFINET协议库P-Net被曝存在10个高危漏洞！Nozomi Networks Labs最新研究发现，这些漏洞可导致设备拒绝服务、内存破坏甚至完全失效。攻击者无需认证，仅通过网络访问即可触发漏洞，对关键工业控制系统造成严重威胁。目前，RT-Labs已紧急发布修复版本，但仍有大量设备面临风险。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**一、协议实现的模糊测试：P-Net PROFINET库中的10个漏洞**  
  
  
PROFINET IO设备是工业自动化组件（如传感器、执行器、驱动器或I/O模块），它们通过PROFINET协议进行通信。该协议是一种基于以太网的实时标准，广泛应用于运营技术（OT）网络。这些设备能够与可编程逻辑控制器（PLC）实现确定性、低延迟的数据交换，支持周期性（实时）和非周期性（诊断/配置）通信。在OT网络中，这些设备对于控制和监测制造、能源和交通等行业的物理过程至关重要，通常构成工业以太网通信的核心。  
  
  
在本文，作者调查了在一次针对P-Net C库的模糊测试活动中发现的十个漏洞。P-Net是RT-Labs开发的一个开源PROFINET协议实现，专用于IO设备。这些漏洞是Nozomi Networks Labs在持续评估OT环境中常用工业通信协议安全状况的过程中发现的。  
  
  
作者已将所有发现负责任地披露给RT-Labs团队，他们迅速并有效地做出了响应，并在该库的最新版本（1.0.2）中修复了所有问题。值得一提的是，在收到作者的报告后，RT-Labs还将模糊测试引入了其开发流程，使用libFuzzer工具，进一步增强了其软件的整体安全性。  
  
  
在接下来的部分中，我们将介绍作者本次研究的关键发现，探讨这些漏洞对工业设备可能造成的影响，并分享作者用于模糊测试PROFINET协议栈的方法和工具。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**二、研究范围**  
  
****  
  
RT-Labs专注于嵌入式系统的软件解决方案，尤其聚焦于工业通信与自动化领域。他们的平台简化了复杂现场总线集成的开发过程，使企业能够更专注于产品功能和性能的优化。  
  
  
RT-Labs提供统一的通信解决方案，以满足对实时性和网络通信要求极高的工业应用，并配备先进的测试自动化工具，从而提升软件质量和开发效率。  
  
  
RT-Labs与众多工业领域的重要企业合作，包括丰田（Toyota）和ABB，并通过GitHub上的开源项目倡导开放协作，开发者可在其中查阅并贡献部分代码。  
  
  
在本次研究中，作者选择了RT-Labs开发的P-Net PROFINET库作为目标。该库采用C语言实现，用于IO设备的PROFINET协议通信，具备高度灵活性并可在各种操作系统下运行，包括裸机系统、实时操作系统（如RT-Kernel）甚至Linux。它唯一的运行前提是支持收发原始以太网数据包。P-Net的评估版本已在RT-Labs的GitHub上公开发布，正是作者此次研究的基础。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**三、漏洞影响**  
  
****  
  
在分析P-Net库的1.0.1版本后，作者发现了与PROFINET协议中UDP RPC功能相关的10个内存损坏漏洞。这些漏洞可被未认证的攻击者利用，只要他们能访问目标设备所在的网络。一旦被成功利用，这些漏洞可能导致设备无法访问、出现严重不稳定，甚至进入拒绝服务（DoS）状态。  
  
  
具体而言，通过利用CVE-2025-32399，攻击者可以让运行P-Net库的CPU陷入无限循环，持续占用100%的CPU资源。这种情况可能导致设备电量迅速耗尽，特别是在依赖电池供电的IO设备上，这将成为一个严重问题，甚至可能需要人工干预才能恢复正常运行。  
  
  
另一个漏洞CVE-2025-32405允许攻击者越界写入连接缓冲区，破坏内存，使设备完全无法使用。考虑到这些IO设备通常部署在工业控制（OT）网络中，此类故障可能造成严重影响，甚至中断或削弱整个工业生产线的可靠性。  
  
  
漏洞列表及受影响的版本如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRjP2CI7EyhCnpzdrU9s4bVicQk03esficU924wMlpEX0asKEmXs0DvxVJ3bVnvWma8icH5zdicr1ZjEg/640?wx_fmt=png&from=appmsg "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**四、模糊测试活动的设置**  
  
****  
在本节中，将概述作者进行模糊测试网络协议栈（如P-Ne库）时所采用的方法以及面临的独特挑战。幸运的是，P-Net库支持Linux，并且该项目的GitHub页面上提供了预编译的IO设备演示程序。  
  
  
作者的第一步是下载并尝试运行该演示程序，以了解其远程攻击面，包括识别可能被攻击者利用的网络服务。在运行时分析过程中，作者发现IO守护进程会监听多个端口的UDP数据包，包括34964和49155（后者被PROFINET的CMRPC协议使用），还会监听原始以太网流量（见下图）。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Gw8FuwXLJnRjP2CI7EyhCnpzdrU9s4bV8EupnSwRrbyJz6tn3Jqea8HqnYsLhRUIMqxTibc61kX3HeHWqicLTRBA/640?wx_fmt=other&from=appmsg "")  
  
  
鉴于基于UDP的RPC服务是外部可访问的，作者将其选为模糊测试活动的主要目标。在对这类目标进行模糊测试时，一个关键要求是构建一个测试驱动程序，使其能够以确定性且可重复的方式执行代码中有意义的部分。确定性对于崩溃复现和根本原因分析至关重要。  
  
  
此外，由于PROFINET是一种有状态协议，作者希望在终止测试驱动前向库发送多个数据包，从而探索协议更深层的状态，而不仅仅是初始的浅层状态。由于P-Net库将RPC功能实现为一个监听传入连接的守护进程，演示用的二进制文件无法直接用于模糊测试。  
  
  
为了使其适用，需要修改源代码，使网络协议栈在处理固定数量的数据包后自动终止。幸运的是，该库包含了一个基于GoogleTest（gtest）的测试套件，能够模拟大多数网络功能，包括RPC协议栈。例如，测试套件中的以下代码片段展示了如何测试一个RPC Connect请求以确保其被正确解析。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Gw8FuwXLJnRjP2CI7EyhCnpzdrU9s4bVic7TB0ibJV0Vy0fibzClt0EyY9VSPG322iczq66psd0UA4QRmziaibROfHVg/640?wx_fmt=other&from=appmsg "")  
  
  
关键函数如下：  
- mock_set_pnal_udp_recvfrom_buffer：该函数允许我们设置将由库处理的网络数据包。  
  
- run_stack：该函数用于在准备好的数据包上运行PROFINET协议栈。  
  
通过使用这两个函数，作者构建了一个简单的模糊测试驱动程序，它可以处理一系列UDP数据包，每个数据包的载荷从标准输入（stdin）读取。下图展示了作者测试驱动的大致实现。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Gw8FuwXLJnRjP2CI7EyhCnpzdrU9s4bVv1bLUKWwpava6xTFbPicjFyribZribYkicPYUb5w3XIr89OpOib9979tlUg/640?wx_fmt=other&from=appmsg "")  
  
  
为简洁起见，以下高亮函数的定义被省略，它们的功能如下：  
- read_all：从标准输入读取全部数据，并保存到全局缓冲区中；  
  
- get_next：使用预定义的分隔符将读取的数据拆分成多个UDP数据包。  
  
作者的方法非常直接：从标准输入读取输入数据，并使用简单的分隔符（例如字符串AAAA）将其划分为多个UDP数据包。虽然本可以采用更复杂的策略，例如自定义变异器（mutator），但作者的方法无需对PROFINET协议有深入理解，而是依赖于一个有意义的初始语料库，由此引导模糊测试器生成新的、多样化的测试用例。  
  
  
为了生成这个初始语料库，作者再次参考了测试套件，从中提取在测试过程中注入到模拟接口中的数据包。然后，作者使用预设的分隔符将这些数据包组合成适用于模糊测试的UDP数据包序列。  
  
  
当测试驱动和初始语料库都准备就绪后，作者就具备了启动模糊测试的全部条件，使用的是AFL++——这是目前最广泛使用且最有效的开源模糊测试工具之一。它以覆盖率引导模糊测试著称，具备强大的插桩技术和丰富的自定义功能，非常适合像P-Net这样复杂的代码库。  
  
  
要运行模糊测试活动，只需使用AFL++编译测试二进制文件，然后按如下方式将其提供给模糊测试器。  
  
```
$ afl-fuzz -i /path/to/corpus -o /path/to/out -- /path/to/pf_test \         --gtest_filter=CmrpcFuzzTest.CmrpcStdinReadTest $ afl-fuzz -i /path/to/corpus -o /path/to/out -- /path/to/pf_test \             --gtest_filter=CmrpcFuzzTest.CmrpcStdinReadTest
```  
  
  
尽管作者的方法非常简单，但使用这个基础测试驱动，成功发现了七个漏洞（CVE-2025-32396至CVE-2025-32402）。受到这些成果的鼓舞，作者决定开发第二个测试驱动，该驱动始终包含一组预定义的数据包序列，模拟攻击者已与设备建立连接的场景，从而能够对更深层的协议状态进行模糊测试。  
  
  
以下是该增强版测试驱动的大致实现示意：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Gw8FuwXLJnRjP2CI7EyhCnpzdrU9s4bVNByP09EDlzM44FribcMhsypw0gicKb92Do1bQLqydHib07H6icDz5QhBQw/640?wx_fmt=other&from=appmsg "")  
  
  
正如结果所示，这个测试驱动与之前的非常相似，复用了相同的read_all和run_stack函数，但这次作者在处理模糊测试器生成的数据包之前，预先添加了必要的数据包以模拟已建立的连接。使用这个新测试驱动，作者又发现了库中的另外三个漏洞（CVE-2025-32403、CVE-2025-32404和CVE-2025-32405）。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**五、漏洞聚焦**  
  
****  
  
本节重点介绍作者通过第二个模糊测试驱动发现的漏洞CVE-2025-32405。该漏洞允许未认证的远程攻击者向存储IO设备与PLC之间应用关系（Application Relation，AR）上下文信息的缓冲区之外写入数据。  
  
  
具体来说，作者发现当库解析ArVendorBlock请求时，会递增一个计数器，并将其作为索引用于将UDP数据包中的数据写入数组。漏洞的根本原因在于该计数器未做适当边界检查：如果攻击者发送足够多的数据包，索引值可能会超出数组范围，导致越界写入。以下是存在漏洞的代码片段：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRjP2CI7EyhCnpzdrU9s4bVPr5l8gyYKYN1pUmVtDhnibiaZDRY0H1IkOEHH3ZHqf0gwokRbTZQRXog/640?wx_fmt=png&from=appmsg "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**六、修复措施**  
  
****  
  
在本文中，作者公布了影响P-Net PROFINET库（包括版本1.0.1及之前版本）的10个内存破坏漏洞。这些漏洞一旦被利用，可能导致针对使用该库的嵌入式IO设备的严重攻击。  
  
  
在收到作者的报告后，P-Net的开发者RT-Labs迅速发布了1.0.2版本，修复了所有已报告的问题。此外，RT-Labs还在作者的建议下将模糊测试集成到了其开发流程中，采用libFuzzer显著提升了其库的安全性。  
  
  
鉴于这些漏洞带来的安全风险，作者强烈建议所有使用P-Net库的开发者和组织尽快升级到最新版本，以保障系统安全。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批网络安全企业的身份，于2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请560多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及  
基础设施安全、云安全、数据安全、应用安全、安全运营、工业互联网安全、信息技术应用创新、安全服务、安全教育等九大类产品服务，50余个行业和场景的完整解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxPibycdiaNQCI4PNojUk3eYCQDZs6c5zNMUkq7yFNeYQIxicAV33eHNdFA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
