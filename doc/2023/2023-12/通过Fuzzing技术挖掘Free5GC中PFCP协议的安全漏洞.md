#  通过Fuzzing技术挖掘Free5GC中PFCP协议的安全漏洞   
 数世咨询   2023-12-13 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RTibZXfXZJRCf7234RAn0mYDpf1o7YawWPmCvbnmNeB3HxDaV6I4fQk2wjw7DUibd5ThD1ZtZnarB3PfM36ygZBw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
 背景介绍   
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlQtUHtqBtw6X9sloXrIwSvZonBSJEnKoPD7RTAjbQuT54ZlcXaibfufkCrRuYVPHT0gGVOqGibhaRG9Edh5iaj5A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
Free5GC是一个开源的5G核心网络实现项目，旨在提供一个完整的5G核心网络解决方案，包括多个关键组件，以支持5G通信网络的部署、测试和研究。随着5G技术的快速发展，Free5GC作为一款受欢迎的工具引起了广泛关注，同时其安全性问题也逐渐受到重视。本次安全研究聚焦于Free5GC中的SMF和UPF节点，运用Fuzzing技术对PFCP协议进行深入测试，以发现潜在的未知漏洞和安全问题。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Y9btpvDIDqoGYse73eGDzYpZVuiciaLzNPE1wkF11ov1MBPq4TibCNZ0KeDUmgcHLnficMXVkhoPhwLNkM3Kz1Zr0w/640?wx_fmt=png&from=appmsg "")  
  
图1：5G通信系统架构总览  
  
1）SMF（Session Management Function）  
- 功能：SMF负责用户会话管理，处理数据面的用户数据传输。  
  
- 作用：管理会话的建立、修改、释放，以及UE的用户面数据流的路由。  
  
2）UPF（User Plane Function）  
- 功能：UPF处理用户数据面的数据包传输。  
  
- 作用：负责数据包的转发、分片、重组等操作，实现用户数据的高效传输。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RTibZXfXZJRCf7234RAn0mYDpf1o7YawWPmCvbnmNeB3HxDaV6I4fQk2wjw7DUibd5ThD1ZtZnarB3PfM36ygZBw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
 Fuzzing技术   
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlQtUHtqBtw6X9sloXrIwSvZonBSJEnKoPD7RTAjbQuT54ZlcXaibfufkCrRuYVPHT0gGVOqGibhaRG9Edh5iaj5A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
Fuzzing，又称模糊测试，是一种自动化测试技术，其目标是通过向软件应用或系统组件注入大量随机或者特定的数据，以发现潜在的漏洞和安全问题。Fuzzing可以用于测试各种软件，包括操作系统、网络协议、编程库、应用程序等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Y9btpvDIDqoGYse73eGDzYpZVuiciaLzNPWMlPB4qnfvJNAevicBGmkP9qqwuSXdwXoqCoMCNIzmicfdYoS0Kc7Kmw/640?wx_fmt=png&from=appmsg "")  
  
图2：通信协议Fuzzing技术  
  
1）技术特点  
- 自动化：Fuzzing是一种自动化测试技术，不需要人为干预。测试人员只需定义一些输入的范围和规则，Fuzzing工具就能够生成并发送大量测试用例。  
  
- 精准性：Fuzzing能够针对协议模型的特点对相关报文域做智能化畸变，同时辅以随机畸变能够生成更加精准的测试用例，模拟了实际攻击者可能使用的各种输入。这使得Fuzzing能够探测到开发者可能没有考虑到的边缘情况和异常情况。  
  
- 普适性：Fuzzing可以用于测试各种类型的软件和系统，包括但不限于操作系统、网络协议、编程库、浏览器、数据库等。这种通用性使得Fuzzing成为发现广泛安全问题的有效手段。  
  
- 高效性：Fuzzing可以在短时间内生成大量测试用例，从而大大提高测试的效率。通过自动产生输入，Fuzzing能够覆盖大量的代码路径，增加发现漏洞的概率。  
  
2）技术优势  
- 发现未知漏洞：Fuzzing能够发现未知漏洞，包括开发者没有预料到的边界情况和异常输入，从而帮助提高软件的鲁棒性。  
  
- 高覆盖率：协议Fuzzing基于标准模型生成“聪明”的测试用例，具有极高的协议和代码覆盖率，能够突破多种检测规则深入测试程序的各个部分。  
  
- 持续集成：Fuzzing可以集成到持续集成（CI）和持续部署（CD）流程中，使得漏洞能够在早期被发现和修复，提高软件开发的整体安全性。  
  
- 节约成本：与手动测试相比，Fuzzing可以更高效地发现漏洞，并且可以在短时间内完成大规模的测试，从而降低了测试的成本。  
  
- 应对复杂性：Fuzzing可以处理复杂的软件系统和协议，即使在无法获取源代码或了解内部实现的情况下，也能进行有效的测试。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RTibZXfXZJRCf7234RAn0mYDpf1o7YawWPmCvbnmNeB3HxDaV6I4fQk2wjw7DUibd5ThD1ZtZnarB3PfM36ygZBw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
 发现过程   
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlQtUHtqBtw6X9sloXrIwSvZonBSJEnKoPD7RTAjbQuT54ZlcXaibfufkCrRuYVPHT0gGVOqGibhaRG9Edh5iaj5A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
研究人员采用软安Fuzz工具对Free5GC的UPF和SMF节点进行了大规模的测试，模拟了各种PFCP消息的异常输入。在PFCP协议测试模块配置和运行后，该工具在短短数小时内完成了近百万测试用例的完全自动执行、监测、记录和统计。  
  
通过仔细分析测试报告，研究人员成功地发现了多个引发数组越界的畸形消息，并进一步根据测试报告验证了相关测试用例能够稳定复现问题并完成了POC的编写。经过漏洞上报、Free5GC更新和最终验证等工作，成功修复了相关问题。  
  
公司最终通过上述漏洞发现和申报验证，获取了CNNVD机构的研判通过以及CVE机构的相关漏洞编号。  
- CVE-2023-47345 （7.5 High）  
  
- CVE-2023-47346 （7.5 High）  
  
- CVE-2023-47347 （7.5 High）  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RTibZXfXZJRCf7234RAn0mYDpf1o7YawWPmCvbnmNeB3HxDaV6I4fQk2wjw7DUibd5ThD1ZtZnarB3PfM36ygZBw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
 漏洞分析   
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlQtUHtqBtw6X9sloXrIwSvZonBSJEnKoPD7RTAjbQuT54ZlcXaibfufkCrRuYVPHT0gGVOqGibhaRG9Edh5iaj5A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
在针对Free5GC中SMF和UPF网元节点进行PFCP消息报文Fuzzing测试的过程中，发现了下列三种导致数组越界的安全漏洞：  
  
1）PFCP消息报文的第二个IE的类型被设置为一个大于0x7fff的值，则SMF和UPF节点在处理该IE时会导致数组越界。  
  
2）PFCP消息报文的IE的长度被畸变为0时，则SMF和UPF节点在处理该IE时会导致数组越界。  
  
3）PFCP消息报文的Sequence Number被畸变为超范围数值（比如0xFFFFFFFF）时，则SMF和UPF节点在处理该域时会导致数组越界。  
  
例如由1）中导致漏洞的代码可分析得知，网元节点在处理PFCP消息报文时没有对第二个IE的类型进行任何检查，直接将其用作读取IE内容的条件。因此当第二个IE的类型被设置为一个大于0x7fff的值，则节点会将该IE的数据复制到一个数组中，而没有检查数组的大小。这将导致数组越界，并最终导致go panic。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Y9btpvDIDqoGYse73eGDzYpZVuiciaLzNPPIiafPAX6BbkBdSbuu4Eexj8voOTN7d4npESFtg94py0AlfXynJaoUg/640?wx_fmt=png&from=appmsg "")  
  
图3：安全漏洞问题代码定位  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RTibZXfXZJRCf7234RAn0mYDpf1o7YawWPmCvbnmNeB3HxDaV6I4fQk2wjw7DUibd5ThD1ZtZnarB3PfM36ygZBw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
 潜在威胁   
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlQtUHtqBtw6X9sloXrIwSvZonBSJEnKoPD7RTAjbQuT54ZlcXaibfufkCrRuYVPHT0gGVOqGibhaRG9Edh5iaj5A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
此类漏洞具有显著的潜在安全威胁，攻击者通过构造特定的PFCP消息可能导致UPF和SMF节点崩溃，造成服务不可用。更为严重的是，通过利用数组越界漏洞，攻击者可能执行恶意代码，获取敏感信息，进而危及整个5G核心网络的安全性。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RTibZXfXZJRCf7234RAn0mYDpf1o7YawWPmCvbnmNeB3HxDaV6I4fQk2wjw7DUibd5ThD1ZtZnarB3PfM36ygZBw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
 应对策略   
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlQtUHtqBtw6X9sloXrIwSvZonBSJEnKoPD7RTAjbQuT54ZlcXaibfufkCrRuYVPHT0gGVOqGibhaRG9Edh5iaj5A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
Free5GC项目组已经意识到这一安全问题，并积极采取措施进行修复。用户和部署Free5GC的组织应及时更新到最新版本，以免受到潜在的威胁。此外，推荐用户在部署Free5GC时采用严格的安全策略，限制网络访问，并及时关注安全社区的最新建议。  
  
  
  
