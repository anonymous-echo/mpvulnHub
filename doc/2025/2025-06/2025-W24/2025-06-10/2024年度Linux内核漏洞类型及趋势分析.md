#  2024年度Linux内核漏洞类型及趋势分析  
原创 unr4v31  山石网科安全技术研究院   2025-06-10 09:06  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxvbibNMMmxDGrTN0Z9ibYzXnSNKobTzADCPgdo1b7ukKNARFEicHqQiajWw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
****  
****  
**Linux内核漏洞频发，2024年竟高达3119个！**  
  
****  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
Linux内核作为操作系统的核心，其安全性直接影响系统的稳定性与可靠性。通过对CVE数据的统计与分析，可以更好地理解内核漏洞的分布。  
  
  
本文统计了2024年Linux内核的CVE数据，共计3119个漏洞，数据来源于NVD。通过对这些漏洞的分析，我们将揭示内核中最易出现漏洞的子系统和常见的漏洞类型。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**一、统计方式**  
  
  
为了对Linux内核的CVE进行有效统计和分析，需要对漏洞信息进行合理的分类。具体的统计和归类方法如下：  
  
- CVE数据获取：  
通过从NVD下载2024年CVE的JSON文件，筛选出漏洞描述中包含“Linux kernel”字段的条目。这种方法可以确保捕捉到与Linux内核相关的漏洞，虽然可能遗漏少部分，但对整体分析的影响较小。  
  
- CVSS评分：  
采用NVD提供的CVSS 3.1评分体系，评估每个漏洞的严重性。  
  
- 子系统归类：  
根据CVE补丁中涉及的源码路径，将漏洞按内核子系统进行分类，如drivers、net、fs、arch、mm、kernel、block等。  
  
- CWE分类：  
利用NVD中的CWE（Common Weakness Enumeration）信息对漏洞进行分类。若NVD未提供CWE类型，则统一归类为“other”。  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**二、子系统漏洞数量分布**  
  
****  
  
除了常见的drivers、net、fs、arch、mm、kernel、block等核心子系统外，某些特殊子系统如bpf和bluetooth也在内核中频繁暴露出漏洞，因此被单独归类。对于那些单个子系统漏洞占比不足1%的，其漏洞将统一归类为“other”类型。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Gw8FuwXLJnTSiaHic9HicItXuicZdfhMPUpzicS81TtGuCdwibZJxiaDnUO2sGqJ7uCv2VuwtO5D783XlcfVBNnWOM4RA/640?wx_fmt=jpeg "")  
  
  
从统计结果中可以看出，漏洞数量最多的前三个子系统分别是  
内核驱动（drivers）  
、  
网络子系统（net）  
和  
文件子系统（fs）  
，它们的漏洞占比分别为45%、16.7%和14.3%。其中，内核驱动代码的漏洞占比最高，反映出内核驱动在安全漏洞中的重要性。驱动代码涉及的模块众多，包括WiFi、DRM显卡驱动、Staging驱动、SCSI设备驱动等，这些模块中漏洞的存在常常对系统的安全性构成威胁。对于那些占比不足1%的子系统漏洞，它们都被归类为“driver”类型，以简化分析。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**三、CWE类型漏洞占比分析**  
  
****  
  
针对CWE（Common Weakness Enumeration）类型的统计有助于揭示Linux内核中不同漏洞类型的分布情况。对于占比小于1%的CWE类型，我们统一归类为“other”类型，该类别通常包含一些较为罕见的漏洞类型。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Gw8FuwXLJnTSiaHic9HicItXuicZdfhMPUpzvtldE7k7D8ibW13s5J6xOtoWwib3ZLEdeicrwCCbjqqNQcsMia3NPjfn2w/640?wx_fmt=jpeg "")  
  
  
从统计图中可以看出，排除掉NVD中无法归类的NVD-cwe-noinfo类型后，内核漏洞中最常见的CWE类型分别为：  
  
- CWE-476：  
空指针引用，通常发生在未初始化的指针被解引用时，可能导致系统崩溃或不可预测的行为。  
  
- CWE-416：  
使用后释放，发生在内存释放后继续访问该内存位置，常见于内存管理不当的漏洞。  
  
- CWE-667：  
不当锁定，发生在多线程或多进程环境下，资源的访问或修改未正确加锁，可能导致竞态条件或数据不一致的情况。  
  
- CWE-401：  
内存泄漏，指程序未能释放不再使用的内存，可能导致系统资源耗尽。  
  
- CWE-787：  
越界写，发生在数据超出预期的内存边界写入时，可能导致数据损坏或控制流劫持。  
  
- CWE-908：  
使用未初始化的资源，指程序访问或使用未经过初始化的资源，这可能导致未定义行为或系统崩溃。  
  
- CWE-125：  
越界读取，指程序读取的数据超出了预定缓冲区的范围，可能导致敏感数据泄露或应用崩溃。  
  
- CWE-362：  
并发执行中的资源竞争（竞态条件），指在并发执行环境中，多个进程或线程对共享资源的访问缺乏适当同步，导致数据不一致或程序行为异常。  
  
- CWE-12  
9  
：  
数组索引验证不当，指程序在计算或使用数组索引时，未对输入进行验证或验证不当，导致可能访问无效或越界的数组位置。  
  
- CWE-415：  
双重释放，指程序对同一内存地址调用两次内存释放函数，可能导致内存损坏或系统崩溃。  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**四、CVSS分数统计**  
  
****  
CVSS（Common Vulnerability Scoring System，公共漏洞评分系统）评分可以帮助我们评估每个漏洞的严重性，并反映出它们对Linux内核安全的潜在影响。为了准确分析，我们排除了没有CVSS评分（即评分为0）的漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Gw8FuwXLJnTSiaHic9HicItXuicZdfhMPUpzmMPDXzQ2VqJn24ib6qXd0peXq4oa80sJk4wpZVpicPtzyYa6ZSSH1AGQ/640?wx_fmt=jpeg "")  
  
  
从统计结果来看，CVSS评分中占比最多的是5.5分，这类漏洞通常由空指针引用（CWE-476）等错误引起，可能导致内核崩溃或引发本地拒绝服务（DoS）攻击。这类漏洞往往能通过访问无效或未初始化的内存位置，触发内核错误，影响系统的稳定性。  
  
  
紧随其后的是  
7.8分  
的漏洞，占比排行第二。这类漏洞可能与  
使用后释放（CWE-416）  
、  
越界写（CWE-787）  
等相关，具有较高的利用价值，攻击者可以通过这些漏洞进行远程代码执行、权限提升或系统崩溃等操作。  
  
  
结合CVSS评分与CWE类型的分析，可以看出，Linux内核中的大部分高危漏洞主要集中在内存管理和指针操作方面，特别是空指针引用、内存释放不当等类型，这些漏洞往往易于利用并能造成严重后果。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**五、总结**  
  
  
根据CVE统计和CWE分析，Linux内核中最常见的漏洞类型主要集中在以下几种：  
  
  
1.  
空指针引用（CWE-476）  
：  
这一类型的漏洞最为常见，通常发生在未初始化或空指针被解引用时，容易导致内核崩溃或拒绝服务攻击（DoS）。  
  
  
2.  
使用后释放（CWE-416）  
：  
这类漏洞在内存管理中非常常见，发生在内存释放后仍然访问该内存位置，可能导致未定义行为或系统崩溃。  
  
  
3.  
越界写（CWE-787）和越界读取（CWE-125）  
：  
这些类型的漏洞往往源于对内存边界的错误处理，可能导致数据损坏、信息泄露或控制流劫持。  
  
  
通过对内核子系统的统计，以下子系统频繁出现漏洞：  
  
  
1.  
内核驱动（drivers）  
：  
这一子系统占据漏洞总数的最大比例（45%），包括WiFi驱动、显卡驱动、SCSI驱动等。这些驱动代码由于涉及硬件交互，容易暴露安全漏洞，成为攻击者的重点目标。  
  
  
2.  
网络子系统（net）  
：  
占  
比为16.7%，网络相关的漏洞常涉及数据传输的安全性，可能导致远程攻击或信息泄露。  
  
  
3.  
文件系统（fs）  
：  
占比14.3%，文件系统的漏洞通常与文件操作、权限管理相关，可能被利用进行本地权限提升或数据泄露。  
  
  
根据CVSS评分和CWE类型分析，最容易被利用的漏洞类型通常具有较高的CVSS评分，具体包括：  
  
  
1.  
7.8分漏洞（CWE-416、CWE-787）  
：  
这  
些漏洞常涉及内存管理错误，可以导致远程代码执行或系统崩溃，攻击者可以轻松利用这些漏洞执行恶意代码。  
  
  
2.  
5.5分漏洞（CWE-476）  
：  
空指针引用问题，虽不如7.8分漏洞严重，但足以造成系统崩溃或拒绝服务（DoS）攻击，常见于内核级别的错误操作。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批网络安全企业的身份，于2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请560多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及  
基础设施安全、云安全、数据安全、应用安全、安全运营、工业互联网安全、信息技术应用创新、安全服务、安全教育等九大类产品服务，50余个行业和场景的完整解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxPibycdiaNQCI4PNojUk3eYCQDZs6c5zNMUkq7yFNeYQIxicAV33eHNdFA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
