#  Unix通用打印系统cups-browsed远程代码执行漏洞分析   
启明星辰  ADLab   2024-12-13 11:18  
  
更多安全资讯和分析文章请关注启明星辰ADLab微信公众号及官方网站（adlab.venustech.com.cn）  
  
  
  
**一、漏洞描述**  
  
  
2024年9月，安全研究员Simone Margaritelli披露了Unix通用打印系统CUPS(Common UNIX Printing System)存在一系列安全漏洞，利用多个漏洞组合可在受影响的系统上执行远程命令。启明星辰ADLab研究人员对该漏洞的原理进行深入分析，同时提出修复建议和缓解措施。  
<table><thead><tr style="mso-yfti-irow:0;mso-yfti-firstrow:yes;"><td width="120" style="border-top: 1pt solid rgb(223, 226, 229);border-right: 1pt solid rgb(223, 226, 229);border-left: 1pt solid rgb(223, 226, 229);border-bottom: none;padding: 2.25pt 4.9pt;"><p style="text-align:center;mso-pagination:
   widow-orphan;"><span style="font-size: 14px;color: rgb(136, 136, 136);"><strong><span lang="EN-US" style="font-size: 14px;font-family: 宋体;">CVE </span></strong><strong><span style="font-size: 14px;font-family: 宋体;">编号</span></strong><strong><o:p></o:p></strong></span></p></td><td width="66" style="border-top: 1pt solid rgb(223, 226, 229);border-left: none;border-bottom: none;border-right: 1pt solid rgb(223, 226, 229);padding: 2.25pt 4.9pt;"><p style="text-align:center;mso-pagination:
   widow-orphan;"><span style="font-size: 14px;color: rgb(136, 136, 136);"><strong><span style="font-size: 14px;font-family: 宋体;">严重程度</span></strong><strong><o:p></o:p></strong></span></p></td><td width="162" style="border-top: 1pt solid rgb(223, 226, 229);border-left: none;border-bottom: none;border-right: 1pt solid rgb(223, 226, 229);padding: 2.25pt 4.9pt;"><p style="text-align:center;mso-pagination:
   widow-orphan;"><span style="font-size: 14px;color: rgb(136, 136, 136);"><strong><span style="color: rgb(136, 136, 136);font-size: 14px;font-family: 宋体;">受影响的服务</span></strong><strong><o:p></o:p></strong></span></p></td></tr></thead><tbody><tr style="mso-yfti-irow:1;"><td width="120" style="border-width: 1pt;border-style: solid;border-color: rgb(223, 226, 229);padding: 2.25pt 4.9pt;"><p style="text-align:center;mso-pagination:widow-orphan;"><span style="font-family: 宋体;font-size: 14px;color: rgb(136, 136, 136);">CVE-2024-47176</span></p></td><td width="66" style="border-top: 1pt solid rgb(223, 226, 229);border-right: 1pt solid rgb(223, 226, 229);border-bottom: 1pt solid rgb(223, 226, 229);border-left: none;padding: 2.25pt 4.9pt;"><p style="text-align:center;mso-pagination:widow-orphan;"><span style="font-family: 宋体;font-size: 14px;color: rgb(136, 136, 136);">8.3</span></p></td><td width="162" style="border-top: 1pt solid rgb(223, 226, 229);border-right: 1pt solid rgb(223, 226, 229);border-bottom: 1pt solid rgb(223, 226, 229);border-left: none;padding: 2.25pt 4.9pt;"><p style="text-align:center;mso-pagination:widow-orphan;"><span style="font-family: 宋体;font-size: 14px;color: rgb(136, 136, 136);">cups-browsed &lt;= 2.0.1</span></p></td></tr><tr style="mso-yfti-irow:2;"><td width="120" style="border-right: 1pt solid rgb(223, 226, 229);border-bottom: 1pt solid rgb(223, 226, 229);border-left: 1pt solid rgb(223, 226, 229);border-top: none;background: rgb(248, 248, 248);padding: 2.25pt 4.9pt;"><p style="text-align:center;mso-pagination:widow-orphan;"><span style="font-family: 宋体;font-size: 14px;color: rgb(136, 136, 136);">CVE-2024-47076</span></p></td><td width="66" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(223, 226, 229);border-right: 1pt solid rgb(223, 226, 229);background: rgb(248, 248, 248);padding: 2.25pt 4.9pt;"><p style="text-align:center;mso-pagination:widow-orphan;"><span style="font-family: 宋体;font-size: 14px;color: rgb(136, 136, 136);">8.6</span></p></td><td width="162" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(223, 226, 229);border-right: 1pt solid rgb(223, 226, 229);background: rgb(248, 248, 248);padding: 2.25pt 4.9pt;"><p style="text-align:center;mso-pagination:widow-orphan;"><span style="font-family: 宋体;font-size: 14px;color: rgb(136, 136, 136);">libcupsfilters &lt;= 2.1b1</span></p></td></tr><tr style="mso-yfti-irow:3;"><td width="120" style="border-right: 1pt solid rgb(223, 226, 229);border-bottom: 1pt solid rgb(223, 226, 229);border-left: 1pt solid rgb(223, 226, 229);border-top: none;padding: 2.25pt 4.9pt;"><p style="text-align:center;mso-pagination:widow-orphan;"><span style="font-family: 宋体;font-size: 14px;color: rgb(136, 136, 136);">CVE-2024-47175</span></p></td><td width="66" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(223, 226, 229);border-right: 1pt solid rgb(223, 226, 229);padding: 2.25pt 4.9pt;"><p style="text-align:center;mso-pagination:widow-orphan;"><span style="font-family: 宋体;font-size: 14px;color: rgb(136, 136, 136);">8.6</span></p></td><td width="162" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(223, 226, 229);border-right: 1pt solid rgb(223, 226, 229);padding: 2.25pt 4.9pt;"><p style="text-align:center;mso-pagination:widow-orphan;"><span style="font-family: 宋体;font-size: 14px;color: rgb(136, 136, 136);">libppd &lt;= 2.1b1</span></p></td></tr><tr style="mso-yfti-irow:4;mso-yfti-lastrow:yes;"><td width="120" style="border-right: 1pt solid rgb(223, 226, 229);border-bottom: 1pt solid rgb(223, 226, 229);border-left: 1pt solid rgb(223, 226, 229);border-top: none;background: rgb(248, 248, 248);padding: 2.25pt 4.9pt;"><p style="text-align:center;mso-pagination:widow-orphan;"><span style="font-family: 宋体;font-size: 14px;color: rgb(136, 136, 136);">CVE-2024-47177</span></p></td><td width="66" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(223, 226, 229);border-right: 1pt solid rgb(223, 226, 229);background: rgb(248, 248, 248);padding: 2.25pt 4.9pt;"><p style="text-align:center;mso-pagination:widow-orphan;"><span style="font-family: 宋体;font-size: 14px;color: rgb(136, 136, 136);">9.0</span></p></td><td width="162" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(223, 226, 229);border-right: 1pt solid rgb(223, 226, 229);background: rgb(248, 248, 248);padding: 2.25pt 4.9pt;"><p style="text-align:center;mso-pagination:widow-orphan;"><span style="font-family: 宋体;font-size: 14px;color: rgb(136, 136, 136);">cups-filters &lt;= 2.0.1</span></p></td></tr></tbody></table>  
  
  
**二、相关介绍**  
  
  
  
CUPS是一个开源的打印系统，用于Linux和其他类UNIX操作系统。CUPS 提供 Web界面和Berkeley  
命令行界面  
等多种方式来管理打印机和打印任务。例如访问http://localhost:631可管理打印机。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XGicR9TOl8nTFvSLwhMQBSAeNIUD2ZYtTl1ria2w4qNf2iaVEDbDZm8sT0xJoHJjb9H8khy2sFYz0lFQgPNekwdPQ/640?wx_fmt=png&from=appmsg "")  
  
CUPS主要使用Internet Printing Protocol(IPP)来实现本地和网络打印机的打印功能。IPP是一个在  
互联网  
上打印的标准  
网络协议  
，它容许用户可以通过互联网作远距离打印及管理打印工作等。IPP采用的超文本传输协议HTTP的POST方法在客户端和打印服务器之间进行会话。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XGicR9TOl8nTFvSLwhMQBSAeNIUD2ZYtTc6kqj2ftwBltFC4Sbv6n6To8CPUA3h3bOhS3hzJHFtmPLaROxkrahA/640?wx_fmt=png&from=appmsg "")  
  
cups-browsed是一个开源的打印服务组件，它是Common UNIX Printing System(CUPS)的一部分。cups-browsed负责在本地网络上自动发现和添加打印机，使用mDNS（多播DNS）或DNS-SD（DNS服务发现）协议来侦测网络上的打印设备。它使得用户能够无需手动配置即可使用网络打印机。  
  
  
**三、原理分析**  
  
  
该漏洞源于cups-browsed服务，该服务绑定在UDP INADDR_ANY:631端口上，接受任何ip发送过来数据。同时该服务适配大多数UNIX系统，且大多数设备默认开启该服务。  
  
该服务的功能是发现互联网上的打印机，然后将打印机添加到系统服务上，相关功能的实现代码在cups-browsed.c文件中。代码中创建一个名为BrowseSocket的套接字，然后绑定在631端口。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XGicR9TOl8nTFvSLwhMQBSAeNIUD2ZYtTYLMxzYNFsS1B4MSwRgRh8m644icPb0Lsc8LTOwyIKSfOqicP3lSiawkPQ/640?wx_fmt=png&from=appmsg "")  
  
当检查到系统支持BrowseRemoteProtocols时，创建一个 UNIX 套接字通道，并设置监视该通道上的输入事件。一旦有数据可读，将调用process_browse_data函数来处理这些数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XGicR9TOl8nTFvSLwhMQBSAeNIUD2ZYtTMJ5C2ANeictkXWnbzqqXC0YSdkohJqgiafBiaXiagYdTS6dEa6tGOD8u7A/640?wx_fmt=png&from=appmsg "")  
  
  
BrowseRemoteProtocols参数可通过/etc/cups/cups-browsed.conf文件进行配置，此处一般默认开启。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XGicR9TOl8nTFvSLwhMQBSAeNIUD2ZYtTzhffG149NLGsyic7qgneWBBbpsnt9QaoolOIWbtyQl4KNVhlmOelo6w/640?wx_fmt=png&from=appmsg "")  
  
process_browse_data是关键的数据处理函数，该函数调用recvfrom从BrowseSocket套接字读取数据包packet。数据包格式遵从HEX_NUMBER HEX_NUMBER TEXT_DATA，使用该格式的数据的原因时是程序在处理packet时使用了下面的函数对数据进行处理。  
  
sscanf (packet, "%x%x%1023s",&type, &state, uri)  
  
接收到数据包后会调用allowed函数对ip进行合理性检查，该检查规则可通过/etc/cups/cups-browsed.conf文件进行配置。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XGicR9TOl8nTFvSLwhMQBSAeNIUD2ZYtTCUZ0EOew3I6b8c37m61K0icp1K4Yh9u848vofRe3Pf0sqE7OHf9JJzA/640?wx_fmt=png&from=appmsg "")  
  
allowed检查通过后会将数据包传入found_cups_printer函数进行进一步处理。  
  
found_cups_printer函数中调用httpSeparateURI函数解析传入的uri参数并将其拆分为协议、用户名、主机名、端口、资源路径等部分。然后根据解析得到的各部分信息，对uri是否等于”/printers/”和”/calsses/”字符串进行检查。检查通过后调用examine_discovered_printer_record函数来处理发现的打印机记录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XGicR9TOl8nTFvSLwhMQBSAeNIUD2ZYtTicS5oSP8DM95mvzOicvldb8GJiavRPofLyticMQkDAoicUW2y468mEhkEuQ/640?wx_fmt=png&from=appmsg "")  
  
处理完数据后调用cfGetPrinterAttributes函数进行回连，其中先使用httpConnect函数先建立http连接，然后调用ippNewRequest建立IPP连接，最后向IPP Server发送获取打印机属性的请求。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XGicR9TOl8nTFvSLwhMQBSAeNIUD2ZYtTVcZLjLAkJVqxwwXQFdVSY7vz8kQ5Tso9bkIjkrpnaEM4xw5ZZ1LMPQ/640?wx_fmt=png&from=appmsg "")  
  
发送完请求后cups-browsed程序会调用ppdCreatePPDFromIPP2函数创建PPD文件然后将接收的打印机属性依次保存到文件里面。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XGicR9TOl8nTFvSLwhMQBSAeNIUD2ZYtT2YMJRr7NlSX0ajJhdakMskH8teWsIRZY7e6zlD4vKiblhHjKA33UGuA/640?wx_fmt=png&from=appmsg "")  
  
至此，已经可以成功设置PPD的属性，接下来就是想办法执行写入的数据。这需要使用CUPS的一个过滤器指令cupsFilter2，该指令用于处理打印作业中的筛选和转换操作。  
  
例如下面的指令要求cups将符合打印机属性的postscript格式的数据传递给program过滤器进行处理，优先级为0。  
  
***cupsFilter2:"application/pdf application/vnd.cups-postscript 0 program**  
  
CUPS规定只能使用/usr/lib/cups/filter路径下面的可执行文件，最终以  
foomatic-rip过滤器  
作为利用的目标。该过滤器接受PPD文件中的FoomaticRIPCommandLine指令，通过它可以执行任意命令。  
  
  
**四、漏洞修复**  
  
  
  
截至目前，Ubuntu，Debian，Fedora等多个系统中涉及漏洞的多个版本已基本修复。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XGicR9TOl8nTFvSLwhMQBSAeNIUD2ZYtTzbEeabPvgmCOygNZOGkKhCxR0mRSVJ0LovhZJlFbB4ZyE6pCgcEx2g/640?wx_fmt=png&from=appmsg "")  
  
  
在Ubuntu最新版的修复方案中完全删除对旧版 CUPS 协议和 LDAP 的支持。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XGicR9TOl8nTFvSLwhMQBSAeNIUD2ZYtTDiaJn7E4Eo6mFkfPvXInQAw0SEAaWvDAOo1S5RDCJh4KzUI3mrPvtlA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**五、缓解措施**  
  
  
漏洞修复版本已经上传，Ubuntu系统中运行下面两条命令即可进行升级。  
  
sudo apt update  
  
sudo apt upgrade  
  
如果上面的升级不成功，使用下面两种办法缓解该漏洞：  
  
（1）直接禁用cups-browsed服务  
  
sudo systemctl stop cups-browsed  
  
sudo systemctl   
disable cups-browsed  
  
（2）如果该功能需要使用，建议将/etc/cups/cups-browsed.conf中BrowseRemoteProtocols指令值从默认的“dnssd cups”更改为“none”。  
  
  
  
  
**参考链接：**  
  
[1]https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/  
  
[2]https://gist.github.com/stong/c8847ef27910ae344a7b5408d9840ee1  
  
[3]https://censys.com/common-unix-printing-service-vulnerabilities/  
  
[4]https://blog.ostorlab.co/cups-vulnerabilities.html  
  
[5]https://github.com/OpenPrinting/cups-browsed/security/advisories/GHSA-rj88-6mr5-rcw8  
  
[6]https://ubuntu.com/security/notices/USN-7043-4  
  
[7]https://ubuntu.com/security/notices/USN-7042-3  
  
[8]https://launchpad.net/ubuntu/+source/cups-browsed/2.0.1-0ubuntu2.1  
  
[9]https://www.upwind.io/feed/analyzing-the-latest-cups-rce-vulnerability-threats-and-mitigations  
  
  
  
  
  
  
启明星辰积极防御实验室（ADLab）  
  
  
  
  
  
ADLab成立于1999年，是中国安全行业最早成立的攻防技术研究实验室之一，微软MAPP计划核心成员，  
“黑雀攻击”概  
念首推者。截至目前，ADLab已通过 CNVD/CNNVD/NVDB/CVE累计发布安全漏洞5000余个，持续保持国际网络安全领域一流水准。实验室研究方向涵盖基础安全研究、数据安全研究、5G安全研究、人工智能安全研究、移动安全研究、物联网安全研究、车联网安全研究、工控安全研究、信创安全研究、云安全研究、无线安全研究、高级威胁研究、攻防体系建设。研究成果应用于产品核心技术研究、国家重点科技项目攻关、专业安全服务等  
。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/XGicR9TOl8nRnsug2VpgvvxBBiam1QbQzzn0ibjIedibQzCZp3TzUgPVZDAicLZyWNVjia3ibCScpE6mKj165jfQib99VQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
