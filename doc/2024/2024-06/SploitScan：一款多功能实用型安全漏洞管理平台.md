#  SploitScan：一款多功能实用型安全漏洞管理平台   
Alpha_h4ck  FreeBuf   2024-06-04 19:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
**关于SploitScan**  
  
  
  
SploitScan是一款功能完善的实用型网络安全漏洞管理工具，该工具提供了用户友好的界面，旨在简化广大研究人员识别已知安全漏洞的相关信息和复现过程。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Eb4tyCQZiaRlIozIemiaJvX8nF8iaibzD6ECp4kr0a0uM76tIu45FLwb6GNIfzqH0neYkt7h2oqMn4A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
SploitScan可以帮助网络安全专业人员快速识别和测试已知安全漏洞，如果你需要寻求加强安全措施或针对新出现威胁制定强大检测策略，那么SploitScan会是你的绝佳选择。  
  
  
**功能介绍**  
  
  
##   
  
当前版本的SploitScan支持下列功能：  
  
> 1、CVE信息检索：从国家漏洞数据库获取CVE详细信息；  
> 2、EPSS集成：包括利用预测评分系统（EPSS）数据，为CVE利用的可能性提供概率评分，有助于确定漏洞优先级；  
> 3、公共漏洞信息聚合：收集公开可用的漏洞及其相关信息，帮助研究人员更好地了解漏洞的信息；  
> 4、CISA KEV：显示CVE是否已列入CISA的已知可利用安全漏洞（KEV）中；  
> 5、修复优先级系统：根据包括公共漏洞可利用性在内的各种因素，评估并分配漏洞修复的优先级；  
> 6、多CVE支持和导出选项：在一次任务执行中支持多个CVE，并允许将结果导出为HTML、JSON和CSV格式；  
> 7、漏洞扫描程序导入：从流行的漏洞扫描程序中导入漏洞扫描功能，并直接搜索已知的漏洞利用PoC；  
> 8、人工智能驱动的风险评估：利用OpenAI提供详细的风险评估、潜在攻击场景、缓解建议和执行摘要；  
> 9、用户友好的界面：易于使用，提供清晰简洁的信息；  
> 10、全面的安全工具：非常适合进行快速安全评估，并随时了解最近的漏洞信息；  
  
##   
  
**支持的漏洞利用数据库**  
  
  
> 1、  
GitHub  
；  
> 2、  
ExploitDB  
；  
> 3、  
VulnCheck  
；（需要一个免费的VulnCheck API密钥）  
> 4、  
Packet Storm  
；  
> 5、  
Nuclei  
；  
  
##   
  
**支持漏洞的扫描功能**  
  
  
##   
> 1、  
Nessus   
(.nessus)  
> 2、  
Nexpose   
(.xml)  
> 3、  
OpenVAS   
(.xml)  
> 4、  
Docker   
(.json)  
  
##   
  
**工具安装**  
  
##   
###   
### GitHub安装  
```
git clone https://github.com/xaitax/SploitScan.git

cd sploitscan

pip install -r requirements.txt
```  
### pip安装  
```
pip install --user sploitscan
```  
### Kali/Ubuntu/Debian安装  
```
apt install sploitscan
```  
### 配置文件  
  
  
在使用该工具之前，我们还需要在下列其中一个位置创建一个config.json文件，并提供自己的API密钥：  
```
~/.当前目录

~/.sploitscan/

~/.config/sploitscan/

/etc/sploitscan/
```  
  
config.json文件内容格式如下：  
```
{"vulncheck_api_key": "your_vulncheck_api_key","openai_api_key": "your_openai_api_key"}
```  
##   
  
**工具使用**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Eb4tyCQZiaRlIozIemiaJvXpibJZicbHqRY8c6wmPo3bZOsZaL3EgKRyZIxtlAbhib5MIDG4ZNcvbPhA/640?wx_fmt=jpeg&from=appmsg "")  
  
### 参数选项  
```
-h, --help            显示工具帮助信息和退出

-e {json,JSON,csv,CSV,html,HTML}, --export {json,JSON,csv,CSV,html,HTML}

                    可选: 将结果导出为JSON、CSV或HTML文件格式

-t {nessus,nexpose,openvas,docker}, --type {nessus,nexpose,openvas,docker}

                    指定导入文件的类型: 'nessus'、'nexpose'、'openvas'或'docker'

-i IMPORT_FILE, --import-file IMPORT_FILE

                    导入文件的路径
```  
### 查询单个CVE  
```
sploitscan CVE-2024-1709
```  
###   
### 查询多个CVE  
```
sploitscan CVE-2024-1709 CVE-2024-21413
```  
### 从漏洞扫描器导入  
  
  
需指定导入的类型，例如'nessus'、'nexpose'、'openvas'或'docker，并提供文件路径：  
```
sploitscan --import-file path/to/yourfile.nessus --type nessus
```  
### 结果导出  
  
  
需指定导出格式，例如'json'、'csv'或'html'：  
```
sploitscan CVE-2024-1709 -e html
```  
###   
### Docker  
```
docker build -t sploitscan .

docker run --rm sploitscan CVE-2024-1709
```  
### Windows（PowerShell）  
```
docker run -v ${PWD}:/app --rm sploitscan CVE-2024-1709 -e JSON
```  
### Linux  
```
docker run -v $(pwd):/app --rm sploitscan CVE-2024-1709 -e JSON
```  
  
**工具输出样例**  
  
  
##   
```
$ sploitscan.py CVE-2024-21413



[...]



┌───[  AI-Powered Risk Assessment ]

|

| 1. Risk Assessment

| -------------------

| The vulnerability identified by CVE-2024-21413 is a critical remote code execution flaw in

| Microsoft Outlook with a CVSS score of 9.8. The impact on business operations can be severe due to

| its high potential to be exploited over a network without any user interactions or elevated

| privileges. This unvalidated input vulnerability (CWE-20) could allow an attacker to execute

| arbitrary code on the target system, thereby compromising the confidentiality, integrity, and

| availability of critical business data and systems. Given its critical rating and the existence of

| multiple exploits on public repositories like GitHub, the likelihood of exploitation is very high.

| This necessitates immediate attention from the security teams to mitigate the risks associated.

|

| 2. Potential Attack Scenarios

| ------------------------------

| An attacker could exploit this vulnerability by sending a specially crafted email to a victim

| using Microsoft Outlook. Once the email is opened or previewed, the malicious payload would

| execute, allowing the attacker to gain control over the victim's system. The process involves: 1.

| Crafting a malicious email leveraging the specific flaw in email handling within Microsoft

| Outlook. 2. Sending the email to the intended victim. 3. Upon opening or previewing the email, the

| victim’s system executes the malicious code. The potential outcomes of this attack include theft

| of sensitive information, installation of malware or ransomware, and compromising other systems

| within the same network due to lateral movement capabilities.

|

| 3. Mitigation Recommendations

| ------------------------------

| Immediate mitigation recommendation includes: 1. Applying the latest security patches provided by

| Microsoft. Reference: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413 2.

| Implementing network-level protections such as email filtering and network segmentation to limit

| the spread of potential infections. 3. Conducting regular security awareness training for users to

| recognize phishing and malicious emails. 4. Monitoring network and system activity for signs of

| suspicious behavior and unauthorized execution. 5. Regularly backing up critical data and ensuring

| the integrity of backups.

|

| 4. Executive Summary

| ---------------------

| CVE-2024-21413, a critical remote code execution vulnerability in Microsoft Outlook, poses a

| significant risk to businesses due to its potential to be exploited without user interaction.

| Multiple exploit proofs are publicly available, increasing the likelihood of attacks.

| Organizations must act swiftly by applying the necessary patches from Microsoft, enhancing their

| email security protocols, and educating their staff to identify potential phishing attempts.

| Mitigating this vulnerability is essential to protect sensitive information, maintain business

| integrity, and ensure system availability, thus preventing potential financial and reputational

| damage. Immediate action is crucial to safeguard the organization against this severe threat.

|

└────────────────────────────────────────
```  
##   
  
**许可证协议**  
  
  
##   
  
本项目的开发与发布遵循  
GPL-3.0  
开源许可协议。  
  
  
**项目地址**  
  
  
  
**SploitScan：**  
  
https://github.com/xaitax/SploitScan  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://poc-in-github.motikan2010.net/  
> https://www.exploit-db.com/  
> https://vulncheck.com/  
> https://packetstormsecurity.com/  
> https://github.com/projectdiscovery/nuclei-templates  
> https://www.tenable.com/products/nessus  
> https://www.rapid7.com/products/nexpose/  
> https://www.openvas.org/  
> https://docs.docker.com/scout/﻿  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493904&idx=1&sn=762560e15729d3a8be68f51c5d846733&chksm=ce1f138ff9689a99f74af688d5eb5dadb7ac5d3639a1a97e47b38e09958df19df7b35eb39a25&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493836&idx=1&sn=618ec2e0ea830222e8c14ea4c912ef27&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
