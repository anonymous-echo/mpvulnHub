#  紧急预警！Linux核心转存漏洞曝光，Ubuntu、红帽系统密码哈希可被窃取   
原创 道玄安全  道玄网安驿站   2025-06-01 23:00  
  
**“**  
 条件竞争。**”**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPA9bic9zzTydWv4XTTHH2NAiamMp8Kxsh4s2lukPuyuwnia3NiaHkiaU8a3JGFhLvNnYvtLvHTFAd91Rw/640?wx_fmt=png&from=appmsg "")  
  
      
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPMwVHx9iaPDKDhBJiajRW2DIdq0Wxe7JcpgKDia3zMfgicaaD6Auwn6Q3GGm2vI0eNh1Qic6OUhHMjE7g/640?wx_fmt=png&from=appmsg "")  
  
  
  
PS：有内网web自动化需求可以私信  
  
  
  
  
01  
  
—  
  
  
  
导语  
  
  
    国家网络安全机构近日监测到新型高危漏洞威胁：  
**多个主流Linux发行版的核心转存（core dump）机制存在严重安全缺陷**  
，攻击者可借此  
**窃取系统密码哈希、加密密钥等敏感内存数据**  
。这一漏洞影响范围覆盖Ubuntu、Red Hat Enterprise Linux（RHEL）和Fedora等主流系统，潜在危害极大。  
  
    安全研究人员警告，攻击者只需拥有  
**普通本地账户权限**  
，即可利用该漏洞突破系统防线，获取本应受保护的关键认证信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yNMu8EREVKiaNa1mI1DbgvYn3GCxuJfnDxbgARPrrVBVlf57ibm2ic80UKYY8SJkTZ3qadVbRGB1ibreQ/640?wx_fmt=png&from=appmsg "")  
## 01 漏洞警报：核心转存机制的安全盲区  
  
    根据Qualys威胁研究部门披露，Linux系统中负责处理应用崩溃报告的核心转存组件存在两处高危漏洞，编号为  
**CVE-2025-5054**  
（影响Ubuntu的Apport）和  
**CVE-2025-4598**  
（影响RHEL/Fedora的systemd-coredump），CVSS评分均为4.7。  
  
    核心转存功能本用于记录程序崩溃时的内存状态，协助开发者调试。但这两处漏洞均属于  
**竞争条件（Race Condition）缺陷**  
，使攻击者可  
**劫持特权进程崩溃瞬间**  
，诱使系统将敏感内存数据写入转储文件。  
  
    更危险的是，攻击完全在本地进行，  
**不触发任何网络告警**  
，传统安全防护系统难以检测。安全专家Jason Soroko指出：“这类漏洞绕过了所有专注于运行时内存保护的防护措施。”  
## 02 攻击原理：密码哈希如何被窃取  
  
漏洞利用链条环环相扣，技术精巧却危害巨大：  
1. **诱导特权进程崩溃**  
：攻击者首先故意触发以  
**SUID权限**  
运行的系统进程（如身份验证工具  
unix_chkpwd  
）崩溃。SUID权限允许程序以所有者权限（常为root）执行。  
  
1. **发动“竞速攻击”**  
：在核心转存处理器收集崩溃数据前的极短时间内，攻击者  
**快速用同名非特权进程替换原进程**  
。由于系统通过进程ID（PID）追踪进程，这一替换可误导转存处理器。  
  
1. **窃取内存快照**  
：转存处理器误将  
**原特权进程的内存数据写入核心转存文件**  
，其中可能包含正在验证的密码哈希、磁盘加密密钥或API凭证等敏感信息。  
  
    Qualys已公开概念验证代码（PoC），证实攻击者可成功提取  
/etc/shadow  
文件中的密码哈希值，直接威胁系统账户安全。  
## 03 影响范围：主流发行版无一幸免  
  
<table><thead><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;text-align: left;"><span cid="n25" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 170.875px;min-height: 10px;"><span md-inline="strong" style="box-sizing: border-box;"><strong style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">受影响系统</span></span></strong></span></span></th><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;text-align: left;"><span cid="n26" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 278.328px;min-height: 10px;"><span md-inline="strong" style="box-sizing: border-box;"><strong style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">漏洞编号</span></span></strong></span></span></th><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;text-align: left;"><span cid="n27" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 273.984px;min-height: 10px;"><span md-inline="strong" style="box-sizing: border-box;"><strong style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">核心转存处理器</span></span></strong></span></span></th><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;text-align: left;"><span cid="n28" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 307.812px;min-height: 10px;"><span md-inline="strong" style="box-sizing: border-box;"><strong style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">默认风险状态</span></span></strong></span></span></th></tr></thead><tbody><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n30" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 170.875px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">Ubuntu全版本</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n31" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 278.328px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">CVE-2025-5054</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n32" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 273.984px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">Apport</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n33" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 307.812px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">所有安装Apport的系统高危</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n35" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 170.875px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">RHEL/CentOS</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n36" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 278.328px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">CVE-2025-4598</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n37" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 273.984px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">systemd-coredump</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n38" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 307.812px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">启用coredump即存在风险</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n40" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 170.875px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">Fedora</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n41" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 278.328px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">CVE-2025-4598</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n42" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 273.984px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">systemd-coredump</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n43" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 307.812px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">同上</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n45" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 170.875px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">Debian</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n46" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 278.328px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">不受CVE-2025-4598影响</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n47" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 273.984px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">无默认coredump处理器</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n48" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 307.812px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">需手动安装才受影响</span></span></span></td></tr></tbody></table>  
**特别说明**  
：亚马逊Linux、Gentoo等衍生版本同样受影响，用户需紧急自查。  
## 04 紧急缓解：三管齐下防御策略  
### 临时处置方案（立即执行）  
  
在终端以root权限执行：  
```
```  
  
    此命令  
**禁用所有SUID程序的核心转存功能**  
，直接切断攻击路径。但需注意：这将  
**牺牲对特权程序崩溃的分析能力**  
，仅作临时补救。  
### 权限与访问控制加固  
- **限制核心转存目录访问**  
：严格控制  
/var/lib/systemd/coredump  
（systemd系统）或  
/var/crash  
（Ubuntu）目录权限，仅限root读写  
  
- **审计本地用户活动**  
：排查拥有shell访问权限的非特权账户，尤其是近期新增或存在异常登录的账户  
  
### 长期升级与架构改造  
- **及时更新系统**  
：密切关注各发行版补丁发布，Ubuntu用户可通过Livepatch服务实现  
**无重启热修复**  
  
- **重构转存处理流程**  
：按安全专家建议，将核心转存处理移至  
**独立容器或命名空间**  
，并对转储文件实施端到端加密  
  
- **禁用非必要SUID程序**  
：通过  
chmod u-s  
移除非关键程序的SUID权限，减少攻击面  
  
## 05 深度防护：企业级安全加固指南  
  
    除漏洞专项修复外，建议企业用户实施  
**纵深防御策略**  
：  
  
**特权隔离**  
：运行核心转存处理的账户权限必须最小化，禁止使用root直接处理转储文件。推荐在  
**独立容器环境**  
中运行分析服务。  
  
**文件系统监控**  
：部署实时文件完整性监控工具（如AIDE、Tripwire），对  
/etc/shadow  
、  
/var/crash  
等敏感路径设置  
**变更告警**  
。  
  
**强化认证体系**  
：  
- 全面启用  
**多因子认证**  
（MFA），即使密码哈希泄露也不致账户沦陷  
  
- 系统密码强制使用  
**16位以上强密码**  
，包含大小写字母、数字和特殊字符组合  
  
- **定期轮转密钥**  
，尤其对数据库凭证和API密钥  
  
**安全运维升级**  
：建立  
**离线备份的应急命令集**  
，预先备份  
ls  
、  
ps  
、  
netstat  
等关键命令的洁净版本，即使系统被植入rootkit仍可进行可信检测。  
  
    某金融机构运维团队在漏洞披露后立即部署了临时防护措施，其安全主管坦言：“  
**核心转存这类底层功能的安全风险最易被忽视**  
，这次漏洞让我们重新评估了整个调试基础设施的风险边界。”  
  
    随着Linux在服务器、云平台及IoT设备中的广泛应用，  
**一次本地权限的突破可能引发全网沦陷**  
。国家网络安全机构紧急提醒：所有使用受影响版本Linux系统的单位需  
**立即验证漏洞状态**  
，并按指引实施防护。毕竟在网络安全领域，  
**最危险的漏洞往往藏在你认为最无害的功能中**  
。  
  
  
免责声明：  
### 本人所有文章均为技术分享，均用于防御为目的的记录，所有操作均在实验环境下进行，请勿用于其他用途，否则后果自负。  
  
第二十七条：任何个人和组织不得从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动；不得提供专门用于从事侵入网络、干扰网络正常功能及防护措施、窃取网络数据等危害网络安全活动的程序和工具；明知他人从事危害网络安全的活动，不得为其提供技术支持、广告推广、支付结算等帮助  
  
第十二条：  国家保护公民、法人和其他组织依法使用网络的权利，促进网络接入普及，提升网络服务水平，为社会提供安全、便利的网络服务，保障网络信息依法有序自由流动。  
  
任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得危害网络安全，不得利用网络从事危害国家安全、荣誉和利益，煽动颠覆国家政权、推翻社会主义制度，煽动分裂国家、破坏国家统一，宣扬恐怖主义、极端主义，宣扬民族仇恨、民族歧视，传播暴力、淫秽色情信息，编造、传播虚假信息扰乱经济秩序和社会秩序，以及侵害他人名誉、隐私、知识产权和其他合法权益等活动。  
  
第十三条：  国家支持研究开发有利于未成年人健康成长的网络产品和服务，依法惩治利用网络从事危害未成年人身心健康的活动，为未成年人提供安全、健康的网络环境。  
  
  
  
  
  
  
