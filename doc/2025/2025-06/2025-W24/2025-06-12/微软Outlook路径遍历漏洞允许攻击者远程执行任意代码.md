#  微软Outlook路径遍历漏洞允许攻击者远程执行任意代码  
 FreeBuf   2025-06-12 11:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38DtAPtkeoBKLW2FEcTvZWWGQ6sYnU0giceCEpAE1ud8TXxibJtIpuD7ciaU9ltIWAKek7L5hY1EeuoQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
微软Outlook电子邮件客户端中存在一个重大安全漏洞，可能允许攻击者远程执行任意代码，即使需要本地访问权限才能触发漏洞利用。该漏洞编号为CVE-2025-47176，于2025年6月10日披露，被微软评为"重要"级别，CVSS评分为7.8分。  
  
  
这一漏洞影响广泛使用的电子邮件应用程序，对企业用户和个人用户构成重大风险，特别是考虑到它只需要低级别权限即可利用，且一旦触发无需用户交互。  
  
### Part01  
### 漏洞技术细节  
  
  
该漏洞的核心是微软Office Outlook中涉及'.../...//'序列的路径遍历(path traversal)问题，使经过认证的攻击者能够在受影响系统上本地执行代码。根据微软的技术分析，该漏洞的CVSS:3.1向量字符串为AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，表明这是一个本地攻击向量，复杂度要求较低。  
  
  
尽管被归类为本地漏洞，微软强调这实际上是一个远程代码执行(RCE)漏洞，因为"远程"指的是攻击者的位置而非执行方法。该漏洞影响所有三个核心安全原则：机密性、完整性和可用性，在CVSS评估中均被评为"高"级别。这种全面的影响特征表明，成功利用该漏洞可能导致系统完全被攻陷，使攻击者能够访问敏感数据、修改系统配置，甚至可能导致系统不可用。  
  
### Part02  
### 漏洞利用条件与发现过程  
###   
  
特权要求(PR:L)指标表明，任何经过认证的用户都可以触发此漏洞，无需管理员或提升的权限，这显著扩大了潜在的攻击面。Morphisec的安全研究人员Shmuel Uzan、Michael Gorelik和Arnold Osipov通过协调披露实践发现并报告了这一漏洞。  
  
  
漏洞利用机制涉及使用目录遍历序列操作文件路径，这是一种通常与任意代码执行(ACE)攻击相关的技术。虽然攻击向量被归类为本地(AV:L)，但实际影响允许远程代码执行场景，攻击者可以利用该漏洞在目标系统上运行恶意代码。  
  
  
值得注意的是，微软已确认预览窗格不是此漏洞的攻击向量，这可能限制了通常依赖被动内容渲染的某些利用场景。用户交互(UI:N)评级表明，一旦满足初始条件，成功利用漏洞无需进一步的用户干预。  
  
### Part03  
### 当前威胁态势与风险因素  
  
  
当前威胁情报显示，在微软发布公告之前，该漏洞尚未被公开披露，也未观察到野外主动利用的情况，漏洞可利用性评估将利用可能性评为"不太可能"。  
  
### Part04  
### 安全建议  
###   
  
微软已承认CVE-2025-47176的严重性，但表示Microsoft 365的安全更新不会立即提供。该公司承诺"尽快"发布补丁，并将在更新可用时通过修订CVE信息通知客户。补丁可用性的延迟提高了组织实施补偿性安全措施并密切监控其Outlook部署的紧迫性。  
  
  
组织应优先监控可疑的Outlook行为，尽可能实施额外的访问控制，并准备在安全更新可用时快速部署。鉴于低权限要求和高影响潜力，该漏洞代表了一个重大的安全问题，需要所有在其通信基础设施中使用微软Outlook的IT安全团队立即关注。  
  
  
**参考来源：**  
  
****  
**Microsoft Outlook Vulnerability Let Attackers Execute Arbitrary Code Remotely**  
  
https://cybersecuritynews.com/microsoft-outlook-rce-vulnerability/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651322750&idx=1&sn=a3c131230639a0c28b18a4475b631066&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
