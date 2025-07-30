> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0MDY1MDU4MQ==&mid=2247583863&idx=1&sn=247a5ef8a5281ed71aa75625259ef035

#  黑客正在利用Wing FTP服务器的关键RCE漏洞  
胡金鱼  嘶吼专业版   2025-07-18 06:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
近期，黑客在技术细节曝光后的第一天就利用了Wing FTP Server中的一个严重远程代码执行漏洞。观察到的攻击执行了多个枚举和侦察命令，随后通过创建新用户来建立持久性。  
  
被利用的Wing FTP Server漏洞被追踪为CVE-2025-47812，并获得了最高的严重性评分。它是空字节和Lua代码注入的组合，允许未经身份验证的远程攻击者以系统（root/ system）上的最高权限执行代码。  
  
Wing FTP Server是一个强大的解决方案，用于管理可以执行Lua脚本的安全文件传输，它广泛用于企业和SMB环境。  
  
安全研究员Julien Ahrens近期发表了一篇CVE-2025-47812的技术文章，解释说该漏洞源于C++中对以空结尾的字符串的不安全处理以及Lua中不正确的输入处理。  
  
研究人员演示了用户名字段中的空字节如何绕过身份验证检查并使Lua代码注入到会话文件中。当这些文件随后由服务器执行时，可以实现以根/SYSTEM的身份执行任意代码。  
  
除了CVE-2025-47812之外，研究人员还提出了Wing FTP中的另外三个漏洞：  
  
**·**  
CVE-2025-27889——如果用户提交登录表单，通过构造的URL可以窃取用户密码，因为  
在JavaScript变量（位置）中包含不安全的密码。  
  
**·**  
CVE-2025-47811——Wing FTP默认以root/SYSTEM身份运行，没有沙箱或特权下降，使得rce更加危险。  
  
**·**  
CVE-2025-47813——提供过长的UID cookie会泄露文件系统路径。  
  
所有的漏洞都影响到7.4.3及更早版本的Wing FTP。供应商在2025年5月14日发布了7.4.4版本修复了这些问题，但 CVE-2025-47811被认为不重要，未做修复。  
  
管理网络安全平台Huntress的威胁研究人员创建了CVE-2025-47812的概念验证漏洞，并展示了黑客如何利用它进行攻击：  
  
Huntress  
的研究人员发现，在7月1日，也就是CVE-2025-47812的技术细节出现的第二天，至少有一个攻击者利用了他们一个客户的漏洞。  
  
攻击者发送了带有空字节注入的用户名的畸形登录请求，目标是‘ loginok.html ’。这些输入创建了恶意session . Lua文件，将Lua代码注入服务器。  
  
注入的代码被设计成十六进制解码有效载荷并通过cmd.exe执行它，使用certutil从远程位置下载恶意软件并执行它。  
  
同一个Wing FTP实例在短时间内被五个不同的IP地址作为攻击目标，这可能表明有几个威胁者试图进行大规模扫描和利用。  
  
在这些尝试中观察到的命令是用于侦察、获取环境中的持久性以及使用cURL工具和webhook端点进行数据泄露。  
  
Huntress表示，黑客攻击失败“可能是因为他们不熟悉这些软件，或者是因为微软防御者阻止了他们的部分攻击”。尽管如此，研究人员还是发现了对Wing FTP服务器关键漏洞的明显利用。  
  
即使  
Huntress  
观察到针对其客户的失败攻击，黑客也可能会扫描可访问的Wing FTP实例，并试图利用易受攻击的服务器。因此，强烈建议相关公司尽快升级到该产品的7.4.4版本。  
  
如果切换到更新的安全版本是不可能的，研究人员的建议是禁用或限制HTTP/HTTPs访问到Wing FTP web门户，禁用匿名登录，并监控会话目录的可疑添加。  
  
参考及来源：  
https://www.bleepingcomputer.com/news/security/hackers-are-exploiting-critical-rce-flaw-in-wing-ftp-server/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28ccRNWmNEetPSlXTmJia692tK74IvXUGyribM3fXfFuiaSJfyfZ9OKYGldj5INlGF04LiaiakhEqLb0IQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28ccRNWmNEetPSlXTmJia692n5RQNNxLtj6PP8l96F0RngjDak6wIwhYialRiaibNlWIRKq1Bklo1EpfA/640?wx_fmt=png&from=appmsg "")  
  
  
