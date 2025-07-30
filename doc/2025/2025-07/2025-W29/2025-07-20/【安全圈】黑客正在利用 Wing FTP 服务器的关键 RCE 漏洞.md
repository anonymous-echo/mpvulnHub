> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070749&idx=2&sn=04105f8ddc32460791073712282f5bbf

#  【安全圈】黑客正在利用 Wing FTP 服务器的关键 RCE 漏洞  
 安全圈   2025-07-20 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
近期，黑客在技术细节曝光后的第一天就利用了 Wing FTP Server 中的一个严重远程代码执行漏洞。观察到的攻击执行了多个枚举和侦察命令，随后通过创建新用户来建立持久性。  
  
被利用的 Wing FTP Server 漏洞被追踪为 CVE-2025-47812，并获得了最高的严重性评分。它是空字节和 Lua 代码注入的组合，允许未经身份验证的远程攻击者以系统（root/ system）上的最高权限执行代码。  
  
Wing FTP Server 是一个强大的解决方案，用于管理可以执行 Lua 脚本的安全文件传输，它广泛用于企业和 SMB 环境。  
  
安全研究员 Julien Ahrens 近期发表了一篇 CVE-2025-47812 的技术文章，解释说该漏洞源于 C++ 中对以空结尾的字符串的不安全处理以及 Lua 中不正确的输入处理。  
  
研究人员演示了用户名字段中的空字节如何绕过身份验证检查并使 Lua 代码注入到会话文件中。当这些文件随后由服务器执行时，可以实现以根 /SYSTEM 的身份执行任意代码。  
  
除了 CVE-2025-47812 之外，研究人员还提出了 Wing FTP 中的另外三个漏洞：  
  
**·**  
CVE-2025-27889 ——如果用户提交登录表单，通过构造的 URL 可以窃取用户密码，因为在 JavaScript 变量（位置）中包含不安全的密码。  
  
**·**  
CVE-2025-47811 —— Wing FTP 默认以 root/SYSTEM 身份运行，没有沙箱或特权下降，使得 rce 更加危险。  
  
**·**  
CVE-2025-47813 ——提供过长的 UID cookie 会泄露文件系统路径。  
  
所有的漏洞都影响到 7.4.3 及更早版本的 Wing FTP。供应商在 2025 年 5 月 14 日发布了 7.4.4 版本修复了这些问题，但 CVE-2025-47811 被认为不重要，未做修复。  
  
管理网络安全平台 Huntress 的威胁研究人员创建了 CVE-2025-47812 的概念验证漏洞，并展示了黑客如何利用它进行攻击：  
  
Huntress 的研究人员发现，在 7 月 1 日，也就是 CVE-2025-47812 的技术细节出现的第二天，至少有一个攻击者利用了他们一个客户的漏洞。  
  
攻击者发送了带有空字节注入的用户名的畸形登录请求，目标是‘ loginok.html ’。这些输入创建了恶意 session . Lua 文件，将 Lua 代码注入服务器。  
  
注入的代码被设计成十六进制解码有效载荷并通过 cmd.exe 执行它，使用 certutil 从远程位置下载恶意软件并执行它。  
  
同一个 Wing FTP 实例在短时间内被五个不同的 IP 地址作为攻击目标，这可能表明有几个威胁者试图进行大规模扫描和利用。  
  
在这些尝试中观察到的命令是用于侦察、获取环境中的持久性以及使用 cURL 工具和 webhook 端点进行数据泄露。  
  
Huntress 表示，黑客攻击失败 " 可能是因为他们不熟悉这些软件，或者是因为微软防御者阻止了他们的部分攻击 "。尽管如此，研究人员还是发现了对 Wing FTP 服务器关键漏洞的明显利用。  
  
即使 Huntress 观察到针对其客户的失败攻击，黑客也可能会扫描可访问的 Wing FTP 实例，并试图利用易受攻击的服务器。因此，强烈建议相关公司尽快升级到该产品的 7.4.4 版本。  
  
如果切换到更新的安全版本是不可能的，研究人员的建议是禁用或限制 HTTP/HTTPs 访问到 Wing FTP web 门户，禁用匿名登录，并监控会话目录的可疑添加。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】吐鲁番首例“特种设备”系统入侵，未检气瓶竟获虚假合格证！](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070725&idx=1&sn=982b3d7e4a51d4cedb62c1c5ac08a23c&scene=21#wechat_redirect)  
  
  
  
[【安全圈】LV遭黑客攻击！官方紧急通知客户立即修改密码](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070725&idx=2&sn=ffa655ec005a16609cb9bbeb76295759&scene=21#wechat_redirect)  
  
  
  
[【安全圈】黑客利用 Apache HTTP 服务器漏洞，部署 Linuxsys 加密货币挖矿程序](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070725&idx=3&sn=0ed096ca126a498dcb6caff13372e355&scene=21#wechat_redirect)  
  
  
  
[【安全圈】制造业安全警报：为何必须彻底废除默认密码？](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070714&idx=1&sn=ccd1231536a99cc8c6648c5aaf2470c1&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
