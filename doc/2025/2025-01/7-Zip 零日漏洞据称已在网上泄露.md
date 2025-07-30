#  7-Zip 零日漏洞据称已在网上泄露   
铸盾安全  河南等级保护测评   2025-01-03 00:10  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sNicKB84ZxoHDlAmV09aZ1WrsSdBhUcwVTEz7Kp6OFn0BLHughLibpcgESTWGenIdf3eLQJwb44icGibFuibm5u1ialA/640?wx_fmt=png&from=appmsg "")  
  
据称，一名在 X 上使用别名“NSA_Employee39”的黑客泄露了一个严重的 7-Zip 零日漏洞，当受害者的机器使用最新版本的 7-Zip 打开或解压时，该漏洞可允许攻击者在受害者的机器上执行任意代码。  
  
这一披露带来了重大的网络安全风险，特别是在信息窃取恶意软件扩散和潜在供应链攻击载体的背景下。  
  
网络安全新闻   
最近报道了  
 一个严重的安全漏洞 CVE-2024-11477，该漏洞  
出现在流行的文件压缩实用程序 7-Zip 中，允许远程攻击者通过特制的档案执行恶意代码。  
## 漏洞：利用 7-Zip 的 LZMA 解码器  
  
此次披露的零日漏洞针对的是 7-Zip 中的 LZMA 解码器。具体来说，它利用格式错误的 LZMA 流来触发RC_NORM  
函数中的缓冲区溢出。  
  
这种复杂的漏洞利用了缓冲区指针和有效载荷对齐，从而在受害者的系统上执行任意代码。  
  
对于用户来说，这意味着使用 7-Zip 应用程序打开或提取恶意 .7z 文件的简单操作可能会危害系统，使攻击者无需任何额外的用户交互即可执行恶意 shellcode。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sNicKB84ZxoHDlAmV09aZ1WrsSdBhUcwVdIicbXicRqc1ia2ubMslQrsnRx5be4ogO9p6ksRbsWNhxPTPZh7yN3OmQ/640?wx_fmt=png&from=appmsg "")  
  
为了演示该漏洞，“NSA_Employee39”通过 Pastebin 分享了一张截图，其中显示了执行良性负载的代码——启动 Windows 计算器应用程序 ( calc.exe  
)。然而，此代码很容易被更有害的负载替换，从而大大加剧了威胁。  
## 信息窃取恶意软件的新途径  
  
在 Infostealer 恶意软件攻击的背景下，这种漏洞尤其令人担忧。这些恶意程序旨在悄悄地从受感染的系统中提取敏感信息，例如登录凭据、银行详细信息和个人数据。  
  
信息窃取者通常依靠社会工程手段进行传播，通常使用受密码保护的 .rar 或 .zip 文件来绕过防病毒扫描。然而，7-Zip 零日漏洞消除了密码保护或复杂方法的需要。  
  
只需打开受感染的 .7z 文件，用户就可以在不知不觉中执行恶意代码，为攻击者提供无缝的感染媒介。  
  
这种漏洞的潜在影响远远超出了个人用户。许多组织，尤其是供应链运营中的组织，都会自动化涉及提取从外部来源收到的文件的工作流程。  
  
通过将 .7z 文件武器化，攻击者可以渗透到这些自动化流程中，嵌入在企业系统内不被察觉地执行的恶意负载。  
  
这种情况会带来重大风险，包括数据泄露、勒索软件传播和大范围的运营中断。  
  
虽然利用此漏洞在概念上很简单，但需要很高的技术专长。例如，攻击者需要制作能够在仅 100-200 字节的受限空间内运行的 shellcode。  
  
尽管存在这种限制，但网络安全专家警告称，熟练的对手可以轻松克服这些挑战，从而使漏洞利用成为一种明显而现实的危险。  
  
7-Zip 零日漏洞的发布引发了人们对软件漏洞和负责任的披露流程的更广泛担忧。  
  
通过官方渠道报告的漏洞可以让开发人员有时间修补，而未经警告的公开披露则为攻击者提供了立即利用未受保护系统的机会。  
  
更令人担忧的是，“NSA_Employee39”暗示即将发布另一个针对开源论坛软件 MyBB 的零日漏洞。如果被揭露，这可能会导致大规模入侵，并暴露无数在线社区的敏感数据库。  
## 用户和组织应该做什么？  
  
虽然 7-Zip 漏洞的官方补丁尚未发布，但网络安全专家建议立即采取行动以最大程度地降低风险。关键步骤包括：  
- **监控更新：**  
用户和组织应密切关注 7-Zip 开发人员的更新，并在补丁发布后立即应用补丁。  
  
- **实施缓解策略：**  
组织应采用文件沙盒和扫描机制，在处理第三方文件之前对其进行仔细检查。  
  
- **提高意识：**  
进行培训，教育用户了解打开未经请求或可疑的存档文件的风险。  
  
- **社区合作：**  
网络安全专家和研究人员必须合作来分析和应对由此和其他漏洞带来的新威胁。  
  
对于防御者来说，这凸显了在迅速演变的威胁面前加强防御和保持警惕的迫切需要。  
  
网络安全社区现在正在等待进一步的发展，包括 7-Zip 开发人员的潜在修复和承诺的 MyBB 零日漏洞披露。  
  
与此同时，组织和个人必须保持警惕，因为这次攻击表明了对全球供应链、关键系统和用户构成的深远风险。  
  
**更新：**  
  
7-Zip 的创建者 Igor Pavlov 在 7-Zip 论坛的漏洞部分驳斥了这些说法，他表示：“Twitter 上的这个报告是假的。我不明白为什么这位 Twitter 用户会做出这样的声明。7-Zip/LZMA 中不存在 ACE 漏洞。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sNicKB84ZxoHDlAmV09aZ1WrsSdBhUcwVuksvFKqIN3wc5edYqyWo5kmacH6hvZMiaPibYolJYd4swkkTB06SPvhQ/640?wx_fmt=png&from=appmsg "")  
  
@NSA_Employee39 账户没有立即回应社交媒体上的评论请求。  
  
**美国东部时间下午 4 点更新：**  
  
@NSA_Employee39 账户在 Pastebin 上分享了最新消息：“该漏洞源于对 LZMA 流结构的验证不足，导致格式错误的输入触发溢出并执行任意代码。请记住，这只是一个概念验证。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sNicKB84ZxoHDlAmV09aZ1WrsSdBhUcwVNkKbtFYa6OuAK35umXo3gsL8yLlJFotAcS2MRwLiasRwiajQkytuMSibw/640?wx_fmt=png&from=appmsg "")  
  
**美国东部时间下午 6 点更新：**  
  
Igor Pavlov 否认了 X 账号分享的说法，他表示“LZMA 解码器中没有 RC_NORM 函数。相反，7-Zip 在 LZMA 编码器和 PPMD 解码器中包含 RC_NORM 宏。因此，LZMA 解码代码不会调用 RC_NORM。漏洞注释中关于 RC_NORM 的说法是不正确的。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sNicKB84ZxoHDlAmV09aZ1WrsSdBhUcwVmcJ53KLM7VaTPPXJG93aOkUibVicHcWDBrR9y2wbTh4H3FuF7T8BSuibw/640?wx_fmt=png&from=appmsg "")  
  
**更新：2025 年 1 月 1 日 - 上午 12:38：**  
  
卡巴斯基研究员 Marc R 表示**RC_NORM 宏**  
是安全的，不存在任何漏洞。  
  
此外，他们确认，**格式错误的 LZMA 流**  
会触发错误，而不是导致溢出，从而确保了处理此类情况的稳健性。此外，概念验证中包含的**shellcode 和偏移量**  
不起作用，导致漏洞利用无效。  
  
  
