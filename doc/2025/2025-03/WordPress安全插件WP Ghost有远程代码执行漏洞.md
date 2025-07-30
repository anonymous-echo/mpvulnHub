#  WordPress安全插件WP Ghost有远程代码执行漏洞   
HackSee安全团队  HackSee   2025-03-22 17:28  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/M8pOVgDSPVLeXbkYsjqpqvKlIC8lK4hoRicV32pcm2X5Lt5nMf005sxyA1Q7o0Pkuea0ECQUTVukcGZNBU1XkxQ/640?wx_fmt=webp&from=appmsg "")  
  
流行的WordPress安全插件WP Ghost容易受到一个严重漏洞的攻击，该漏洞可能允许未经身份验证的攻击者远程执行代码并劫持服务器。  
  
WP Ghost是一个流行的安全插件，在超过20万个WordPress网站中使用，声称每月阻止14万次黑客攻击和超过900万次暴力破解尝试。  
  
它还提供针对SQL注入、脚本注入、漏洞利用、恶意软件丢弃、文件包含利用、目录遍历攻击和跨站点脚本的保护。  
  
然而，正如Patchstack所揭示的那样，安全工具本身容易受到一个严重的（CVSS得分：9.6）远程代码执行（RCE）漏洞的攻击，这可能导致整个网站被接管。  
  
该漏洞被追踪为CVE-2025-26909，影响到5.4.01之前的所有版本的WP Ghost，并且源于‘showFile()’函数中的输入验证不足。利用这个漏洞，攻击者可以通过操纵的URL路径来包含任意文件。  
  
只有当WP Ghost的“更改路径”功能设置为Lite或Ghost模式时，才会触发该漏洞。虽然这些模式在默认情况下不启用，但Patchstack注意到本地文件包含（LFI）部分几乎适用于所有设置。  
  
Patchstack的报告中写道：“漏洞的发生是由于用户通过URL路径输入的值不足，而URL路径将作为文件包含。”  
  
“由于LFI案例的行为，该漏洞可能导致几乎所有环境设置上的远程代码执行。”  
  
因此，该漏洞普遍允许LFI，但是否升级为RCE取决于特定的服务器配置。  
  
没有RCE的LFI在信息泄露、会话劫持、日志中毒、访问源代码和拒绝服务（DoS）攻击等情况下仍然可能是危险的。  
  
在研究员Dimas Maulana于2025年2月25日发现该漏洞后，Patchstack在内部进行了分析，并最终于3月3日通知了供应商。  
  
第二天，WP Ghost的开发人员以对用户提供的URL或路径进行额外验证的形式进行了修复。  
  
这个补丁是在WP Ghost 5.4.02版本中加入的，同时也发布了5.4.03版本。  
  
建议用户升级到其中一个版本以缓解CVE-2025-26909。  
  
  
  
