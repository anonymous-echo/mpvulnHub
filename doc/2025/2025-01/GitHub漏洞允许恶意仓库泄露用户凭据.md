#  GitHub漏洞允许恶意仓库泄露用户凭据   
邑安科技  邑安全   2025-01-27 07:17  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8vktCwe8bqvDZZ949Vj1VbVR05U9jSHPGGicOKzjNdrFWb2RSYJZibg9eibT7RLtekQZrKkv89y5HK5g/640?wx_fmt=png&from=appmsg "")  
  
  
最近发现了 Git 相关项目（包括 GitHub Desktop、Git Credential Manager、Git LFS 和 GitHub Codespaces）中的关键安全漏洞，这些漏洞涉及对基于文本的协议的不当处理，使攻击者有可能泄露用户凭据。  
  
这一发现凸显了软件安全方面的重大风险，尤其是在凭证管理机制方面。  
  
Git 使用 Git 凭证协议从凭证帮助程序中检索凭证，该帮助程序存储和提供凭证（例如，git-credential-store、git-credential-winstore、git-credential-osxkeychain）。不正确的消息处理导致许多项目出现漏洞和潜在的凭证泄漏。  
  
Git 通过交换消息与凭证帮助程序通信，例如：  
  
**请求：**  
```
protocol=https  
host=github.com
```  
  
**响应：**  
```
protocol=https  
host=github.com  
username=USERNAME  
password=PASSWORD
```  
  
消息以换行符分隔，并由双方解析。为了防止属性注入，Git 会阻止属性名称和值中的换行符和 NULL 字节。  
## 凭证漏洞说明  
  
GitHub Desktop （CVE-2025-23040） 因其凭证帮助程序而面临凭证漏洞，该漏洞允许攻击者通过制作恶意仓库 URL 来利用“回车走私”。  
  
此漏洞利用了 Git 和 GitHub Desktop 之间换行符解析的差异，从而能够将用户凭据泄露给未经授权的主机。  
  
同样，Git 凭据管理器 （CVE-2024-50338） 存在 .NET StreamReader 类的不当使用，其中换行符和回车符的解析不正确允许攻击者通过构建的 URL 泄露凭据。  
  
```
 public TextReader In
        {
            get
            {
                if (_stdIn == null)
                {
                    _stdIn = new StreamReader(Console.OpenStandardInput(), EncodingEx.UTF8NoBom);
                }

                return _stdIn;
            }
        }
```  
  
  
Git Large File Storage （LFS） （CVE-2024-53263） 在处理恶意制作的文件时也存在漏洞。  
  
攻击者可以注入换行符以绕过验证并将用户凭据暴露给恶意主机。GitHub CLI （CVE-2024-53858） 遇到了一个逻辑漏洞，即访问令牌被错误地发送到任意主机。  
  
该问题源于一个有缺陷的函数 IsEnterprise，它未能正确区分 GitHub 拥有的实例和外部域。  
  
最后，GitHub Codespaces Credential Helper 有一个重大缺陷：它总是返回 ，而不管请求的主机如何。  
  
当 Codespace 中克隆的存储库与恶意域交互时，此漏洞会暴露访问令牌，从而导致潜在的凭据泄漏。  
  
这些漏洞是由国外的一个安全工程师在参与 GitHub 漏洞赏金计划期间发现的。这些发现通过详细的博客文章分享，此后促使受影响的平台采取了缓解措施和补丁。  
  
为了应对这些发现，Git 开发人员和 GitHub 团队引入了几种缓解措施：  
- **深度防御验证 （CVE-2024-52006）**  
：Git 添加了一个默认启用的新配置，该配置拒绝包含回车符的凭证。credential.protectProtocol  
  
- GitHub Codespaces 修改了其凭证帮助程序，以便在共享凭证之前验证请求的主机。  
  
- GitHub Desktop 和 Git Credential Manager 实施了额外的输入清理，以防止回车走私。  
  
这些发现强调了基于文本的协议中处理不当的风险，尤其是在处理凭证交换时。即使是很小的架构疏忽也可能导致重大的安全漏洞。  
  
RyotaK 强调了在所有软件应用程序中进行稳健验证和输入清理的重要性，尤其是那些处理凭据等敏感信息的应用程序。  
  
原文来自:   
cybersecuritynews.com  
  
原文链接:https://cybersecuritynews.com/github-vulnerability-let-malicious-repos-to-leaks-users-credentials/   
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
  
  
