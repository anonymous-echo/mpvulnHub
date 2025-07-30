> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0MTUwMjQ5Nw==&mid=2247489271&idx=1&sn=1124171741d1fb9886d2bb445926af65

#  一键账户接管 | XSS | CORS 配置错误 | JWT 伪造  
原创 红云谈安全  红云谈安全   2025-07-13 16:57  
  
**免责声明**  
  
由于传播、利用本公众号红云谈安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号红云谈安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢！请在授权的站点测试，遵守网络安全法！  
**仅供**  
**学习使用，****如若非法他用，与平台和本文作者无关，需自行负责！**  
  
这一发现已报告给漏洞赏金计划，但由于保密协议而被删除。  
# 寻找线索  
  
在寻找漏洞时，我会尝试像普通用户一样与网站进行交互，探索其所有功能。借助 Burp 等工具，这样做可以发现一些有趣的端点。  
## CORS配置错误  
  
访问redacted.com/account/profile后，系统向redacted_auth.com/api/v1/profile发出了**POST**请求。我倾向于尽可能先进行被动侦察，因为它不会产生噪音。Waymore 是一款非常棒的工具，可以用来查找来自被动来源的链接，它帮助我找到了更多 API 端点。  

```
waymore -i 'https://redacted_auth.com/api/v1/' -mode U -oU urls_waymore.txt'https://redacted_auth.com/api/v1/' -mode U -oU urls_waymore.txt
```

  
  
  
  
redacted_auth.com/web/cookie/token立刻引起了我的注意。它的响应中反映了会话 cookie。  
  
  
  
  
端点还会盲目地将任何提供的**Origin**反映为**Access-Control-Allow-Origin**标头。  
  
  
  
  
会话 cookie 的**SameSite**属性被设置为**“严格”**，以防止第三方站点将其包含在其请求中，但此限制不适用于子域，因为它们被视为同源。  
  
这些漏洞结合在一起，构成了严重的威胁。  
- 在响应中反映会话 cookie 会使其**HttpOnly**属性无效。  
- CORS漏洞将攻击面扩展到redacted.com的任何子域**，**因为它们都能够读取用户会话 cookie。  
现在，在任何子域上找到接管或**XSS**都可以劫持会话。  
  
  
  
# 漏洞链  
## 子域名接管  
  
**首先，我使用subfinder**搜索子域，并确保在配置文件中包含 API 密钥以查找更多结果。  

```
subfinder -d redacted.com -all -recursive | anew subdomains.txt
```

  
**然后， dnsReaper**对子域名进行分析以查找接管情况。  

```
docker run -it — rm -v $(pwd):/etc/dnsreaper punksecurity/dnsreaper file — 文件名 /etc/dnsreaper/subdomains.txtrm -v $( pwd ):/etc/dnsreaper punksecurity/dnsreaper 文件 — 文件名 /etc/dnsreaper/subdomains.txt
```

  
  
  
  
手动验证结果后，确定所有劫持均无效。这并不奇怪，因为子域名劫持漏洞类别是高度自动化的。  
## 跨站点脚本  
  
我花了大约两周时间寻找XSS漏洞。大多数子域名都受到WAF保护，很难测试，所以我用httpx扫描了它们，找出了那些没有受到保护的子域名。  

```
httpx-pd -l subdomains.txt -td -sc -title -fr | grep -viE 'akamai|cloudflare''akamai|cloudflare'
```

  
分析其中一个子域的源代码后，我们发现了一个有趣的现象。  
  
  
  
  
**url**变量已定义但从未使用，可能是因为开发人员忘记从之前的提交中删除它。此端点还未能过滤查询参数中反射的用户输入，因此容易受到 XSS 攻击。  
  
  
  
# 不断升级的影响  
## JWT 伪造  
  
大多数 Web API 都需要输入当前密码才能更改密码，但通常可以通过编辑当前电子邮件地址，然后调用重置密码端点来绕过此检查。遗憾的是，redacted_auth.com/ api/v1/profile 不允许修改电子邮件地址。  
  
经过进一步侦察，我在redacted_widget.com上找到了一个不同的 API 。通过此端点进行的更改已与主 API 同步，但需要**UUID**和**JWT**。  
  
  
  
  
所需的**UUID**包含在之前 XSS 弹出窗口中显示的**JWT中，并且由于使用的是版本 4，因此无法破解。https**://en.wikipedia.org/wiki/Universally_unique_identifier  
  
然而， JWT cookie**的**结构与主 API 上使用的结构不同。  
  
  
  
  
为了验证此令牌，应用程序将其电子邮件与请求中的电子邮件地址进行了比较。不幸的是，尝试使用现有电子邮件注册用户会返回错误，因此似乎无法复制令牌。  
  
  
  
  
**经过彻底的测试后，我发现了一个批量分配漏洞，通过将区域设置为EU**可以绕过重复用户检查。  
  
  
  
  
  
请注意，重复帐户生成的令牌不包含区域属性，因此它与受害者的 JWT 相同。  
  
现在可以使用以下链完成**ATO 。**  
- redacted_widget.com/v1/widget/update  
- redacted_widget.com/v1/widget/resetToken  
# 结论  
## 重现攻击的步骤。  
1. 受害者访问我们的恶意网站。  
1. 使用我们的有效载荷，受害者被重定向到易受 XSS 攻击的子域。  
1. 有效载荷执行，从主 API 获取受害者的会话 cookie，并将其发送到我们的服务器。  
1. 我们利用小部件 API 中发现的批量分配漏洞在**欧盟地区创建了一个重复用户。**  
1. 我们使用窃取的**UUID**和**JWT**来更新受害者的电子邮件。  
1. 我们使用重置密码端点来更新受害者的密码并接管他们的帐户。  
## 补救措施  
1. 为主要 API 接受的来源实施允许列表。  
1. 不要在请求中反映会话 cookie。  
1. 为易受 XSS 攻击的子域添加 WAF 保护。  
1. 清理传递到易受攻击的子域上的**url**端点的用户输入，或将其完全删除。  
1. 在小部件 API 创建的每个**JWT**中包含一个区域属性。  
1. 验证令牌时检查**JTI**和**区域**属性。****  
1. 在用户注册时验证**区域**属性。  
