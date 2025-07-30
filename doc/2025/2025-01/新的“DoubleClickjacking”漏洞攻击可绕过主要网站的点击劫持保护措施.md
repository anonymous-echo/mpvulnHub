#  新的“DoubleClickjacking”漏洞攻击可绕过主要网站的点击劫持保护措施   
会杀毒的单反狗  军哥网络安全读报   2025-01-03 01:01  
  
**导****读**  
  
  
  
“DoubleClickjacking”漏洞绕过了主要网站的保护措施，利用双击序列进行点击劫持和帐户接管攻击。  
  
  
DoubleClickjacking 是一种允许攻击者通过利用双击序列来绕过主要网站的保护措施的技术。  
  
  
攻击者可以利用该技术对几乎所有主要网站发起点击劫持攻击和账户接管。  
  
  
点击劫持攻击诱骗用户进行非预期的点击，由于现代浏览器强制使用“SameSite: Lax” cookie，阻止跨站点身份验证，这种做法已经减少。  
  
  
DoubleClickjacking 利用双击序列绕过 X-Frame-Options 和 SameSite cookie 等点击劫持保护，可能允许平台帐户接管。  
  
  
DoubleClickjacking 是这一经典主题的新变种：它不再依赖单击，而是利用双击序列。虽然这听起来可能只是一个小小的变化，但它为新的 UI 操纵攻击打开了大门，这些攻击可以绕过所有已知的点击劫持保护措施，包括 X-Frame-Options 标头或 SameSite：Lax/Strict cookie。  
  
  
这种技术似乎影响了几乎每个网站，导致许多主要平台的帐户被接管。  
  
  
DoubleClickjacking 利用 mousedown 和 onclick 事件之间的时间差异来劫持用户操作。通过在双击过程中快速切换窗口，攻击者可以将点击重定向到敏感目标，例如 OAuth 提示，而无需依赖弹出式技巧。  
  
  
以下是DoubleClickjacking技术的描述：  
  
  
攻击者首先通过按钮或在网页上自动打开一个新窗口。  
  
点击按钮会打开一个新窗口并提示双击，同时父窗口会重定向到目标页面（例如，OAuth 授权）。  
  
双击会关闭顶部窗口并无意中触发父窗口的授权，从而授予攻击者任意范围的访问权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaF67kEVvgr3vXibaKLvAmI5NkeoyxOIoXlowdvWonTWZZialjcA90vdGAiaUJhynKU1yCUU9xVhewQAw/640?wx_fmt=png&from=appmsg "")  
  
  
DoubleClickjacking 可让攻击者诱骗用户通过 OAuth 授权恶意应用，这通常会导致账户立即被盗用。它还可以操纵用户进行未经授权的账户更改，例如更改安全设置或确认交易。  
  
  
研究人员发布了此次攻击的概念验证 (PoC) 代码以及一系列演示此次攻击的视频。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaF67kEVvgr3vXibaKLvAmI5NjvdwA4PvpQ9qrTicUh5r1NrAKhqorIBxQp1nwKB0rymfANBX9fCFQ4Q/640?wx_fmt=png&from=appmsg "")  
  
  
为了缓解 DoubleClickjacking 攻击，管理员可以禁用关键按钮，直到检测到鼠标手势或按键。其他解决方案包括浏览器供应商采用 X-Frame-Options 等新标准进行保护。  
  
  
“DoubleClickjacking 是针对一种众所周知的攻击类别的花招。”文章总结道。“通过利用点击之间的事件时间，攻击者可以在眨眼间无缝地将良性 UI 元素替换为敏感元素。  
  
  
安全建议：  
  
加强对嵌入式或基于开启器的窗口的控制。  
  
对所有形式的点击劫持保持警惕——甚至是多次点击模式。  
  
  
技术报告：  
  
https://www.paulosyibelo.com/2024/12/doubleclickjacking-what.html  
  
  
新闻链接：  
  
https://securityaffairs.com/172572/hacking/doubleclickjacking-clickjacking-on-major-websites.html  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
