#  7-Zip高危漏洞曝光！攻击者可绕过安全机制远程执行代码，速升级   
看雪学苑  看雪学苑   2025-01-22 09:59  
  
近日，一款广泛使用的开源文件压缩软件7-Zip被曝出存在严重的安全漏洞，编号为CVE-2025-0411，该漏洞的CVSS评分为7.0，属于高危漏洞，引发了广泛的安全担忧。根据相关报道，该漏洞允许远程攻击者绕过Windows系统的一项关键安全功能——“网络标记”（Mark of the Web，简称MotW），从而在受影响的系统上执行任意代码。  
  
  
MotW是微软Windows系统的一项安全功能，用于标识从不可信来源（如互联网）下载的文件。当用户尝试打开这些带有MotW标记的文件时，系统会弹出警告对话框，提醒用户该文件可能来自不安全的来源，从而降低用户误运行恶意文件的风险。然而，7-Zip在处理带有MotW标记的压缩文件时出现了问题。当用户使用存在漏洞的7-Zip版本解压此类文件时，解压后的文件不会保留MotW标记，这就使得攻击者能够绕过这一关键的安全检查，进而在当前用户权限下执行任意代码。  
  
  
根据相关安全研究人员的分析，攻击者可以通过精心构造的恶意压缩包来触发该漏洞。当用户打开这些恶意文件或访问恶意网页时，攻击者就可以利用该漏洞在用户的计算机上执行任意代码。这一漏洞的存在使得用户在处理来自不可信来源的文件时面临巨大的安全风险，尤其是在用户具有管理员权限的情况下，攻击者可能会利用该漏洞获取系统的完全控制权，进而分发恶意软件或进行未经授权的操作。  
  
  
值得注意的是，该漏洞影响了7-Zip的24.07及之前的所有版本。不过，好消息是，7-Zip的开发者Igor Pavlov已经在2024年11月30日发布的7-Zip 24.09版本中修复了这一漏洞。在24.09版本的更新说明中提到，7-Zip File Manager在处理嵌套压缩文件时未能正确传播Zone.Identifier流，导致解压后的文件丢失了MotW标记。而24.09版本修复了这一问题，确保解压后的文件能够正确保留MotW标记，从而恢复了Windows系统的安全防护功能。  
  
  
鉴于该漏洞的严重性，安全专家强烈建议所有7-Zip用户尽快检查自己的软件版本，并升级到7-Zip 24.09或更高版本。此外，用户在日常使用中还应保持警惕，避免打开来自未知或不可信来源的压缩包。同时，建议用户启用额外的终端安全解决方案，以检测和阻止可疑文件活动，从而进一步降低安全风险。  
  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibExiboJzOiafqGLvlOkrmU6NIr3qSr7ibpkIo2N5mhCTNXoMl37s2oRSIDw/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
