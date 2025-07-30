#  WPA3协议存在安全漏洞，黑客可获取WiFi密码   
老布  乌雲安全   2025-01-03 03:00  
  
研究人员成功结合中间人攻击（MITM）和社会工程学技术，绕过了Wi - Fi保护协议——WPA3 ，进而获取网络密码。  
此次研究由西印度大学的Kyle Chadee、Wayne Goodridge和Koffka Khan开展，这一研究揭示了最新无线安全标准存在的安全漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38HhiaXTrdT6htRicEufibw4pUK1Oh6oibiaXTAmonuI9F6LuyVQV6vI316oA3S58bfou287ztbg6rShbQ/640?wx_fmt=jpeg&from=appmsg "")  
  
WPA3于2018年推出，其目的是弥补前身WPA2的缺陷，为Wi - Fi网络提供更强的安全性。其中，“对等同时认证”（SAE）协议是其关键功能之一，该协议旨在让密码能够抵御离线字典攻击。研究人员证实，可利用WPA3过渡模式中的弱点来达成目的，这种过渡模式允许与WPA2设备向后兼容。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38HhiaXTrdT6htRicEufibw4pUalxic0eMXYSawclxYSwVdTpGAExW86tXvSkWkSfD0JK0aNAdgzPibVGQ/640?wx_fmt=jpeg&from=appmsg "")  
  
借助降级攻击，他们能够捕获部分WPA3交互信息，再结合社会工程技术恢复网络密码。  
  
这种攻击方法主要包含三个步骤：  
- 其一，运用降级攻击捕获交互信息；  
  
- 其二，将用户从原始的WPA3网络中解除认证；  
  
- 其三，创建带有强制门户的虚假账号接入点以获取密码。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38HhiaXTrdT6htRicEufibw4pUONevmgorJa2PKV1EemdbL60KuFPqSIg29q7ucPb6gf2lpCd2cPTd7Q/640?wx_fmt=jpeg&from=appmsg "")  
  
研究人员利用树莓派模拟WPA3接入点，并借助Airgeddon等开源工具创建恶意接入点。当不知情的用户尝试连接伪造网络时，就会被提示输入Wi - Fi密码，随后该密码会与捕获的交互信息进行验证。  
  
这项研究引发了对WPA3安全性的担忧，特别是在其过渡模式下。研究发现，如果未实施保护管理，攻击就会成功，而很多用户可能并不清楚或者没有启用这一设置。有趣的是，研究人员还发现一些设备无法连接到WPA3网络，这与Wi - Fi联盟所说的与WPA2向后兼容的说法相互矛盾。  
  
尽管这种攻击需要特定条件并且要有用户交互，但它展示了保护无线网络面临的持续挑战。研究人员强调了用户教育以及正确配置WPA3网络以降低此类风险的重要性。  
  
网络安全专家呼吁进一步调查WPA3的漏洞，并开发额外的保护措施。随着Wi - Fi网络不断成为企业和个人的关键基础设施，确保其安全性至关重要。  
  
这项研究的结果提醒我们，即便最先进的安全协议也可能受到技术漏洞与社会工程学巧妙组合的影响。随着WPA3的普及，用户和制造商都必须保持警惕，并实施最佳实践，从而保护无线网络免受潜在攻击。  
  
  
  
