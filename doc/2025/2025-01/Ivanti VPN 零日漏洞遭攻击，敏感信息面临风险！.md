#  Ivanti VPN 零日漏洞遭攻击，敏感信息面临风险！   
Hankzheng  技术修道场   2025-01-15 08:14  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wWBwsDOJT4ibibFudvEuGBeT9mn4DzE0Pqvxl2YEX9r9zKwVaWIJM9QBjIHGMTlu7JEtIl3womD9Yvu8ibkV8KYXQ/640?wx_fmt=png&from=appmsg "")  
  
各位朋友们，速速关注！Ivanti Connect Secure VPN 设备爆出严重零日漏洞 (CVE-2025-0282)，黑客已开始利用该漏洞进行攻击，并部署名为 "Dryhook" 和 "Phasejam" 的新型恶意软件！  
  
**漏洞详情**  
  
该漏洞是一个堆栈缓冲区溢出漏洞，影响 Ivanti Connect Secure、Policy Secure 和 Neurons for ZTA  等多个产品线的旧版本。黑客可利用该漏洞远程执行代码，完全控制受影响设备。  
  
**攻击手段**  
- 攻击者首先通过 VPS 或 Tor 网络隐藏身份，发送 HTTP 请求探测设备版本。  
  
- 随后利用 CVE-2025-0282 漏洞入侵设备，禁用安全防护措施，修改系统配置，并植入恶意软件。  
  
- 攻击者部署 "Phasejam"  dropper，释放 Web shell，执行任意命令，并修改升级脚本以维持持久性感染。  
  
- 此外，攻击者还使用 "Spawn" 工具包，包括隧道工具、SSH 后门和日志篡改工具等。  
  
- 为了躲避 Ivanti 的完整性检查工具 (ICT)，攻击者会重新计算恶意文件的哈希值，伪造签名。  
  
**攻击目标**  
  
攻击者的主要目标是窃取 VPN 设备中的敏感信息，包括 VPN 会话、cookie、API 密钥、证书和用户凭据等。他们会将窃取的数据打包并上传到公共服务器进行提取。  
  
**新型恶意软件**  
  
本次攻击中发现的 "Dryhook" 和 "Phasejam" 恶意软件此前从未被发现，目前尚未与任何已知 APT 组织关联。其中 "Dryhook" 可用于捕获用户登录凭据。  
  
**安全建议**  
- Ivanti 官方已发布补丁，强烈建议所有用户立即升级到最新版本 (Connect Secure 22.7.R2.5)。  
  
- 建议即使 ICT 扫描未发现异常，也应执行恢复出厂设置并重新配置设备。  
  
- Mandiant 已发布攻击指标 (IoC) 和 YARA 规则，可用于检测相关恶意活动。  
  
**形势严峻**  
  
据统计，Ivanti 发布补丁时仍有超过 3600 台设备暴露在互联网上，目前仍有约 2800 台设备未修复，面临巨大安全风险。  
  
请各位管理员务必高度重视，及时采取措施，保护您的网络安全！  
  
