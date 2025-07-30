#  漏洞预警 | JetBrains IntelliJ IDE信息泄露漏洞   
浅安  浅安安全   2024-06-22 08:30  
  
**0x00 漏洞编号**  
- # CVE-2024-37051  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
JetBrains IntelliJ是一个集成开发环境平台，支持Java、Kotlin、Scala、Groovy、Python、JavaScript、TypeScript、Go、Rust等多种编程语言。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUCvWsrh7R7ibajz8fLo9iatwsqZny0VUuyOr3ZJPnnLHchvDQcUP5iaYQjFq6RXymIcib6onN6SzOSXA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**CVE-2024-37051**  
  
**漏洞类型：**  
信息泄露  
  
**影响：**  
获取敏感数据  
  
**简述：**  
JetBrains IntelliJ平台上的JetBrains GitHub插件中存在信息泄露漏洞，当在IDE中使用GitHub拉取请求功能时可能导致将访问令牌暴露给第三方主机，导致敏感信息泄露。  
###   
  
**0x04 影响版本**  
- Aqua：2024.1.2  
  
- CLion：2023.1.7, 2023.2.4, 2023.3.5, 2024.1.3, 2024.2 EAP2  
  
- DataGrip：2024.1.4  
  
- DataSpell：2023.1.6, 2023.2.7, 2023.3.6, 2024.1.2  
  
- GoLand：2023.1.6, 2023.2.7, 2023.3.7, 2024.1.3, 2024.2 EAP3  
  
- IntelliJ IDEA：2023.1.7, 2023.2.7, 2023.3.7, 2024.1.3, 2024.2 EAP3  
  
- MPS：2023.2.1, 2023.3.1, 2024.1 EAP2  
  
- PhpStorm：2023.1.6, 2023.2.6, 2023.3.7, 2024.1.3, 2024.2 EAP3  
  
- PyCharm：2023.1.6, 2023.2.7, 2023.3.6, 2024.1.3, 2024.2 EAP2  
  
- Rider：2023.1.7, 2023.2.5, 2023.3.6, 2024.1.3  
  
- RubyMine：2023.1.7, 2023.2.7, 2023.3.7, 2024.1.3, 2024.2 EAP4  
  
- RustRover：2024.1.1  
  
- WebStorm：2023.1.6, 2023.2.7, 2023.3.7, 2024.1.4  
  
**0x05****POC**  
  
  
https://github.com/LeadroyaL/CVE-2024-37051-EXP  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.jetbrains.com/  
  
  
  
