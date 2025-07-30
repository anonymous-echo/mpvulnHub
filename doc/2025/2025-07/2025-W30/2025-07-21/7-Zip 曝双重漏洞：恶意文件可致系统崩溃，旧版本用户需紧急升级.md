> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458597663&idx=2&sn=7653176976d03c02843744f4f628e2ff

#  7-Zip 曝双重漏洞：恶意文件可致系统崩溃，旧版本用户需紧急升级  
看雪学苑  看雪学苑   2025-07-21 09:59  
  
近日，研究人员披露了全球广泛使用的开源文件归档工具 7 - Zip 中存在的两个新漏洞，编号分别为 CVE - 2025 - 53816 和 CVE - 2025 - 53817 ，影响 7 - Zip 25.0.0 之前的版本。虽暂无法实现远程代码执行，但会引发内存损坏与拒绝服务（DoS）风险，CVSSv4 基础评分为 5.5 ，属中等严重程度，处理不可信归档文件的用户需格外关注。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EIxUERyFibtQeU9UiaiapHnbvia9nNORa047KgOgolEfCerc708lTfzX4IXDdM8oHVh7icAWmIibDLEwicg/640?wx_fmt=png&from=appmsg "")  
  
  
第一个漏洞（CVE - 2025 - 53816 ）存在于 7 - Zip 对 RAR5 归档的处理流程。提取文件时，软件会依据攻击者可控值，错误计算需在内存中置零的字节数。CVE 描述指出，“在 25.0.0 之前版本的 7 - Zip 中，RAR5 处理程序里堆缓冲区外写入零，可能导致内存损坏和拒绝服务” 。这源于涉及 _lzEnd 变量的算术运算错误，该变量依赖归档中前一项的大小，易受攻击者影响。虽无证据表明可用于代码执行，但堆内存损坏会致程序不稳定或崩溃 。  
  
  
第二个漏洞（CVE - 2025 - 53817 ，原文此处编号疑似笔误，应为 53817 ）影响 7 - Zip 对复合文档格式文件的提取支持。攻击者构造畸形复合文档文件，可使 7 - Zip 应用意外崩溃，打乱工作流程，在自动化文件处理环境中还可能引发服务中断 。  
  
  
目前，7 - Zip 最新版本 25.0.0 已修复这两个漏洞。强烈建议用户立即更新，以保障压缩归档文件（尤其是来自不可信、未知来源的文件 ）处理安全，避免遭受漏洞带来的不良影响 。  
  
  
  
资讯来  
源：  
securityonline  
  
转载请注明出处和本文链接  
  
  
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
  
