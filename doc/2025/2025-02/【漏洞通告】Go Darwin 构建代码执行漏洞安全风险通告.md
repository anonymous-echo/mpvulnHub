#  【漏洞通告】Go Darwin 构建代码执行漏洞安全风险通告   
 嘉诚安全   2025-02-09 01:00  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Go Darwin 构建代码执行漏洞，漏洞编号为：  
CVE-2025-22867。  
  
  
Go（也称为 Golang）是由 Google 开发的开源编程语言，旨在提供高效、简洁和易于并发编程的功能。它具有垃圾回收、内存安全和强大的并发支持（goroutines）。Go 语言广泛应用于服务器端开发、网络编程和云计算等领域，特别适合需要高性能和可扩展性的应用。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞  
。该漏洞影响Go 1.24rc2版本的漏洞，存在于Darwin（macOS）平台上。该漏洞源于Go构建过程中，CGO模块与Apple版本的ld（链接器）配合使用时，滥用#cgo LDFLAGS指令中的@executable_path、@loader_path或@rpath等特殊路径值，可能导致任意代码执行。攻击者可通过精心构造的Go模块触发此漏洞，在构建过程中执行恶意代码，从而危及系统安全。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
Go 1.24rc2  
  
  
**处置建议**  
  
  
  
  
  
  
  
  
1.升级版本  
  
升级至 Go 1.24rc3 或更高版本。  
  
下载链接：  
  
https://github.com/golang/go/tags/3.2   
  
2.通用建议  
  
定期更新系统补丁，减少系统漏洞，提升服务器的安全性。  
  
加强系统和网络的访问控制，修改防火墙策略，关闭非必要的应用端口或服务，减少将危险服务（如SSH、RDP等）暴露到公网，减少攻击面。  
  
使用企业级安全产品，提升企业的网络安全性能。加强系统用户和权限管理，启用多因素认证机制和最小权限原则，用户和软件权限应保持在最低限度。  
  
启用强密码策略并设置为定期修改。  
  
3.参考链接  
  
https://go.dev/cl/646996  
  
https://nvd.nist.gov/vuln/detail/CVE-2025-22867  
  
https://go.dev/issue/71476  
  
https://pkg.go.dev/vuln/GO-2025-3428  
  
https://groups.google.com/g/golang-dev/c/TYzikTgHK6Y  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrLftD6NkjwibfelSiaDSA8r1TnUsJzNguibKyupaNJsEgic28FoR6ROXp2XFyNticXHhFOibN80WcAKXvHw/640?wx_fmt=gif&from=appmsg "")  
  
