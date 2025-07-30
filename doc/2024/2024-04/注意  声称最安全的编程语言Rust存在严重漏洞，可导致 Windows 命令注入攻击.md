#  注意 | 声称最安全的编程语言Rust存在严重漏洞，可导致 Windows 命令注入攻击   
 安全客   2024-04-10 16:47  
  
威胁行为者可以利用 Rust 标准库中的漏洞通过命令注入攻击 Windows 系统。该漏洞被追踪为CVE-2024-24576，是由于操作系统命令和参数注入中的弱点造成的，这可能允许攻击者在操作系统上执行意外且潜在的恶意命令。  
  
GitHub 已将此漏洞评为CVSS得分  
10/10的严重漏洞。未经身份验证的攻击者可以在无需用户交互的情况下以低复杂度的攻击远程利用此漏洞。  
  
Rust 安全响应工作组表示：“Rust 安全响应工作组收到通知，在 Windows 上使用命令 API 调用批处理文件（带有 bat 和 cmd 扩展名）时，Rust 标准库无法正确转义参数。能够控制传递给正在运行的进程的参数的攻击者可以执行任意 shell 命令而无需转义。如果您在 Windows 上使用不受信任的参数执行批处理文件，则此漏洞非常严重。这不会影响任何其他平台或应用程序。“  
  
如果程序代码或其依赖项之一使用不受信任的参数调用并执行批处理文件，则 Windows 上 1.77.2 之前的所有 Rust 版本都会受到影响。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Ok4fxxCpBb6ia29VKTtic20o7zmuUWSn1bnOAEI3UK0Dnn3lARcj9IruaS8eKgI88gsL7uiaVSShNGqQrPlhaGUMw/640?wx_fmt=jpeg&from=appmsg "")  
  
Rust 安全团队在处理 cmd.exe 的复杂性时面临着重大挑战，因为他们无法找到在所有情况下都能正确转义参数的解决方案。  
  
因此，他们必须提高失控代码的可靠性并修改 Command API。如果命令 API 在创建进程时无法安全地转义参数，则会返回 InvalidInput 错误。  
  
Rust 安全响应工作组补充道：“如果您自己实现转义或仅处理受信任的输入，那么在 Windows 上您还可以使用 CommandExt::raw_arg 方法来绕过标准库转义逻辑。”  
  
今年 2 月，白宫国家网络安全总监办公室 (ONCD) 敦促科技公司采用 Rust 等内存安全编程语言。最终目标是通过最大限度地减少内存漏洞的数量来提高软件安全性。  
  
  
**来**  
  
**领**  
  
**资**  
  
**料**  
  
**【免费领】**  
**网络安全专业入门与进阶学习资料，轻松掌握网络安全技能！**  
  
****![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb4N2VUg5icoU6eUKJ14GUznZiaB5GRRWfKMn3k9mc03BRO6zB0LoPzN4UFb1vIKXwibvsEkPLy6ozj8Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
