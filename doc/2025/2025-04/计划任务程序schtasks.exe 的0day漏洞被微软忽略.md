#  计划任务程序schtasks.exe 的0day漏洞被微软忽略   
 独眼情报   2025-04-18 01:15  
  
## 引言  
  
schtasks.exe二进制文件是Windows中任务调度器服务的核心组件，使用户能够自动安排和管理任务。  
  
作为Windows任务调度框架的一部分，schtasks.exe为系统管理员和普通用户提供了通过自动执行任务来简化操作的能力，从简单程序到复杂的系统维护过程。  
  
在网络安全领域，schtasks.exe是一个强大的工具，可用于恶意活动，与MITRE ATT&CK框架中的持久性、权限提升、执行和横向移动战术相符。  
  
本博客披露了我们发现的新漏洞和技术，包括UAC绕过、元数据中毒、任务事件日志溢出和安全事件日志覆盖，将该技术添加到新的战术类别"防御规避"中，并加强了关于提权机制滥用的"权限提升"类别。  
## 摘要  
  
在Microsoft Windows中发现了一个UAC绕过漏洞，使攻击者能够绕过用户账户控制提示，允许他们在没有用户批准的情况下执行高权限(SYSTEM)命令。通过利用这个弱点，攻击者可以提升他们的权限并以管理员权限运行恶意负载，导致未授权访问、数据窃取或进一步的系统入侵。  
  
当攻击者使用批处理登录而非交互式令牌创建任务时，就会发生这种情况。任务调度器服务模拟用户，授予运行进程最大允许权限，将其从任何完整性级别提升到最高可用级别。  
  
此外，还发现了两种新的防御规避技术。第一个漏洞允许攻击者利用任务元数据中**Author**  
字段的无限缓冲区，该字段随后由Windows事件日志处理，覆盖整个日志描述。  
  
第二个漏洞基于第一个漏洞。由于事件日志中的缓冲区由用户控制，单个溢出的日志创建占用8KB。通过循环创建任务2280次，事件日志安全文件(Security.evtx)的默认大小被溢出，使威胁行为者能够清除日志。  
## 目录  
- 基于凭证的UAC绕过(最高级别)  
  
- RunLevel HIGHEST – 访问拒绝绕过  
  
- 使用批处理登录的基于凭证的模拟  
  
- 计划任务元数据中毒  
  
- 任务事件日志中毒 – CWE-117  
  
- 任务事件日志溢出 – CWE-117, CWE-400  
  
- 安全日志饱和 – CWE-117, CWE-400  
  
## 任务调度器UAC绕过  
  
规格：  
- 需要本地管理员凭证  
  
- 绕过最高UAC级别(始终通知)  
  
- 可提升至高或SYSTEM完整性级别  
  
作为标准用户使用XML任务文件创建计划任务时，我发现该功能需要凭证才能工作。  
  
提供带有 **/ru**  
 和 **/rp**  
 的凭证后，我收到以下错误消息：  
  
![使用schtasks.exe的/ru和/rp标志时的命令行错误消息](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiad1fW7m0pUpsHThtNrdvVESEFHcoOamGVpTesdUO6oJ9CPCnLUwaiadA/640?wx_fmt=png&from=appmsg "")  
  
使用schtasks.exe的/ru和/rp标志时的命令行错误消息  
  
使用XML文件创建任务时，需要 **/ru**  
 和 **/rp**  
 标志才能允许服务模拟任务主体。  
  
实际上，由_svchost.exe_托管的_taskhostw.exe_进程是以SYSTEM身份运行的。当服务模拟用户时，会为任务运行启动高完整性上下文。命令在任务创建后执行时，会创建以下日志：  
  
![显示凭证调度后以SYSTEM完整性创建的任务的事件日志条目](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiaaPibub9Nl44wTofNH5ILs7nib8biaYUn7SAuuh2kV6WuuBjMBnnocnyuw/640?wx_fmt=png&from=appmsg "")  
  
显示凭证调度后以SYSTEM完整性创建的任务的事件日志条目  
  
绕过最高级别的UAC：  
  
![绕过最高级别的UAC](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEia5WzGNyGico2dC0ABlEobOonyTVUzEXxwWk2G2Y7Et5TiaLEsD4QVaVvQ/640?wx_fmt=png&from=appmsg "")  
  
绕过最高级别的UAC  
  
**示例：**  
  
![演示使用计划任务以提升权限运行的UAC绕过的屏幕截图](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiaicYXVicOvXCBbBEvgVh8ydwudMSoxic5BlxDYbczxLd44Gk2KONpTBVuA/640?wx_fmt=png&from=appmsg "")  
  
演示使用计划任务以提升权限运行的UAC绕过的屏幕截图  
  
密码注册（批处理登录）和默认注册（交互式令牌）之间的区别是身份验证方法，如MSDN中所述。它将决定要运行的进程的完整性级别。  
  
![密码注册（批处理登录）和默认注册（交互式令牌）之间的区别是身份验证方法](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiavPhguibKoLNiaQR7qcEteIIIpepEbrRP3w5oD9hjT4ZPLIN3fxGYcNTA/640?wx_fmt=png&from=appmsg "")  
  
密码注册（批处理登录）和默认注册（交互式令牌）之间的区别是身份验证方法  
  
唯一的限制是知道密码。  
  
因此，不应忽视一些方法。  
  
第一种方法是从客户端获取NTLMv2挑战到SMB服务器，并在离线模式下破解它。如果可以使用适当的单词列表破解密码，则可以使用这些凭证。  
  
**示例：**  
  
首先使用当前会话对SMB服务器进行身份验证：  
  
![首先使用当前会话对SMB服务器进行身份验证](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiallALvcQFl8bNqMIqztn9GTJGv2IuqLqn9rDlGc4aHrm59ecwWlamLA/640?wx_fmt=png&from=appmsg "")  
  
首先使用当前会话对SMB服务器进行身份验证  
  
然后从服务器端获取NTLMv2哈希。  
  
![然后从服务器端获取NTLMv2哈希](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiaYuZhS4DD8z4G0EkhoicFSV6E4hF9BFtgNU2zev6jiayWJbha0iaqGwT0Q/640?wx_fmt=png&from=appmsg "")  
  
然后从服务器端获取NTLMv2哈希  
  
最后使用单词列表和破解工具（下面是_hashcat_）破解它。密码已破解。  
  
![最后使用单词列表和破解工具（下面是hashcat）破解它。密码已破解](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiamC1s1CJcHZpUvWczRrE2XVulcrCrnW7Lvvdvf17dicpN4mIibIEoWppA/640?wx_fmt=png&from=appmsg "")  
  
最后使用单词列表和破解工具（下面是hashcat）破解它。密码已破解  
  
另一种方法可以使用明文存储的密码，利用像非常有趣的CVE-2023-21726这样的漏洞，这是OOBE进程中发现的权限提升漏洞，将本地管理员凭证以明文形式存储在任何人都可读的HKU注册表值中。有关更多详细信息，请阅读gmo-cybersecurity报告。  
  
密码存储在：  
  
HKEY\_USERS\\.DEFAULT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OOBE\\Broker\\LocalSystemAuthBuffer  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiadmiaKuNHaYwBvicNUt2Pj0JQA01HWfBFRBHUvZbJaETufcQHaVA0INicA/640?wx_fmt=png&from=appmsg "")  
## RunLevel HIGHEST – 访问拒绝绕过  
  
同样，从中等完整性提升到高完整性后，对于我们的任务以SYSTEM身份运行来说还不够。使用批处理登录模拟管理员用户并不保证能够以SYSTEM身份运行，因为它本来就不打算以提升的方式运行。如果我们在方法中添加**/RL HIGHEST**标志，我们会得到_访问拒绝_。  
  
但要解决这个问题，我们可以通过创建临时任务将我们的权限提升到**高**  
，使用前面提到的UAC绕过，然后从内部创建我们的SYSTEM主任务：  
  
![使用临时计划任务进行SYSTEM执行的提升任务创建序列](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiahVNjpvOHicrZy04xuGdvk5EgWAVzRibd7R0LzapgGib16D7JxaWia119gA/640?wx_fmt=png&from=appmsg "")  
  
使用临时计划任务进行SYSTEM执行的提升任务创建序列  
## 使用批处理登录的基于凭证的模拟  
  
由于SYSTEM执行了运行任务的主体用户的模拟，被模拟的用户必须具有批处理登录权限。  
  
这一点不是漏洞，而更多是一个功能，以及执行横向移动和获取Windows和Active Directory利用的枢轴选项的策略。  
  
默认授予批处理登录的组有：  
- 管理员  
  
- 备份操作员  
  
- 性能日志用户  
  
任何低权限用户都可以利用**schtasks.exe**  
二进制文件并模拟这些组中具有已知密码的成员，以获得最大允许权限。  
  
以下解释揭示了有关这些组的额外信息。  
### 管理员  
  
对于管理员组，通过使用本地管理员密码，任何低权限用户都可以使用前面提到的**schtasks**  
方法（参见上一部分）模拟SYSTEM权限。  
  
为了使其工作，我们可以像之前在UAC上所做的那样操作 - 从中等到系统。请注意，我们以低权限用户身份运行，因此无法查询我们自己创建的SYSTEM任务。但我们可以直接从**System32\Tasks**  
查询文件的XML。  
  
![通过模拟本地管理员创建的SYSTEM级别任务的屏幕截图](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiaZ09yRRnwUw3G9HQq412IqfhDWLXv6RdXibwVzzekmyOlgZUgp2Y1QcQ/640?wx_fmt=png&from=appmsg "")  
  
通过模拟本地管理员创建的SYSTEM级别任务的屏幕截图  
### 性能日志用户  
  
该组以臭名昭著的CVE-2024-38061和优秀的Decoder's Blog关于他的发现的帖子而闻名。  
  
该漏洞可能允许**分布式COM用户**  
和**性能日志用户**  
的成员远程启动、激活和分发COM对象，通过强制+NTLM中继攻击（Bloodhound）危及登录在DC上的用户。  
  
修补后，上述组的用户似乎仍然拥有提到的权限，并且可以在本地利用它们，但不再启用远程登录权限。请注意，由于它具有批处理登录权限，因此可以使用_schtasks_登录。  
### 备份操作员  
  
授予备份SAM、SECURITY和SYSTEM注册表配置单元的权限，导致本地/域PE和DCSYNC。  
  
来源：BackupOperatorToDA，impacket-reg。  
  
在备份操作员组用户的常规会话上下文中运行时，我们无法对敏感文件和注册表配置单元执行备份。  
  
在典型情况下会发生这种情况：一个持久的基于schtasks的反向shell，在备份操作员用户的上下文中运行，带有其**InteractiveToken**  
。  
  
![一个持久的基于schtasks的反向shell，在备份操作员用户的上下文中运行，带有其InteractiveToken](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiaElXs9tR3s53D6jJ4EZChk2WR18bxX5ffjGO4kozB1WaGje2sFKy4ug/640?wx_fmt=png&from=appmsg "")  
  
一个持久的基于schtasks的反向shell，在备份操作员用户的上下文中运行，带有其InteractiveToken  
  
这将导致_访问拒绝_错误，因为需要提升的会话。注意，这里谈到的提升会话是指为当前用户启用的最大权限，而不是本地管理员权限。  
  
在这种情况下，我们使用_schtasks.exe_的批处理登录用户模拟很有意思。  
  
在同一用户下运行schtasks时，我们从任务调度器服务获得了授予我们用户的以下权限：  
  
![在同一用户下运行schtasks时，我们从任务调度器服务获得了授予我们用户的以下权限](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiaLl0y8vpQKGfrbiaCxeGKCIBvbphv3yp1miaO1icKtKSibSiagr6xJtlZWew/640?wx_fmt=png&from=appmsg "")  
  
在同一用户下运行schtasks时，我们从任务调度器服务获得了授予我们用户的以下权限  
  
成功了。让我们实现它并从计划任务中备份它。结果成功！  
  
![通过任务调度器服务显示授予的权限的任务属性](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiapiaoL0593WzLiby7aIBbGHCkHQwN7WKeict3pZtbOJf1LzbAwtT6sqROw/640?wx_fmt=png&from=appmsg "")  
  
通过任务调度器服务显示授予的权限的任务属性  
## 计划任务元数据中毒  
### 本地中毒  
  
使用**InteractiveToken**  
身份验证方法从命令行注册计划任务时，运行用户上下文信息会保存到相同的计划任务元数据中。  
  
然而，使用带有XML文件的批处理登录身份验证方法时，元数据是根据XML标签保存的，而不是根据当前运行用户信息保存的。  
  
例如，如果用户**low**  
创建以SYSTEM权限运行的管理员任务，它可以修改任务元数据**Author**  
为**Administrator**  
而不是**low**  
。  
  
实质上，可以在**Author**  
标签中写入任意数据。  
  
让我们创建一个基本任务，导出其XML并用不同的元数据重新创建它。  
  
schtasks /create /tn poc /tr calc.exe /sc minute /mo 10 /f  
  
schtasks /query /xml /tn poc > poc.xml  
  
在更改任何内容之前，我们可以观察任务的常规元数据状态：  
  
![显示低权限用户作为作者的默认任务元数据XML](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEia8fcbtB7vUq2iaBhPw6QKB7CBxQPS9pgAAW6KTiau9geL1FVqgAd0lJwA/640?wx_fmt=png&from=appmsg "")  
  
显示低权限用户作为作者的默认任务元数据XML  
  
现在在重新导入之前更改我们文件的XML任务。  
  
![显示管理员列为作者的修改后XML](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiavpz39JdiaUgcXOfdoYAjSamhuTeYX7MqiamYpL5ibepgLcRRibnfjnJCibg/640?wx_fmt=png&from=appmsg "")  
  
显示管理员列为作者的修改后XML  
  
我们删除并重新创建任务以观察结果。  
  
schtasks /delete /tn poc /f  
  
schtasks /create /tn poc /xml poc.xml /ru low /rp Password2  
  
任务元数据已更改。  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEia2OVgrygHNtSI6dyKK5rFaia9GPWHfv8etSed7O7gqAU4A0uzCJMBYfg/640?wx_fmt=png&from=appmsg "")  
  
image  
### 远程中毒  
  
我们还可以通过RPC使用任务调度器服务创建具有中毒元数据的任务。  
  
由于任务的XML是通过RPC发送的，因此可以修改相同的标签。例如，我们可以尝试使用众所周知的impacket-atexec脚本。  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiaBnU8kmEBdRmiczJDIPR7YJABzgQZbSgoH3j8P53FUZIxLlZ0j9iaNpUw/640?wx_fmt=png&from=appmsg "")  
  
image  
  
更改作者的值，使其看起来像可信的东西。比如**TrustedInstaller**  
。  
  
不要忘记修补impacket脚本，不要在之后删除任务，因为我们希望查看它已注册而不是隐藏。  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEia3WfGxV2sBaHhSC0SJkNcQcJQrefkcWjrXlfva0M6soV8dgkghPLBRQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
任务信息：  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiaNQWia6kFkzhrRwj9xiblc5Oxn0LibibW56E9NwWFplK5kkxwYoLljSZU2w/640?wx_fmt=png&from=appmsg "")  
  
image  
  
查看procmon，显示这些元数据也存储在HKLM中。我立即猜测安全产品可能会访问这些元数据以检查任务的合法性，这可能导致大多数安全产品出现安全问题。  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiaWKaEEianmp6aykbl38aoyUlickXiak7cbr1xXpBt6HgZWXPf4WKOSFKFw/640?wx_fmt=png&from=appmsg "")  
  
image  
  
向MSRC报告后，我得到以下回答：  
  
"我们认为您报告的是，当您加载XML任务时，它似乎是由XML中指定的用户创作的，而不是由该用户执行的 […]  
  
我们还认为您误解了'作者'的用途，实际上整个'RegistrationInfo'块 […]  
  
值得注意的是，文档并没有说它是用于安全目的，而是用于存储有关任务的一般详细信息。  
  
我们认为这份报告更像是一种网络钓鱼攻击，用户会将其视为管理员创建的任务并信任它以执行"  
  
好的！这些元数据和**RegistrationInfo**  
块仅存在于"存储一般详细信息"。  
  
自然地，我寻找使用和依赖这些元数据的产品和功能，而且我不必看得太远。  
## 任务事件日志中毒  
  
事件日志中的任务创建LogID为4698。更多信息在MSDN。  
  
如我们所见，任务的XML被注册为日志记录为**任务信息**  
。  
  
![显示任务创建的事件日志ID 4698，在任务信息下列出了XML任务详细信息](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiaNgObQSE0fDiapYKVboib9kRdDuYacedDibF5LC6Ce9VXMicn4m0MiczvtFg/640?wx_fmt=png&from=appmsg "")  
  
显示任务创建的事件日志ID 4698，在任务信息下列出了XML任务详细信息  
  
除了毒化任务的HKLM条目外，我们还可以毒化关于它的事件日志。我使用用户**Cymuser**  
创建了一个任务，并将作者更改为**Administrator**  
。  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiaCiblWrKicmTTYRb9KlYEgnUA7rQ2beEoU93kAIFejUFKCx6rm4cPgicvg/640?wx_fmt=png&from=appmsg "")  
  
image  
  
这是一个CWE-117漏洞，但说实话这并不那么有趣。我感觉**author**  
 XML可写值还有更有趣的东西。  
## 任务事件日志溢出  
  
如引言中所述，任务调度器主要用于执行和后门。那么，在任务日志中最想隐藏什么？负载。  
  
我发现一方面，任务注册过程不限制**Author**  
标签值的缓冲区大小。另一方面，4698事件日志中包含整个XML任务日志描述符的**TaskContent**  
条目有约3500字节的限制。  
  
这基本上意味着创建一个名为A*3500的作者的任务将覆盖整个XML日志描述**TaskContent**  
，包括我们的负载。  
  
我创建了一个带有充满内容的作者缓冲区的XML文件。  
  
![使用过大的作者标签覆盖事件日志4698 TaskContent并隐藏负载的XML任务文件](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiaCiaxzROEMSpiaKGEGubFicQdHBtVO4OC4RoiazjZarfibnU64VbBROkTuyg/640?wx_fmt=png&from=appmsg "")  
  
使用过大的作者标签覆盖事件日志4698 TaskContent并隐藏负载的XML任务文件  
  
然后，我注册了任务。  
  
schtasks /create /tn poc /xml poc.xml /ru Cymuser /rp Password1  
  
然后，见证奇迹：  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiar0AzUspkzadNFvPQlJOVkVaJxib0ZQISHygqD80LoE0PQib0PqSCeHpg/640?wx_fmt=png&from=appmsg "")  
  
image  
  
正常的日志会如下所示  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiaiaia2DvZFBGOWk37Hibmoogz07HoSMpBpYic39EGQm0ORhvXBiaSBEp8YqQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
当直接从PowerShell查询事件时，我们可以确认它被覆盖了，并且这不是显示错误。  
  
Get-WinEvent -FilterHashtable @{logname='security'; id=4698} \| Select-Object -Property TimeCreated, Id, @{N='Detailed Message'; E={$\_.Message}} \| Sort-Object -Property TimeCreated \| Select-Object -ExpandProperty 'Detailed Message'  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiaicYBt4L8eQDfGAgwZSPBibNib30k3oX3UIII7bo9te3xiaIKTsuradic7Fw/640?wx_fmt=png&from=appmsg "")  
  
image  
  
如前所述，XML也是通过RPC发送的，任务调度器服务也不执行检查。**因此，XML日志也可以远程覆盖。**  
### 事件日志溢出 – 远程方法  
  
让我们修改通过**impacket-atexec**  
脚本的RPC发送的负载。  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiaELmFsSiaoHXNqdwh2k4wwVXcSkialxv3UnQdgLGnq6ek1czX84Cz2qIQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
运行脚本。  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiawX6312tBez10al9X3Vzv8GKw7NicZ8018z4iauDAx45mbfTS0n54Pzfg/640?wx_fmt=png&from=appmsg "")  
  
image  
  
最后检查日志。  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiahn81fZiaMq2z2OXHhUPIaNiaYiay67POAKmupWgDVQIYCBxGUd30ooxIA/640?wx_fmt=png&from=appmsg "")  
  
image  
  
是的，它正在工作。  
  
不要忘记，只有当主体具有批处理登录权限时，任务才会运行，并且基于XML文件注册任务需要密码。我为不同场景映射了可能性。  
  
![批处理登录权限](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiakCiamEcTZ72rTA8BTwibLydjvaC0dP4xr6xUvpIibg1SPZz0KMRKhvLsg/640?wx_fmt=png&from=appmsg "")  
  
批处理登录权限  
  
注意**运行用户**  
和**其他用户**  
类别之间的区别。  
  
当批处理登录用户在没有密码的情况下创建任务时，它自己的交互式令牌会记录它，并且任务被注册并运行。但是当任务运行时，权限不会被提升，因为SYSTEM不执行任何模拟。  
  
我还发现，说批处理登录权限是从运行用户上下文注册XML任务所必需的并不准确。它也可以是**SeImpersonate**  
权限。  
  
例如，如果管理员账户从XML文件中为自己创建任务而不使用密码，则相同的shell完整性将应用于任务运行。  
  
当由任何用户创建任务时模拟带密码的批处理登录用户，权限将被提升，因为SYSTEM正在执行模拟。  
  
当特权用户为另一个用户作为主体创建任务时，不需要密码，并且任务将以中等完整性运行。  
## 安全日志饱和  
  
所以，我们可以使用低权限用户和密码注册一个5KB的XML文件任务，**该任务不会运行**  
。但是日志仍然被注册，带有3500字节的缓冲区。这闻起来像我们可以覆盖整个Security.evtx数据库，因为它默认配置为最多包含20MB的日志。  
  
我创建了一个4行批处理脚本来完成这项工作：  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEia8sPe9n3Whxxv9fQMelvRPhVtVNvkutcIRjicb8HARdQrCiabPibicCRqHA/640?wx_fmt=png&from=appmsg "")  
  
image  
  
运行1分15秒，你就会看到日志完全被覆盖。  
  
**第一条日志，03:54:23。**  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiajOuH32yiaITgBQgGwv2vPjBG8UlISGK02StXo6InnononsPOoKdic5VQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
**最后一条日志，03:55:38。**  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiauibpfcrBcA9DLWIHzsDj6eZklu27gpwlyy2p9jgsd8icaQC2ibPjqFGWg/640?wx_fmt=png&from=appmsg "")  
  
image  
  
不，这不是玩笑。20MB的日志确实被覆盖了。  
  
该漏洞之所以有效，是因为我们在这里结合了3个链式漏洞：  
- 基于XML的任务注册中Author标签的不受控制的缓冲区  
  
- 任务日志记录的可信用户输入，导致任务长度超重  
  
- 不受控制的任务注册流，垃圾邮件轰炸安全事件数据库  
  
计算垃圾邮件日志的大小和安全事件日志文件（20480 Kb）的接受默认大小后，我调整了脚本以精确运行以覆盖日志：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiazzjgo5rOYH3icO02tJroN92r62lSicgrIickcJr5dumTaO9vR2Oo9BKgA/640?wx_fmt=png&from=appmsg "")  
  
为了证明这一点，让我们清除日志。应该出现第一个也是唯一的1102**日志清除**  
事件。然后运行脚本并重新检查1102事件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSN3uP2AyzXcmk1E0TrdFEiayGsoydWmIUaHmxXlicqlRLc9Cw4n8crcu7hicAkCxibyMDUeOYpKsz7Iw/640?wx_fmt=png&from=appmsg "")  
## 结论  
  
任务调度器是一个非常有趣的组件。任何人都可以访问它来创建任务，由SYSTEM运行的服务启动，在权限、进程完整性和用户模拟之间左右摇摆。  
  
第一个报告的漏洞不仅仅是UAC绕过。它远不止于此：本质上，它是一种从CLI使用密码模拟任何用户并在任务执行会话上获得最大授予权限的方式，使用 **/ru**  
 和 **/rp**  
标志。  
  
从元数据中毒，到事件日志中毒，我们发现如何溢出单个日志的**TaskContent**  
条目，甚至如何溢出整个安全事件文件。  
  
MSRC 并未将任何一份报告视为漏洞。  
>   
> 原文地址：https://cymulate.com/blog/task-scheduler-new-vulnerabilities-for-schtasks-exe/  
  
  
  
