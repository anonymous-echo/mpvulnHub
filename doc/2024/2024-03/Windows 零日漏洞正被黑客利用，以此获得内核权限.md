#  Windows 零日漏洞正被黑客利用，以此获得内核权限   
 网安百色   2024-03-03 19:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1QIbxKfhZo6TLA19pviaCFfbrwwfDkd81KlLEPjVUhNmpUTv82EJhu2QnczPmf7nU0UicVQhD3icJZp2vicGaWur0w/640?wx_fmt=gif "")  
  
  
被称为 Lazarus Group 的朝鲜威胁行为者利用 Windows AppLocker 驱动程序 （appid.sys） 中的漏洞作为零日漏洞来获取内核级访问权限并关闭安全工具，从而绕过嘈杂的 BYOVD（自带易受攻击的驱动程序）技术。  
  
Avast 分析师检测到此活动，他们立即将其报告给 Microsoft，从而修复了该漏洞，该漏洞现在被跟踪为 CVE-2024-21338，作为   
2024 年 2 月补丁星期二  
的一部分。但是，Microsoft并未将该漏洞标记为零日漏洞。  
  
Avast   
报告称  
，Lazarus 利用 CVE-2024-21338 在其 FudModule rootkit 的更新版本中创建了一个读/写内核原语，ESET 于 2022 年底首次记录了该版本。以前，rootkit   
滥用戴尔驱动程序  
进行 BYOVD 攻击。  
  
FudModule的新版本在隐身性和功能方面具有显着增强功能，包括用于逃避检测和关闭安全保护（如Microsoft Defender和CrowdStrike Falcon）的新的和更新的技术。  
  
此外，通过检索大部分攻击链，Avast 发现了 Lazarus 使用的一个以前未记录的远程访问木马 （RAT），该安全公司承诺在 4 月份的   
BlackHat Asia  
 上分享更多细节。  
## Lazarus 0 天漏洞利用  
  
该恶意软件利用了Microsoft的“appid.sys”驱动程序中的漏洞，该驱动程序是提供应用程序白名单功能的 Windows AppLocker 组件。  
  
Lazarus 通过操纵 appid.sys 驱动程序中的输入和输出控制 （IOCTL） 调度器来调用任意指针，诱骗内核执行不安全的代码，从而绕过安全检查。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljSE8yiak6JHIoRcXTQldm1X8iaYyD0u0wYbeHh5DVLD6xTPORa5ua1OwvDQVrwQe0m2zsnyEibXA7Lg/640?wx_fmt=png&from=appmsg "")  
  
**漏洞利用中使用的直接系统调用** （Avast）  
  
FudModule rootkit 内置在与漏洞利用相同的模块中，可执行直接内核对象操作 （DKOM） 操作，以关闭安全产品、隐藏恶意活动并在被破坏的系统上保持持久性。  
  
目标安全产品是 AhnLab V3 Endpoint Security、Windows Defender、CrowdStrike Falcon 和 HitmanPro 反恶意软件解决方案。  
  
Avast 在新的 Rootkit 版本中观察到了新的隐身功能和扩展功能，例如通过操纵句柄表条目来怀疑受保护进程轻量级 （PPL） 保护的进程、通过 DKOM 进行选择性和有针对性的中断、篡改驱动程序签名强制和安全启动等。  
  
Avast 指出，这种新的漏洞利用策略标志着威胁参与者内核访问能力的重大演变，使他们能够发起更隐蔽的攻击并在受感染的系统上持续更长时间。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljSE8yiak6JHIoRcXTQldm1Xic579tJr8AVMk8PVOUiaZywG7qafEeibcFYBJdKYiamC5ib5HqAl8o5BW2A/640?wx_fmt=png&from=appmsg "")  
  
**Rootkit 的主要功能是执行单个技术** （Avast）  
  
唯一有效的安全措施是尽快应用 2024 年 2 月的 Patch Tuesday 更新，因为 Lazarus 利用 Windows 内置驱动程序使得检测和阻止攻击特别具有挑战性。  
  
可  
在此处  
找到 YARA 规则，以帮助防御者检测与最新版本的 FudModule rootkit 相关的活动。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo6M60aLu6MNdy20VjcnyaGECz7d9mYhdbclWg7wibJsickPUrnmNyFcvsjSYUqq5OPVPEXfW1SwkXCw/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1QIbxKfhZo57Spb4ibrib8VUZd2ibdF9wHbvr4RwYJ4H2z6571icFIdSZXIpNH2YfW16ETwHh3ict3gtpW3W2fJqDmw/640?wx_fmt=gif "")  
  
长按添加关注，为您保驾护航！  
  
  
