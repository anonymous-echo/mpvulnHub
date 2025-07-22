> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU2OTcxNjE4Mw==&mid=2247486072&idx=1&sn=ce36707ae3974cc872b4432a8edf2dee

#  "银狐"新进展：多Rootkit配合，内核InfinityHook+穿透读写  
原创 ch  鹰眼威胁情报中心   2025-07-21 12:52  
  
# 攻击背景  
  
近期金山毒霸安全团队接到多位用户求助，发现在未操作电脑的情况下，鼠标自行移动操作微信，群发多个病毒文件。安全工程师介入分析后发现这是新型"银狐"远控木马。之后的溯源排查中发现病毒来源于搜索引擎推广，攻击者批量投放多个仿冒下载页涉及 CMake、Chrome浏览器、快连 VPN、Gmail邮箱客户端等软件，目标群体广泛。本次样本在隐蔽性上进一步提升，在运行中释放多个RootKit驱动程序，利用InfinityHook内核hook技术挂钩系统进程遍历Api达到隐藏自身进程的目的，为了进一步持久化使用内核读写穿透移除或禁用安全软件在内核的回调函数，达到致盲AV和EDR等安全软件。应用层最终加载”winos“远控木马来操控用户设备。  
  
### 执行流程：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJic77ibLXlJ84vqmM0ynLtJfh8JIEvhWiaRrNeA1EV5FtdiaDN1l2y8RcwA/640?wx_fmt=png&from=appmsg "")  
###   
### 1.核心驱动  
  
####   rwdriver.sys  
  
  
功能为读写任意地址数据，进行拷贝覆盖。驱动使用的为泄露的“中兴通讯股份有限公司”过期签名  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJQbtHznrJUSJp8EkHibDhO8R36ia5Dianw8MngSaCibEDfKDgG6AROjWulQ/640?wx_fmt=png&from=appmsg "")  
  
Pdb符号显示这是一个在桌面编译的 rwdriver开源内核穿透读写项目。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJMUlhfiaRv0HbP3zuicKEnialebZVCzc5icqibAoRS3CUg3cM2BiaclNCrCZQ/640?wx_fmt=png&from=appmsg "")  
  
驱动接收控制码请求后，对指定地址进行读写操作  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJXe2X2IQBHWSCYfdhABDxpRTYb7sBuknzM3Q6bibibynwiciae5t6R3LTuw/640?wx_fmt=png&from=appmsg "")  
#### Cndom6.sys  
  
  
驱动签名为“深圳市至高通讯技术发展有限公司”的过期签名。该驱动使用 InfinityHook 技术实现内核 API HOOK，通过针对不同系统版本设置特定偏移值，配合 SSDT 表定位目标函数地址，从而实现对系统关键 API 的 HOOK 操作。  
  
由于 Windows 系统通过内置的 PatchGuard（内核补丁保护）机制，对包括 SSDT 表项、NotifyRoutine、ObRegisterCallback 等多个关键内核结构进行完整性校验，防止篡改系统核心逻辑。一旦检测到异常修改，将立即触发系统蓝屏以防止攻击。而InfinityHook正是为了绕过PatchGuard检查hook SystemCall而生，其原理通过修改系统数据的回调指针获得控制权，再遍历堆栈数据查找SSDT函数修改为自己的函数达到hook效果。早期以ETW的回调数据结构作为切入点，后来微软补丁更新后被修复，但开源项目中依然有开发者不断寻找系统新的利用点更新这个项目。 限于篇幅本文不再详细展开细述。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJg9Kiceem2boyqTPUDE0icoP8CcSL6QsAzC3PBmicTnxiadCnmqLW6hZB5g/640?wx_fmt=png&from=appmsg "")  
###   
  
本次驱动主要HOOK 三个API，被HOOK API与功能如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJk6wqJnSoehV8npGQbKDCAo7A92fDrPmpaT0WtHIlFekvYHgVibjjEtg/640?wx_fmt=png&from=appmsg "")  
  
驱动会获取系统版本信息，根据不同版本信息，通过遍历SSDT表获取函数地址，定位到函数地址后，HOOK为自定义函数  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJxbTeCyKRN5RGkS2p3AoKxACxApXRANggdLF3m9LicnzVHzj9du3bM0w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJCvk87XQic3HJ8iaKRrveql2G7w78hQicickJ8N8Ek8Kxe4G3rrC7LcMtIQ/640?wx_fmt=png&from=appmsg "")  
  
调用NtQuerySystemInformation，API执行时如果判断为被保护进程，则进行断链隐藏进程，非保护进程则执行正常API函数调用，返回正常结果  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJdgEaKB35vCI0waIcogIOBAJYN57WeoSS9Tibs0RNk1jsfVPVWIIVWcQ/640?wx_fmt=png&from=appmsg "")  
  
调用NtOpenProcess，判断为保护进程后，则返回错误码0xC0000022，实现禁止其它进程获取保护进程句柄  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJeVk1JHOGYkQX4dfw8eyMbSIy2NdOZdsriaPRlNYxCibfZcBtgXiamFuuw/640?wx_fmt=png&from=appmsg "")  
  
调用NtDuplicateObject，判断保护进程后，则返回错误码0xC0000022，禁止其它进程复制进程句柄  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJk0hUmrSibjeRtGEhnN1d23ibY30oTjUDm9Obl8MibK0nocbofyMqEzgyw/640?wx_fmt=png&from=appmsg "")  
#### XiaoH.sys  
  
  
该驱动签名为“上海启思教育科技服务有限公司”的过期签名。其主要功能是通过获取 nsiproxy.sys 驱动对象，劫持其 IRP 回调函数指针，实现对网络连接枚举流程的拦截与篡改。Windows 中nsiproxy.sys是负责与 “Network Store Interface” 服务交互，向用户态提供网络连接状态、TCP/UDP连接表等网络状态数据。  
  
用户态程序例如netstat、tasklist等，会通过IOCTL发送请求到 nsiproxy.sys，由其转发至内核中TCP/IP协议栈，读取网络连接状态，攻击者通过定位nsiproxy驱动对象，获取函数指针进行HOOK，当其它程序枚举网络连接时，拦截处理并返回一个被修改的结构，实现“隐藏通讯”的目的  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJpwsBPx0leJ6yv3MYUppHUjADf5y7TM6dD1ibOuBjDHnJRnOEPoot0dA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJd9OlSjXjn8P65ngbmsvpEnBgJHSm84uicbvVsj2icpyJiar5iau6RG3ZdA/640?wx_fmt=png&from=appmsg "")  
  
获取驱动对象指针，保存原始回调函数，根据偏移修改 nsiproxy.sys 驱动对象结构体的回调函数指针，替换为自定义 Hook 函数  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJgPkgaFRnAeTU41kbZxkrbaSR1AvZoVSMdl1b02OWy9CLmCVPkC4LLg/640?wx_fmt=png&from=appmsg "")  
  
执行HOOK函数后，当调用此回调函数时，会判断是否为受保护进程，如果为受保护进程，则伪造一个虚假的结构体，隐藏网络连接行为  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJkibm0vmooNw4RkS9L2KAx54ibvLNiaoCPJbEn4ITe7EgekRhVZZsvicFMg/640?wx_fmt=png&from=appmsg "")  
#### NSecKrnl.sys  
  
  
该驱动签名为“山东安在信息技术股份有限公司”有效签名程序，由于内核结束进程操作没有有效鉴权被攻击者恶意利用，通过传入进程PID可以结束任意进程，在使用时释放在%temp%路径下，文件名称为随机名  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJ7tEE1739ibCjVraq5hmKUQfXeRGCoh5qHroSvKpRY77tRSnDuoibtVcQ/640?wx_fmt=png&from=appmsg "")  
  
接收控制码 0x2248E0，调用ZwTerminateProcess结束目标进程  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJplBgXZDA71fuSm9gP9ic1jyyOtUDYUwxUH64DyhGKgXNLTV59SMDTiag/640?wx_fmt=png&from=appmsg "")  
### 2.初始执行  
  
  
此次分析的样本由伪造的"CMake"安装包释放，采用 Inno Setup 打包，释放路径为C:\Users\Public\Documents\WindowsData 目录，在目录中释放多个文件用于后续执行，其中main.xml和me.key都是压缩包文件，解压密码分别为“Server8888”、“htLcENyRFYwXsHFnUnqK”，在执行过程中解压执行,释放文件列表如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJiam9uhNTzoCKam7PUeo09FicicTsJXbiaxCZKNCehBSxswyzymGMpYU9Gw/640?wx_fmt=png&from=appmsg "")  
  
样本执行时调用unzip.exe解压main.xml释放man.exe，执行后调用main.exe、bypass.exe、NtHandleCallback.exe，并启动服务 rwdriver.sys，并在执行 main.exe 后通过遍历系统进程，找到杀毒软件执行目录删除杀软的可执行文件  
  
man.exe启动后执行 NtHandleCallback.exe ，并注册rwdriver.sys驱动，等待服务启动成功后执行 main.exe，  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJNO1QGUmKRrvEvhUglbvZqIunjfVSde3OPmYZcRhe9YHDrTcB3ASfLg/640?wx_fmt=png&from=appmsg "")  
  
成功启动服务和 main.exe 后，遍历杀软进程，其本意是想通过main.exe覆盖 MiniFilter回调函数后，遍历杀软进程获取文件目录，并删除杀软的可执行文件，但是病毒实际运行过程中并未成功删除  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJsypzt4dUibYfpd2bvbvUCWBpywuKJ2PRFdVOMWmgxic23hznoNoPibsTA/640?wx_fmt=png&from=appmsg "")  
  
通过调用系统组件 wdc.dll 中导出的 WdcRunTaskAsInteractiveUser函数，以实现计划任务的创建与执行。该函数用于以交互式用户身份运行任务，具有较高的权限，被滥用后实现持久化和权限提升。与常见的 schtasks.exe等计划任务接口相比，WdcRunTaskAsInteractiveUser具备更强的隐蔽性，调用该接口时不会触发明显的命令行行为，更容易绕过安全软件的检测。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJHDZcxyG19Sw2UGM4z1tggAa7OeWHPAY6xtQuc2f2dByXCLoib7DOafQ/640?wx_fmt=png&from=appmsg "")  
### 3.杀软对抗  
  
#### 1.main.exe  
  
  
main.exe 通过加载驱动 rwdriver.sys 获取内存读写权限，并根据系统版本进行适配。随后字节码特征匹配，定位各类内核回调函数的实际地址。命中目标回调即调用驱动接口清除函数指针，实现在不终止安全软件进程的前提下，屏蔽其对进程、线程、文件、注册表等行为的监控能力，具体清除内核回调和功能如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJguuQReNrrBJAbKicWhlrACibMazDOUO0d0xtibsl3btiaKibUDG2uzowHCg/640?wx_fmt=png&from=appmsg "")  
  
清理内核回调函数  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJHggMXPfBbVkLyHhWGGnHKzL8N4vhMWfRJSPo28IJv3hqHOWb2ZV0PQ/640?wx_fmt=png&from=appmsg "")  
  
遍历内核函数字节码特征，找到对应函数地址后调用驱动进行清除  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJG51TRA2k2auyVJeab15Q5gvBkEqBDSZt4LwryKKKibShDSaxeErn33g/640?wx_fmt=png&from=appmsg "")  
#### 2.NVIDIA.exe  
  
  
bypass.exe执行后，调用COM接口{6EDD6D74-C007-4E75-B76A-E5740995E24C},创建一个提权对象，执行NVIDIA.exe，该文件为伪造无效的毒霸签名  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJTSh69ibYBC8nl9A58picLK5NzkH5GN7ibqHlKTe0sUeMxfODUe1GbLvgw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJUQQZBos4pFciat4R07BaPUic4e3dEhKlbX4hjWkoGOQNgnNO7rNwJGIg/640?wx_fmt=png&from=appmsg "")  
  
NVIDIA.exe执行后会读取目录下Windows.log，通过RC4解密，密钥 “??Bid@locale@std”，解密出DLL文件后加载，具体功能为通过获取系统进程快照，不断循环遍历杀软进程，如果发现杀软进程启动则发送控制码 0x2248E0 到驱动   
NSecKrnl.sys  
 关闭杀软进程  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJIicUhLCJhk5V7gQC5dWwXTv1NVvQzIzGHMFwkr5JlMev7AKTKkiaGC9w/640?wx_fmt=png&from=appmsg "")  
### 4.远控模块执行  
  
  
NtHandleCallback.exe 使用白加黑加载 log.dll，执行后启动三个线程，分别负责：  
  
1.WinOs 远控模块：读取  SerVer.log文件，通过密钥 "?Bid@locale@std" 进行 RC4 解密，执行远控模块。  
  
2.进程保护：获取 NtHandleCallback.exe 的 PID，向 Cndom6.sys 驱动发送控制码，HOOK 内核 API，形成 RootKit，实现全局隐藏进程  
  
3.Windows defender路径过滤：调用PowerShell命令，将病毒执行目录添加到Windows defender过滤目录  
  
  
读取SerVer.log文件，使用密钥??Bid@locale@std通过RC4解密，解密后执行远控模块  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJfk1pNzYOskpzulEq9Xe3Svou35DCfB7xpufMpnzicOIagxicgRLy20LA/640?wx_fmt=png&from=appmsg "")  
  
WinOs远控模块执行后，连接远程服务器实现远控逻辑，后续长期驻留和进行信息窃取。”WinOS“远控上线配置如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJibIN3JibxaZyoBPrBTAmLe5xJSFO5LwY6uxI3cLRaM0KxdiaHMB3iasewA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJkiampmDgYk0sP6Ae6n524nzUHwuz5d7vaiconbDnLzEic1xVh1XYvoSuQ/640?wx_fmt=png&from=appmsg "")  
  
获取NtHandleCallback.exe PID，向XiaoH.sys驱动发送控制码，隐藏自身网络连接，再向驱动Cndom6.sys发送控制码，隐藏自身进程和启动自保功能  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJnPAGheFlNSQiagZxbowzFtiaqxXgsCwpPB4ckZqGBlSenM2tdLHGuIzQ/640?wx_fmt=png&from=appmsg "")  
  
调用PowerShell将病毒执行路径加入windows defender过滤目录 C:\\Users\\Public\\Documents 躲避windows defender查杀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJwrEtXXUWDCCCxez4UCYHtwXC5KpazBpEMfCOsKCxK6u89PfBBW4uZQ/640?wx_fmt=png&from=appmsg "")  
# 总结:  
  
"银狐"目前还在不断迭代更新，通过本次分析来看该"银狐"变种更倾向于隐藏自身长期驻留用户设备，技术上还是以开源项目组合为主，末端载荷依然使用"winos"远控。本次攻击中的多个 Rootkit驱动大量使用泄露过期签名证书，甚至一些是大厂。目前一些交易市场上也存在提供泄露签名买卖，甚至驱动按次代签服务，对安全防护带来了严峻挑战。另一方面一些厂商发行版本的驱动程序对于控制码的调用没有有效鉴权，导致轻易被恶意程序利用，从近期的安全事件看此类利用层出不穷 。广大用户在搜索引擎中寻找需要的软件时，避免盲目点击首位链接，仔细甄别进入官网和正规渠道下载，以防止下载运行恶意程序。对于有发现与本文中相似异常的用户可以点击金山毒霸百宝箱中的“顽固病毒木马专杀”进行处置，或在毒霸主界面点击“客服”按钮联系7*24h在线工程师协助处置。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34Cufgojvcu8nCtIj8flzliayBnzSZJJGSbAXBRowpibjCfnS6l1ibFBekMlNPpoZJ0brzuTianQNSgXH87X9Duw/640?wx_fmt=png&from=appmsg "")  
  
  
IOC：  
  
    ailletll.top:8880  
  
MD5：  
  
    F08A735829E4E95F8922189314C124E7  
  
    EFF329C6B8C4C980FEB0D867C7082736  
  
    893EDFA3A3A71D71CA670424E554E04C  
  
    4B249ACC6B88C276690514F76B781DBC  
  
    5231A08C5286803E300AC657E37272F8  
  
    80961850786D6531F075B8A6F9A756AD  
  
#   
  
  
  
  
  
  
  
  
  
###   
  
#   
  
  
  
