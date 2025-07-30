#  创新终端主动防护-多种通用0day漏洞检测方案   
原创 xiaoliangliu  xiaoliangliu   2025-02-01 03:08  
  
2019 可能会是过去十年里最差的一年，但却是未来十年里最好的一年。没想到日子这么快已经2025  
，祝福大家新年快乐，我写了一篇关于0day漏洞检测的技术文章进行开源分享，供互相交流学习。  
  
## 摘要  
  
在真实世界中，APT组织使用0day/Nday进行一系列攻击的比例居高不下，在企业安全的角度，我们必须开发一套0day检测系统去检测0day漏洞，抵御未知的威胁。根据google的在野漏洞报告，我们研究出了针对windows内核提权漏洞，windows服务提权漏洞，chrome v8远程执行漏洞等的一套组合式0day漏洞检测系统，帮助我们检测0day，抵御风险。在多年的对抗中我们检测到了CVE-2023-21768 windows 内核0day漏洞，和其他若干的Nday漏洞，比如CLFS内核漏洞，V8 RCE漏洞等。  
  
      
  
    在这次演讲中我们首先会分享多个方向的漏洞利用手法，其次会分享构造一套0day检测系统的方法论，其中会说明我们的0day漏洞检测方法和运营方法。最后我们会分享检测到的0day/nday漏洞样本，还会介绍一个我们捕获到的APT组织，并且介绍该组织是如何利用漏洞实现完整攻击。同时还会分享在甲方构造一套企业级的0day漏洞检测系统的经验，以及为什么我们能检测到0day的原因，期望能给业界一些灵感和思路。  
## 1. 0day漏洞攻击趋势  
  
    APT攻击愈演愈烈,近几年发生了一系列的勒索，漏洞攻击事件。2019到2023年间 0day漏洞攻击趋势一直呈现上涨趋势，APT组织利用0day漏洞攻击的比例越来越高，企业非常有必要去防御0day攻击。如下是总结google在野0day表格得到的0day攻击统计图，在后续我们会讲解主要的0day攻击和防御方式。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9lXcmDricUUsURKDvKSLmd53GqEOmc6BaibC1et0A7KoXIdicD6rYmMe6eCSYVicsuRyMMBy0nibbiar6CxI11T1j9Lw/640?wx_fmt=png&from=appmsg "")  
## 2. 漏洞利用方式总结  
### 2.1.Windows内核提权漏洞利用方式  
  
近3-5年内公开了一系列Windows内核提权漏洞的任意读写函数，主要来自于在野漏洞的公布和研究员的分享，比如NtUpdateWnfStateData/NtQueryWnfStateData,SubmitIoRing。 借助这些函数我们可以把当前token地址提高到system token地址或者更改token的privilge count，同时一种叫更改previousmode的技术被APT组织越来越多的使用，该项技术被用来绕过内核对应用层参数的检查，进而借助NtReadVirtualMemory/NtWriteVirtualMemory等类似的函数实现任意读写。当然还有Pipe Attribute的面世也引领了内核提权漏洞的进步，我们把一系列有代表性的任意读写函数和CVEs做了总结。这些函数的共同特点是都可以利用漏洞实现任意读写达到提高权限的目的。值得一提的是我们捕获到的0day样本CVE-2023-21768 并没有使用任何的读写原语。  
<table><tbody><tr><td data-colwidth="291" width="291" valign="top"><section><span leaf="">任意读写函数</span></section></td><td data-colwidth="194" width="194" valign="top"><section><span leaf="">CVE</span></section></td><td data-colwidth="191" width="191" valign="top"><section><span leaf="">os</span></section></td></tr><tr><td data-colwidth="291" width="291" valign="top"><section><span leaf="">NtQuerySystemInformation</span></section></td><td data-colwidth="194" width="194" valign="top"><section><span leaf="">CVE-2022-37969 </span></section><section><span leaf="">CVE-2023-21768 </span></section></td><td data-colwidth="191" width="191" valign="top"><section><span leaf="">win10</span><span style="font-size: var(--articleFontsize);letter-spacing: 0.034em;background-color: transparent;"><span leaf="">/11</span></span></section></td></tr><tr><td data-colwidth="291" width="291" valign="top"><section><span leaf="">SetWindowLong(</span><span style="font-size: var(--articleFontsize);letter-spacing: 0.034em;background-color: transparent;"><span leaf="">Ptr</span></span><span style="font-size: var(--articleFontsize);letter-spacing: 0.034em;background-color: transparent;"><span leaf="">)</span></span></section></td><td data-colwidth="194" width="194" valign="top"><section><span leaf="">CVE-2021-1732</span></section></td><td data-colwidth="191" width="191" valign="top"><section><span leaf="">win10</span></section></td></tr><tr><td data-colwidth="291" width="291" valign="top"><section><span leaf="">NtUpdateWnfStateData/</span></section><section><span leaf="">NtQueryWnfStateData </span></section></td><td data-colwidth="194" width="194" valign="top"><section><span leaf="">CVE-2021-31956</span></section></td><td data-colwidth="191" width="191" valign="top"><section><span leaf="">win10</span></section></td></tr><tr><td data-colwidth="291" width="291" valign="top"><section><span leaf="">CreatePipe/</span></section><section><span leaf="">NtFsControlFile </span></section></td><td data-colwidth="194" width="194" valign="top"><section><span leaf="">CVE-2021-36955</span></section></td><td data-colwidth="191" width="191" valign="top"><section><span leaf="">win10</span></section></td></tr><tr><td data-colwidth="291" width="291" valign="top"><section><span leaf="">NtReadVirtualMemory/ NtWriteVirtualMemory  </span></section></td><td data-colwidth="194" width="194" valign="top"><section><span leaf="">CVE-2022-37969</span></section><section><span leaf="">CVE-2023-36802 </span></section></td><td data-colwidth="191" width="191" valign="top"><section><span leaf="" data-pm-slice="1 1 [&#34;table&#34;,{&#34;interlaced&#34;:null,&#34;align&#34;:null,&#34;class&#34;:null,&#34;style&#34;:&#34;table-layout:fixed;border-collapse:collapse;border:1px solid #d9d9d9;width:887px&#34;},&#34;table_body&#34;,null,&#34;table_row&#34;,{&#34;class&#34;:null,&#34;style&#34;:&#34;height: 63px;&#34;},&#34;table_cell&#34;,{&#34;colspan&#34;:1,&#34;rowspan&#34;:1,&#34;colwidth&#34;:[250],&#34;width&#34;:&#34;250&#34;,&#34;valign&#34;:&#34;top&#34;,&#34;align&#34;:null,&#34;style&#34;:&#34;border: 1px solid #d9d9d9;&#34;},&#34;para&#34;,{&#34;tagName&#34;:&#34;p&#34;,&#34;attributes&#34;:{&#34;style&#34;:&#34;margin: 0;padding: 0;min-height: 24px;&#34;},&#34;namespaceURI&#34;:&#34;http://www.w3.org/1999/xhtml&#34;}]">win10/11</span></section></td></tr><tr><td data-colwidth="291" width="291" valign="top"><section><span leaf="">BuildIoRingReadFile/</span></section><section><span leaf="">SubmitIoRing</span></section></td><td data-colwidth="194" width="194" valign="top"><section><span leaf="">CVE-2023-21768 </span></section></td><td data-colwidth="191" width="191" valign="top"><section><span leaf="">win11</span></section></td></tr><tr><td data-colwidth="291" width="291" valign="top"><section><span leaf="">Direct Write Address</span></section></td><td data-colwidth="194" width="194" valign="top"><section><span leaf="">CVE-2023-21768</span></section></td><td data-colwidth="191" width="191" valign="top" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span leaf="">win11</span></p></td></tr></tbody></table>  
### 2.2.Windows服务逻辑漏洞提权利用方式  
  
**和符号链接相关的服务提权漏洞:**  
  
在过去的几年内，Windows服务逻辑漏洞大量的出现，而这些漏洞的典型特征是服务在进行读写，移动，删除文件时并没有很好的做好校验权限，总是以NT AUTHORITY\SYSTEM权限执行，此时如果我们通过符号链接挂载这些被写或者移动，删除的文件，则可能会创造出任意文件写/任意文件移动/任意文件删除到提权的效果，比较典型的案例有  
CVE-2020-0668  
，该漏洞是一个任意文件移动漏洞，它的典型漏洞利用手法如下  
```
1.Create (or copy) a file with a size greater than 0x8000 (32,768) bytes.
2.Create a new directory (C:\EXPLOIT\mountpoint\ for example) and set it as a mountpoint to \RPC Control.
3.Create the following symbolic links:
    \RPC Control\RASTAPI.LOG -> \??\C:\EXPLOIT\FakeDll.dll (owner = current user)
    \RPC Control\RASTAPI.OLD -> \??\C:\Windows\System32\WindowsCoreDeviceInfo.dll
4.Configure the following values in the registry:
    FileDirectory = C:\EXPLOIT\mountpoint
    MaxFileSize = 0x8000 (32,768 bytes)
    EnableFileTracing = 1
5.Trigger RASTAPI related events using the RasDial function from the Windows API.
6.Trigger the Update Session Orchestrator service to load the DLL in the context of NT AUTHORITY\SYSTEM.

source :https://itm4n.github.io/cve-2020-0668-windows-service-tracing-eop/#the-tracing-feature-for-services
```  
  
我们可以看到当我们借助符号链接实现文件移动后，再借助  
Update Session Orchestrator service 加载该dll即可实现system级别的提权，同样还有  
CVE-2020-0787，CVE-2020-0753等，2024年跟符号链接漏洞相关比较近的是  
 CVE-2024-1694   
，  
该漏洞是Google Update Service的提权漏洞，Google Update Service会以system权限删除在%AppData$\Local目录下的文件，该目录下的文件可如果被挂载，则会造成任意文件删除到提权的效果  
。  
  
****  
**和符号链接无关的服务提权漏洞:**  
  
在Windows服务逻辑漏洞提权中当然还有不借助于符号链接的手法，比较典型的就是打印机中的  
PrintNightmare系列漏洞，比如  
CVE-2021-1675  
，该漏洞可以  
通过普通用户的权限添加打印机驱动，在进行一系列的绕过后，可以让Spooler服务加载我们设定的恶意dll，而Spooler服务本身是以NT AUTHORITY\SYSTEM权限运行，进而完成了从medium到system级别的提权。还有一系列类似的漏洞，例如  
CVE-2021-34527  
，   
CVE-2021-34481  
，  
CVE-2021-36958  
等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9lXcmDricUUsURKDvKSLmd53GqEOmc6BaGjAicmMfeUiavSNicUFS6Xt1cEqo8b683eAjiakd2gosv43dSqJQ1lCedQ/640?wx_fmt=png&from=appmsg "")  
  
以上就是在过去3-5年内windows服务侧逻辑漏洞提权利用方式，虽然微软对符号链接漏洞添加了缓解措施，但仍存在公开已知的符号链接利用手法，最新的windows中hardlink,symlink等均要求管理员权限，但是Juntion(目录链接并无任何要求)。同时大量的客户端软件，安全软件面临类似的提权操作，甚至我们看到chrome也有相似的问题，攻击者借助这类漏洞攻击会难以防御，对企业内部造成重大损失。  
### 2.3.chromeV8漏洞利用方式总结  
  
Google在2023年收录了很多V8的在野0day,比如CVE-2023-2033，CVE-2023-3079，CVE-2023-4762等，因为V8 SandBox的原因，又有很多研究员找到了绕过v8 sandbox的方法并进一步利用的方式，典型案例是  
CVE-2024-0517  
。  
  
同样在v8的对抗中，攻击手法是不断的进步和更迭，我们总结到90%的v8漏洞利用都使用到了wasm，并且它的利用方式是一个通用套路模板，整体核心目标都是找到wasm的RWX地址，接着使用任意读写原语将shellcode覆盖该地址，紧接着调用wasm的exports函数执行shellcode，如下示例。  
```
  var wasmCode = new Uint8Array([[ TRUNCATED ]]);
  var wasmModule = new WebAssembly.Module(wasmCode);
  var wasmInstance = new WebAssembly.Instance(wasmModule);
  let addr_wasminstance = addrof(wasmInstance);
  let wasm_rwx = v8h_read64(addr_wasminstance+wasmoffset);
  var f = wasmInstance.exports.main;
  v8h_write64(addr_wasminstance+wasmoffset, 0x41414141n);
  f();
  
source :https:/blog.exodusintel.com/2024/01/19/google-chrome-v8-cve-2024-0517-out-of-bounds-write-code-execution/
```  
## 3. 终端主动防御0day漏洞检测方案  
### 3.1.构建终端主动防御0day漏洞检测系统  
  
我总结和分析得到了近3-5年内的windows内核，服务，chrome方面的漏洞攻防知识，在这套基础上我们针对于不同的方向设计了相关的检测方案。我们构建了虚拟化级别和驱动级别的底层引擎，该层主要目标是实现在win10/11平台上对任意读写函数的Hook和系统行为信息的采集，应用层通过采集到的高质量数据源，结合研究知识，漏洞利用特征，漏洞利用行为实现多维度的0day漏洞检测，当我们检测到真实的0day/nday后则上报到威胁狩猎平台，借助高质量的检测数据第一时间可发现阻断0day攻击。  
  
#### 3.1.1.windows内核漏洞检测  
  
 基于任意读写原语的检测方案  
  
    内核漏洞提权的本质是借助API实现任意读写并提权，我们在虚拟化层面对任意读写函数进行了监控，并且传递事件到应用层实现提权的检测逻辑，比如检测token地址的更改，检测token privilege count 递增。基于虚拟化技术拥有了底层Hook的能力并根据提权特征实现相关的检测，但是误报无可避免，主要的误报原因是进程在启动初始化过程中token并不是一成不变，例如chrome是一个多进程架构产品，它有很多的权限操作会导致大量误报导致无法检测到0day，我们深入研究了Windows是如何保证权限在初始化后不被更改(非漏洞)，解决了token变化的误报问题，达到了数千万机器日均只有数百左右告警的能力，进而检测到了一系列提权漏洞。  
  
 基于敏感行为的检测方案  
  
    微软在驱动层提供了各种回调帮助我们实现进程，文件，注册表，LoadImage等的一系列行为检测，我们在驱动层注册了微软的驱动回调实现了对进程，文件，注册表，LoadImage等的一系列事件监控。而在APT攻击中当借助漏洞实现提权后往往会进行一系列的后渗透行为，比如启动shell，远程下载后门文件，改写敏感注册表值等，而这些行为都可以通过微软提供的回调实现监控，在这些敏感行为处我们增加了提权漏洞的检测逻辑，这样即使是APT组织使用未公开的任意读写函数进行了提权，我们也可以在行为中实现权限检测，如下是我们使用到的驱动回调。  
<table><tbody><tr><td data-colwidth="287" width="287" valign="top"><section><span leaf="">监控回调函数</span></section></td><td data-colwidth="287" width="287" valign="top"><section><span leaf="">监控类型</span></section></td></tr><tr><td data-colwidth="287" width="287" valign="top"><section><span leaf="">PsSetCreateProcessNotifyRoutine(</span><span style="font-size: var(--articleFontsize);letter-spacing: 0.034em;background-color: transparent;"><span leaf="">Ex)</span></span></section></td><td data-colwidth="287" width="287" valign="top"><section><span leaf="">进程监控</span></section></td></tr><tr><td data-colwidth="287" width="287" valign="top"><section><span leaf="">PsSetCreateThreadNotifyRoutine</span></section></td><td data-colwidth="287" width="287" valign="top"><section><span leaf="">线程监控</span></section></td></tr><tr><td data-colwidth="287" width="287" valign="top"><section><span leaf="">PsSetLoadImageNotifyRoutine</span></section></td><td data-colwidth="287" width="287" valign="top"><section><span leaf="">LoadImage监控</span></section></td></tr><tr><td data-colwidth="287" width="287" valign="top"><section><span leaf="">CmRegisterCallback</span><span leaf="" style="font-size: var(--articleFontsize);letter-spacing: 0.034em;background-color: transparent;">(</span><span style="font-size: var(--articleFontsize);letter-spacing: 0.034em;background-color: transparent;"><span leaf="">Ex)</span></span><span style="font-size: var(--articleFontsize);letter-spacing: 0.034em;background-color: transparent;"><span leaf=""> </span></span></section></td><td data-colwidth="287" width="287" valign="top"><section><span leaf="">注册表监控</span></section></td></tr><tr><td data-colwidth="287" width="287" valign="top"><section><span leaf="">FltRegisterFilter</span></section></td><td data-colwidth="287" width="287" valign="top"><section><span leaf="">文件监控</span></section></td></tr><tr><td data-colwidth="287" width="287" valign="top"><section><span leaf="">ObRegisterCallbacks</span></section></td><td data-colwidth="287" width="287" valign="top"><section><span leaf="">句柄监控</span></section></td></tr></tbody></table>####  3.1.2.windows服务提权漏洞检测  
  
符号链接的挂载往往是为了让高权限服务在写，移动，删除文件的时候可以把恶意dll写/移动到特殊目录，并让拥有system权限的服务加载该dll实现提权，非符号链接挂载的逻辑漏洞则是绕过一系列检测从而让system权限的服务加载恶意dll。  
  
我们发现逻辑漏洞的提权本质是让system权限的服务加载恶意dll，在内存上并没有很显眼的特征，但是在行为处特征显眼，比如会触发符号链接挂载，加载dll，任意文件移动/写等行为，所以为什么不从行为处检测这类型漏洞？基于以上漏洞利用的行为，我们决定通过微软提供的回调实现符号链接挂载监控，对特殊目录的(类似system32)写/删除文件监控，特殊服务(比如Spooler)的LoadImage行为监控。但是这些行为通常也是应用运行的正常行为，并不只是漏洞专属行为，我们无法监控某个行为从而判断出是漏洞攻击，所以基于漏洞触发到提权的行为特征->符号链接挂载，任意写/移动/删除文件到特殊目录，特殊服务加载dll，我们设计了相关的计算逻辑去检测逻辑提权漏洞，比如针对打印机服务，我们认为一个普通符号链接挂载的dll是被打印机或者通信打印机的client端写到特殊目录，打印机服务加载了该dll我们才会认为是一个疑似提权漏洞，  
并且该dll和client在我们的云查系统是确切白以外的二进制文件我们才会认为是疑似恶意，这样也避免了很多误报。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/9lXcmDricUUsURKDvKSLmd53GqEOmc6BaTKPPZxmsCm6VpDxtDX9KL4b79PibGhnOicoOw6fXdf2kC4NajxLRhohQ/640?wx_fmt=jpeg&from=appmsg "")  
####  3.1.3.chrome v8漏洞利用检测  
  
我们已经说过v8 大多数的漏洞利用是基于wasm的，传统的检测都是对ROP的利用方式检测或者是判断一下内存属性。这些方案已经远远跟不上v8的漏洞攻防，对于v8的漏洞利用检测我们从wasm的研究起手。  
  
wasm研究:  
  
我们已经在上文看到了v8的漏洞利用模板，查看如下wasm的js代码示例  
```
var wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0,
1, 96, 0, 1, 127, 3, 130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0,
1, 112, 0, 0, 5, 131, 128, 128, 128, 0, 1, 0, 1, 6, 129, 128, 128, 128, 0, 0,
7, 145, 128, 128, 128, 0, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97,
105, 110, 0, 0, 10, 138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 42, 11]);
var wasm_mod = new WebAssembly.Module(wasm_code);//Generate rwx data
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var main = wasm_instance.exports.main;
main();
```  
  
    首先是wasm的内存标记，如下可以看到当我们打印出wasmCode的地址后可以看到data_ptr指向的内存标记为.asm,可以通过这个标记清楚的知道wasm的内存，初期我以为wasm的RWX内存在这块内存内，并被VirtualProtect更改内存属性，最后发现wasm的RWX内存是被重新分配的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9lXcmDricUUsURKDvKSLmd53GqEOmc6BaicVDTVqzGqLNfaz0TWCicG4qXWBNKvatVZqmutRBBJ52cOhISwQILtyA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9lXcmDricUUsURKDvKSLmd53GqEOmc6BagjjIon6cPhoz9VwvAP67bKpzlx7eSFnWic3sA4CN5UvccVwqAibw0TEg/640?wx_fmt=png&from=appmsg "")  
  
    接着我们的故事->去寻找wasm的RWX内存。我发现v8会通过VirtualAlloc申请一块PAGE_NOACCESS的内存，接着再把这块内存中一块小内存设置为RWX，而v8的漏洞利用中往往覆盖的就是这块内存地址。  
  
    在理解清楚wasm的RWX内存申请逻辑后，我研究了cs，msf加载shllcode的流程，因为shellcode并不能直接调用api，所以需要遍历_LDR_DATA_TABLE_ENTRY寻找函数位置并调用，这是shellcode中比较显眼的特征。综合v8的漏洞利用特征和shellcode特征，我们得到了标记wasm内存，查找shellcode和wasm内存的关系来检测漏洞攻击的方法论，这套检测逻辑帮我们检测到了不少Nday。如下是检测到的相关CVE示例。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9lXcmDricUUsURKDvKSLmd53GqEOmc6BaKBwxLLENEpSGtbUReDg9VRUzxaRJPH0FUYh4xhfJNzdpEWia1Bva5icw/640?wx_fmt=png&from=appmsg "")  
### 3.2.云端威胁分析平台  
  
    我们的0day分析平台基于ES实现了大数据的存储和聚合，基于flink实现了大数据的实时计算，构造了相关的实时计算引擎，结合云端的威胁情报和大样本库，我们可以快速的实现相关的告警分析和运营，并且因为我们的强优点在于在终端基于内存和漏洞利用特征实现检测而非云端规则匹配，使其云端误报量非常低，在千万级的机器部署后云端只有几百的告警量，基于es的查询聚合能力和威胁情报，我们可以快速的分析样本并且第一事件处置。  
## 4. 成果分享  
### 4.1.0day CVE-2023-21768的捕获和分析  
  
这是对于0day CVE-2023-21768的分享,它的漏洞原因是内核未校验应用层传入的地址，导致可以直接任意写，漏洞利用难度低，但是因为没有借助任何公开的读写函数，检测难度很高。  
  
分析该样本可看到循环调用了NtSetIoCompletion 0xff次，紧接着调用了ProcessSocketNotifications， 该函数会通信到驱动调用afd!IoRemoveIoCompletion，  
  
在afd!IoRemoveIoCompletion内，receivedEntryCount参数会被赋值为0xff，而receivedEntryCount是一个地址，从应用层传入到内核时却未被检测是否合理，因此我们可以通过NtQuerySystemInformation得到当前进程的token privilge count地址并赋值到receivedEntryCount实现递增。在样本的利用中我们看到它并未使用任何公开的任意读写函数，通过历史因素去扫描完全是没有特征可以借鉴的。  
该样本在提权后，借助PPID技术更改父子进程，伪造进程链逃避检测。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9lXcmDricUUsURKDvKSLmd53GqEOmc6BakthMoBnaiavoj9fWyJuRHmPh22e9N26mLmicGP9Rx2fWgfenheicnDYcw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9lXcmDricUUsURKDvKSLmd53GqEOmc6BanJVm7vIO9m7VvI5ibMDHJibxNZk6waJKts3SNhBQ669lZJ0xnoCia4PIg/640?wx_fmt=png&from=appmsg "")  
  
  
chompie和b33f也公布了借助IoRing实现CVE-2023-21768的提权  
```
https:/github.com/chompie1337/Windows_LPE_AFD_CVE-2023-21768
```  
### 4.2.Nday系列分析  
  
让我们再来看一下捕获到的一系列Nday，我觉得这也是比较有代表性的样本，首先是关于CLFS系列漏洞样本，第一个CLFS样本是CVE-2022-24521，它首先通过NtQuerySystemInformation获取到了当前进程的EPROCESS地址，在这个基础上计算得到了PreviousMode位置，紧接着获取到了ClfsSetEndOfLog的函数指针，并且通过漏洞利用该函数实现了PreviousMode的更改，接着利用NtWriteVirtualMemory去实现任意地址写，覆盖当前进程的token为system进程的token。整体来看它借助NtQuerySystemInformation实现kernel leak，借助ClfsSetEndOfLog去更改previousMode，最后利用NtWriteVirtualMemory实现token替换达到提权的目的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9lXcmDricUUsURKDvKSLmd53GqEOmc6BaGwwn9EhxnkktGmncTBra1aNWgZCbalbgy6Dfcg2Wsuribr5alhZgVHQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9lXcmDricUUsURKDvKSLmd53GqEOmc6Bayj7J9ZtOicPUtD08wAib1YTJyk7f51RFChw22PR0JRmfw1aib8eiaytNuQ/640?wx_fmt=png&from=appmsg "")  
  
      
  
    紧接着是另一个CLFS漏洞样本  
CVE-2021-36955  
，经过分析得到通过该样本调用  
hal!XmXchgOp实现任意写，当触发漏洞的时候调用hal!XmXchgOp实现token地址的替换，我们可以看到攻击者使用任意读写原语已经偏向于到使用内核函数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9lXcmDricUUsURKDvKSLmd53GqEOmc6BaadqgxCxBDugYGEXy66LnydriaYQD48No9UxHoXowAibibrEhPe5jFBomg/640?wx_fmt=png&from=appmsg "")  
  
Origin token  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9lXcmDricUUsURKDvKSLmd53GqEOmc6BaJKrdBvKLssaoiacQ4XMAWcCIZvic7LIFHnFXb8ib3UR9RuO3hRnJicoibjQ/640?wx_fmt=png&from=appmsg "")  
  
Now token(system token)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9lXcmDricUUsURKDvKSLmd53GqEOmc6BajvhpXplO4AUaySgmsjntHkCic9j3E8D4XXqee4V8VznPdrgK7JfgE5w/640?wx_fmt=png&from=appmsg "")  
  
    第三个Nday是CVE-2022-21882,它是CVE-2021-1732的变体，它绕过了CVE-2021-1732的补丁并且再次使用GetMenuBarInfo和SetWindowLongPtr的任意读写原语实现权限的提升。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9lXcmDricUUsURKDvKSLmd53GqEOmc6BaHmT0lPwpCY5jxXK5dQicNTic5icYc9WGwqAyJVWa6WWxn6FT8aeWg5yTw/640?wx_fmt=png&from=appmsg "")  
### 4.3.APT级别的漏洞攻击案例  
  
    我们捕获到了几个APT组织借助漏洞实现恶意攻击，我将分享紫狐利用CVE-2021-1732实现攻击的案例，我们可以看到当紫狐入侵到客户机器后直接启动powershell远程下载png文件，而该png文件中包含了恶意的漏洞利用代码，它反射注入该jpg到poershell并执行，在内存中实现了提权，把当前powershell的权限从medium提权到了system级别，紧接着写入sens.dll到system32目录并重启系统使其服务加载该恶意dll，再进一步实现提权和远程c2实现连接。虽然紫狐在内存中进行了提权并且没有明显的行为信息，但是它依旧使用了SetWindowLongPtr任意读写函数进行了token更改，我们第一时间发现了这个不寻常的攻击。经过分析得到紫狐使用的是  
CVE-2021-1732  
内核漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/9lXcmDricUUsURKDvKSLmd53GqEOmc6BaCw5117PSkmXVibwbXvylzUcGnp74KEALTTxUAVSW9r6fH7djtz0vVqQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
    综上我们可以看到不论是0day还是Nday都有自己一些独特的漏洞利用手法，而这些手法社区很多可能都是不公开的，比如0day CVE-2023-21768借助直接写的方式实现提权，而Nday CLFS的样本使用了内核函数  
hal!XmXchgOp，当触发漏洞的时候才会调用该函数指针实现提权，  
CVE-2022-21882是CVE-2021-1732的变体，是社区经常提到的绕过补丁再次利用的典型手法，0day的检测需要持续性更进和创新。  
## 5.展望  
  
    希望我们做出的如上技术分享可以帮助到社区去更好的对抗漏洞攻击，提高业界整体的对抗能力。感谢优秀的进攻侧研究员让我了解到了一线攻击技术，使我可以更好的抵御攻击  
，  
在未来我仍然会紧跟漏洞攻防技术、APT攻防技术，在第一线去实时对抗并分享安全技术，谢谢大家。  
## 6.引用  
```
1.https://www.sstic.org/media/SSTIC2020/SSTIC-actes/pool_overflow_exploitation_since_windows_10_19h1/SSTIC2020-Article-pool_overflow_exploitation_since_windows_10_19h1-bayet_fariello.pdf
2:https://research.nccgroup.com/2021/07/15/cve-2021-31956-exploiting-the-windows-kernel-ntfs-with-wnf-part-1/
3:https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/
4:https://github.com/yardenshafir/IoRingReadWritePrimitive
5:https://github.com/oct0xor/presentations/blob/master/2019-02-Overview%20of%20the%20latest%20Windows%20OS%20kernel%20exploits%20found%20in%20the%20wild.pdf
6:https://itm4n.github.io/cve-2020-0668-windows-service-tracing-eop/#the-tracing-feature-for-services
7:https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks
8: https://github.com/thezdi/PoC/tree/master/FilesystemEoPs
9:https://blog.exodusintel.com/2024/01/19/google-chrome-v8-cve-2024-0517-out-of-bounds-write-code-execution/
```  
  
  
Finally，感谢PJF的指导，pengyan，dongjie，wupeng，lijian，pengcheng，shunguang的深度合作。  
  
  
祝福大家2025工作顺利，阖家团圆！  
  
  
author:liuxiaoliang  
  
twitter:Xiaoliang Liu(@flame36987044)  
  
  
微信:chenxiaolxc  
  
  
