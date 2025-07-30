#  威胁分子通过多条攻击链大肆利用Progress WS_FTP漏洞   
布加迪  嘶吼专业版   2023-10-23 12:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
从2023年9月30日开始，SentinelOne观察到一伙威胁分子利用Progress的WS_FTP最近披露的漏洞，攻击运行该软件高危版本的Windows服务器。两个最严重的漏洞是CVE -2023-40044和CVE -2023-42657，CVSS评分分别为10分和9.9分。  
  
我们观察到至少有三种类型的多阶段攻击链，它们从漏洞利用开始，然后下达命令从远程服务器下载攻击载荷，常常通过IP地址URL，这种活跃的漏洞利用标志着Progress Software产品在2023年遭到第三波攻击。  
  
虽然漏洞利用可能是伺机下手，但信息技术托管服务提供商（IT MSP)、软件和技术、法律服务、工程和建筑、石油和天然气、医疗保健和非营利等行业部门的组织都受到了影响。  
# 技术细节  
  
漏洞利用活动可能会显示在命令日志中，比如引用父进程中应用程序池WSFTPSVR_WTM以进行后续漏洞利用活动的活动，比如：  
  
C:\Windows\SysWOW64\inetsrv\w3wp.exe -ap "WSFTPSVR_WTM" -v "v4.0" -l  
  
"webengine4.dll" -a \\.\pipe\iisipme{GUID_String} -h  
  
"C:\inetpub\temp\apppools\WSFTPSVR_WTM\WSFTPSVR_WTM.config" -w "" -m 1  
  
-t 20 -ta 0  
  
利用WS_FTP漏洞之后出现了几条攻击链。  
# 攻击链1：编码的PowerShell和Certutil投放Metasploit  
  
该漏洞调用的命令执行以下操作：  
  
•检查系统架构是32位还是64位：脚本使用该信息从正确的路径运行PowerShell。  
  
•使用经过混淆处理的字符串来禁用脚本执行时的PowerShell日志记录。  
  
•解码、提取和执行由Base64编码、由Gzip压缩的字符串，并将解码后的值作为一个新进程来启动。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibOK3LpVlqrCiaEfwwWXhBFDjB35Xh7pf1OicGVeSXia24fPIzkeM785fwIZ5fu2yb7OHv56bUxXKTMg/640?wx_fmt=png "")  
  
图1. 含有攻击链1的编码命令  
  
上面经过混淆处理的代码含有的C#代码有这几个函数或功能：  
  
•14函数：使用.Net反射从Windows API获取GetProcAddress方法和GetModuleHandle方法。  
  
•pR函数：设置参数，以便动态组装运行。  
  
•$dYKA变量：解码由base64编码的PowerShell代码，该代码含有对certutil的调用，以便从IP地址URL下载攻击载荷。  
  
•$pq5zc变量：使用VirtualAlloc为外壳代码（shellcode）分配内存。  
  
•将外壳代码拷贝到已分配的内存中。  
  
•创建并执行一个新线程，以便外壳代码使用所有已建立的参数来运行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibOK3LpVlqrCiaEfwwWXhBFD8fNFkwpPUkbUxMleIsoL6D5VXkB0ibwkPDt6EATeZ01KBl9koNFXrGQ/640?wx_fmt=png "")  
  
图2. 负责运行certutil.exe调用的C#代码，该调用从远程服务器下载攻击载荷  
  
新的进程是certutil.exe，带有-urlcache标志，用于从IP地址URL下载攻击载荷。该命令的示例如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibOK3LpVlqrCiaEfwwWXhBFDCZFoZMb3kAk61ibibZJKCzVbkQ26rDpBFsd7wzoXiaNfMeSHw7t7E5kQQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibOK3LpVlqrCiaEfwwWXhBFDpkWQ5U6waX7Gic5VcMgy6RdQibkQQNZEnZOqQ2zOicIyRSibTjDTibcle3w/640?wx_fmt=png "")  
  
图3. 解码的certutil.exe命令，该命令下载攻击载荷，并作为新进程启动  
  
VirusTotal上的检测规则将从该服务器下载的攻击载荷（SHA-1: 83140ae9951b66fba6da07e04bfbba4e9228cbb8）分类为Metasploit阶段。在这种情况下，活动崩溃，导致系统启动Windows错误报告二进制文件WerFault.exe。由于我们在几分钟后看到了另外的漏洞利用尝试，我们认为这次尝试未得逞，导致威胁分子再次尝试。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wpkib3J60o287jwk8LWD9icmgWlahS21WB8lECGmeJOXSiafEcxpJYOHrph36wNX7lyjD7jckJk6EMZ4bGp59RNrA/640?wx_fmt=png "")  
  
攻击链2：  
通过cl.exe 进行Curl &实时编译  
  
另  
一条攻击链使用curl下载由cl.exe  
执行的攻击载荷，在运行时动态编译攻击载荷。  
攻击链是这样的：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibOK3LpVlqrCiaEfwwWXhBFDDnI7tY2Rr1Wxv432CBNRTrBI4w5TuH9gp73fhcJEEAy0sPEg1OQDMw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibOK3LpVlqrCiaEfwwWXhBFDgslQEWXQ9jbicJjMFrLK1ibfYhQjVPAn46c0EVe97icGnmHwYScJoicOHQ/640?wx_fmt=png "")  
  
虽然该工具可用于合法的安全测试目的，但我们无法确认可以将这起活动归因于攻击性安全团队。  
然而，AssetNote把oastify[.]com查询整合到漏洞分析中，这种分析包括使用Ysoserial .NET反序列化小工具利用漏洞的逐步演练。  
防御者可以针对oastify[.]com的子域使用curl或nslookup来识别这些调用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wpkib3J60o287jwk8LWD9icmgWlahS21WB8lECGmeJOXSiafEcxpJYOHrph36wNX7lyjD7jckJk6EMZ4bGp59RNrA/640?wx_fmt=png "")  
  
攻击链3：  
可执行文件和AD活动  
  
这条攻击链利用了位于服务器的ProgramData路径中的许多不同的Windows可执行文件。虽然有对PowerShell的调用，但这条攻击链不使用任何脚本。相反，下面列出的每个命令都是由一系列可执行文件调用的，这些可执行文件的名称很短，通常由一个字母和一个数字组成，比如n1.exe、n2.exe和s.exe等。我们无法获得这些二进制文件进行分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibOK3LpVlqrCiaEfwwWXhBFDEZQ7ia8apNJKm82MW3DFm8M2fqM8SkwkeEoVgFd1uV2udBa13U5N2kA/640?wx_fmt=png "")  
  
二进制文件xmpp.exe由开发远程管理软件的SimpleHelp公司签名。  
每次在后续命令执行之前，xmpp.exe二进制文件都会执行。  
威胁分子很可能使用xmpp.exe作为一种远程访问工具。  
  
威胁分子试图向Administrators（管理员）组添加名为temp的活动目录（AD）用户，其密码为p@ssw0rd123，如果添加成功，将提供权限升级。接下来是几次尝试，试图添加同一个用户而不添加到Administrators组，最后是对whoami进行调用，这显示了控制台会话的活跃用户。按照事件的这个顺序，添加Administrative用户的尝试很可能失败。由于该活动在whoami命令之后停止，所以创建普通用户很可能成功。  
# 结论  
  
如果组织使用Progress的WS_FTP产品，应该立即更新版本或将受影响的系统断网，这些攻击很可能是伺机下手，威胁分子扫描互联网，寻找易受攻击的系统。  
  
如果将这起活动与6月份Clop勒索软件组织发起的MOVEit大规模漏洞利用攻击进行比较，则有一线希望：Censys研究团队发现，与如今易受攻击的MOVEit Transfer实例数量相比，网上WS_FTP实例要少得多。  
  
发现这些漏洞的研究人员特别指出，由于之前在MOVEit Transfer中的发现，他们分析了更多的文件传输产品。我们在此基础上可以假设，随着研究人员专注于这类产品套件，更多的漏洞将被识别、沦为武器化，基于目前和过去的成功，漏洞研究人员对Progress给予了更大的关注。  
# 攻陷指标  
  
网络指标—URL  
  
hxxp://34[.]77[.]65[.]112:25565  
  
hxxp://34[.]77[.]65[.]112:25565  
  
hxxp://103[.]163[.]187[.]12:8080/3P37p073LKuQjOE64pjEVw  
  
hxxp://103[.]163[.]187[.]12:8080/c8e3vG0e3TMiqcjcZOXhhA  
  
hxxp://103[.]163[.]187[.]12:8080/cz3eKnhcaD0Fik7Eexo66A  
  
hxxp://103[.]163[.]187[.]12:8080/cz3eKnhcaD0Fik7Eexo66A  
  
hxxp://103[.]163[.]187[.]12:8080/cz3eKnhcaD0Fik7Eexo66A  
  
hxxp://103[.]163[.]187[.]12:8080/Sw8J6d3NVuvrBiTCXrg4Og  
  
hxxp://103[.]163[.]187[.]12:8080/xkJ5de2brMfvCNNnBoRRAg  
  
hxxp://141[.]255[.]167[.]250:8081/o1X7qlIaYzSmCj[.]hta  
  
hxxp://176[.]105[.]255[.]46:8080/aqmCG0mZlo_xnZRAWbz6MQ  
  
hxxp://176[.]105[.]255[.]46:8080/OFmLqOxFRIkoENjCZsC7OQ  
  
hxxp://176[.]105[.]255[.]46:8080/Rn0KQbPo22laaUbKGy30sg  
  
hxxp://81[.]19[.]135[.]226:8080/_1TZ–18Hpqm06wvtjLMAg  
  
hxxps://filebin[.]net/soa40iww2w8jhgnd/svchostt[.]dll  
  
hxxps://tmpfiles[.]org/dl/2669123/client[.]txt  
  
hxxps://tmpfiles[.]org/dl/2669853/client[.]txt  
  
hxxps://tmpfiles[.]org/dl/2671793/sl[.]txt  
  
45[.]93[.]138[.]44/cl[.]exe   
  
网络指标– 域  
  
2adc9m0bc70noboyvgt357r5gwmnady2[.]oastify[.]com  
  
bgvozb1wnz86q952zxjlwusv2m8gw5[.]oastify[.]com  
  
qzt3iqkb6erl9oohic20f9bal1rsfh[.]oastify[.]com  
  
网络指标– IP地址  
  
34[.]77[.]65[.]112  
  
45[.]93[.]138[.]44  
  
81[.]19[.]135[.]226  
  
103[.]163[.]187[.]12  
  
141[.]255[.]167[.]250  
  
176[.]105[.]255[.]46   
  
文件哈希– SHA-1  
  
1d41e0783c523954ad12d950c3805762a1218ba6  
  
1d7b08bf5ca551272066f40d8d55a7c197b2f590  
  
32548a7ef421e8e838fa31fc13723d44315f1232  
  
3fe67f2c719696b7d02a3c648803971d4d1fd18c  
  
40b2d3a6a701423412bb93b7c259180eb1221d68  
  
65426816ef29c736b79e1969994adf2e74b10ad8  
  
790dcfb91eb727b04d348e2ed492090d16c6dd3e  
  
83140ae9951b66fba6da07e04bfbba4e9228cbb8  
  
83e6ede4c5f1c5e4d5cd12242b3283e9c48eea7e  
  
8c14a4e7cee861b2fad726fc8dd0e0ae27164890  
  
8dbca2f55c2728b1a84f93141e0b2a5b87fa7d35  
  
923fd8fb3ddc1358cc2791ba1931bb4b29580bb6  
  
98321d034ddc77fe196c6b145f126b0477b32db9  
  
b4a5bf6c9f113165409c35726aec67ff66490787  
  
b70aa1d07138b5cae8dd95feba9189f1238ee158  
  
d00169f5eff9e0f2b5b1d473c0ee4fe9a3d8980e  
  
d669b3977ebebf7611dd2cb1d09c31b3f506e9bd  
  
e5ac227f143ec3f815e475c0b4f4f852565e1e76  
  
f045a41def1752e7f8ef38d4ce1f7bd5e01490fc  
  
参考及来源：https://www.sentinelone.com/blog/threat-actors-actively-exploiting-progress-ws_ftp-via-multiple-attack-chains/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibOK3LpVlqrCiaEfwwWXhBFDlKmxAFLFmA6H7u4E5VIPicretkiaWs0GZAL5iciaFp4iaeDhT1jlQDzw0icQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibOK3LpVlqrCiaEfwwWXhBFDXyC3dEkpVf2KMahepXm7OhC5yvbuibEuoeaKbLyWIo5hGIO2cVicvVvA/640?wx_fmt=png "")  
  
  
