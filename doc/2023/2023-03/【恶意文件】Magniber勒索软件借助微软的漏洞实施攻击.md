#  【恶意文件】Magniber勒索软件借助微软的漏洞实施攻击   
深盾研究实验室  深信服千里目安全技术中心   2023-03-30 19:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1kuw175o6KBYESQtM1yvkPORRiaXelrAJBPhDticQGTsqcz303jcHEwaw/640?wx_fmt=gif "")  
  
  
**恶意家族名称：**  
  
Magniber  
  
**威胁类型：**  
  
勒索软件  
  
**简单描述：**  
  
Magniber勒索家族的前身是Cerber，至少从2021年10月已经开始活跃，最初主要针对韩国，从今年年初开始，该组织日益活跃，攻击范围开始遍布全球，包括中国大陆、中国台湾、中国香港、马来西亚、新加坡和欧洲等。  
  
  
  
  
**恶意文件分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1sibqLX2ibgZqR5sNbKEgVqCjVJzDHQ42vUerGzG4Szd6Qm3jve42uiaBw/640?wx_fmt=gif "")  
  
**恶意事件描述**  
  
深信服深盾终端实验室在近期的运营工作中，捕获了的Magniber勒索家族的最新变种，此次捕获的样本通过MSI进行传播，同时使用微软的漏洞CVE-2023-24880（注：3月14日官方已发布补丁）来绕过 SmartScreen从受感染的网站下载和安装Magniber勒索软件，CVE-2023-24880漏洞由CVE-2022-44698漏洞未完全修复引起的。  
  
CVE-2023-24880 利用了Windows SmartScreen 安全功能的绕过。SmartScreen是Windows版本 10 和 11中的一项安全功能，主要用于检测和阻止网络钓鱼和恶意软件的下载和安装。绕过该功能即代表允许攻击者在没有任何安全警告的情况下下载Magniber勒索软件。  
  
  
该漏洞已在今年3月15日进行及时响应，相关链接如下所示：   
  
https://mp.weixin.qq.com/s/f4uA3Loc2ooG_1_tcvxnUA  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1sibqLX2ibgZqR5sNbKEgVqCjVJzDHQ42vUerGzG4Szd6Qm3jve42uiaBw/640?wx_fmt=gif "")  
  
**恶意事件分析**  
  
在所有的勒索家族中，Magniber绝对是最独树一帜的存在，样本本身使用了大量的混淆、解码，通过采用新的混淆技术和规避方法不断更新其策略，极度干扰研究人员的分析工作。其次使用漏洞，Magniber Ransomware 近年来一直通过 IE (Internet Explorer) 漏洞传播，但自 IE 停止支持后，Magniber Ransomware 在 Microsoft Edge 和 Google Chrome 浏览器中以 Windows 安装包文件 (.msi) 的形式分发。  
  
  
样本启动后，会加密系统中的部分文件，并释放勒索信以诱使受害者通过勒索信中的联系方式与攻击者进行沟通及缴纳赎金，其中被加密文件添加扩展“mhkgchqs”，勒索信文件名为“README.html”，勒索信中并未表明赎金金额及支付方式。  
  
  
**README.html勒索信文件内容如下所示：**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE14QMGpiaHx9loJ8iaUiagDpxcvzQVrRGHAKcrz50jDibAwQhR055rRvTmJQ/640?wx_fmt=png "")  
  
  
  
**被加密后文件系统情况：**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1T3llTTGGYQa7B73YMnAIrJguB3SptJiaxHiaXdkVvkeo02mZJ75O7ahw/640?wx_fmt=png "")  
  
  
**MSI文件分析**  
  
  
攻击者正在使用无效但自制的验证码签名的 MSI 文件。格式错误的签名会导致 SmartScreen 返回错误，当不受信任的文件包含 Web 标记 （MotW） 时，该错误会导致不会向用户显示安全警告对话框，实则已经从 Internet 下载了潜在的恶意文件。   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE117yhiavY0WTfl4DFaYZnXttF5Pe4D54rCBYkgTWBlFBJHW9ZbShMnUQ/640?wx_fmt=png "")  
  
  
使用Orca打开MSI文件查看表的结构和内容。发现MSI会调用CustomAction属性执行MSI内嵌DLL的导出函数j6tow27o。  
  
  
SetProgramFilesFolder：将该程序的文件夹设置为LocalAppData目录，即“C:\Users\用户名\AppData\Local”。  
  
Ucjvnpaclba：获取二进制文件ilzwngaiyktz，type为65表示该文件为dll类型，Target表示导出函数为j6tow27o。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1dcQxmPKbNbr2mhb1W3Fp627oy5If5uXTIL1gse4MwSXlYibmzZmo3Zw/640?wx_fmt=png "")  
  
  
**DLL文件分析**  
  
****  
Ilzwngaiyktz文件为勒索功能模块，下面对该文件进行详细分析：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1O7ptWm7sUaLibC4dl12ZELmU1PhvFFhsXc5TUrOicYMnpibKHia8L3AZ9Q/640?wx_fmt=png "")  
  
****  
**Windows系统版本判断**  
  
****  
查看Windows系统版本，只针对Windows10、Windows11、Windows Server 2022系统进行加密  
  
  
该代码通过XOR解码过程遍历循环语句 (do-while)，并将勒索软件shllcode注入当前正在运行的白进程中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1TUYyc0HdJ6QOfM6KPEYvsPkh3xibxC4zTAxIe2oE8sDxumxtI9Kktfg/640?wx_fmt=png "")  
  
  
该病毒会释放DLL格式的文件，该文件导入表、执行主体在DLL主函数中，释放shellcode到内存并执行，无文件加载能够降低自身被内存代码检测引擎发现的风险，同时Magniber并不直接通过调用API实现相应功能，而是模拟相应API在ntdll中的行为，传入参数，然后指定syscall ID，直接调用syscall，同样可以实现直接调用系统API的作用。  
  
  
**反调试**  
  
****  
Magniber 使用 NtDelayExecution 以随机间隔休眠以逃避分析。随机休眠间隔可能会阻止沙盒或防病毒检测成功。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1albP8Cs0n4dRSS2o7egBVCABxfl1g6NOaJNQ2D1jq40xnlnFPB0TgA/640?wx_fmt=png "")  
  
  
**持久化**  
  
****  
在HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 注册表中添加一个键值，其中ouPBdEoNXxUS.3fr文件为密钥文件  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1ibmG9oR1NNqAmEXIsHDm3ntB6UicvFVLkTFyjyDQPuLYCUocFW4gCSZg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1ZXicyLSO9iaiblbUqibibf4AdTlk0cdwj6bHpIlNKSuF8iaaDx7FpznPzlNw/640?wx_fmt=png "")  
  
  
**绕过UAC**  
  
****  
在注册表中写入下载Magniber勒索软件的命令  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1IOxguKSnVhwZe9SDM48l9WqBxe1OO6jvVKibjpV2WjKlLqia1s2rlRmQ/640?wx_fmt=png "")  
  
  
上述写入注册表的内容能够实现，当系统重新启动时，注册到 Run 键的 .3fr 文件扩展名与指定同时激活的注册表一起执行，导致每次系统重新启动时都会下载Magniber勒索软件并实施加密活动。  
  
  
**高级远程线程注入**  
  
****  
blackbox.dll可用于绕过软件安全措施,一般用于注入恶意代码或执行其他非法操作。fwcwsp.dll 文件是 Windows 操作系统中的一个 DLL 文件，它是 Windows Firewall 的一部分，用于提供网络连接的安全性。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1LXiamT4AueRBxJVFdnb0ico58wicHcCOnn3jicRqCYFNXtz6LiaOVNxbFvg/640?wx_fmt=png "")  
  
  
**1、遍历进程**  
  
****  
解密代码后，首先会枚举受感染系统上所有正在运行的进程以识别勒索软件可以在其中注入shellcode的进程,Magniber将解压后的shellcode注入满足以下条件的进程  
  
  
进程名是否大于6字节  
  
该进程未在WoW64环境中运行。WoW64 是 Windows 操作系统的一个子系统，可以在 64 位 Windows 操作系统上执行 32 位应用程序  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE153b2OPOibicTPXaNPdnoibIPyXIa0UDhqqcbW3EkA1kaqQPMOvUY3d0rg/640?wx_fmt=png "")  
  
****  
**2、远程注入**  
  
****  
注入过程如下所示：  
  
NtOpenProcess：打开目标进程  
  
NtAllocateVirtualMemory：在目标进程中为即将写入的shellcode分配内存空间  
  
NtWriteVirtualMemory：将shellcode写入分配的内存区域。  
  
NtProtectVirtualMemory：修改内存保护属性  
  
NtCreateThreadEx：创建远程线程，执行shellcode  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1LSNcjpiawDx9sjjjcAaWMmIiahmGh9E00DLX7m5wqicibkgL2NsgzconCQ/640?wx_fmt=png "")  
  
  
随后将带有勒索加密功能的shellcode注入到符合条件的进程中（如：sihost.exe）RWX属性的内存中。但由于它使用系统调用，因而无法直接通过调试器监控内存写入来跟踪注入的shellcode。相反可以直接通过运行msi程序，然后使用procexp等进程监视器挂起进程然后dump写入的shellcode。  
  
   
  
通过查看该shellcode的字符串发现被混淆后的勒索信内容  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1tDqFO4APbklanhvqkOG8B9gCdfQ7sBesDZrK7amIxpMXSPr7EEibcIA/640?wx_fmt=png "")  
  
  
解除混淆后，内容如下所示：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1TWMFVibKLUnueBYGuAA3icvAyWdhWc3bzXbejPHbic8LG6wBFMHYtS6Dw/640?wx_fmt=png "")  
  
  
使用shellcode加载器加载注入的shellcode，然后使用x64dbg继续调试，发现在“C:\Users\Public”目录下释放RDTBADQ.xarh文件。  
  
  
**删除卷影**  
  
****  
执行VBS脚本，删除卷影副本，禁用Windows系统恢复功能。  
  
Wscript.exe /B /E:VBScript.Encode ../../Users/Public/RDTBADQ.xarh  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1WjQNW3xt67BxaTQpC72z5xvMJXFXLINGTD3iaMnhC1JvBby4ICOEhAw/640?wx_fmt=png "")  
  
  
在执行RDTBADQ.xarh文件时，文件被编码了，编码后文件内容如下图所示：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE115RP1HMxiaBOmaxLW9PAKeopxktQibFOxUlITnquE1lU3zqS9PIKDYtA/640?wx_fmt=png "")  
  
  
对VBS进行解码，解除一层混淆后  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1NoPibTYicQuMdMz2hibhTCVfLz6bSrVicByYSvnicaRZ6JrwlHicwyUa7mHg/640?wx_fmt=png "")  
  
  
解除二层混淆后  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1gV185GIzjOxmx0jQ5ZnFN5tiaeqvUfic7TPrK7CKerBkicKvliaJaquEfw/640?wx_fmt=png "")  
  
****  
**加密**  
  
****  
避免加密的目录和文件  
  
documents and settings/appdata/local settings/sample music/sample pictures/sample videos/tor browser/recycle/windows/boot/intel/msocache/perflogs/program files/programdata/recovery/system volume information/winnt/README.html  
  
**加密的文件后缀**  
  
****  
.abm/.abs/.abw/.accdb/.act/.adn/.adp/.aes/.aft/.afx/.agif/.agp/.ahd/.ai/.aic/.aim/.albm/.alf/.adn/.adp/.aes/.aft/.afx/.agif/.agp/.ahd/.ai/.aic/.aim/.albm/.alf/.ans/.apd/.apm/.apng/.aps/.agif/.agp/.ahd/.ai/.aic/.aim/.albm/.alf/.ans/.apd/.apm/.apng/.aps/.apt/.apx/.arc/.art/.arw/.aim/.albm/.alf/.ans/.apd/.apm/.apng/.aps/.apt/.apx/.arc/.art/.arw/.asc/.ase/.asf/.ask/.asm/.apm/.apng/.aps/.apt/.apx/.arc/.art/.arw/.asc/.ase/.asf/.ask/.asm/.asp/.asw/.asy/.aty/.avi/.arc/.art/.arw/.asc/.ase/.asf/.ask/.asm/.asp/.asw/.asy/.aty/.avi/.awdb/.awp/.awt/.aww/.azz/.asf/.ask/.asm/.asp/.asw/.asy/.aty/.avi/.awdb/.awp/.awt/.aww/.azz/.bad/.bak/.bay/.bbs/.bdb/.asy/.aty/.avi/.awdb/.awp/.awt/.aww/.azz/.bad/.bak/.bay/.bbs/.bdb/.bdp/.bdr/.bean/.bib/.bmp/.awt/.aww/.azz/.bad/.bak/.bay/.bbs/.bdb/.bdp/.bdr/.bean/.bib/.bmp/.bmx/.bna/.bnd/.boc/.bok/.bay/.bbs/.bdb/.bdp/.bdr/.bean/.bib/.bmp/.bmx/.bna/.bnd/.boc/.bok/.brd/.brk/.brn/.brt/.bss/.bean/.bib/.bmp/.bmx/.bna/.bnd/.boc/.bok/.brd/.brk/.brn/.brt/.bss/.btd/.bti/.btr/.c/.ca/.bnd/.boc/.bok/.brd/.brk/.brn/.brt/.bss/.btd/.bti/.btr/.c/.ca/.cals/.can/.cd/.cdb/.cdc/.brn/.brt/.bss/.btd/.bti/.btr/.c/.ca/.cals/.can/.cd/.cdb/.cdc/.cdg/.cdmm/.cdmt/.cdmz/.cdr/.btr/.c/.ca/.cals/.can/.cd/.cdb/.cdc/.cdg/.cdmm/.cdmt/.cdmz/.cdr/.cdt/.cf/.cfu/.cgm/.cimg/.cd/.cdb/.cdc/.cdg/.cdmm/.cdmt/.cdmz/.cdr/.cdt/.cf/.cfu/.cgm/.cimg/.cin/.cit/.ckp/.class/.clkw/.cdmt/.cdmz/.cdr/.cdt/.cf/.cfu/.cgm/.cimg/.cin/.cit/.ckp/.class/.clkw/.cma/.cmx/.cnm/.cnv/.colz/.cfu/.cgm/.cimg/.cin/.cit/.ckp/.class/.clkw/.cma/.cmx/.cnm/.cnv/.colz/.cpc/.cpd/.cpg/.cpp/.cps/.ckp/.class/.clkw/.cma/.cmx/.cnm/.cnv/.colz/.cpc/.cpd/.cpg/.cpp/.cps/.cpx/.crd/.crt/.crw/.cs/.cnm/.cnv/.colz/.cpc/.cpd/.cpg/.cpp/.cps/.cpx/.crd/.crt/.crw/.cs/.csr/.csv/.csy/.ct/.cvg/.cpg/.cpp/.cps/.cpx/.crd/.crt/.crw/.cs/.csr/.csv/.csy/.ct/.cvg/.cvi/.cvs/.cvx/.cwt/.cxf/.crt/.crw/.cs/.csr/.csv/.csy/.ct/.cvg/.cvi/.cvs/.cvx/.cwt/.cxf/.cyi/.dad/.daf/.db/.dbc/.csy/.ct/.cvg/.cvi/.cvs/.cvx/.cwt/.cxf/.cyi/.dad/.daf/.db/.dbc/.dbf/.dbk/.dbs/.dbt/.dbv/.cvx/.cwt/.cxf/.cyi/.dad/.daf/.db/.dbc/.dbf/.dbk/.dbs/.dbt/.dbv/.dbx/.dca/.dcb/.dch/.dcr/.daf/.db/.dbc/.dbf/.dbk/.dbs/.dbt/.dbv/.dbx/.dca/.dcb/.dch/.dcr/.dcs/.dct/.dcx/.dd/.dds/.dbs/.dbt/.dbv/.dbx/.dca/.dcb/.dch/.dcr/.dcs/.dct/.dcx/.dd/.dds/.ded/.der/.dgn/.dgs/.dgt/.dcb/.dch/.dcr/.dcs/.dct/.dcx/.dd/.dds/.ded/.der/.dgn/.dgs/.dgt/.dhs/.dib/.dif/.dip/.diz/.dcx/.dd/.dds/.ded/.der/.dgn/.dgs/.dgt/.dhs/.dib/.dif/.dip/.diz/.djv/.djvu/.dmi/.dmo/.dnc/.dgn/.dgs/.dgt/.dhs/.dib/.dif/.dip/.diz/.djv/.djvu/.dmi/.dmo/.dnc/.dne/.doc/.docb/.docm/.docx/.dif/.dip/.diz/.djv/.djvu/.dmi/.dmo/.dnc/.dne/.doc/.docb/.docm/.docx/.docz/.dot/.dotm/.dotx/.dpp/.dmi/.dmo/.dnc/.dne/.doc/.docb/.docm/.docx/.docz/.dot/.dotm/.dotx/.dpp/.dpx/.dqy/.drw/.drz/.dsk/.docb/.docm/.docx/.docz/.dot/.dotm/.dotx/.dpp/.dpx/.dqy/.drw/.drz/.dsk/.dsn/.dsv/.dt/.dta/.dtsx/.dotm/.dotx/.dpp/.dpx/.dqy/.drw/.drz/.dsk/.dsn/.dsv/.dt/.dta/.dtsx/.dtw/.dv/.dvi/.dwg/.dx/.drw/.drz/.dsk/.dsn/.dsv/.dt/.dta/.dtsx/.dtw/.dv/.dvi/.dwg/.dx/.dxb/.dxf/.eco/.ecw/.ecx/.dt/.dta/.dtsx/.dtw/.dv/.dvi/.dwg/.dx/.dxb/.dxf/.eco/.ecw/.ecx/.edb/.efd/.egc/.eio/.eip/.dvi/.dwg/.dx/.dxb/.dxf/.eco/.ecw/.ecx/.edb/.efd/.egc/.eio/.eip/.eit/.em/.emd/.emf/.emlx/.eco/.ecw/.ecx/.edb/.efd/.egc/.eio/.eip/.eit/.em/.emd/.emf/.emlx/.ep/.epf/.epp/.eps/.epsf/.egc/.eio/.eip/.eit/.em/.emd/.emf/.emlx/.ep/.epf/.epp/.eps/.epsf/.eq/.erf/.err/.etf/.etx/.emd/.emf/.emlx/.ep/.epf/.epp/.eps/.epsf/.eq/.erf/.err/.etf/.etx/.euc/.exr/.fa/.faq/.fax/.epp/.eps/.epsf/.eq/.erf/.err/.etf/.etx/.euc/.exr/.fa/.faq/.fax/.fb/.fbx/.fcd/.fcf/.fdf/.err/.etf/.etx/.euc/.exr/.fa/.faq/.fax/.fb/.fbx/.fcd/.fcf/.fdf/.fdr/.fds/.fdt/.fdx/.fdxt/.fa/.faq/.fax/.fb/.fbx/.fcd/.fcf/.fdf/.fdr/.fds/.fdt/.fdx/.fdxt/.fes/.fft/.fi/.fic/.fid/.fcd/.fcf/.fdf/.fdr/.fds/.fdt/.fdx/.fdxt/.fes/.fft/.fi/.fic/.fid/.fif/.fig/.fla/.flr/.flv/.fdt/.fdx/.fdxt/.fes/.fft/.fi/.fic/.fid/.fif/.fig/.fla/.flr/.flv/.fmv/.fo/.fodt/.fpos/.fpt/.fi/.fic/.fid/.fif/.fig/.fla/.flr/.flv/.fmv/.fo/.fodt/.fpos/.fpt/.fpx/.frm/.frt/.frx/.ftn/.fla/.flr/.flv/.fmv/.fo/.fodt/.fpos/.fpt/.fpx/.frm/.frt/.frx/.ftn/.fwdn/.fxc/.fxg/.fzb/.fzv/.fodt/.fpos/.fpt/.fpx/.frm/.frt/.frx/.ftn/.fwdn/.fxc/.fxg/.fzb/.fzv/.gcdp/.gdb/.gdoc/.gem/.geo/.frt/.frx/.ftn/.fwdn/.fxc/.fxg/.fzb/.fzv/.gcdp/.gdb/.gdoc/.gem/.geo/.gfb/.gfie/.ggr/.gif/.gih/.fxg/.fzb/.fzv/.gcdp/.gdb/.gdoc/.gem/.geo/.gfb/.gfie/.ggr/.gif/.gih/.gim/.gio/.glox/.gpd/.gpg/.gdoc/.gem/.geo/.gfb/.gfie/.ggr/.gif/.gih/.gim/.gio/.glox/.gpd/.gpg/.gpn/.gro/.grob/.grs/.gsd/.ggr/.gif/.gih/.gim/.gio/.glox/.gpd/.gpg/.gpn/.gro/.grob/.grs/.gsd/.gthr/.gtp/.gv/.gwi/.gz/.glox/.gpd/.gpg/.gpn/.gro/.grob/.grs/.gsd/.gthr/.gtp/.gv/.gwi/.gz/.h/.hbk/.hdb/.hdp/.hdr/.grob/.grs/.gsd/.gthr/.gtp/.gv/.gwi/.gz/.h/.hbk/.hdb/.hdp/.hdr/.hht/.his/.hp/.hpg/.hpi/.gv/.gwi/.gz/.h/.hbk/.hdb/.hdp/.hdr/.hht/.his/.hp/.hpg/.hpi/.hs/.htc/.hwp/.hz/.ib/.hdb/.hdp/.hdr/.hht/.his/.hp/.hpg/.hpi/.hs/.htc/.hwp/.hz/.ib/.ibd/.icn/.icon/.icpr/.idc/.hp/.hpg/.hpi/.hs/.htc/.hwp/.hz/.ib/.ibd/.icn/.icon/.icpr/.idc/.idea/.idx/.igt/.igx/.ihx/.hwp/.hz/.ib/.ibd/.icn/.icon/.icpr/.idc/.idea/.idx/.igt/.igx/.ihx/.ii/.iiq/.imd/.info/.ink/.icon/.icpr/.idc/.idea/.idx/.igt/.igx/.ihx/.ii/.iiq/.imd/.info/.ink/.ipf/.ipx/.iso/.itdb/.itw/.igt/.igx/.ihx/.ii/.iiq/.imd/.info/.ink/.ipf/.ipx/.iso/.itdb/.itw/.iwi/.j/.jar/.jas/.java/.imd/.info/.ink/.ipf/.ipx/.iso/.itdb/.itw/.iwi/.j/.jar/.jas/.java/.jbig/.jbmp/.jbr/.jfif/.jia/.iso/.itdb/.itw/.iwi/.j/.jar/.jas/.java/.jbig/.jbmp/.jbr/.jfif/.jia/.jis/.jng/.joe/.jpe/.jpeg/.jar/.jas/.java/.jbig/.jbmp/.jbr/.jfif/.jia/.jis/.jng/.joe/.jpe/.jpeg/.jpg/.jps/.jpx/.jrtf/.js/.jbr/.jfif/.jia/.jis/.jng/.joe/.jpe/.jpeg/.jpg/.jps/.jpx/.jrtf/.js/.jsp/.jtf/.jtx/.jw/.jxr/.joe/.jpe/.jpeg/.jpg/.jps/.jpx/.jrtf/.js/.jsp/.jtf/.jtx/.jw/.jxr/.kdb/.kdbx/.kdc/.kdi/.kdk/.jpx/.jrtf/.js/.jsp/.jtf/.jtx/.jw/.jxr/.kdb/.kdbx/.kdc/.kdi/.kdk/.kes/.ke/.kic/.klg/.knt/.jtx/.jw/.jxr/.kdb/.kdbx/.kdc/.kdi/.kdk/.kes/.ke/.kic/.klg/.knt/.kon/.kpg/.kwd/.lay/.lbm/.kdc/.kdi/.kdk/.kes/.ke/.kic/.klg/.knt/.kon/.kpg/.kwd/.lay/.lbm/.lbt/.ldf/.lgc/.lis/.lit/.kic/.klg/.knt/.kon/.kpg/.kwd/.lay/.lbm/.lbt/.ldf/.lgc/.lis/.lit/.ljp/.lmk/.lnt/.lrc/.lst/.kwd/.lay/.lbm/.lbt/.ldf/.lgc/.lis/.lit/.ljp/.lmk/.lnt/.lrc/.lst/.ltr/.ltx/.lue/.luf/.lwo/.lgc/.lis/.lit/.ljp/.lmk/.lnt/.lrc/.lst/.ltr/.ltx/.lue/.luf/.lwo/.lwp/.lws/.lyt/.lyx/.ma/.lnt/.lrc/.lst/.ltr/.ltx/.lue/.luf/.lwo/.lwp/.lws/.lyt/.lyx/.ma/.mac/.man/.map/.maq/.mat/.lue/.luf/.lwo/.lwp/.lws/.lyt/.lyx/.ma/.mac/.man/.map/.maq/.mat/.max/.mb/.mbm/.mbox/.mdb/.lyt/.lyx/.ma/.mac/.man/.map/.maq/.mat/.max/.mb/.mbm/.mbox/.mdb/.mdf/.mdn/.mdt/.me/.mef/.map/.maq/.mat/.max/.mb/.mbm/.mbox/.mdb/.mdf/.mdn/.mdt/.me/.mef/.mel/.mft/.mgcb/.mgmf/.mgmt/.mbm/.mbox/.mdb/.mdf/.mdn/.mdt/.me/.mef/.mel/.mft/.mgcb/.mgmf/.mgmt/.mgmx/.mgtx/.mid/.min/.mkv/.mdt/.me/.mef/.mel/.mft/.mgcb/.mgmf/.mgmt/.mgmx/.mgtx/.mid/.min/.mkv/.mm/.mmat/.mnr/.mnt/.mos/.mgcb/.mgmf/.mgmt/.mgmx/.mgtx/.mid/.min/.mkv/.mm/.mmat/.mnr/.mnt/.mos/.mov/.mpeg/.mpf/.mpg/.mpo/.mid/.min/.mkv/.mm/.mmat/.mnr/.mnt/.mos/.mov/.mpeg/.mpf/.mpg/.mpo/.mrg/.mrxs/.msg/.mud/.mwb/.mnr/.mnt/.mos/.mov/.mpeg/.mpf/.mpg/.mpo/.mrg/.mrxs/.msg/.mud/.mwb/.mwp/.mx/.my/.myd/.myi/.mpf/.mpg/.mpo/.mrg/.mrxs/.msg/.mud/.mwb/.mwp/.mx/.my/.myd/.myi/.ncr/.nct/.ndf/.nef/.nfo/.msg/.mud/.mwb/.mwp/.mx/.my/.myd/.myi/.ncr/.nct/.ndf/.nef/.nfo/.njx/.nlm/.now/.nrw/.nsf/.my/.myd/.myi/.ncr/.nct/.ndf/.nef/.nfo/.njx/.nlm/.now/.nrw/.nsf/.nyf/.nzb/.obj/.oce/.oci/.ndf/.nef/.nfo/.njx/.nlm/.now/.nrw/.nsf/.nyf/.nzb/.obj/.oce/.oci/.ocr/.odb/.odg/.odm/.odo/.now/.nrw/.nsf/.nyf/.nzb/.obj/.oce/.oci/.ocr/.odb/.odg/.odm/.odo/.odp/.ods/.odt/.of/.oft/.obj/.oce/.oci/.ocr/.odb/.odg/.odm/.odo/.odp/.ods/.odt/.of/.oft/.omf/.oplc/.oqy/.ora/.orf/.odg/.odm/.odo/.odp/.ods/.odt/.of/.oft/.omf/.oplc/.oqy/.ora/.orf/.ort/.orx/.ost/.ota/.otg/.odt/.of/.oft/.omf/.oplc/.oqy/.ora/.orf/.ort/.orx/.ost/.ota/.otg/.oti/.otp/.ots/.ott/.ovp/.oqy/.ora/.orf/.ort/.orx/.ost/.ota/.otg/.oti/.otp/.ots/.ott/.ovp/.ovr/.owc/.owg/.oyx/.ozb/.ost/.ota/.otg/.oti/.otp/.ots/.ott/.ovp/.ovr/.owc/.owg/.oyx/.ozb/.ozj/.ozt/.p/.pa/.pan/.ots/.ott/.ovp/.ovr/.owc/.owg/.oyx/.ozb/.ozj/.ozt/.p/.pa/.pan/.pano/.pap/.paq/.pas/.pbm/.owg/.oyx/.ozb/.ozj/.ozt/.p/.pa/.pan/.pano/.pap/.paq/.pas/.pbm/.pcd/.pcs/.pdb/.pdd/.pdf/.p/.pa/.pan/.pano/.pap/.paq/.pas/.pbm/.pcd/.pcs/.pdb/.pdd/.pdf/.pdm/.pds/.pdt/.pef/.pem/.paq/.pas/.pbm/.pcd/.pcs/.pdb/.pdd/.pdf/.pdm/.pds/.pdt/.pef/.pem/.pff/.pfi/.pfs/.pfv/.pfx/.pdb/.pdd/.pdf/.pdm/.pds/.pdt/.pef/.pem/.pff/.pfi/.pfs/.pfv/.pfx/.pgf/.pgm/.phm/.php/.pic/.pdt/.pef/.pem/.pff/.pfi/.pfs/.pfv/.pfx/.pgf/.pgm/.phm/.php/.pic/.pict/.pix/.pjpg/.pjt/.plt/.pfs/.pfv/.pfx/.pgf/.pgm/.phm/.php/.pic/.pict/.pix/.pjpg/.pjt/.plt/.pm/.pmg/.png/.pni/.pnm/.phm/.php/.pic/.pict/.pix/.pjpg/.pjt/.plt/.pm/.pmg/.png/.pni/.pnm/.pntg/.pnz/.pobj/.pop/.pot/.pjpg/.pjt/.plt/.pm/.pmg/.png/.pni/.pnm/.pntg/.pnz/.pobj/.pop/.pot/.potm/.potx/.ppam/.ppm/.pps/.png/.pni/.pnm/.pntg/.pnz/.pobj/.pop/.pot/.potm/.potx/.ppam/.ppm/.pps/.ppsm/.ppsx/.ppt/.pptm/.pptx/.pobj/.pop/.pot/.potm/.potx/.ppam/.ppm/.pps/.ppsm/.ppsx/.ppt/.pptm/.pptx/.prt/.prw/.psd/.psdx/.pse/.ppam/.ppm/.pps/.ppsm/.ppsx/.ppt/.pptm/.pptx/.prt/.prw/.psd/.psdx/.pse/.psid/.psp/.pst/.psw/.ptg/.ppt/.pptm/.pptx/.prt/.prw/.psd/.psdx/.pse/.psid/.psp/.pst/.psw/.ptg/.pth/.ptx/.pu/.pvj/.pvm/.psd/.psdx/.pse/.psid/.psp/.pst/.psw/.ptg/.pth/.ptx/.pu/.pvj/.pvm/.pvr/.pwa/.pwi/.pwr/.px/.pst/.psw/.ptg/.pth/.ptx/.pu/.pvj/.pvm/.pvr/.pwa/.pwi/.pwr/.px/.pxr/.pza/.pzp/.pzs/.qd/.pu/.pvj/.pvm/.pvr/.pwa/.pwi/.pwr/.px/.pxr/.pza/.pzp/.pzs/.qd/.qmg/.qpx/.qry/.qvd/.rad/.pwi/.pwr/.px/.pxr/.pza/.pzp/.pzs/.qd/.qmg/.qpx/.qry/.qvd/.rad/.rar/.ras/.raw/.rb/.rctd/.pzp/.pzs/.qd/.qmg/.qpx/.qry/.qvd/.rad/.rar/.ras/.raw/.rb/.rctd/.rcu/.rd/.rdb/.rft/.rgb/.qry/.qvd/.rad/.rar/.ras/.raw/.rb/.rctd/.rcu/.rd/.rdb/.rft/.rgb/.rgf/.rib/.ric/.riff/.ris/.raw/.rb/.rctd/.rcu/.rd/.rdb/.rft/.rgb/.rgf/.rib/.ric/.riff/.ris/.rix/.rle/.rli/.rng/.rpd/.rdb/.rft/.rgb/.rgf/.rib/.ric/.riff/.ris/.rix/.rle/.rli/.rng/.rpd/.rpf/.rpt/.rri/.rs/.rsb/.ric/.riff/.ris/.rix/.rle/.rli/.rng/.rpd/.rpf/.rpt/.rri/.rs/.rsb/.rsd/.rsr/.rst/.rt/.rtd/.rli/.rng/.rpd/.rpf/.rpt/.rri/.rs/.rsb/.rsd/.rsr/.rst/.rt/.rtd/.rtf/.rtx/.run/.rw/.rzk/.rri/.rs/.rsb/.rsd/.rsr/.rst/.rt/.rtd/.rtf/.rtx/.run/.rw/.rzk/.rzn/.saf/.sam/.sbf/.scad/.rst/.rt/.rtd/.rtf/.rtx/.run/.rw/.rzk/.rzn/.saf/.sam/.sbf/.scad/.scc/.sch/.sci/.scm/.sct/.run/.rw/.rzk/.rzn/.saf/.sam/.sbf/.scad/.scc/.sch/.sci/.scm/.sct/.scv/.scw/.sdb/.sdf/.sdm/.sam/.sbf/.scad/.scc/.sch/.sci/.scm/.sct/.scv/.scw/.sdb/.sdf/.sdm/.sdoc/.sdw/.sep/.sfc/.sfw/.sci/.scm/.sct/.scv/.scw/.sdb/.sdf/.sdm/.sdoc/.sdw/.sep/.sfc/.sfw/.sgm/.sh/.sig/.skm/.sla/.sdb/.sdf/.sdm/.sdoc/.sdw/.sep/.sfc/.sfw/.sgm/.sh/.sig/.skm/.sla/.sld/.sldm/.sldx/.slk/.sln/.sep/.sfc/.sfw/.sgm/.sh/.sig/.skm/.sla/.sld/.sldm/.sldx/.slk/.sln/.sls/.smf/.sms/.snt/.sob/.sig/.skm/.sla/.sld/.sldm/.sldx/.slk/.sln/.sls/.smf/.sms/.snt/.sob/.spa/.spe/.sph/.spj/.spp/.sldx/.slk/.sln/.sls/.smf/.sms/.snt/.sob/.spa/.spe/.sph/.spj/.spp/.spq/.spr/.sq/.sqb/.srw/.sms/.snt/.sob/.spa/.spe/.sph/.spj/.spp/.spq/.spr/.sq/.sqb/.srw/.ssa/.ssk/.st/.stc/.std/.sph/.spj/.spp/.spq/.spr/.sq/.sqb/.srw/.ssa/.ssk/.st/.stc/.std/.sti/.stm/.stn/.stp/.str/.sq/.sqb/.srw/.ssa/.ssk/.st/.stc/.std/.sti/.stm/.stn/.stp/.str/.stw/.sty/.sub/.suo/.svf/.st/.stc/.std/.sti/.stm/.stn/.stp/.str/.stw/.sty/.sub/.suo/.svf/.svg/.svgz/.swf/.sxc/.sxd/.stn/.stp/.str/.stw/.sty/.sub/.suo/.svf/.svg/.svgz/.swf/.sxc/.sxd/.sxg/.sxi/.sxm/.sxw/.tab/.sub/.suo/.svf/.svg/.svgz/.swf/.sxc/.sxd/.sxg/.sxi/.sxm/.sxw/.tab/.tar/.tbk/.tcx/.tdf/.tdt/.swf/.sxc/.sxd/.sxg/.sxi/.sxm/.sxw/.tab/.tar/.tbk/.tcx/.tdf/.tdt/.te/.tex/.text/.tgz/.thp/.sxm/.sxw/.tab/.tar/.tbk/.tcx/.tdf/.tdt/.te/.tex/.text/.tgz/.thp/.tif/.tiff/.tlb/.tlc/.tm/.tcx/.tdf/.tdt/.te/.tex/.text/.tgz/.thp/.tif/.tiff/.tlb/.tlc/.tm/.tmd/.tmv/.tmx/.tne/.tpc/.text/.tgz/.thp/.tif/.tiff/.tlb/.tlc/.tm/.tmd/.tmv/.tmx/.tne/.tpc/.trm/.tvj/.udb/.ufr/.unx/.tlb/.tlc/.tm/.tmd/.tmv/.tmx/.tne/.tpc/.trm/.tvj/.udb/.ufr/.unx/.uof/.uop/.uot/.upd/.usr/.tmx/.tne/.tpc/.trm/.tvj/.udb/.ufr/.unx/.uof/.uop/.uot/.upd/.usr/.utxt/.vb/.vbr/.vbs/.vcd/.udb/.ufr/.unx/.uof/.uop/.uot/.upd/.usr/.utxt/.vb/.vbr/.vbs/.vcd/.vct/.vdb/.vdi/.vec/.vm/.uot/.upd/.usr/.utxt/.vb/.vbr/.vbs/.vcd/.vct/.vdb/.vdi/.vec/.vm/.vmdk/.vmx/.vnt/.vob/.vpd/.vbr/.vbs/.vcd/.vct/.vdb/.vdi/.vec/.vm/.vmdk/.vmx/.vnt/.vob/.vpd/.vrm/.vrp/.vsd/.vsdm/.vsdx/.vdi/.vec/.vm/.vmdk/.vmx/.vnt/.vob/.vpd/.vrm/.vrp/.vsd/.vsdm/.vsdx/.vsm/.vstm/.vstx/.vue/.vw/.vnt/.vob/.vpd/.vrm/.vrp/.vsd/.vsdm/.vsdx/.vsm/.vstm/.vstx/.vue/.vw/.wav/.wbk/.wcf/.wdb/.wgz/.vsd/.vsdm/.vsdx/.vsm/.vstm/.vstx/.vue/.vw/.wav/.wbk/.wcf/.wdb/.wgz/.wire/.wks/.wma/.wmdb/.wmv/.vstx/.vue/.vw/.wav/.wbk/.wcf/.wdb/.wgz/.wire/.wks/.wma/.wmdb/.wmv/.wn/.wp/.wpa/.wpd/.wpg/.wcf/.wdb/.wgz/.wire/.wks/.wma/.wmdb/.wmv/.wn/.wp/.wpa/.wpd/.wpg/.wps/.wpt/.wpw/.wri/.wsc/.wma/.wmdb/.wmv/.wn/.wp/.wpa/.wpd/.wpg/.wps/.wpt/.wpw/.wri/.wsc/.wsd/.wsh/.wtx/.x/.xar/.wpa/.wpd/.wpg/.wps/.wpt/.wpw/.wri/.wsc/.wsd/.wsh/.wtx/.x/.xar/.xd/.xdb/.xlc/.xld/.xlf/.wpw/.wri/.wsc/.wsd/.wsh/.wtx/.x/.xar/.xd/.xdb/.xlc/.xld/.xlf/.xlgc/.xlm/.xls/.xlsb/.xlsm/.wtx/.x/.xar/.xd/.xdb/.xlc/.xld/.xlf/.xlgc/.xlm/.xls/.xlsb/.xlsm/.xlsx/.xlt/.xltm/.xltx/.xlw/.xlc/.xld/.xlf/.xlgc/.xlm/.xls/.xlsb/.xlsm/.xlsx/.xlt/.xltm/.xltx/.xlw/.xps/.xwp/.xyp/.xyw/.ya/.xls/.xlsb/.xlsm/.xlsx/.xlt/.xltm/.xltx/.xlw/.xps/.xwp/.xyp/.xyw/.ya/.ybk/.ym/.zabw/.zdb/.zdc/.xltm/.xltx/.xlw/.xps/.xwp/.xyp/.xyw/.ya/.ybk/.ym/.zabw/.zdb/.zdc/.zip/.zw/.xyp/.xyw/.ya/.ybk/.ym/.zabw/.zdb/.zdc/.zip/.zw/.zabw/.zdb/.zdc/.zip/.zw  
  
该样  
本采用典型的 RSA+AES模式结合的加密算法对文件进行加密，并且采用了多线程的方式加速加密过程，样本加密的总体流程如下：  
  
   
  
1) 遍历文件和文件夹，判断当前要加密的文件后缀是否在黑名单中，如果在则进行加密。  
  
2) 随机生成 AES 加密所需要的 Key 和 IV。  
  
3) 使用 AES 加密算法对当前文件进行加密。  
  
4) 使用使用 CryptoAPI通过内置的 RSA 公钥对 AES 的 Key 和 IV 进行加密，它每次迭代加密大小相等的数据块（1,048,576字节）  
  
5) 将被加密的文件添加扩展名 .mhkgchqs。  
  
6) 加密操作完成后，在各个文件夹下创建 README.html 勒索信。  
  
**IOCs**  
  
**Sha256**  
  
  
**MSI**  
  
e25443afb01606f6cbd8efdfc2eecb1c67d0c9122cc27b01dd28aecce50d4339  
  
1c290d16344bfb15ee27b6efc21dc973151c7c4a717ce254fe3c2554d258a3ed  
  
22bd495b318471d6183904e5f2bed598cb4ef685672350d51ab7bd53fe841277  
  
42db5cec13c4a0a1964dac11759029e59e3c819c282dbab6ecf266dfe24622ef  
  
77436ce13e345b39525806708becc20c3f527b8c1d5a84523bcbcef5d8c18102  
  
8efb4e8bc17486b816088679d8b10f8985a31bc93488c4b65116f56872c1ff16  
  
98d3fca413a3bbd7566b1fc26bf18e96ad590185a5e30355d4fb724c285a5f9c  
  
c0b21eb4ddfbd0138bc6a6b1dacdd7c70312e154da788abb4ab0abe6cabadf6b  
  
cf90ffcf978ec1d052d0a6c2365273f1cac9966eff066baffca0db9d48640f25  
  
  
**DLL**  
  
07c8ab61570fe9ec86e168aa96c58fe24246b35db78241fe7c83928ed559b3f6  
  
1c303d6ba7fd9dc1c84bf5311657d0ea08924fe59ea047055f9e6341de1f8931  
  
1deaa7f390951217266bbb432f62b7d54823ac525687024aee4bbc24c5bea943  
  
3aa29b6b4a9e39b3c3f3f12ca56cbe19178815c6d4d86c9f14d463dd21fc773e  
  
441634c99c59f57271a68c841fa4ab33e01762d4991e7465e6bd37ef7305356e  
  
586294d477b30613fbb31cf222d16cf2396ba9ce5d5665b6556a5901c248c50f  
  
7a46fe71b140677f1eb29da8ae6f72f9636e2f53e8f49cd81ebb38e54bf8c65c  
  
a05352ca7f5049f607d26785e5d42fa51df0b158db4fc1db2b2f91eb4762e46d  
  
defed38da9110f4820f60f3545384202ada94e97676301f15ef298f3fe876575  
  
  
**ip**  
  
45.32.88.152  
  
  
**ATT&CK**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1Ahj7qEd3qIrjQkK9rxvtyyZB2zhxiaCcicLJJBHUeKgV95BwIAdyLbXw/640?wx_fmt=png "")  
  
****  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1sibqLX2ibgZqR5sNbKEgVqCjVJzDHQ42vUerGzG4Szd6Qm3jve42uiaBw/640?wx_fmt=gif "")  
  
**处置建议**  
  
1、避免打开可疑或来历不明的邮件，尤其是其中的链接和附件等，如一定要打开未知文件，请先使用杀毒软件进行扫描查杀。  
  
2、重要的数据最好双机备份或云备份。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1sibqLX2ibgZqR5sNbKEgVqCjVJzDHQ42vUerGzG4Szd6Qm3jve42uiaBw/640?wx_fmt=gif "")  
  
**深信服解决方案**  
  
**【深信服终端检测响应平台EDR】**  
  
已支持查杀拦截此次事件使用的病毒文件，请更新软件（如有定制请先咨询售后再更新版本）和病毒库至最新版本，并接入深信服安全云脑，及时查杀新威胁；  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1tQ2Fd6A7LMlVO2gA8pPPt5vLiaqLa0qZyBS0tsAD1QDHibXohfjRzQPA/640?wx_fmt=png "")  
  
  
**【深信服下一代防火墙AF】**的安全防护规则更新至最新版本，接入深信服安全云脑，“云鉴” 服务即可轻松抵御此高危风险。**【深信服安全感知管理平台SIP】**建议用户及时更新规则库，接入深信服安全云脑，并联动【深信服下一代防火墙AF】实现对高危风险的入侵防护。**【深信服安全托管服务MSS】**以保障用户网络安全“持续有效”为目标，通过将用户安全设备接入安全运营中心，依托于XDR安全能力平台和MSSP安全服务平台实现有效协同的“人机共智”模式，围绕资产、脆弱性、威胁、事件四个要素为用户提供7*24H的安全运营服务，快速扩展持续有效的安全运营能力，保障可承诺的风险管控效果。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5w1DEJPGanlE1YaM3oK7NE1aa0s8bTwAofRUicLXiaT0hPLgKUTcslYLKJ8cHHKePkkebesVNPibednQ/640?wx_fmt=jpeg "")  
  
  
  
