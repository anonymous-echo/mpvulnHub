#  【勒索防护】Tellyouthepass利用国内知名视频监控厂商漏洞卷土重来   
原创 深盾终端实验室  深信服千里目安全技术中心   2023-11-24 14:53  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xrCbEqJiaibH6wYrNcKvzazC8b6MHBsAHIcddom0VmOb8QB7ZI18KH8lSQkRBRRkVI1vfyMD7unZ3g/640?wx_fmt=gif&from=appmsg "")  
  
**恶意文件家族：**  
  
Tellyouthepass  
  
**威胁类型：**  
  
勒索病毒  
  
**简单描述：**  
  
Tellyouthepass勒索病毒于2019年3月首次在国外出现，同年4月在国内被首次发现，早期利用永恒之蓝漏洞攻击套件扩散传播，之后通过 Log4j2 漏洞、Shiro反序列化漏洞等执行任意代码，从而控制受害主机。该家族针对 Windows 和 Linux 实现双平台勒索，多次活跃直接导致国内多个企业大面积业务停摆。  
  
  
  
  
  
**恶意文件描述**  
  
最近，深信服深盾终端实验室收到了来自海内外多家单位的勒索应急求助。经过分析发现，大量主机遭受了不定向的勒索攻击。经过排查，我们发现本轮攻击为Tellyouthepass 勒索家族利用了国内某知名视频监控厂商综合安防管理平台的任意文件上传漏洞，获取了服务器权限，在/opt/*/web/components/tomcat85linux64.1/webapps/els/static 目录下上传 1424 大小的 12 个随机字符串命名的 webshell 文件，随后批量投放了勒索病毒。  
  
  
**恶意文件分析**  
  
  
样本启动后，会加密系统中的文件，并释放勒索信以诱使受害者通过勒索信中的联系方式与攻击者进行沟通及缴纳赎金，被加密文件添加特定扩展“.locked1”，勒索信文件名“README2.html”或者“READ_ME4.html”,勒索信中展示受害者可以通过邮箱与攻击者取得联系。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5xrCbEqJiaibH6wYrNcKvzazCUMjt7LEglx9flzgqLMOcf9zTMlNrT4pqzziaJwvcKY4ceTYb1twzxdQ/640?wx_fmt=png&from=appmsg "")  
  
  
通过查看进程，我们发现 mshta.exe 执行了可疑的进程。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5xrCbEqJiaibH6wYrNcKvzazCeORgPich8thBz1kMf2CicbIt8FD3TaLJW615A8xF4l0o71TCBzGicsYhg/640?wx_fmt=png&from=appmsg "")  
  
  
从下载缓存中拷贝出 debug2.hta 文件后，发现该文件采用 VBScript 编写。在文件中，存在使用 Base64ToStream 函数将经过 Base64 编码的字符串转换为 MemoryStream 对象，并随后使用 BinaryFormatter 对象进行反序列化的代码。这种技术可能被用于执行反序列化攻击，其中恶意序列化数据被传递给应用程序，从而导致恶意代码执行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5xrCbEqJiaibH6wYrNcKvzazCib31LgKRrmwJRtu58NtLpEgFyGzib2JuB2gjnp5DHOT0aDR2yKyNZFvQ/640?wx_fmt=png&from=appmsg "")  
  
  
根据提取的恶意可执行文件发现，该文件是使用 .NET 编译的。对该文件进行分析后发现，其中使用了 RSAUtil 类来生成 RSA 密钥对，并针对指定系统路径下的文件进行加密处理，随后将加密后的数据重新写入文件，删除初始文件。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5xrCbEqJiaibH6wYrNcKvzazCPiaf8o0IjyljY5xGia60bCHSxXYhqSkV1j8BYm8auxiaxUZNdY6yPeMmA/640?wx_fmt=png&from=appmsg "")  
  
  
获取系统信息包括主机名、用户名、处理器数量、.NET Framework 版本以及主机的 IP 地址列表。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5xrCbEqJiaibH6wYrNcKvzazCicwQ3PicLl6IygtEOwhOAcM24PHC93GXmg6H6fUDdqw2WgjZ7TQL250Q/640?wx_fmt=png&from=appmsg "")  
  
  
创建名为 "WindowsUpgradeProcessN" 的互斥量，以确保只有一个实例在运行，避免勒索软件重复运行造成冲突或文件损坏。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5xrCbEqJiaibH6wYrNcKvzazCicU9sBR9wJPzl2xc7mXSGQ1Y6OPcNiaDvQuRlnv0osyJfWibVTpEYcsibQ/640?wx_fmt=png&from=appmsg "")  
  
  
使用 HTTP 请求将之前收集到的受害者系统信息发送到攻击者的 C&C 服务器。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5xrCbEqJiaibH6wYrNcKvzazCN1SB71SU8icuafkTUe0KVuLwz2M4HRDu6XuHMYmKo98VU7Koll9uMZQ/640?wx_fmt=png&from=appmsg "")  
  
  
加密以下文件类型  
  
  
1  
cd,  
3  
dm,  
3  
ds,  
3f  
r,  
3  
g2,  
3  
gp,  
3  
pr,  
602  
,  
7  
z,ps1,  
7  
zip,aac,ab4,accdb,accde,accdr,accdt,ach,acr,act,adb,adp,ads,aes,agdl,ai,aiff,ait,al,aoi,apj,arc,arw,asc,asf,asm,asp,aspx,asx,avi,awg,back,backup,backupdb,bak,bank,bat,bay,bdb,bgt,bik,bin,bkp,blend,bmp,bpw,brd,c,cdf,cdr,cdr3,cdr4,cdr5,cdr6,cdrw,cdx,ce1,ce2,cer,cfg,cgm,cib,  
class  
,cls,cmd,cmt,conf,config,contact,cpi,cpp,cr2,craw,crt,crw,cs,csh,csl,csr,css,csv,dac,dat,db,db3,db_journal,dbf,dbx,dc2,dch,dcr,dcs,ddd,ddoc,ddrw,dds,der,des,design,dgc,dif,dip,dit,djv,djvu,dng,doc,docb,docm,docx,dot,dotm,dotx,drf,drw,dtd,dwg,dxb,dxf,dxg,edb,eml,eps,erbsql,erf,exf,fdb,ffd,fff,fh,fhd,fla,flac,flf,flv,flvv,fpx,frm,fxg,gif,gpg,gray,grey,groups,gry,gz,h,hbk,hdd,hpp,html,hwp,ibank,ibd,ibz,idx,iif,iiq,incpas,indd,jar,java,jnt,jpe,jpeg,jpg,jsp,jspx,ashx,js,kc2,kdbx,kdc,key,kpdx,kwm,laccdb,lay,lay6,ldf,lit,log,lua,m,m2ts,m3u,m4p,m4u,m4v,mapimail,max,mbx,md,mdb,mdc,mdf,mef,mfw,mid,mkv,mlb,mml,mmw,mny,moneywell,mos,mov,mp3,mp4,mpeg,mpg,mrw,ms11,msg,myd,myi,nd,ndd,ndf,nef,nk2,nop,nrw,ns2,ns3,ns4,nsd,nsf,nsg,nsh,nvram,nwb,nx2,nxl,nyf,oab,obj,odb,odc,odf,odg,odm,odp,ods,odt,ogg,oil,orf,ost,otg,oth,otp,ots,ott,p12,p7b,p7c,pab,pages,paq,pas,pat,pcd,pct,pdb,pdd,pdf,pef,pem,pfx,php,pif,pl,plc,plus_muhd,png,pot,potm,potx,ppam,pps,ppsm,ppsx,ppt,pptm,pptx,prf,ps,psafe3,psd,pspimage,pst,ptx,pwm,py,qba,qbb,qbm,qbr,qbw,qbx,qby,qcow,qcow2,qed,r3d,raf,rar,rat,raw,rb,rdb,rm,rtf,rvt,rw2,rwl,rwz,s3db,safe,sas7bdat,sav,save,say,sch,sd0,sda,sdf,sh,sldm,sldx,slk,sql,sqlite,sqlite3,sqlitedb,sr2,srf,srt,srw,st4,st5,st6,st7,so,st8,stc,std,sti,stm,stw,stx,svg,swf,sxc,sxd,sxg,sxi,sxm,sxw,tar,tar.bz2,tbk,tex,tga,tgz,thm,tif,tiff,tlg,txt,uop,uot,vb,vbox,vbs,vdi,vhd,vhdx,vmdk,vmsd,vmx,vmxf,vob,wab,wad,wallet,war,wav,wb2,wk1,wks,wma,wmv,wpd,wps,x11,x3f,xis,xla,xlam,xlc,xlk,xlm,xlr,xls,xlsb,xlsm,xlsx,xlt,xltm,xltx,xlw,xml,ycbcra,yuv,zip  
  
  
避免加密目录或者包含如下字符串的文件名的文件  
  
  
EFI  
.Boot  
,  
EFI  
.Microsoft  
,  
Program  
   
Files  
,:.Windows,  
All  
   
Users  
,  
Boot  
,  
IEidcache  
,  
ProgramData  
,  
desktop  
.ini  
,  
autorun  
.inf  
,  
netuser  
.dat  
,  
ntuser  
.dat  
,  
bootsect  
.bak  
,  
iconcache  
.db  
,  
thumbs  
.db  
,  
Local  
   
Settings  
,  
bootfont  
.bin  
,  
System  
   
Volume  
   
Information  
,  
AppData  
,  
Recycle  
.Bin  
,:.Recovery,  
Windows  
\\  
System32  
,  
Windows  
\\  
System  
,  
Windows  
\\  
SysWOW64  
,  
Windows  
\\  
security  
,  
Windows  
\\  
Microsoft  
.NET  
,  
Windows  
\\  
Fonts  
,  
Windows  
\\  
IME  
,  
Windows  
\\  
boot  
,  
Windows  
\\  
inf  
,  
show  
,  
pubkey  
,  
READ_ME  
,  
README  
  
  
终止服务，终止了SQL Server、MySQL 、 Message Queuing、RabbitMQ等服务，禁用目标系统上的数据库和消息传递服务，以使系统无法正常运行或访问关键数据，从而迫使受害者支付赎金以恢复服务或数据访问权限。  
  
  
execute  
 net   
stop  
 mssqlserver   
  
execute  
 net   
stop  
 msmq   
  
execute  
 net   
stop  
 mysql   
  
execute  
 net   
stop  
 rabbitmq   
  
  
终止进程，包括数据库服务进程（如 msftesql.exe, sqlagent.exe, sqlbrowser.exe, sqlservr.exe, oracle.exe, mysqld.exe 等）、办公软件进程（如 excel.exe, infopath.exe, msaccess.exe, winword.exe 等）、邮件客户端进程（如 outlook.exe, thunderbird.exe 等）以及其他常见软件进程（如 steam.exe, wordpad.exe 等）。  
  
  
execute  
 taskkill /f /im msftesql.exe   
  
execute  
 taskkill /f /im sqlagent.exe   
  
execute  
 taskkill /f /im sqlbrowser.exe   
  
execute  
 taskkill /f /im sqlservr.exe   
  
execute  
 taskkill /f /im sqlwriter.exe   
  
execute  
 taskkill /f /im oracle.exe   
  
execute  
 taskkill /f /im ocssd.exe   
  
execute  
 taskkill /f /im dbsnmp.exe   
  
execute  
 taskkill /f /im synctime.exe   
  
execute  
 taskkill /f /im mydesktopqos.exe   
  
execute  
 taskkill /f /im agntsvc.exeisqlplussvc.exe   
  
execute  
 taskkill /f /im xfssvccon.exe   
  
execute  
 taskkill /f /im mydesktopservice.exe   
  
execute  
 taskkill /f /im ocautoupds.exe   
  
execute  
 taskkill /f /im agntsvc.exeagntsvc.exe   
  
execute  
 taskkill /f /im agntsvc.exeencsvc.exe   
  
execute  
 taskkill /f /im firefoxconfig.exe   
  
execute  
 taskkill /f /im tbirdconfig.exe   
  
execute  
 taskkill /f /im ocomm.exe   
  
execute  
 taskkill /f /im mysqld.exe   
  
execute  
 taskkill /f /im mysqld-nt.exe   
  
execute  
 taskkill /f /im mysqld-opt.exe   
  
execute  
 taskkill /f /im dbeng50.exe   
  
execute  
 taskkill /f /im sqbcoreservice.exe   
  
execute  
 taskkill /f /im excel.exe   
  
execute  
 taskkill /f /im infopath.exe   
  
execute  
 taskkill /f /im msaccess.exe   
  
execute  
 taskkill /f /im mspub.exe   
  
execute  
 taskkill /f /im onenote.exe   
  
execute  
 taskkill /f /im outlook.exe   
  
execute  
 taskkill /f /im powerpnt.exe   
  
execute  
 taskkill /f /im steam.exe   
  
execute  
 taskkill /f /im sqlservr.exe   
  
execute  
 taskkill /f /im thebat.exe   
  
execute  
 taskkill /f /im thebat64.exe   
  
execute  
 taskkill /f /im thunderbird.exe   
  
execute  
 taskkill /f /im visio.exe   
  
execute  
 taskkill /f /im winword.exe   
  
execute  
 taskkill /f /im wordpad.exe   
  
execute  
 taskkill /f /im tnslsnr.exe   
  
  
删除卷影  
  
  
execute  
 vssadmin   
delete  
 shadows /  
all  
   
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xrCbEqJiaibH6wYrNcKvzazCjS4KcsYSz108vPJnxz6hQabsCyickQaWgKbBqaxO7GsmBFbPyL7j2XA/640?wx_fmt=gif&from=appmsg "")  
  
**ATT&ck**  
  
<table><tbody><tr style="height:4.5000pt;"><td width="79" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">TA</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">阶段</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="27" valign="top" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top-width: 1pt;border-top-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">T</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">技术</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="87" valign="top" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top-width: 1pt;border-top-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">S</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">技术</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="241" valign="top" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top-width: 1pt;border-top-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">动作</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td></tr><tr style="height:20.0000pt;"><td width="99" valign="center" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">初始访问</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">TA0001<o:p></o:p></span></section></td><td width="27" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1190<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">利用面向公众的应用程序</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="87" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">N/A<o:p></o:p></span></section></td><td width="261" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">利用<span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">HKWS</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">综合安防管理平台漏洞获取初始访问权限</span></span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td></tr><tr style="height:20.0000pt;"><td width="99" valign="center" rowspan="2" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">TA0002<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">执行</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"> </span></section></td><td width="27" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1059<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">系统服务</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="87" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1059.003<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">Windows<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">Command Shell<o:p></o:p></span></section></td><td width="261" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">使用一系列</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">Windows</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">命令，如</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">vssadmin </span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">、</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">taskkill </span>等</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td></tr><tr style="height:13.2500pt;"><td width="141" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1106<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">原生</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">API</span></span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);"><o:p></o:p></span></span></section></td><td width="20" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">N/A<o:p></o:p></span></section></td><td width="192" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">使用多个系统</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">API </span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">函数</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td></tr><tr><td width="99" valign="center" rowspan="2" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: 宋体;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">TA0005<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">防御规避</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="27" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1140<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">解密或解混淆文件和信息</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="87" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">N/A<o:p></o:p></span></section></td><td width="261" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">使用</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">base64</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">编码</span></span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td></tr><tr><td width="141" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1070<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">指标清除</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="20" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1070.004<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">文件删除</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="192" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">勒索程序执行后，删除勒索相关文件</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td></tr><tr><td width="99" valign="center" rowspan="3" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="text-align: justify;line-height: 1.6em;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">TA0007<o:p></o:p></span></section><section style="text-align: justify;line-height: 1.6em;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">发现</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="27" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1057<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">枚举进程</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="87" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">N/A<o:p></o:p></span></section></td><td width="261" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">枚举当前系统环境中所有正在运行的进程</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td></tr><tr><td width="141" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1083<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">文件和目录发现</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="20" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">N/A<o:p></o:p></span></section></td><td width="192" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">查询指定的文件、文件夹和文件后缀</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td></tr><tr><td width="141" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1082<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">系统信息发现</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="20" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">N/A<o:p></o:p></span></section></td><td width="192" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: 宋体;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">获取系统信息包括主机名、用户名、处理器数量、<span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">.NET Framework </span>版本以及主机的 <span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">IP </span>地址列表。<o:p></o:p></span></section></td></tr><tr><td width="99" valign="center" rowspan="2" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;letter-spacing: 1px;text-decoration: none;">横向移动<span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">TA0008</span><o:p></o:p></span></section></td><td width="27" valign="center" rowspan="2" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="text-align: justify;line-height: 1.6em;margin: 0px;text-indent: 0em;"><span style="font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">T1021</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;font-family: 宋体;color: rgb(110, 107, 107);"><o:p></o:p></span></span></section><section style="text-align: justify;line-height: 1.6em;margin: 0px;text-indent: 0em;"><span style="font-family: 宋体;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">远程服务<o:p></o:p></span></section><section style="text-align: justify;line-height: 1.6em;margin: 0px;text-indent: 0em;"><span style="font-family: 宋体;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"> </span></section></td><td width="87" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1021.004<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;letter-spacing: 1px;text-decoration: none;">SSH<o:p></o:p></span></section></td><td width="261" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">使用<span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">SSH</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">登录到内网其他机器</span></span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td></tr><tr><td width="134" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: 宋体;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1021.002<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">SMB/Windows</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">管理员共享</span></span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;font-family: 宋体;color: rgb(110, 107, 107);"><o:p></o:p></span></span></section></td><td width="194" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">使用<span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">SMB</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">横向移动</span></span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td></tr><tr><td width="99" valign="center" rowspan="2" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: 宋体;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">命令与控制<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">TA0011</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;"><o:p></o:p></span></span></section></td><td width="27" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: 宋体;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1102<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">入口工具传输</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="87" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">N/A<o:p></o:p></span></section></td><td width="261" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">将当前受害机器作为</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">FTP</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">服务器，通过</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">FTP</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">将</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">Tellyouthepass</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">传播到内网其他机器</span></span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td></tr><tr><td width="141" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: 宋体;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1071<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: 宋体;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">应用层协议<o:p></o:p></span></section></td><td width="20" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1071.001<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">Web</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">协议</span></span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="192" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">使用</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">HTTP</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">请求将收集到的信息传输到</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;">C&amp;C</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">服务器</span></span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td></tr><tr><td width="99" valign="center" rowspan="3" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="text-align: justify;line-height: 1.6em;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">影响</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;letter-spacing: 1px;text-decoration: none;">TA0040<o:p></o:p></span></section></td><td width="27" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1490<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">禁止系统恢复</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="87" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">N/A<o:p></o:p></span></section></td><td width="261" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">删除卷影副本</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td></tr><tr style="height:30.1500pt;"><td width="141" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1489<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">终止服务</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="20" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">N/A<o:p></o:p></span></section></td><td width="192" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">终止与数据库、办公软件等相关的进程和服务</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td></tr><tr><td width="141" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">T1486<o:p></o:p></span></section><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: 宋体;">为影响而加密的数据</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;color: rgb(110, 107, 107);font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></section></td><td width="20" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="font-family: &#34;Times New Roman&#34;;color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;">N/A<o:p></o:p></span></section></td><td width="192" valign="center" style="padding: 0pt 5.4pt;border-left: none;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;word-break: break-all;"><section style="line-height: 1.6em;text-align: justify;margin: 0px;text-indent: 0em;"><span style="color: rgb(110, 107, 107);font-size: 15px;letter-spacing: 1px;text-decoration: none;"><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;font-family: 宋体;color: rgb(110, 107, 107);">加密计算机上的文件</span><span style="text-decoration: none;letter-spacing: 1px;font-size: 15px;font-family: &#34;Times New Roman&#34;;color: rgb(0, 0, 0);"><o:p></o:p></span></span></section></td></tr></tbody></table>  
  
**IOC**  
  
  
MD5  
  
5b32e7326712bb4219f6d6f8ad976609  
（  
hta  
）  
  
e8f42e43ec16d9d5ca97d04c4a7fc88c  
（提取出的  
exe  
）  
  
IP  
  
80.92.205.18  
1  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xrCbEqJiaibH6wYrNcKvzazCjS4KcsYSz108vPJnxz6hQabsCyickQaWgKbBqaxO7GsmBFbPyL7j2XA/640?wx_fmt=gif&from=appmsg "")  
  
**处置建议**  
  
  
1. 为本地和域账户设置强密码策略，定期更改账号密码  
  
2. 及时更新操作系统和软件，使用杀毒软件定期查杀。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xrCbEqJiaibH6wYrNcKvzazCjS4KcsYSz108vPJnxz6hQabsCyickQaWgKbBqaxO7GsmBFbPyL7j2XA/640?wx_fmt=gif&from=appmsg "")  
  
**深信服解决方案**  
  
  
**【深信服统一端点安全管理系统aES】**已支持查杀拦截此次事件使用的病毒文件，aES全新上线“动静态双AI引擎”，静态AI能够在未知勒索载荷落地阶段进行拦截，动态AI则能够在勒索载荷执行阶段进行防御，通过动静态AI双保险机制可以更好地遏制勒索蔓延。不更新也能防护；但建议更新最新版本，取的更好防护效果。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5xrCbEqJiaibH6wYrNcKvzazCHLgCLbXQTEmOruTXR77EV5icicet2gnVfa2YXkibsn7hEYQuLfDJB1Epw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5xrCbEqJiaibH6wYrNcKvzazCTnohia85uokhPCycTCIog3kMPAhGdj2Ng8qTT5Pw5OXUABlck2vSkqA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
