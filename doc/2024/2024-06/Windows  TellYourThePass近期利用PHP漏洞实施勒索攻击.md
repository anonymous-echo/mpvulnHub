#  Windows | TellYourThePass近期利用PHP漏洞实施勒索攻击   
Tahir  TahirSec   2024-06-17 20:31  
  
TellYouThePass勒索组织，最早于2019年3月开始活动。根据历史攻击活动线索推测，TellYouThePass组织为国内黑产组织，常利用Web远程命令执行漏洞如，“永恒之蓝”系列漏洞、WebLogic应用漏洞、Log4j2漏洞、某OA系统漏洞等下发勒索软件，自动化实施勒索攻击。  
  
该组织19年至24年间歇性活动，基本上只利用高可利用漏洞被披露后，漏洞补丁发布或修补前的时间窗口进行攻击。  
  
今年6月，PHP CGI 远程代码执行漏洞（CVE-2024-4577）POC披露后，TellYouThePass勒索组织又开始活动，利用该漏洞扫描公网PHP服务器，下发勒索软件。  
  
本次攻击活动TellYouThePass勒索组织，组合使用  
开源攻击套件，如DotNetToJScript、EfsPotato提权、  
RealBlindingEDR致盲EDR、asmloader加载等，自动化完成勒索攻击。攻击流程如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwic2ib13XoG4WQXHR5IU6HM5AHmhTZVysk1mZyh7ydpU1rj1eh4sL3TO1Q/640?wx_fmt=png&from=appmsg "")  
  
有趣的是勒索信中直接建议受害者去电商平台找数据解密的中间商完成解密交易，提高其勒索的成功率。  
## 1. 攻击入口点d3.hta  
  
今年6月，TellYouThePass勒索组织利用PHP CGI 远程代码执行漏洞（CVE-2024-4577）EXP，扫描公网PHP服务器，下发d3.hta。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwic9X6gQOuwaicVia4LRPiawDjjKghUHKRogS8v0ydMYpDRjEvyqgZJnS0bA/640?wx_fmt=png&from=appmsg "")  
  
d3.hta使用DotNetToJScript项目，将.NET程序转换为JScript代码，利用mshta程序远程内存加载hta文件，实现无文件攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwicjAvYY254xWbF8E2HXDqOicYvZhL3n0TrkDsDDQZ9ibCbSpz6XxFAfGKQ/640?wx_fmt=png&from=appmsg "")  
  
解开base64里面为.NET序列化数据，但还是能截取到原始.NET程序。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwicvofcUIsAqmTrqtwgr5lTbibMZ8iaeEwMvFp6YFd8KYcPCwVibAuUa87Rw/640?wx_fmt=png&from=appmsg "")  
## 2. 权限提升EfsPotato  
  
导出数据后发现是基于开源的权限提升组件EfsPotato修改的.NET程序。EfsPotato集合了多种提权组件BadPotato，EfsPotato，GodPotato，PingCastle，Potato，PrintNotifyPotato，PrintNotifyPotato，PrintNotifyPotato。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwic6B7EvWfOl9QFMfHlUFU9FW1V0fXKyMX1ToGhE4XBsfrbj6E9p8Kojw/640?wx_fmt=png&from=appmsg "")  
  
该程序依次执行EDR致盲模块、加载器、勒索模块。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwiceHgHI0Iq8ze0qDCEMM2CMXwKeGkQiaibqpyUZS0VAwfG1WUaJKvHMvsA/640?wx_fmt=png&from=appmsg "")  
## 3. EDR致盲模块RealBlind  
  
EfsPotato在TEMP目录下释放2个带有合法签名bin文件，其文件的CueckSum字段是随机生成的，在不影响签名有效性下，规避EDR只对文件HASH检测。利用开源组件asmloader加载bin文件和shellcode。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwicRhdJZJ25iaahGaq5xibHevBdPoZfibpT7OO5Ur8LgTczPYqGsLdE30XOw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwic1BPj2thak2hbPFdk7qFqq2TwQCOFnbG70xd28586TmAnlOHV9c3Bwg/640?wx_fmt=png&from=appmsg "")  
  
shellcode为开源工具RealBlindingEDR。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwicrUH2sBTnZ6J6qWG5vWvDharAROl2KOWCZwhibsAxiaC5N2icnVsaiaf5icw/640?wx_fmt=png&from=appmsg "")  
  
利用驱动摘除回调（PsSetCreateProcessNotifyRoutine、PsSetCreateThreadNotifyRoutine、PsSetLoadImageNotifyRoutine、ObRegisterCallbacks 、CmRegisterCallback、MiniFilter）用于致盲EDR。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwicaFFvfsypW5CexkicIo0fQudOQt1OFchrB77HHNKCE8EHHmOqqhx4VYg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwicGzmLRn0Sp8PwTVYvz73Yic6w2vFnO3QaU6COJbyUTibNSyOkic6vPNSgw/640?wx_fmt=png&from=appmsg "")  
  
释放加载的驱动文件为echo_driver.sys。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwic1l72U9OXV8Mr7nMDRiaIQQcJQQYCJYGMckxicCVhdicXAudwL26ScIlzA/640?wx_fmt=png&from=appmsg "")  
## 4. 加载器loaderpe  
  
回到EfsPotato程序，致盲EDR后在TEMP目录释放2个文件，分别为加载器loaderpe和被加密的勒索模块EncDll。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwicIFgLIYX4Vxx8CM2ibduNibw5mjrQlO32AGYzOJvpnt1WxGEbuGmW041A/640?wx_fmt=png&from=appmsg "")  
  
Base64解码后的勒索模块EncDll数据，使用AES加密算法进行加密操作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwic6LLoV33ibd267xNZSkFQP2jNyAmictTIVia5v8AUUQ8XPegcyEfkstyGQ/640?wx_fmt=png&from=appmsg "")  
  
最终调用cmd执行加载器loaderpe，传递key和IV参数加载勒索模块EncDll。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwic4IO8hNz3CkVBTuVFo2iaS3ezHJ2e5XOibh2lHFrKO3fNAPxrRQrz5gHA/640?wx_fmt=png&from=appmsg "")  
  
加载器loaderpe，读取bin文件（EncDll）数据、获取密钥key和初始向量IV参数值，利用.NET Assembly机制反射加载，执行最终勒索模块。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwicWuoEHOqDb99eYPvFDjIa6nU7AhkMCYTKfJxI9bNdeyCxESfeyXj3JQ/640?wx_fmt=png&from=appmsg "")  
  
勒索模块EncDll，通过密钥key和初始向量IV进行AES解密操作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwiceENiawJnXzgGKvMvTLicTVddB9kZn8xfRQK2T0nf2wPHibVVXicy2TVBfg/640?wx_fmt=png&from=appmsg "")  
## 5. 勒索模块EncDll  
  
首先通过WindnowsUpgradeProcessN信号量判断勒索模式是否已经运行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwicPz8TLUJpuDDiajnO6eia7OyQWibpzb2fxWvic6NORXZyA4LRacYZBbn64g/640?wx_fmt=png&from=appmsg "")  
  
向C2服务器发送执行期间的情况。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwic9lLcvwR3Tcz5n1rMbV4wIYz1DrLfzlrRXuzlhEhd7ibiaDKYtW9KckEg/640?wx_fmt=png&from=appmsg "")  
  
停止或结束数据库相关的进程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwicydPHpg1UXA5Kibianp5Bpza5go0bqV8PFxzqUicm8dQ2fW6jcmu97KxMQ/640?wx_fmt=png&from=appmsg "")  
  
生成随机RSA公钥和私钥，用于本次勒索攻击；在ALLUSERSPROFILE或HOMEDRIVE目录下生成pubkey12.txt、show12.txt、hellotest1.txt、more12.txt文件。  
- pubkey12.txt文件保存着使用攻击者的公钥personPubKey，RSA加密的主机当前时间和主机基本信息的数据；  
  
- show12.txt文件保存着使用攻击者的公钥personPubKey，RSA加密的用于勒索的私钥数据，为了攻击者以后解密受害者主机数据；  
  
- hellotest1.txt文件只用于测试勒索模块是否已经运行；  
  
- more12.txt文件暂未使用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwicA8ribR8P6FC48S6kCtd1OSze3hQib9WVRJx4jS3oZX4urBJjMJFiaEYmw/640?wx_fmt=png&from=appmsg "")  
  
读取USERPROFILE 、PUBLIC、HOMEPATH、各个逻辑分区下的目录文件，进行加密操作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwicjVDB1chT2VF42zQd12Xe4kcB0rOb2BXFVs9rxcEQqVoJZovQUYJxibQ/640?wx_fmt=png&from=appmsg "")  
  
加密过程跳过包含pubkey.txt、show.txt、READ_ME9.html字符串的文件，以及包含以下字符串的目录：  
```
"EFI.Boot","EFI.Microsoft",":.Windows","All Users","Boot","IEidcache","ProgramData","desktop.ini","autorun.inf","netuser.dat","ntuser.dat","bootsect.bak","iconcache.db","thumbs.db","Local Settings","bootfont.bin","System Volume Information","AppData","Recycle.Bin",":.Recovery","Windows\\System32","Windows\\System","Windows\\SysWOW64","Windows\\security","WindowsPowerShell","Windows\\assembly","Windows\\Microsoft.NET","Windows\\Fonts","Windows\\IME","Windows\\boot","Windows\\inf","show","pubkey","READ_ME","README"
```  
  
加密包含以下后缀名的文件：  
```
1cd,3dm,3ds,3fr,3g2,3gp,3pr,602,7z,ps1,7zip,aac,ab4,accdb,accde,accdr,accdt,ach,acr,act,adb,adp,ads,aes,agdl,ai,aiff,ait,al,aoi,apj,arc,arw,asc,asf,asm,asp,aspx,asx,avi,awg,back,backup,backupdb,bak,bank,bat,bay,bdb,bgt,bik,bin,bkp,blend,bmp,bpw,brd,c,cdf,cdr,cdr3,cdr4,cdr5,cdr6,cdrw,cdx,ce1,ce2,cer,cfg,cgm,cib,class,cls,cmd,cmt,conf,config,contact,cpi,cpp,cr2,craw,crt,crw,cs,csh,csl,csr,css,csv,dac,dat,db,db3,db_journal,dbf,dbx,dc2,dch,dcr,dcs,ddd,ddoc,ddrw,dds,der,des,design,dgc,dif,dip,dit,djv,djvu,dng,doc,docb,docm,docx,dot,dotm,dotx,drf,drw,dtd,dwg,dxb,dxf,dxg,edb,eml,eps,erbsql,erf,exf,fdb,ffd,fff,fh,fhd,fla,flac,flf,flv,flvv,fpx,frm,fxg,gif,gpg,gray,grey,groups,gry,gz,h,hbk,hdd,hpp,html,hwp,ibank,ibd,ibz,idx,iif,iiq,incpas,indd,java,jnt,jpe,jpeg,jpg,jsp,jspx,ashx,js,kc2,kdbx,kdc,key,kpdx,kwm,laccdb,lay,lay6,ldf,lit,log,lua,m,m2ts,m3u,m4p,m4u,m4v,mapimail,max,mbx,md,mdb,mdc,mdf,mef,mfw,mid,mkv,mlb,mml,mmw,mny,moneywell,mos,mov,mp3,mp4,mpeg,mpg,mrw,ms11,msg,myd,myi,nd,ndd,ndf,nef,nk2,nop,nrw,ns2,ns3,ns4,nsd,nsf,nsg,nsh,nvram,nwb,nx2,nxl,nyf,oab,obj,odb,odc,odf,odg,odm,odp,ods,odt,ogg,oil,orf,ost,otg,oth,otp,ots,ott,p12,p7b,p7c,pab,pages,paq,pas,pat,pcd,pct,pdb,pdd,pdf,pef,pem,pfx,php,pif,pl,plc,plus_muhd,png,pot,potm,potx,ppam,pps,ppsm,ppsx,ppt,pptm,pptx,prf,ps,psafe3,psd,pspimage,pst,ptx,pwm,py,qba,qbb,qbm,qbr,qbw,qbx,qby,qcow,qcow2,qed,r3d,raf,rar,rat,raw,rb,rdb,rm,rtf,rvt,rw2,rwl,rwz,s3db,safe,sas7bdat,sav,save,say,sch,sd0,sda,sdf,sh,sldm,sldx,slk,sql,sqlite,sqlite3,sqlitedb,sr2,srf,srt,srw,st4,st5,st6,st7,so,st8,stc,std,sti,stm,stw,stx,svg,swf,sxc,sxd,sxg,sxi,sxm,sxw,tar,tar.bz2,tbk,tex,tga,tgz,thm,tif,tiff,tlg,txt,uop,uot,vb,vbox,vbs,vdi,vhd,vhdx,vmdk,vmsd,vmx,vmxf,vob,wab,wad,wallet,war,wav,wb2,wk1,wks,wma,wmv,wpd,wps,x11,x3f,xis,xla,xlam,xlc,xlk,xlm,xlr,xls,xlsb,xlsm,xlsx,xlt,xltm,xltx,xlw,xml,ycbcra,yuv,zip
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwic7oqAnAphUicQWnTCCHEymmVZOs0HvibQ6sdD2nOe1Q1Qf1Ms86S2IAjA/640?wx_fmt=png&from=appmsg "")  
  
攻击者的C2服务器地址、攻击者的公钥、BTC钱包地址、邮箱、勒索信名称、加密文件后缀名.locked。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwicS3VO1OdJZaB69AxqchJo7ORShqHjibdfoSc7T6T2AHlbfDNe5mSSGNA/640?wx_fmt=png&from=appmsg "")  
  
勒索信内容，提示受害者通过电商平台联系数据解密的中间商完成解密交易。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bTmZNzhzqratjDd1iajkMSraJMoiaicqvwicXXH4zFnQ9J2icUQqC94kNVsklKib5ibqaNZjsbATGycJIbq4iaibWD9kPLQ/640?wx_fmt=png&from=appmsg "")  
## IoC  
  
88.218.76.13  
  
bc1qnuxx83nd4keeegrumtnu8kup8g02yzgff6z53l  
  
service@cyberkiller.xyz  
  
BgIAAACkAABSU0ExAAQAAAEAAQABo5INMgvZRHU+odxc8HTZUnsValb+zVbnhjhUK0Smo6MnGNYvaQY6vN9j5viFHTfCgu0NculsfILwXtUVUn8WqEHjm0xfbsKl93uazKHzyuiiepA5ggNHgGbZ5vnpo5MKE3ykwdqYPst8ULxCZNPCdu3kK2PKC2li150Dl8e2zA==  
  
262d0c43b9204fdfc4a575bc85d7f019  
  
4563a3d29574740f60a4d2ca0d6ee263  
  
abdc87d7b415ad0a3bde1b0ae426fd1b  
  
6d448cba987a24c3ddbde760d76c5a15  
  
d8cc5986811b4f9c034313d80660334c  
  
dba0c214cee715b3dfe871ef5ed1cb95  
  
9756c914712292d5dbeb5593c5eb5ceb  
  
