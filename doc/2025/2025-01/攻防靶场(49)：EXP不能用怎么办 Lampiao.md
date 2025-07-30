#  攻防靶场(49)：EXP不能用怎么办 Lampiao   
原创 罗锦海  OneMoreThink   2025-01-23 16:00  
  
欢迎提出宝贵**建议**  
、欢迎**分享**  
文章、欢迎**关注**  
公众号 OneMoreThink 。  
  
目录  
  
1. 侦查  
  
    1.1 收集目标网络信息：IP地址  
  
    1.2 主动扫描：扫描IP地址段  
  
    1.3 主动扫描：字典扫描  
  
2. 初始访问  
  
    2.1 利用面向公众的应用  
  
3. 权限提升  
  
    3.1 利用漏洞提权：操作系统内核  
  
靶场下载地址：https://www.vulnhub.com/entry/lampiao-1,249/  
## 1. 侦查  
### 1.1 收集目标网络信息：IP地址  
  
靶机启动后，没有提供IP地址。由于Kali和靶机在同一个C段，可以扫描ARP协议获取靶机IP地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91MCvzSf6NuibiaS0XnpuzSTr2sE1SLsn4uzjBlTIelEe3GM2EicvRWuX2kprfaT8AASGfPmjKbBg53w/640?wx_fmt=png&from=appmsg "")  
### 1.2 主动扫描：扫描IP地址段  
  
对靶机进行全端口扫描、服务扫描、版本扫描，发现22/SSH、80/HTTP、1898/HTTP。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91MCvzSf6NuibiaS0XnpuzSTrCsGxIbXlVv3mnlWCTADreVgRQictMVHGRiaLNLhdMFPZP55hFvgv9ofw/640?wx_fmt=png&from=appmsg "")  
### 1.3 字典扫描  
  
扫描80/HTTP、1898/HTTP的目录和页面，发现1898/HTTP服务存在/robots.txt页面。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91MCvzSf6NuibiaS0XnpuzSTrLLWoqzbonvsTgsbxEq00z4e8GicnDiciaARTwia0ic67rEbZwwsWTGBV7Qg/640?wx_fmt=png&from=appmsg "")  
  
逐个访问/robots.txt页面中的目录和页面，在/CHANGELOG.txt页面中，发现Drupal的版本是7.54。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91MCvzSf6NuibiaS0XnpuzSTrzNdXN1FuyiawLWjS2icYQjLRaHwia98BjWDcupRt60aVVvEdSCRjEHYQQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91MCvzSf6NuibiaS0XnpuzSTrj0P1u5CMTicmDfkiaeSQXXCEy35QpfbxprFzYLVKpU32FvMiapBHhGaOQ/640?wx_fmt=png&from=appmsg "")  
## 2. 初始访问  
### 2.1 利用面向公众的应用  
  
7.54版本的Drupal存在RCE漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91MCvzSf6NuibiaS0XnpuzSTrQzwibz7oAo82icJicwuEwic5eYGK8t7a4btp1qHicJMv6BPD2YuYicNaD12g/640?wx_fmt=png&from=appmsg "")  
  
所有非MSF的EXP只有一个ruby脚本可用，但会报错，需先 sudo gem install highline 安装依赖，然后利用EXP可以**获得www-data用户权限。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91MCvzSf6NuibiaS0XnpuzSTrXwzlNrfjc2IEFneOg3lBqM8Y0ccMNrmiaYZJ85UtGJErl0gB7BSiaAHA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91MCvzSf6NuibiaS0XnpuzSTr2QaALvIG3UA6pRPMolPSJRDuMh6Q4p5SnoenSe9xncHETCxhrNLRCQ/640?wx_fmt=png&from=appmsg "")  
## 3. 权限提升  
### 3.1 利用漏洞提权：操作系统内核  
  
查看操作系统的内核版本和发行版本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91MCvzSf6NuibiaS0XnpuzSTrAccsgVXEh0bTz9TfqWXQmOyJz4LiaNEnibc9lnSHql5TcAAVg4dvQARA/640?wx_fmt=png&from=appmsg "")  
  
发现该内核版本和发行版本存在提权漏洞，但逐个利用EXP，均失败。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91MCvzSf6NuibiaS0XnpuzSTrlgsPIMYFia25Bjyym8iaq787CodXKkStbrfTibT5ROdqQ5vhHWXIaLdFg/640?wx_fmt=png&from=appmsg "")  
  
需要更换内核提权EXP，先上传linpeas.sh到靶机中，赋予权限后执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91MCvzSf6NuibiaS0XnpuzSTrJp4I6kg9sB4yIib5OvoJVCuriajrNz08nmx4ts54jCMtms2fa4LiacnkA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91MCvzSf6NuibiaS0XnpuzSTrLxjj8CwbUic4ZLF5SwRRibXBNRnzqfIeAMSHch4YhNKCU1iatx9o2uXug/640?wx_fmt=png&from=appmsg "")  
  
对于linpeas.sh识别到的内核提权EXP，把有need的去掉，看来可以尝试一下脏牛。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91MCvzSf6NuibiaS0XnpuzSTrDAQCQo6V6Mn1s1tXE8eHxFKCuKyzhfsicGibWY6aicqIRibUFt2ohHdI5w/640?wx_fmt=png&from=appmsg "")  
  
上传脏牛EXP，赋予权限后执行，EXP会修改root用户密码，最终可以**获得root用户权限。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91MCvzSf6NuibiaS0XnpuzSTr0AKuy4xpHwaIrsJibF3Ho6nNg2fdtdc2OoAu7eOicsIUB3LCicibibHECxA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91MCvzSf6NuibiaS0XnpuzSTrB8Gt0FBwlgYJsWXFL9mRjGTK4EiaTrwxQgQbdGickmgtbfRLSn97bbUw/640?wx_fmt=png&from=appmsg "")  
  
  
