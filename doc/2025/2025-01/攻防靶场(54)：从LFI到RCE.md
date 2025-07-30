#  攻防靶场(54)：从LFI到RCE   
原创 罗锦海  OneMoreThink   2025-01-29 00:04  
  
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
  
    3.1 利用漏洞提权：可写文件  
  
    3.2 滥用特权控制机制：Sudo和Sudo缓存  
  
公众号后台回复   
20250129 获取靶场下载地址。  
## 1. 侦查  
### 1.1 收集目标网络信息：IP地址  
  
靶机启动后，没有提供IP地址。由于Kali和靶机在同一个C段，可以扫描ARP协议获取靶机IP地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBDzBOjV8ickPziaUSQXEGUkic3E2qHyI4bf3qjDMqe2Vqhia1RjV9F8w59A/640?wx_fmt=png&from=appmsg "")  
### 1.2 主动扫描：扫描IP地址段  
  
对靶机进行全端口扫描、服务扫描、版本扫描，发现22/SSH、80/HTTP。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBjrThclIzcRib3WpnU9icnM7vGsjU9J8HeLA7bVvabqjfAFiaqvfBm5woA/640?wx_fmt=png&from=appmsg "")  
### 1.3 主动扫描：字典扫描  
  
扫描80/HTTP服务的目录和页面，发现/console/目录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBdvaHIpGFLeBk4ShbXPPqX36d0NKSulvbHficWkaWVmAJpIn1e9WzUsA/640?wx_fmt=png&from=appmsg "")  
  
访问/console/目录，发现file.php文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXB47UGUSx2pFq9WMDKfrfFPaWLP3R5icEQqHc4BBUhROIREuLmqFwqJ7Q/640?wx_fmt=png&from=appmsg "")  
## 2. 初始访问  
### 2.1 利用面向公众的应用  
  
访问/console/file.php文件，返回空白。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBiaXS8ZInuHZWGO44KiborSG8qsaPbmxupucxVctyzM23IEy17W7I5zuw/640?wx_fmt=png&from=appmsg "")  
  
猜测文件file.php的功能是打开文件，可能存在文件包含漏洞。尝试爆破打开文件的参数，成功获得参数file。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBbN1UL5uKGOPdXmgtBumnCXoL7deVDNr04orvcfdasiccfnicew28mn3w/640?wx_fmt=png&from=appmsg "")  
  
爆破操作系统中的文件，发现22/SSH服务的访问日志。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBicNFR4yQrsibvZ7Fibn89JIlYljSlV8Qyq4IX08Ubpd41p7xibc2F69rcg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBxEEpWLxicnfEXxOfPLg59mdibjNibAQQLyuwvCMwhicSgOaEHTQm66x4rg/640?wx_fmt=png&from=appmsg "")  
  
向22/SSH服务的访问日志投毒，成功写入webshell。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBWYtVTrCZ2Cx1Tx2CD2Msrw9dC0DNdcyaGIex8S7XewWPLftYGovtGQ/640?wx_fmt=png&from=appmsg "")  
  
连接webshell，**获得www-data用户权限。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBic6UzribrtO3YPcrjbRgoVZclUdTRyALSVuFBO6WiaVsAZr9K3icicBIdEQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBgPC9Egicg9GGEWibdT3jxBKTgG64vAsMdFB8G5cQuCLOMz13NKWcezMg/640?wx_fmt=png&from=appmsg "")  
## 3. 权限提升  
### 3.1 利用漏洞提权：可写文件  
  
任何用户都能编辑Apache服务的配置文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBJyZxZJCrUXzFOcu6o3bWjq8MFXtteTv9gC6qDjdYK9vapy1053eiaCg/640?wx_fmt=png&from=appmsg "")  
  
编辑配置文件，修改启动Apache服务的用户和用户组。经测试，无法使用root用户启动Apache服务，natraj用户无法提权到root用户，因此将启动Apache服务的用户修改为mahakal。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBkUdbpmoUCX0HrEN5XF0X18K8G2U6YDvxGKh08ZdmwmdnvPRic0uaCog/640?wx_fmt=png&from=appmsg "")  
  
重启靶机，从而重启Apache服务。重新连接webshell，**获得mahakal用户权限。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBzFdjjJ0hm3M864f2K9dfPP3ibYD1Ngbeod0vq6AA2yHYDHmX9hVn8sw/640?wx_fmt=png&from=appmsg "")  
### 3.2 滥用特权控制机制：Sudo和Sudo缓存  
  
mahakal用户能以root用户的权限执行nmap命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBoBnFsKeXDsLmiaCSnYzZyKF940oUrW7tMyib80pa4A0uGWETpKGWdAgQ/640?wx_fmt=png&from=appmsg "")  
  
nmap命令能用于提权。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBAOiciaSuCJDNtkCXUOdmqMEqaKk7XcpSSsh657uJlfs1FZExrdOGY1Vw/640?wx_fmt=png&from=appmsg "")  
  
使用nmap命令提权，**获得root用户权限。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBnicP8uvpySp6j1gBnwwRXK5VfIDoAg4t9iam8ZOPTNRLU5rR2l8kO2cg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92TMXvkvgG0YgLrZdJ0rBXBWxC9SgfmPbsb3r7b4kqjkVhJaYgAULub6IawPza3pK8chc0IpolZqg/640?wx_fmt=png&from=appmsg "")  
  
  
