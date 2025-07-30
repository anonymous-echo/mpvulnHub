#  【漏洞预警】Rsync缓冲区溢出漏洞风险通告   
原创 MasterC  企业安全实践   2025-01-20 02:17  
  
## 一、漏洞描述  
  
Rsync是一个用于文件同步和传输的命令行工具，广泛用于UNIX和Linux系统。Rsync Daemon（Rsyncd）则是Rsync提供的服务端进程（需要手动开启），主要用于远程文件同步、公开镜像站管理以及数据分发等场景。  
  
近日，互联网上披露了关于Rsync中存在一个缓冲区溢出漏洞，在受影响版本中，由于Rsync对用户控制的校验和长度 (s2length)处理不当，攻击者只需要拥有对Rsync服务器匿名读取的权限，通过向开放在互联网上的Rsync服务端口（默认873/TCP）发送特定探测或恶意请求包来触发该漏洞，成功利用该漏洞可在Rsyncd上远程执行任意操作。该漏洞对应的CVE编号为CVE-2024-12084和CVE-2024-12085，该漏洞危害较高，请受影响用户做好安全加固。  
## 二、漏洞等级  
  
高  
## 三、影响范围  
  
CVE-2024-12084：3.2.6 <= version <= 3.3.9  
  
CVE-2024-12085：version <= 3.3.9  
## 四、安全版本  
  
version >= 3.4.0  
## 五、修复建议  
  
目前官方已修复该漏洞，建议受影响用户尽快前往官网升级至安全版本。  
## 六、缓解方案  
  
修改Rsyncd的配置，添加 auth users 和 secrets file 配置，并创建包含用户和密码的密码文件，禁止 Rsync 的匿名读取权限。  
## 七、参考链接  
  
https://lists.samba.org/archive/Rsync-announce/2025/000120.html  
  
https://www.openwall.com/lists/oss-security/2025/01/14/3  
  
https://download.samba.org/pub/rsync/NEWS  
  
  
