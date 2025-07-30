> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2Mzg2NDM0NA==&mid=2247485361&idx=1&sn=1848475721009d2894847479ed3a090c

#  Notepad++ 存在严重权限提升漏洞及白加黑  
 柠檬赏金猎人   2025-06-25 00:00  
  
Notepad++8.8.1版本中发现的一个严重权限提升漏洞，该漏洞编号为CVE-2025-49144。利用此漏洞，攻击者可通过二进制植入技术获取SYSTEM级权限，进而完全控制系统，也可以作为白加黑进行利用。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OkRKg4J9smVZql0hkh4YOfC305Y2YFE9bCWePfOY8hLVDOcWHgP5ohRiaXibGXZInb7Jt3pNQTqqkDOPEfNtkZIQ/640?wx_fmt=png "")  
  
  
攻击者可通过在Notepad++安装程序目录放置恶意可执行文件(如篡改的regsvr32.exe)，当用户运行安装程序时，系统会自动以SYSTEM权限加载恶意文件，使攻击者获得完全控制权。  
  
  
Notepad++开发团队迅速做出响应，发布8.8.2版本修复该关键漏洞。建议更新到修复版本。  
  
  
仅限交流学习使用，如您在使用本工具或代码的过程中存在任何非法行为，您需自行  
承担相应后果，我们将不承担任何法律及连带责任。  
“如侵权请私聊公众号删文”。  
  
  
  
  
