#  近 20 年来 OpenSSH 的第一个高危 RCE！   
 刨洞之眼   2024-07-01 21:55  
  
Qualys 威胁研究部门（TRU）在基于 glibc 的 Linux 系统中的 OpenSSH 服务器（sshd）中发现了一个远程未经身份验证的代码执行（RCE）漏洞。分配给此漏洞的 CVE 为 CVE-2024-6387  
  
该漏洞是 OpenSSH 服务器（sshd）中的信号处理程序争用条件，允许在基于 glibc 的 Linux 系统上以 root 身份执行未经身份验证的远程代码执行（RCE）;这带来了重大的安全风险。此争用条件会影响 sshd 的默认配置。  
  
## 受影响版本  
  
  
version < 4.4p1  
  
8.5p1 <= version < 9.8p1  
  
## 修复  
  
  
等待官方补丁更新到最新版  
  
如果 sshd 无法更新或重新编译，请在配置文件中将 LoginGraceTime 设置为 0。这会通过用完所有 MaxStartups 连接将 sshd 暴露在拒绝服务中，但它可以防止远程代码执行风险。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HWREJselCribXKZnW4g6I2gicDlib73KLnWBMib7xPga814txqfxcPWBtkYhkXX3BVdG42szWtx3eib5YmzeeuoibE1Q/640?wx_fmt=png "")  
  
  
  
  
  
  
  
关注公众号后台回复 0001  
 领取Windows   
Proxifier激活码，0002  
 领取Mac   
Proxifier激活码，0003  
 获取无需登录在线即用的New Bing地址，0004  
   
获取CobaltStrike4.9.1破解版  
，0005  
   
获取VMware Pro 17.5永久Key  
，0006  
   
获取现代亚洲APT组织TTP报告  
，0007  
 获取IDA Pro 8.3 keygen，0008获取AWVS v24.1破解版  
  
  
加我微信好友，邀请你进交流群  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaHPCQdRh2mD7k15P3gvI6IxzUohyGZicOqn7LDO0yXmtSuZtNh9gWULo1m2N435YwLmtlMFQibzTAuB4d4dMbjMw/640?wx_fmt=png "")  
  
  
  
文章号，欢迎关注  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfTd6rd9CyvNRMW8I9cvI1CK5gKiaYqg2veTn9t9dAe1GxYic7pAvgvRIKNFickConFyX8AvW2reAq8GchJI6aBpA/640?wx_fmt=gif "")  
  
  
  
