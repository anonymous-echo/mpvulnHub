#  OpenSSH漏洞预警：无需用户交互，可提权至 root   
 FreeBuf   2024-07-02 19:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39gF1icmjhPwHiactKvDYdZOlW8kjficbJ0EEjjHCibxKic60DfrCHCXIkVKYFlIgc5icl9TTYNfY1wyNTw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39gF1icmjhPwHiactKvDYdZOlic2JNGl07z31VwsRct7uSLsnTnQN2Vs73GFfdQs1SARvxcHibxUgokfQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JZsjTFuKtyGmHzPq6cM1naaNrsCpJo1cqXI3QSDutjDZr8cuicDXTrkC2ZrCzXLhvRaNJr5YfTxls/640?wx_fmt=svg&from=appmsg "")  
  
左右滑动查看更多  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JZsjTFuKtyGmHzPq6cM1naaNrsCpJo1cqXI3QSDutjDZr8cuicDXTrkC2ZrCzXLhvRaNJr5YfTxls/640?wx_fmt=svg&from=appmsg "")  
  
  
  
OpenSSH 自 1995 年问世近 20 年来，首次出现了未经验证的远程执行（RCE）漏洞，攻击者可以提权至 root 最高权限，在不需要用户交互的情况下执行任意代码。  
  
  
OpenSSH 是一套基于 Secure Shell（SSH）协议的网络实用程序，广泛用于安全远程登录、管理远程服务器，通过 scp 或 sftp 备份、远程文件传输等功能。  
  
  
2024年5月，网络安全公司 Qualys首次发现并报告该漏洞，编号 CVE-2024-6387，存在于 OpenSSH 服务器（sshd）中，由于信号处理器竞赛条件存在缺陷，可以让未经认证的远程攻击者以 root 用户身份执行任意代码。  
  
  
7 月，网上公开披露了一个 OpenSSH 的远程代码执行漏洞（CVE-2024-6387）。鉴于该漏洞虽然利用较为困难但危害较大，建议所有使用受影响的企业尽快修复该漏洞。  
  
  
**漏洞描述**  
  
  
##   
### 漏洞成因  
  
  
CVE-2024-6387 是 OpenSSH 服务器中的一个严重漏洞，影响基于 glibc 的 Linux 系统。默认配置下的OpenSSH Server (sshd)中存在信号处理程序竞争条件漏洞，如果客户端未在LoginGraceTime 秒内（默认情况下为 120 秒，旧版 OpenSSH 中为 600 秒）进行身份验证，则 sshd 的 SIGALRM 处理程序将被异步调用，但该信号处理程序会调用各种非async-signal-safe的函数（例如syslog()），威胁者可利用该漏洞在基于 glibc 的 Linux 系统上以root 身份实现未经身份验证的远程代码执行。  
  
### 漏洞影响  
  
  
成功利用该漏洞的攻击者可以以 root 身份进行未经身份验证的远程代码执行 (RCE)。在某些特定版本的 32 位操作系统上，攻击者最短需 6-8 小时即可获得最高权限的 root shell。而在 64 位机器上，目前没有在可接受时间内的利用方案，但未来的改进可能使其成为现实。  
  
- 处置优先级：高  
  
- 漏洞类型：远程代码执行  
  
- 漏洞危害等级：高  
  
- 触发方式：网络远程  
  
- 权限认证要求：无需权限  
  
- 系统配置要求：默认配置可利用  
  
- 用户交互要求：无需用户交互  
  
- 利用成熟度：部分 EXP 已公开（适配单一版本，32 位系统）  
  
- 批量可利用性：可使用通用原理 POC/EXP 进行检测/利用  
  
- 修复复杂度：中，官方提供升级修复方案  
  
###   
### 影响版本  
  
  
8.5p1 <= OpenSSH < 9.8p1  
  
OpenBSD系统不受该漏洞影响  
  
### 缓解措施  
  
1. 可以在配置文件中将 LoginGraceTime 设置为 0（永不超时）。这样虽然会使 sshd 暴露于拒绝服务攻击（占满所有 Startups 连接），但可以避免远程代码执行风险。  
  
1. 启用 fail2ban 等防护机制，封禁发生过多次失败登录 ssh 尝试的来源 IP。  
  
###   
### 升级修复方案  
  
  
将 OpenSSH 更新到最新版本 9.8 或者各发行版本的修复版本。  
  
  
注：资料来源于互联网  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494513&idx=1&sn=d121e4f2e20b5ccd61ecf0ad3d8c2106&chksm=ce1f11eef96898f81380d9a50b1420949d8ab4fb9df77944c1d0a9368a1aa2df63106b75b47b&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493976&idx=1&sn=70a35df0a9bd52d9ac09818483ff8810&chksm=ce1f13c7f9689ad10260fd6af11bcf78034d697b75e295281d4d5ce4a941d42ec8a24b9fc044&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
