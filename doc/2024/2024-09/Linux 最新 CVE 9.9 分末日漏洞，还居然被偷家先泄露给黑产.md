#  Linux 最新 CVE 9.9 分末日漏洞，还居然被偷家先泄露给黑产   
原创 SenderSu  wavecn   2024-09-29 23:56  
  
上周也就是在2024年9月26日，有报道指 Linux 环境存在多个 CVE 评分可达   
**9.9 分**（满分10分）的漏洞，如果最后确证这一系列的漏洞的确符合 9.9 的评分，那么称之为末日漏洞也毫不为过。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HSHUiabvXVfNZIV6mNuboVDb3ibEzODaMtLbUJbjXTqMUTiavHQgwfhlchCSpPoEQns6ibOyf177wPHpzvA4IJR56A/640?wx_fmt=jpeg&from=appmsg "")  
<table><tbody style="outline: 0px;visibility: visible;"><tr style="outline: 0px;visibility: visible;"><td valign="middle" align="right" width="124" style="border-color: rgb(255, 255, 255);outline: 0px;word-break: break-all;hyphens: auto;visibility: visible;"><span style="font-size: 12px;">笔者：</span></td><td valign="middle" align="left" width="453" style="border-color: rgb(255, 255, 255);outline: 0px;word-break: break-all;hyphens: auto;visibility: visible;"><p><span style="font-size: 12px;">国际认证信息系统审计师（CISA）</span></p><p><span style="font-size: 12px;">软考系统分析师</span></p><p><span style="font-size: 12px;">软件工程硕士</span></p></td></tr></tbody></table>  
  
而根据最新消息[1]，这多个漏洞所关联的 Linux 系统组件就是 CUPS，Common Unix Printing System，用于控制打印作业的 Linux 系统组件。既然是和打印组件关联，那么这漏洞的覆盖面是真不小：  
  
**国产操作系统很可能全部都受影响。**  
  
发现这多个漏洞的安全研究员 Simone Margaritelli [2] 在向发行版厂商报告漏洞后，由于对厂商解决漏洞的缓慢过程和态度感到失望，已经公开了这些漏洞情况的第一篇解析文章[3]，估计后续还会有更多解析文章发布。  
  
话说笔者之前就写过如下的文章：  
  
[国产化替代：观察漏洞修补的及时性以供应链关系选择操作系统](http://mp.weixin.qq.com/s?__biz=Mzg4Njc0Mjc3NQ==&mid=2247486205&idx=1&sn=a47508c99ccafd011e86a8fb42ae3512&chksm=cf944165f8e3c873a0157831fb119876e8ef31033344b985479f9dddef514efe77fb8baac15b&scene=21#wechat_redirect)  
  
  
这次，各位读者也可以顺带观察一下：  
  
**国产操作系统哪个厂商的修补速度是最快的？**  
  
当务之急，安全管理员或者系统管理员可以进行如下风险缓解措施：  
  
**1、检查系统内是否存在 CUPS-BROWSED 服务，如果有，禁用或删除该服务。**  
  
**2、检查系统补丁更新，如果有 CUPS-BROWSED 相关补丁，立即全面安装。**  
  
**3、设置本机防火墙，拦截对 UDP 端口 631 的访问。**  
  
**4、确保局域网内不应该有向公共互联网开放 UDP 端口 631 的计算机。**  
  
**5、攻击者还可能利用 DNS-SD（DNS Service Discovery）、mDNS 或者 zeroconf 等手段通过局域网发起攻击，因此有必要确认是否需要在内网开放使用这些协议，如无必要应一律拦截。**  
  
熟知 Linux 安全历史的读者都应该知道，CUPS 这个打印组件是频发安全漏洞的典型。  
  
有经验的系统管理员对于不需要执行打印任务的计算机（也就是服务器）会直接选择不安装这个组件。但在办公室终端环境中，不安装 CUPS 是不可能的。所以这个漏洞的风险程度确实较高。  
  
简单说说具体攻击的实施方式：  
  
远程攻击者可以不需要被验证身份就能用恶意的 IPP URL 地址[4]替换掉（或者是添加） Linux 系统里面配置的打印机的地址，然后让受害的 Linux 系统通过恶意地址获取恶意操作命令到自身成为打印作业的 PPD（PostScript Printer Description）临时文件[5]。  
  
当用户执行打印操作时，这个 PPD 临时文件中的数据就会被执行，于是......  
  
这个过程从技术上其实还比较复杂，牵涉到4个具体的 CUPS 细分组件，也就是四个 CVE 漏洞，按以上的执行过程排列：  
  
**1、CVE-2024-47176**：cups-browsed 2.0.1 或以上版本。该漏洞使得 CUPS 监听 UDP 端口 631 的行为不正常，会信任来自任何来源的任何数据包，并使用该数据包向攻击者控制的 恶意 IPP URL 发出获取 IPP 的请求。  
  
**2、CVE-2024-47076**：libcupsfilters 2.1b1 或以下版本。该漏洞导致 CUPS 不会验证上述 IPP 请求返回的属性，从而允许攻击者将恶意数据传送进入 CUPS。  
  
**3、CVE-2024-47175**：libppd 2.1b1 或以下版本。该漏洞导致 CUPS 在将 IPP 属性写入临时 PPD 文件时不对其进行验证。  
  
**4、CVE-2024-47177**：cups-filters 2.0.1 及以上版本。该漏洞导致 CUPS 按 PPD 文件中的数据执行任意命令。  
  
而本文的标题，说的就是这件事的吊诡之处：  
  
有人把安全研究员 Margaritelli  向 CERT VINCE [6] 私下报告的漏洞情况泄露到了网络黑产论坛，逼得研究员 Margaritelli 要提前公布并在社交平台上声明，我提前公布是因为漏洞情况已经被泄露。  
  
**这数据泄露居然都透到网络安全研究的本家去了，也真是丢脸。**  
  
注：CERT VINCE 属于卡内基梅隆大学软件工程学院，有兴趣的读者可以自行搜索该学院在信息技术上的地位。  
  
参考链接：  
  
[1] That doomsday critical Linux bug: It's CUPS. May lead to remote hijacking of devices  
h  
ttps://www.theregister.com/2024/09/26/cups_linux_rce_disclosed  
  
[2] Simone Margaritelli @evilsocket  
https://github.com/evilsocket  
  
[3] Attacking UNIX Systems via CUPS, Part I  
https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/  
  
[4] Internet Printing Protocol/1.1: IPP URL Scheme  
https://datatracke  
r.ietf.org/doc/html/rfc3510  
  
[5] CUPS PPD Extensions  
https://www.cups.org/doc/spec-ppd.html  
  
[6] Vulnerability Information and Coordination Environment  
https://www.kb.cert.org/vince/  
  
**点赞和转发都是免费的**  
↓   
  
  
  
还可以看看这些内容：  
  
[国产化替代：观察漏洞修补的及时性以供应链关系选择操作系统](http://mp.weixin.qq.com/s?__biz=Mzg4Njc0Mjc3NQ==&mid=2247486205&idx=1&sn=a47508c99ccafd011e86a8fb42ae3512&chksm=cf944165f8e3c873a0157831fb119876e8ef31033344b985479f9dddef514efe77fb8baac15b&scene=21#wechat_redirect)  
  
  
[有什么蛛丝马迹可以判断系统存在SQL注入漏洞，且如何临时应对？](http://mp.weixin.qq.com/s?__biz=Mzg4Njc0Mjc3NQ==&mid=2247485995&idx=1&sn=f27c3739b9f261d06642bcea8b9e5c27&chksm=cf9441b3f8e3c8a5ddde56ed74c051cd2ca5f5128c3d04500c1caa33a91043e65f34374fceec&scene=21#wechat_redirect)  
  
  
