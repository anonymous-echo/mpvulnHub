> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5Mzc4MzUzMQ==&mid=2650261308&idx=1&sn=f169299b08c451fc44c011aaa602aaea

#  ​​iPhone “玻璃笼”：利用两枚零日漏洞的国家级攻击链揭秘​​  
原创 骨哥说事  骨哥说事   2025-06-19 06:58  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
  
#   
  
****# 防走失：https://gugesay.com/archives/4464  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
#   
# 前言  
  
2024 年 12 月，国外研究人员发现了一个从未被记录的零点击攻击利用链，针对 iOS 设备通过 iMessage 发送的恶意 PNG 文件。  
  
这个漏洞链（现在被称为“玻璃笼（Glass Cage）”）使远程攻击者能够悄无声息地破坏设备、访问加密的钥匙串数据、劫持 Wi-Fi 设置，甚至完全锁定设备。  
  
这次攻击反映了像 NSO 的 Pegasus 或三角行动这样的国家级网络间谍活动特征，但引入了在移动设备上前所未见的“创新载体”。  
# 总结  
  
玻璃笼（Glass Cage） 是一个关键的零点击 iMessage 漏洞利用链，它通过恶意制作的 PNG 文件来破坏 iOS 设备。  
  
该攻击由 Apple 的原生图像处理管道触发，并成功绕过了多层 iOS 防御，包括 BlastDoor 沙箱、WebKit Integrity 检查和核心媒体特权边界，无需用户进行任何交互。  
  
触发后，利用链会通过 **WebKit RCE （CVE-2025-24201）**  
 和 **Core Media 内核漏洞利用 （CVE-2025-24085）**  
 的组合升级为完全 ROOT 访问权限 。  
  
它访问 **iCloud 钥匙串数据**  
 ， 通过 
```
wifid
```

  
 劫持**网络代理设置**  
 ，并通过基于 
```
launchd
```

  
 的服务注入实现其**持久性**  
 ，在某些情况下，它甚至可以通过在 
```
IODeviceTree
```

  
 中作硬件级参数， 最终导致**设备的不可逆变砖**  
 。  
  
主要风险包括：  
- 通过 WebKit 路径注入进行**远程代码执行 （RCE）**  
  
- 通过 CoreMedia 释放后使用进行**内核权限提升**  
  
- **iCloud 钥匙串凭证泄露**  
  
- 通过恶意代理注入进行**网络重定向**  
  
- 通过未经授权的 launchd 守护程序进行**持久性**  
  
- **日志和取证逃避**  
  
- 作为清理机制的**可选设备自毁**  
  
# 重现步骤  
  
“玻璃笼”漏洞复现只需攻击者进行一次操作，设备可以是锁定的、休眠的，以及放在用户的口袋中。  
- 制作具有特定 Exif 和容器元数据的恶意 HEIF 图像，旨在破坏“ Atxencoder”处理  
  
- 将Payloads编码为 WebP 封装的 HEIF 格式，以绕过过滤  
  
- 通过 iMessage 将图像发送到目标 iPhone（默认配置）  
  
- iOS 的 BlastDoor 子系统处理图像以生成预览 — 无需用户交互  
  
该利用链在多个子系统中自主执行，最终实现内核代码执行和持久性。  
# 概念验证（PoC）  
  
尽管 Payload 没有被共享，但以下是攻击向量的高级分解：  
- **容器格式**  
 ：WebP 封装的 
```
.heic
```

  
 文件  
  
- **Payload**  
 ：损坏的 EXIF 元数据和 ASTC 解码参数  
  
- **触发器**  
 ：通过 
```
MessagesBlastDoorService
```

  
 → 
```
QuickLook
```

  
 → 
```
WebKit
```

  
 调用预览生成  
  
- **元数据示例**  
 ：  
  

```
subsample: 1.000000, source: (234x234), dest: (175x175)
codecctl: Register at offset 0x004 is 0x00000001

```

  
发送标准的 iMessage，没有附件或预览元素  
  
❗ 预览渲染管道被滥用于触发多个子系统：**BlastDoor**  
、**QuickLook**  
、**WebKit**  
 和 **CoreMedia**  
。  
# 漏洞影响  
  
成功利用会导致：  
- 设备完全被破坏，**内核级代码执行**  
  
- iCloud 钥匙串和系统机密的**凭证被盗**  
  
- 通过恶意代理注入进行**网络流量重定向**  
  
- 通过未经授权的 
```
launchd
```

  
 守护程序注册实现**持久性**  
  
- **可选的设备变砖**  
 ，可用作清理机制或破坏性Payload  
  
- **日志和取证逃避**  
  
这是一次完整的零点击远程设备接管，仅需通过 iMessage 发送的一张图片来实现。  
## 阶段一：初始 Payload 与 BlastDoor 故障  
### 1. 传递恶意 HEIF  
  
漏洞利用从 iMessage 发送精心制作的 WebP 编码的 HEIF 图像开始  

```
BCSBlastDoorHelper safeImageURLFromImage:imageFormat:error:

```

  
它在默认解包配置下到达 
```
MessagesBlastDoorService
```

  
：  

```
Unpacking with instance type: Default

```

  
尽管 BlastDoor 是沙盒环境，但漏洞发生在图像解析期间（进程间切换之前），这意味着畸形的内存布局被信任，并允许更深入地传递到系统中。  
### 2. 利用 HEIF→ASTC 解码器  
  
使用经过处理的 EXIF 元数据：  

```
subsample: 1.000000, source: (234x234), dest: (175x175)

```

  
图像损坏了 
```
ATXEncoder
```

  
 内部的堆计算，尽管如此，BlastDoor 还是愉快地验证并传递了它。  

```
BlastDoor.PreviewImage : Success

```

> 🔍 **BlastDoor 上下文**  
 ：引入 BlastDoor 是为了阻止 Pegasus 风格的漏洞利用，BlastDoor 本应隔离不受信任的iMessage内容，然而因低估了图像内存边界限制而失败，从而允许损坏的文件继续向下游移动。  
  
## 阶段二：QuickLook Thumbnailer → Sandbox Escape  
### 3. 调用 QuickLook 缩略图  
  
在 BlastDoor 验证图像后，它会暂存为 
```
.ktx
```

  
 文件，并通过 Apple 的缩略图基础设施进行路由：  
- 
```
UserNotificationsUIThumbnailProvider
```

  
  
- 
```
com.apple.quicklook.ThumbnailsAg
```

  
  

```
IMG_0708-preview.ktx IMTranscoderAgent: found no value for key IIOEnableOOP

```

  
这表明缩略图默认为程序内渲染，因为
```
IIOEnableOOP
```

  
 未定义 - 直接将 QuickLook 代理暴露在不安全的内存中。  
> 🧠 **QuickLook 的作用**  
 ：QuickLook 经过专门设计，可在后台安全地生成预览。但是，在这种情况下，它会**在进程内**  
执行图像缩略图逻辑 ，从而为攻击者提供进入 BlastDoor 沙箱外部特权内存的入口点。  
  
### 4. 通过 Thumbnail Agent 实现横向沙盒逃逸  
  
通过在预览生成期间解析损坏的元数据，攻击者利用缺乏进程外执行来实现从 iMessage 沙箱到更广泛的系统上下文的**横向逃逸**  
 。  
## 阶段三：WebKit 路径注入→ RCE  
### 5. WebKit 访问内部资产  
  
在预览渲染期间触发 WebKit，以通过不受信任的元数据获取系统资源：  

```
debug 2025-01-09 09:41:29.993302 -0500 com.apple.WebKit.WebContent
Resourcelookup:file:///System/Library/PrivateFrameworks/WebCore.framework/modern-media-controls/images/airplay-placard@3x.png

```

### 6. 通过 Injected Path 执行代码  
  
路径混淆漏洞会导致 WebKit 将内部 UI 资源解析为代码执行向量 — 在浏览器沙箱之外，通常是在**通知中心**  
或 **QuickLook**  
 中。  
#### CVE-2025-24201 拆解  
- **类型：**  
 路径注入 → RCE  
  
- **受影响的组件：**
```
com.apple.WebKit.WebContent
```

  
  
- **触发器：**  
 不受信任的预览元数据会触发内部资产提取  
  
- **结果：**  
 在特权 WebKit 上下文中远程执行代码  
  
## 阶段四：通过 Use-After-Free 进行内核提权  
  
📎 **CVE-2025-24085**  
 漏洞  
### 7. CoreMedia 管道中断  
  

```
mediaPlaybackd
```

  
 在执行过程中重新配置：  

```
fpfs_ConfigureRatePlan: requested rate 0.000 => using 1.000

```

### 8. 在 codecctl 中触发UAF  
  
CoreMedia 释放的内存由 
```
codecctl
```

  
 访问 ：  

```
codecctl: Register at offset 0x004 is 0x00000001

```

### 9. 通过 IOHIDInterface 进行堆整理  
  
缓冲区淹没内存空间：  

```
IOHIDInterface: Creating temporary buffer for report data

```

  
这使攻击者能够控制重新分配的区域，并劫持函数指针以实现内核代码执行。  
#### CVE-2025-24085 拆解  
- **类型**  
 ： 释放后重用 （UAF）  
  
- **向量**  
 ：codecctl 重用 CoreMedia 缓冲区  
  
- **结果**  
 ：任意内核级代码执行  
  
## 阶段五：凭证和网络泄露  
### 10. 钥匙串泄露  

```
CloudKeychainProxy Getting object for key syncdefaultsd confirms retrieval

```

  
以静默方式从 iCloud 钥匙串中提取凭据和机密信息。  
### 11.用于网络重定向的代理劫持  

```
wifid: overrideWoWState 0 - Forcing proxy override IP: 172.16.101.176

```

  
所有网络流量都可以通过攻击者控制的基础设施进行路由。  
## 阶段六：日志和取证逃避  
### 12. 删除 Tombstone 日志  

```
Error accessing tombstone logs: File missing

```

### 13. syslogd 抑制  

```
syslogd - Skipping event due to invalid timestamp

```

  
系统日志被修剪或注明日期错误，以防止事件响应。  
## 阶段七：Persistence、C2 和 Kill Switch  
### 14.launchd 后门安装  

```
launchd - New launch daemon: com.attacker.persistentDaemon

```

### 15. 向 C2 发送隐蔽信标  

```
remoteservice - External C2 at 51.76.129.13:443

```

### 16. 可选“变砖”触发  

```
&#34;IOAccessoryPowerSourceItemBrickLimit&#34; = 0

```

> ⚠️ **注**  
 ：默认情况下不会触发该利用，但攻击者可能会在泄露后使用它来销毁设备或擦除证据。  
  
## 入侵指标 （IOC）  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlnqo0RWEtDf5Qd1SpSvBXC2jXzWUL7OXnDaXhA7emnzxqiaR4CUsNGCoa0WQaO0t0ySqWDKJcB55Q/640?wx_fmt=png&from=appmsg "")  
  
  
原文：https://weareapartyof1.substack.com/p/glass-cage-zero-day-imessage-attack  
  
- END -  
  
  
**加入星球，随时交流：**  
  
**********（会员统一定价）：128元/年（0.35元/天）******  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～**  
  
  
