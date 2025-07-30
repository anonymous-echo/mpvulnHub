#  警惕AI扒手：Pickai后门正通过ComfyUI漏洞传播  
原创 奇安信X实验室  奇安信XLab   2025-06-11 08:39  
  
背景  
  
目前已有境外黑客组织利用ComfyUI漏洞对我网络资产实施网络攻击，伺机窃取重要敏感数据  
 -- 来自 国家网络安全通报中心  
  
**2025年5月27日，国家网络安全通报中心发布预警**  
，指出ComfyUI存在数个高危漏洞，且已被黑客组织利用，要求企业采取防护措施，避免网络与数据安全风险。显然，随着私有化部署AI模型的浪潮席卷各行各业，作为大模型图像生成领域的热门框架，ComfyUI在获得广泛应用的同时，也不可避免地成为了黑客攻击的重点目标。本文将介绍**奇安信XLab**  
视野中的攻击活动，并详细分析这些攻击活动的具体特征和危害方式。  
  
让我们把时钟拨回到2025年3月17日，Xlab大网威胁感知系统  
检测到IP **185.189.149.151**  
通过ComfyUI漏洞传播多个伪装成配置文件的VT 低检测ELF可执行程序（如config.json，tmux.conf，vim.json等）经过分析，我们确认这几个文件属于同一个后门木马，基于它们具有窃取AI敏感数据的能力，我们从扒手（pickpocket）一词获得灵感，将它命名为AI扒手，**Pickai**  
。  
  
Pickai是一个由C++编写的轻量级后门程序，主要功能包括远程命令执行和反弹shell。麻雀虽小，但五内脏俱全，Pickai具有较强的隐蔽性，健壮性以及持久化能力。在主机行为层面，它支持反调试、进程伪装和多种持久化机制；在网络通信层面，虽然未采用加密算法，但内置了多个C2（命令与控制）服务器作为冗余备份，定时检测C2可用性，自动切换以维持控制链路的稳定。  
  
在逆向分析过程中，我们发现Pickai的一个C2域名 **h67t48ehfth8e.com**  
 处于未注册状态后，立即进行了抢注。通过接管该域名，我们成功获取了部分威胁视野，数据显示全球共有695台服务器被感染。Pickai的作者发现这一情况后，马上更新样本，投入一个有效期长达5年的C2 域名 **historyandresearch.com**  
，表现出一种针锋相对的对抗姿态。  
  
另外值得注意的是Pickai 的恶意样本托管在电商赋能平台 **Rubick.ai**  
 的官方网站。Rubick是一家AI电子商务公司，它的业务覆盖美国、印度、新加坡、中东等国际市场。从官网和其他的公开信息来看，Rubick已为200多家领先的电子商务品牌提供服务，部分知名客户包括：  
- 亚马逊（Amazon）：利用   
Rubick.ai  
 的目录管理服务优化其产品数据。  
  
- The Luxury Closet（阿联酋）：奢侈品电商，使用其 AI 工具进行图像编辑和产品属性提取  
  
- Hudson Bay：北美零售商，使用其 PIM 和营销工具提升产品展示效率。  
  
- Myntra：印度领先的时尚电商平台，依赖 Rubick.ai 的目录管理服务处理超过 700 万个 SKU  
  
  
Rubick.ai  
作为众多客户的 upstream 服务提供商，它被黑客入侵就意味着它的产品、服务都有可能被值入恶意代码，带来严重的供应链攻击  
风险。再考虑到当前安全厂商对 Pickai 样本的检测多为泛型（Generic）结果，且大量 C2 服务器尚未被有效标记。我们决定撰写本文向社区分享这一发现，共同维护网络安全。  
# 时间线  
#   
- 2025年2月28日，Pickai的早期版本从香港上传到VT，使用的C2为195.43.6.252  
。  
  
- 2025年3月17日，XLab首次捕获通过ComfyUI漏洞传播Pickai的Payload。  
  
![pickai.tmux.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnpicRVOtz6ckA6rVw8NibVvPJhEw2cAH0rN9TDGyomXuBmGxCDxhPibCAUQ/640?wx_fmt=png&from=appmsg "")  
  
  
- 2025年5月3日，XLab向Rubick.ai通告被入侵，遗憾的是该公司并未回应。  
  
![pickai_email.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnpqWpLibCShAE8B3oDqRklCR46ibsZiakCGAq08HlLFAuhtSEWad64PUQyA/640?wx_fmt=png&from=appmsg "")  
  
  
- 2025年5月26日，XLab监测到Pickai的另一个下载服务器78.47.151.49  
。  
  
  
# 感染分布与基础设施  
#   
  
2025年3月17日，我们对C2 **h67t48ehfth8e.com**  
进行抢注，依托于该域名，我们获得了Pickai后门的部分感染视野。从数据来看，全球有近700台设备被感染，主要分布在德国，美国和中国。  
  
![pickai_stat.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnpTOhicCl5Ah3vglib61yK0w7kkNoBflKF0JyYy3WHxQRBYvK0Yrpv85BQ/640?wx_fmt=png&from=appmsg "")  
  
Pickai对于C2的访问是有先后顺序的，其中h67t48ehfth8e的优先级最低。4月13日以及5月5日两天出现Spike，峰值超过400。我们认为，该数字体现了Pickai真实的日活。Spike的原因是在那两天其余C2出现故障，从而使得h67t48ehfth8e有机会一窥全貌。  
  
![pickai_ips.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnppTicicXFicR4RGj8w7ia4So3PyhtiaoGjLYib1CqCLajjAkUT9SK9wPicBPwQ/640?wx_fmt=png&from=appmsg "")  
  
Pickai样本更新后，引入一个有效期长达5年的C2 historyandresearch.com  
,该域名的构词，以及没有开启DNS解析的行为，都像是对我们抢注行为的回应。我们推测攻击者的心理活动是这样的：  
> "XLab你们不是挺能抢注域名嘛，来，我整个5年有效期的C2，再抢过去给我看看？！哈哈，我就是要挑衅你们，把你们气个半死却拿我没办法，爽！"  
  
  
对此，我们只想说，“不能接管这个域名，我们可以曝光其他的C2呀！”。目前Pickai的C2服务器虽然检测率接近零，但相信安全社区很快就会让它的作者明白：恶意软件的生存周期，从来都是由防御者书写的。  
  
![pickai_vt.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnpTkJW3wU1CHPAMLVuqFnPZXYrYqzAGtQthWHUABwxVlTag01Rbtxiapw/640?wx_fmt=png&from=appmsg "")  
# 样本分析  
#   
  
我们一共捕获了7个Pickai样本，本文以5月26日最新的样本为主要分析对象，它的基本信息如下所示：  
```
MD5:8680f76a9faaa7f62967da8a66f5a59c
MAGIC:ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 3.2.0, stripped
```  
  
Pickai的功能比较简单，当它运行时，首先对加密的字符串进行解密，包括C2，持久化脚本等各种敏感的配置信息，然后通过检测进程的TracerPid字段进行反调试，使用pid文件确保单一实例运行，调用prctl函数对进程名进行修改进。接着根据当前用户的不同权限，通过init.d或systemd实现持久化，最后和C2建立通信，等待执行C2下发的指令。  
  
下文将从主机行为与网络通信两个维度对Pickai后门进行分析，重点关注字符串解密、持久化机制和网络协议等关键技术特征。  
  
Part 1: 解密字串  
  
Pickai的大部分敏感字符串加密存储在rodata段，加密方法为单字节与0xAF进行异或。因此密文有一个明显的特征，即以0xAF结尾。  
  
![pickai_0xaf.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnp830azrCASy7QVRqzMZ6iaBwUbiaLUgicBjfeS7o2VQFbG7ncJVSicx4kxQ/640?wx_fmt=png&from=appmsg "")  
  
为了逆向分析的方便，可以使用以下idapython代码进行解密，只需要确定密文的开始与结尾  
即可。  
```
startAddr=0x000000000000D028
endAddr=0x000000000000DBD8
buf=ida_bytes.get_bytes(startAddr,endAddr-startAddr)
items=buf.replace(b'\x00',b'').split(b"\xaf")
for item in items:
    plaintxt=bytearray()
    ciphertxt= ' '.join(f'{byte:02X}' for byte in item)
    addr=idc.find_binary(startAddr,idaapi.SEARCH_DOWN,ciphertxt)

    for i in item:
        plaintxt.append(i^0xaf)
    print(f"0x{addr:x}, has {len(plaintxt)} bytes ----> {plaintxt}")
    plaintxt.append(0)
    ida_bytes.patch_bytes(addr,bytes(plaintxt))
    idc.create_strlit(addr,addr+len(plaintxt))
```  
  
效果如下所示，解密出的明文中包括C2，进程伪装，持久化等功能相关的信息。  
  
![pickai_dec.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnp5ALZn8x2u3Y6NFZQv61SKIeECbhXwqG3B6tibsf8YsOibAdPM0ibJEmmg/640?wx_fmt=png&from=appmsg "")  
## Part 2: 主机行为  
##   
  
Pickai在主机行为方面，支持反调试，单一实例，进程伪装，持久化等特性。它们的技术实现上并无特别的“脑洞”，进程伪装和持久化稍有特色，它们都体现了一个“多”的特点。  
#### 0x1: 进程伪装  
####   
  
进程伪装的“多”，体现在伪装的进程名上。Pickai会在20个进程名中随机选择一个，使用prctl函数对自身进程名进行修改。  
  
![pickai_fakeproc.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnp3ibCl02mtmLbxicKCaN0XnUhYYPWWuW77MpcRiapOPzfauI4wNOgtIDlA/640?wx_fmt=png&from=appmsg "")  
  
伪装进程名的详细信息如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnpz4plte3IkKZLUpw1GdK3leZWTjy6pHy1qpX7jmslVnLiazpCB8V4NHw/640?wx_fmt=png&from=appmsg "")  
  
0x2:持久化  
  
持久化的“多”，体现在持久化服务数量上：root用户10个，普通用户5个。  
  
![pickai_persistance.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnpGb81py7mVq2JurCtqaXfGia8V5usicTwMJDzvOFH0nO8nn1rh5v6zOOw/640?wx_fmt=png&from=appmsg "")  
  
当前用户权限为root时，Pickai首先会将自身复制到5个不同的路径，并同步它们的“最后修改时间”至“/bin/sh”文件的时间戳，然后创建服务，利用init.d & systemd 两种机制实现持久化。  
  
![pickai_root.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnp26MxfyZFba7uRT3BvcIiasjHAEHveriaryaFcicpXvIK2ibibxEib65TneLA/640?wx_fmt=png&from=appmsg "")  
  
以下为Pickai副本所在的路径，以及它们对应的持久化服务。使用init.d机制时，这些服务位于/etc/init.d/目录，而systemd机制，这些服务则位于/usr/lib/systemd/system/或/lib/systemd/system/。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnpVhAWE5iajpxUaECfrVNSgsuPQvVt2UZ2XO585awFibGoHib1icBsGFxNtg/640?wx_fmt=png&from=appmsg "")  
  
很明显，Pickai试图仿冒正常系统服务，蒙混过关。实际创建的auditlogd持久化脚本如下所示：  
  
![pickai_auditlogd.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnpfOGq78UvnQf8SIJh4HanvaJjFEtn2g37J6Yb2PicKGDtFypgic0Sx1Yw/640?wx_fmt=png&from=appmsg "")  
  
另外值得一提的是，Pickai在自我复制过程中，会在文件尾部追加随机数据。这种技术手段很明显是在规避基于文件哈希值的检测机制。  
  
![pickai_append.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnpB4ct1GCqTZMyyNUXqO9Qe5r80ric4nOU9BK2jNpRCrKGQMYviaLAGtaQ/640?wx_fmt=png&from=appmsg "")  
  
可以看出5个Pickai副本的MD5完全不一样：  
  
![pickai_md5s.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnpMpluusD6wHmBIR8vgUn7FrecuNkDeIyPBEjIqbLkM3cz8pQ73s1TJg/640?wx_fmt=png&from=appmsg "")  
  
当用户权限不是root时，Pickai使用systemd机制实现持久化，整个过程与root权限相似，只不过副本路径以及服务名称有所不同。这些服务位于$HOME/.config/systemd/user/  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnps4FKiaZjiclTbOlKEsPd9B9DUYAiarWGRHicDCXT02F1v7Cv6cdbQRLytQ/640?wx_fmt=png&from=appmsg "")  
  
Pickai正是通过这种冗余的持久化机制，在被感染设备上实现多个分身，只要一处没有清理干净，它就能卷土重来  
。  
## Part 3: 网络通信  
##   
  
Pickai通过一个永真的循环进行网络通信，它的通信机制采用三级定时策略：每43200秒（12小时）从6个硬编码C2中轮换活跃节点，每1200秒周期性上报设备信息，每120秒向C2请求指令。  
  
![pickai_time.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnpslDQPsxTATABibeYRzz3xPEO0FssB2mfKduLHXgicyNb1ajhQVBIt0aw/640?wx_fmt=png&from=appmsg "")  
#### 0x1: 请求指令报文  
####   
  
长度1024字节，前7字节为“LISTEN|”，其余部分0x00填充。支持EXECUTE  
和REVERSE  
俩个指令，它们分别对应执行系统命令和反弹shell俩个功能。  
  
![pickai_cmd.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnpSCAcX7tWXdfrc7p4eEsaBow0DcjQtNq3ib6mAcftibgV9wOMITKicn6MA/640?wx_fmt=png&from=appmsg "")  
  
#### 0x2: 上报设备信息报文  
####   
  
长度1024字节，前7字节为“UPDATE|”，其后紧跟着3部分元数据，未使用的空间使用0x00填充  
- 系统指纹（uname -a）  
  
- 特权状态（当前用户是否为root）  
  
- 是否为docker（检测1号进程是否为init或systemd）  
  
  
![pickai_update.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnpBiatMU7AC0ashVsXESGZNYKHenFooFpem616JfzLMY1FCtVUSw4LfjQ/640?wx_fmt=png&from=appmsg "")  
#### 0x3: C2验活报文  
####   
  
样本中硬编码了6个C2，Bot以先后顺序为优先级，依次向这些C2发送验活请求，直至收到首个活跃C2的响应。这种设计使得高优先级C2在正常通信时掩盖低优先级C2的存在，在一定程度上能够对抗基于沙箱流量进行IOC生产的系统。  
  
![pickai_c2.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnpDhMhCNlPn7ibVTcI5Tibec2NjhMhMO3rZKeiafWTKE2N3mm2Q5ZPLFzuQ/640?wx_fmt=png&from=appmsg "")  
  
验活报文长度7字节，固定为“STATUS|”，当C2回复LISTENING  
时，表示该C2处于活跃状态。  
  
![pickai_checkalive.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnpFruibkUB1Jb6xRwTicf45NnicUcWQutCHb7w4e7W2Iz9x6geC7ZBV6GHg/640?wx_fmt=png&from=appmsg "")  
  
#### 0x4: 跟踪到的指令  
  
我们在XLab指令跟踪系统中实现了Pickai的协议，只在6月6日接收2条指令，用于开启反弹shell。由于尚未对REVERSE、EXECUTE等后续攻击指令进行模拟，攻击者在成功建立shell会话后的具体攻击意图暂无法完整溯源。  
  
![pickai_reverse.png](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbia1sTHw1sdfUY1kvJ0gKtnpicjPm56264JwoQGzMOZibOvxT7h5QHZQa1SFwFiakFOJHjRLQoKsHuQOw/640?wx_fmt=png&from=appmsg "")  
# 总结  
#   
  
Pickai的冗余持久化机制使其具备类似顽固木马的特性，即使仅残留一处未被清理，就能触发再生。网络管理员可基于前文所述的Pickai主机行为特征进行深度排查，确保其植入的5个副本被彻底清除，避免残留导致二次感染。  
  
这是我们当前掌握的关于Pickai的基本情报，诚邀具有独特视角的同行企业及受此后门木马影响的网络管理员和我们联系提供进一步的线索。  
  
