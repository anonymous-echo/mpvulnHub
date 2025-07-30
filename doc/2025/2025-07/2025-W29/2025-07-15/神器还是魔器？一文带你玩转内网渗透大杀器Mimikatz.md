> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzA5NzQxMTczNA==&mid=2649167196&idx=1&sn=d88a6788e0bfd95d16f494fa279ab4db

#  神器还是魔器？一文带你玩转内网渗透大杀器Mimikatz  
原创 hackerson  黑客联盟l   2025-07-15 04:40  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWhqjlIpdACpYtdVvKD3OPyBmYA5brJN4sK34dYRQcSL3uKNsGNoib9fEN3CEGeChjIvOx8qClscs5w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
用心做分享，只为给您最好的学习教程  
  
如果您觉得文章不错，欢迎持续学习  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/dhzGXdxNSYviccX1icZO96TxE8hTso7BGelNASkCaGXx9yyBkpjIlg488licm5f4j8vwGFwZt8KMY48hD6M0rLwvQ/640?wx_fmt=jpeg&from=appmsg "")  
  
嘿，各位未来的“网络安全大师”，欢迎来到今天的技术盛宴！  
  
想象一个场景：在一次紧张刺激的渗透测试中，你通过一个漏洞成功拿下了某台主机，但权限却低得可怜。你环顾四周，发现自己身处一个庞大的内网之中，域控、文件服务器、核心数据库……无数宝藏近在咫尺，却隔着一道无形的墙——**权限**  
。  
  
这时候，你最需要的是什么？没错，一把能够打开所有门的“万能钥匙”。  
  
在黑客的世界里，这把“钥匙”真实存在，它就是我们今天的主角，一个让无数管理员闻风丧胆，也让无数攻击者梦寐以求的神器——**Mimikatz**  
。  
> ⚠️ **免责声明：**  
 本文所有内容仅供技术学习与研究，旨在帮助网络安全从业者提升防御能力。严禁用于任何非法用途，否则后果自负！在授权的靶场环境中练习是唯一的正确姿势。  
  
### 🗡️ 知己知彼：Mimikatz究竟是何方神圣？  
  
简单来说，Mimikatz是一款功能强大的轻量级调试工具，由法国神犇 **Benjamin Delpy**  
 开发。它最初的使命是向大家展示Windows安全机制的脆弱性，但由于其功能过于逆天，迅速成为了后渗透（Post-Exploitation）阶段的王牌工具。  
  
它的核心绝技是什么？  
  
**直接从Windows系统的内存（特别是lsass.exe进程）中，抓取明文密码、哈希值、PIN码和Kerberos票据。**  
  
打个比方，Windows为了方便用户登录和验证，会在内存里临时“记住”你的凭证。而Mimikatz就像一个能潜入这个“记忆中枢”的顶级特工，把你刚刚输入、还温热的密码直接“看”得一清二楚。这就是为什么，即便你的密码设置得再复杂，只要在登录状态下，Mimikatz一出，也可能瞬间“裸奔”。  
### ⚙️ 战前准备：请赐予我“神力”  
  
在释放这头猛兽之前，你需要满足几个关键条件，否则它只会水土不服，罢工给你看。  
1. **管理员权限 (Administrator/SYSTEM):**  
 这是最重要的前提！没有管理员权限，Mimikatz就是一把没有开刃的废铁。你需要先通过其他手段将当前权限提升至管理员或SYSTEM。  
  
1. **架构匹配:**  
 64位的Windows系统需要使用64位的Mimikatz，32位同理。别搞混了！  
  
1. **关闭杀软/EDR:**  
 Mimikatz早已被全球各大杀毒软件列为“头号通缉犯”。在实战中，你需要对它进行免杀处理（如混淆、加密、反射加载等），否则它刚一落地就会被无情“绞杀”。（关于免杀技术，我们以后再开专题细聊！）  
  
1. **官方下载:**  
 请务必从官方GitHub仓库下载，野路子的版本可能有“惊喜”等着你。  
  
1. 
```
https://github.com/gentilkiwi/mimikatz
```

  
1.   
### ⚔️ 实战演练：三步夺取内网控制权  
  
好了，假设你已经在一个授权的测试环境中，并成功获取了目标主机的管理员权限。现在，好戏开场！  
#### 第一步：赋予“调试”特权  
  
这是Mimikatz能正常工作的第一步。我们需要为它申请
```
SeDebugPrivilege
```

  
权限，这相当于给它颁发一张“通行证”，允许它窥探其他进程的内存空间。  
  
打开一个具有管理员权限的
```
cmd
```

  
或
```
powershell
```

  
，运行
```
mimikatz.exe
```

  
，然后输入以下命令：  

```
mimikatz # privilege::debug
Privilege '20' OK
```

  
看到
```
Privilege '20' OK
```

  
的返回，就代表你已经成功了！  
#### 第二步：抓取登录凭证（经典大招）  
  
这是Mimikatz最经典、最直接的用法。一条命令，让当前系统中所有登录用户的凭证无所遁形。  

```
mimikatz # sekurlsa::logonpasswords


```

  
执行后，你会看到一长串信息，里面包含了用户名、域名以及最重要的——**密码**  
！根据系统版本和配置，你可能会直接看到明文密码，也可能是NTLM哈希。  
- **Authentication Id:**  
 标识一个登录会话。  
  
- **User:**  
 用户名。  
  
- **Domain:**  
 所属域名。  
  
- **Password:**  
 梦寐以求的明文密码（如果存在）。  
  
- **NTLM:**  
 密码的NTLM哈希值。即使没有明文，拿到这个也威力巨大！  
  
**拿到NTLM哈希能干嘛？**  
 这就要引出我们的下一步——哈希传递攻击。  
#### 第三步：哈希传递 (Pass-the-Hash, PtH)  
  
哈希传递是一种“降维打击”。我不需要知道你的密码原文，只要有你的哈希，我就能冒充你，登录到网络中的其他机器。就像我不需要知道你银行卡的密码，但我复制了你的银行卡，照样能刷。  
  
假设我们从上一步获取了
```
Administrator
```

  
用户的NTLM哈希：
```
e52cac67419a9a224a3b108f3fa6cb6d
```

  
。  
  
现在，我们用Mimikatz来“传递”这个哈希，并弹出一个新的命令行窗口。  

```
mimikatz # sekurlsa::pth /user:Administrator /domain:WORKGROUP /ntlm:e52cac67419a9a224a3b108f3fa6cb6d


```

- 
```
/user
```

  
: 目标用户名。  
  
- 
```
/domain
```

  
: 目标域名或工作组名。  
  
- 
```
/ntlm
```

  
: 刚刚抓到的NTLM哈希。  
  
命令执行后，你会惊奇地发现，一个新的
```
cmd.exe
```

  
窗口弹了出来。**这个窗口拥有了Administrator的“灵魂”！**  
  
在这个新窗口里，你可以尝试访问其他需要管理员权限才能访问的网络资源，比如直接访问域控的C盘：  

```
dir \\DC_SERVER_IP\c$


```

  
如果成功列出了文件列表，恭喜你，你已经横向移动到了域控！整个内网的大门已向你敞开。  
### 🛡️ 防御加固：道高一尺，魔高一丈  
  
了解了Mimikatz的强大，我们更要知道如何防御。作为一名合格的“白帽子”，不仅要会“攻”，更要精通“防”。  
1. **启用Credential Guard (Windows 10/Server 2016+):**  
 这是微软的官方大招。它使用基于虚拟化的安全技术（VBS）将
```
lsass.exe
```

  
进程隔离起来，让Mimikatz无法直接读取其内存。  
  
1. **开启LSA保护 (LSA Protection):**  
 通过修改注册表，可以阻止不受信任的进程读取LSA内存。将
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa
```

  
下的
```
RunAsPPL
```

  
键值设为
```
1
```

  
。  
  
1. **最小权限原则:**  
 永远不要用域管账号登录普通服务器或个人电脑！日常操作请使用普通账户。  
  
1. **及时更新补丁:**  
 微软一直在努力修复可以被利用的漏洞，保持系统最新是基本操作。  
  
1. **加强监控:**  
 监控
```
lsass.exe
```

  
进程的异常访问行为，检测网络中是否存在哈希传递等攻击特征。  
  
### 总结  
  
Mimikatz无疑是一把双刃剑。在攻击者手中，它是收割内网的魔器；而在安全人员手中，它是检验系统防御强度、理解攻击手法的神器。  
  
掌握它，不是为了作恶，而是为了更好地理解黑暗，从而拥抱光明。希望今天的分享能让你对内网渗透有更深刻的认识。  
  
**点个“在看”，分享给更多热爱技术的朋友。持续关注我们，下期带来更硬核的干货！**  
  
  
本文仅作技术分享 切勿用于非法途径  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/dhzGXdxNSYu9NHeLQtcv3btw1zjO4LfzWI3eeGE0fkD9CaQEgDh4FHsKYk8iaVOjhRgGKfEbfRwZf64QibNxEmWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
关注【**黑客联盟**  
】带你走进神秘的黑客世界  
  
  
