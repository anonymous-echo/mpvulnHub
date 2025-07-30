#  漏洞赏金实战分享 | 发现并利用开放的 SMB 服务   
白帽子左一  白帽子左一   2025-02-18 04:00  
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
大家好！这次我要分享的是在测试某个目标时，发现的 SMB 服务器配置错误及其利用过程。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFxfOJgcTYpwzFWPwTORtmuI1Cyk4Y1t5AOI7YENrkibrwk2jibJYckjrfVsNSHSLfmOFgiaib4xibVsCw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
**服务器消息块（SMB）** 是一种通信协议，用于在网络中的节点之间共享文件、打印机、串行端口及其他资源。SMB 为客户端应用程序提供了一种安全且受控的方法，可用于在远程服务器上打开、读取、移动、创建和更新文件。此外，该协议还可以与配置为接收 SMB 客户端请求的服务器程序进行通信。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSFxfOJgcTYpwzFWPwTORtmuP8mrCKfNBpZ7KzAYyzMVZrdsTaPxQ46iclBbO6RfoM9EbaEdtvdkhFg/640?wx_fmt=jpeg&from=appmsg "null")  
  
img  
  
我们以“**target.com**”作为目标。在进行初步信息收集后，我决定在 Shodan 上测试该目标的服务。使用 Shodan 侦查技巧，我开始在 Shodan 上搜索目标。  
  
**搜索语法：**  
```
ssl.cert.subject.cn:target.com
```  
  
我找到一个指向“**variated.target.com**”的 IP 地址。  
  
Shodan 显示该 IP 地址上运行着一个 **开放的 SMB 服务**。随后，我在 Censys 上进一步检查相关细节，并成功验证了该问题。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFxfOJgcTYpwzFWPwTORtmu5phkcqmXYkWaekCJWvbPiabozwQGccyyJMemcDCshyibCVyDSL67zn3g/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
后来，我使用 **Nmap** 扫描进一步确认了这一点，执行的命令如下：  
```
nmap -sC -sV <target_ip> -p445 -Pn
```  
  
参数说明：  
  
•-sC 运行默认的 Nmap 脚本  
  
•-sV 用于探测服务的具体版本  
  
•-p445 指定扫描 **445 端口**（SMB 服务通常运行在此端口）  
  
•-Pn **禁用主机发现**（默认情况下，Nmap 会通过 ICMP 回显请求（ping）或其他探测包（如 TCP SYN/ACK）来判断主机是否在线。如果主机不响应，Nmap 可能会跳过扫描。使用 -Pn 选项可以强制扫描目标，即使它不响应 ping）  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFxfOJgcTYpwzFWPwTORtmujJXjGjwrt0b9SrQjcVQXCQHvBPZLSjuJ0FNpxITpLPWkvgnjP6eV6A/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
确认 SMB 端口开放后，我使用 **Nmap** 的默认脚本来枚举 SMB 共享，并检查是否能获取有效的响应。  
```
nmap --script smb-enum-shares.nse -p445 <target_ip>
```  
  
参数说明：  
  
•--script 用于指定要运行的 Nmap 脚本  
  
•smb-enum-shares.nse 是用于枚举 SMB 共享的 Nmap 脚本  
  
在收集所有必要的详细信息并确认漏洞存在后，下一步就是检查 **用户权限**，看看是否存在 **错误配置**。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFxfOJgcTYpwzFWPwTORtmubNmu2xB4feccPJXhmaK2Sfy4OcKQk42U4PkoV7kLTGslj8aoHu9XNw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
在这里，我发现 **匿名用户** 拥有 **读/写权限**。  
  
在确认允许 **guest 用户** 访问后，我尝试使用 **guest** 用户名连接到 SMB 共享，并成功登录，能够在 shell 中执行命令。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFxfOJgcTYpwzFWPwTORtmuYxAetp4VUKwJm6iaBNAuXvMqg5FEI0mXRcpgCjZicWzuiad1Z4f7HHA1A/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
在此阶段，我决定不再进一步测试，并报告该问题。我创建了 PoC，提供了所有参考资料，并提交了报告。  
  
提交报告后，审核人员要求我验证该问题，因为他的设备无法访问目标。我重新创建了 PoC 并发送给他。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFxfOJgcTYpwzFWPwTORtmuBzzj5o9cAOh1UcYJhCBEcgUue3zHXmBDforAnpl9ia2o6EgaONBEaog/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
随后，审核人员询问我是否确认该问题存在，因为当他尝试测试写入权限时，主机返回了“**Access Denied（访问被拒绝）**”的响应。  
  
为了进一步测试权限，我使用了“**smbmap**”工具重新检查权限，结果发现 **nmap 扫描结果是误报**。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFxfOJgcTYpwzFWPwTORtmu4eLn9VZJIgDFBlT8tZDZklrwMAiawm87zlxibovWXvCv8w5fC4sBbib8A/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
在进一步调查权限后，我发现目标仅具有**读取权限**，并**不允许写入**。  
  
于是，我请求审核人员将漏洞的**严重性降级为“高”**，因为我无法证明存在写入权限。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFxfOJgcTYpwzFWPwTORtmuWYWXRvxu0VTmlyZMCwBar9J1icICRm51zM9TI5jKcibKWpNErV3YAE9Q/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
至此，该问题已最终确认。  
  
希望这篇文章能让你对如何测试**开放的 SMB 服务**有所启发，如果你在测试过程中遇到类似情况，不妨尝试这些方法。  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
****  
  
