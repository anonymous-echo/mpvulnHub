#  研究人员揭露 macOS 漏洞可导致系统密码泄露   
山卡拉  嘶吼专业版   2025-03-28 14:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28b88XUVXZgbMtQHzEicadkLENAOYZdKrkibSY47qmrDUNWicUJibpStAR0FWvCZgrrU2Ee7frA33gXCw/640?wx_fmt=png&from=appmsg "")  
  
Noah Gregory 最近发表的一篇文章，着重指出了 macOS 系统中一个严重的漏洞，其编号为 CVE - 2024 - 54471。好在该漏洞已在 macOS Sequoia 15.1、macOS Sonoma 14.7.1 以及 macOS Ventura 13.7.1 的最新安全更新中得到修复。此漏洞存在暴露系统密码的风险，这也充分说明了将 macOS 设备更新至最新版本的重要性。  
# 背景和技术细节  
  
该漏洞利用了 macOS 中的进程间通信（IPC）机制，尤其是 Mach 内核的消息传递系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28b88XUVXZgbMtQHzEicadkLrp6CgMhMywlYc7YwYvODwdxxYwVddqACpz55YnpdIw3kEGeHicf14aw/640?wx_fmt=png&from=appmsg "")  
  
凭证存储在 macOS 钥匙串中  
  
Mach 内核融合了 BSD 和 Mach 组件，是 Apple 操作系统的核心部分。据相关报告显示，它运用任务、线程、端口和消息等抽象概念来管理 IPC。端口作为通信通道，对于任务间安全地交换数据起着关键作用。然而，一旦这些机制没有得到妥善保护，就极有可能被不法分子利用。  
  
Mach 接口生成器（MIG）在此次漏洞事件中扮演了重要角色。MIG 能够简化发送和接收 Mach 消息接口的创建过程，但它本身缺乏原生的安全防护措施。这就意味着，任何有权限向 MIG 服务器发送信息的任务，都能够在无需验证身份的情况下调用其例程。倘若 MIG 服务器缺乏对发件人的验证这一问题得不到妥善解决，将会给系统带来极大的安全隐患。  
# 漏洞利用与修补  
  
该漏洞是通过处理文件服务器凭据的 NetAuthAgent 守护程序被利用的。在未进行修补之前，攻击者能够向 NetAuthAgent 发送消息，从而获取任何服务器的凭据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28b88XUVXZgbMtQHzEicadkLxmFVmrAOYl9VlUrSh5CfwRvgTApKKHNUJspYtT9nHqIRRJLQRxibxbw/640?wx_fmt=png&from=appmsg "")  
  
此次漏洞事件凸显了保护 IPC 机制的重要性，同时也表明所有任务必须对其接收到的消息的真实性进行验证。  
  
目前，该漏洞的补丁已被包含在最近的 macOS 更新中，这再次强调了用户及时保持系统更新，以防范此类漏洞攻击的必要性。像 ipsw CLI 这类工具，能够通过定位使用与 MIG 服务器相关特定符号的二进制文件，帮助识别潜在的漏洞。不过，要是没有恰当的安全措施作为保障，这些机制依旧很容易遭到利用。  
  
此次漏洞的曝光，凸显了保护像 macOS 这样复杂的操作系统安全所面临的持续性挑战。同时，也进一步强调了定期进行系统更新以及践行强有力的安全实践，对于保护用户数据和维护系统完整性的重要意义。  
  
参考及来源：  
https://gbhackers.com/researchers-reveal-macos-vulnerability/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28b88XUVXZgbMtQHzEicadkLXS3r4ibcIjWLic2N8zhA4ND4b7dia5iaTx2Q1reXrAttgtfycbfRia3tZMw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28b88XUVXZgbMtQHzEicadkLMf63WCQKS1vBCJRibkOVEMZUnVAhVriat2CI6OeNWzpIywMJX6ZkLtYQ/640?wx_fmt=png&from=appmsg "")  
  
  
