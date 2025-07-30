> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyOTQ0MjE1NQ==&mid=2247502497&idx=1&sn=a56fc6826180049ddff3ca02c4c1655a

#  【工具分享】NemucodAES 勒索病毒恢复工具  
solarsec  solar应急响应团队   2025-07-18 08:32  
  
## 前言  
  
NemucodAES（也称 Nemucod 勒索家族变体）于约 2017 年夏首次出现。这是一种基于 JavaScript 和 PHP 的勒索病毒，通过 AES 和 RSA 加密技术对文件进行加密，通常以“未投递包裹”形式的钓鱼邮件传播，附件中包含恶意 
```
.js
```

  
 脚本，执行后下载并部署 PHP 加密组件。感染完成后，NemucodAES 通过生成 
```
DECRYPT.hta
```

  
 勒索通知要求赎金来进行数据恢复。  
## 特征  
  
NemucodAES 在系统中遍历本地及网络驱动器上的多种文件，但它仅加密每个文件前约 2 KB 的数据。使用 AES‑128（ECB 模式）随机密钥进行加密，并用 RSA 加密该密钥保存于 
```
%TEMP%
```

  
 的数据库文件中。加密后，文件保留原名但开头被篡改内容，旨在阻止直接访问。  
  
感染结束后，该病毒会删除系统卷影副本，并在桌面生成 
```
DECRYPT.hta
```

  
 勒索焦警页面，同时可能更改桌面背景，要求支付约 0.13 BTC 的赎金以进行数据恢复。  
  
NemucodAES 通过 ZIP 附件伪装成 UPS 等快递通知进行传播，下载后执行 
```
.js
```

  
 文件并部署勒索组件。它往往与 Kovter 点击欺诈木马协同作用，形成复杂的恶意攻击链。  
  
尽管使用了强加密方式，NemucodAES 的随机机制存在可预测性，使得安全厂商如 Emsisoft 成功开发出可免费进行有限数据恢复的工具。  
## 工具使用说明  
  
通过采用“数据恢复”而非“解密”一词，更贴合安全行业应对勒索攻击后提供文件恢复的实际操作，希望这版内容符合你的需求，有其他细节可继续优化。  
  
1.从提供本“操作指南”文档的同一网站下载恢复工具。  
  
2.运行下载得到的恢复工具可执行文件。程序将自动搜寻系统中的 NemucodAES 文件数据库，并尝试恢复加密中的数据。  
>   
> 根据系统配置不同，此过程可能耗时较长，请保持耐心。  
  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntrqX2R4ZdFRug4r3mJFib7Z5ahcUT8F4TVO2ficTcrc1aN5AricVQnq3ud0oWwicooOJJnTld2xmmhKyA/640?wx_fmt=png&from=appmsg "")  
  
3.数据恢复工具完成数据库重建后，会提示复原完成。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntrqX2R4ZdFRug4r3mJFib7Z5uu5qz3iaUX3FECrEIMUXF8xsorOLmynm5GYUrTepJZSurDkrzW88tbw/640?wx_fmt=png&from=appmsg "")  
  
4.接下来会弹出许可协议窗口，点击“是”按钮以同意协议。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntrqX2R4ZdFRug4r3mJFib7Z5w0qAFMqTkYnwfsKtU7BBIpXycJhTXW303PobnURcCuqj9icOzVxsrCw/640?wx_fmt=png&from=appmsg "")  
  
5.同意协议后，主界面将打开，显示可恢复文件列表。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntrqX2R4ZdFRug4r3mJFib7Z5Izpb7GdIAIJXmxR13qZwjQBkMbHcyU9jdr7uep5W9lKalbqmgW60Xw/640?wx_fmt=png&from=appmsg "")  
  
6.默认情况下，工具会根据数据库信息自动加载待恢复的文件列表。  
  
7.您可在“选项”选项卡中调整高级设置。该工具针对不同勒索病毒家族，支持多种自定义选项（详见下文）。  
  
8.点击“恢复”按钮开始恢复数据。界面将切换为状态视图，显示恢复进度及各个文件的状态。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntrqX2R4ZdFRug4r3mJFib7Z5vmv02kTwba6bLoicy5SZzcSoRVpPmasSqIq4vBJ20MVtDW8QpyVn0Lw/640?wx_fmt=png&from=appmsg "")  
  
9.恢复完成后，工具会提示操作结束。  
>   
> 若您需要保存操作记录，可点击“保存日志”按钮进行本地保存，或复制到剪贴板，用于邮件或论坛帖回复等。  
  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntrqX2R4ZdFRug4r3mJFib7Z5TYLGU6CIsQNf6iba7ARdlrJw8wWgoXldeTwXLrLEuJxUHtQ9KibkSLXA/640?wx_fmt=png&from=appmsg "")  
  
**可用恢复工具选项：**  
 由于勒索软件不会保存有关未加密文件的信息，解密工具无法保证恢复的数据与原始数据完全相同。因此，恢复工具默认不会在数据恢复后删除任何加密文件，以避免数据丢失。如果您的磁盘空间有限，您可以禁用此选项，让恢复工具在处理完成后删除加密文件。  
### 工具下载地址  
  
**点击关注下方名片****进入公众号**  
  
**回复关键字【****NemucodAES****】获取****下载链接**  
  
  
**全国热线| 400-613-6816**  
  
**更多资讯| 扫码加入群组交流**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntpabHUHgoXsxhR7eRUkMt5NhNiciboVodnnMqJgDtZ6oNP6lt64CVq0hmalgtIrx7XCfflZKyIkDk2g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
喜欢此内容的人还喜欢  
  
  
[【紧急警示】Weaxor最新变种“.wxx”来袭，批量入国内知名财务类管理系统发起勒索攻击！](https://mp.weixin.qq.com/s?__biz=MzkyOTQ0MjE1NQ==&mid=2247498941&idx=1&sn=bc6215afc52c9833b559b1385aca6ac6&scene=21#wechat_redirect)  
  
  
索勒安全团队  
  
  
[【紧急通告】Outlook公布高危漏洞CVE‑2025‑47176，攻击者可远程执行代码！](https://mp.weixin.qq.com/s?__biz=MzkyOTQ0MjE1NQ==&mid=2247500223&idx=1&sn=de4b65078010ed784d57d6d36465b175&scene=21#wechat_redirect)  
  
  
索勒安全团队  
  
# 【病毒分析】888勒索家族再出手！幕后加密器深度剖析索勒安全团队  
  
  
