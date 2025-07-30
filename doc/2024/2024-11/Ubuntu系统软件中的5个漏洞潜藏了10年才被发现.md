#  Ubuntu系统软件中的5个漏洞潜藏了10年才被发现   
Zicheng  FreeBuf   2024-11-21 11:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oQ6bDiaGhdyoFWEgZIHic7sqnootFEuOic7RlQNGhKY6d2ZESG3WpiaTMRlD0z4xO6mQrTZjkWHCkMpO2QtCfUJH6g/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
Ubuntu系统中的实用程序 needrestart 近日被曝出存在5个本地权限提升 （LPE） 漏洞，这些漏洞不是最近才产生，而是已经潜藏了10年未被发现。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Yib4V42TxSau0bRFaxq0jxmlYWEcQJ9xEn47CAicIgdyC8Xuka5WXXI0CFX3dnRI0ud82GPYZs2qg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
这些漏洞由 Qualys 发现，并被跟踪为 CVE-2024-48990、CVE-2024-48991、CVE-2024-48992、CVE-2024-10224 和 CVE-2024-11003，由 2014 年 4 月发布的Needrestart  0.8 版本中引入，直到最近的11月19日才在3.8 版本中修复。  
  
  
这5个漏洞允许攻击者在本地访问有漏洞的 Linux 系统，在没有用户交互的情况下将权限升级到 root：  
  
- CVE-2024-48990：Needrestart 使用从运行进程中提取的 PYTHONPATH 环境变量执行 Python 解释器。如果本地攻击者控制了这个变量，就可以通过植入恶意共享库，在 Python 初始化过程中以 root 身份执行任意代码。  
  
- CVE-2024-48992：Needrestart 使用的 Ruby 解释器在处理攻击者控制的 RUBYLIB 环境变量时存在漏洞。这允许本地攻击者通过向进程注入恶意库，以 root 身份执行任意 Ruby 代码。  
  
- CVE -2024-48991：Needrestart 中的争用条件允许本地攻击者用恶意可执行文件替换正在验证的 Python 解释器二进制文件。通过仔细把握替换时机，可以诱使 Needrestart 以 root 身份运行他们的代码。  
  
- CVE-2024-10224：Needrestart 使用的 Perl ScanDeps 模块未正确处理攻击者提供的文件名。攻击者可以制作类似于 shell 命令的文件名（例如 command|），以便在打开文件时以 root 身份执行任意命令。  
  
- CVE-2024-11003：Needrestart 对 Perl 的 ScanDeps 模块的依赖使其暴露于 ScanDeps 本身的漏洞中，其中不安全地使用 eval（） 函数会导致在处理攻击者控制的输入时执行任意代码。  
  
值得注意的是，为了利用这些漏洞，攻击者必须通过恶意软件或被盗帐户对操作系统进行本地访问，这在一定程度上降低了风险。但攻击者过去也利用过类似的 Linux 权限提升漏洞来获得 root 权限，包括 Loony Tunables 和利用 nf_tables 漏洞，因此不能因为这些漏洞需要本地访问权限就疏于修补。  
  
  
除了升级到版本 3.8 或更高版本（包括所有已识别漏洞的补丁）之外，建议用户修改Needrestart.conf 文件以禁用解释器扫描功能，从而防止漏洞被利用。  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
> https://www.bleepingcomputer.com/news/security/ubuntu-linux-impacted-by-decade-old-needrestart-flaw-that-gives-root/  
  
  
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302087&idx=1&sn=29d91904d6471c4b09f4e574ba18a9b2&chksm=bd1c3a4c8a6bb35aa4ddffc0f3e2e6dad475257be18f96f5150c4e948b492f32b1911a6ea435&token=21436342&lang=zh_CN&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302006&idx=1&sn=18f06c456804659378cf23a5c474e775&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
