> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3OTc0NDcyNQ==&mid=2247494081&idx=1&sn=a1421640c4cb4056f1d971c7730e3d2f

#  Linux漏洞链致使主流发行版均可获取Root权限  
鹏鹏同学  黑猫安全   2025-06-22 13:12  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceic81h17jrkaSFBrlKsvQFswmELZniaESiacGGFMic4y2HBNBtUprCdt5dicgI0vaYHYkZW4yXMlhJBIIg/640?wx_fmt=png&from=appmsg "")  
  
Qualys研究人员发现两处本地提权漏洞（LPE），攻击者可利用其在主流Linux发行版上获取root权限。  
  
这两处漏洞分别为：  
- **CVE-2025-6018**  
：通过*SUSE 15的PAM模块从普通用户提权至allow_active权限  
  
- **CVE-2025-6019**  
：通过libblockdev的udisks服务从allow_active权限提权至root  
  
首个漏洞（CVE-2025-6018）允许通过SSH连接的本地低权限用户伪装成物理终端用户，获取本应仅限现场操作者的权限。第二个漏洞（CVE-2025-6019）存在于libblockdev组件中，可通过默认启用的udisks服务利用，使得物理接触者或已入侵用户提升至root权限。二者结合后，攻击者能完全控制系统。  
  
尽管从任意低权限用户直达root的攻击本就危险，但该漏洞链的威胁性尤为突出——因其极易被串联利用。研究人员指出，近期多起知名攻击均利用了相同的"allow_active"用户漏洞，例如Pumpkin Chang的博客所述通过D-Bus和Polkit规则在SSH中伪装物理用户的手法。  
  
Qualys在报告中强调："虽然CVE-2025-6019本身需要allow_active上下文，但结合CVE-2025-6018后，完全无特权的攻击者也能获得root权限。这个libblockdev/udisks漏洞影响极其广泛——尽管名义上需要allow_active权限，但udisks默认预装在几乎所有Linux发行版中。而获取allow_active权限的方法（包括本文披露的PAM漏洞）进一步降低了攻击门槛，攻击者只需简单串联漏洞即可轻松实现root提权。"  
  
经确认，Ubuntu、Debian等主流系统均受影响。Qualys已开发概念验证代码验证漏洞有效性。建议用户尽快安装补丁，或临时修改Polkit规则强制要求管理员认证。  
  
  
