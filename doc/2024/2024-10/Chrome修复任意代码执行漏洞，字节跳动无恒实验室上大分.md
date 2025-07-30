#  Chrome修复任意代码执行漏洞，字节跳动无恒实验室上大分   
 独眼情报   2024-10-04 09:58  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnQ0UL7gborIjpet3fLGB2ibbEcBf3O2JOibRiauyfXz72uXVzeTFfleaLg1AhCGRA8ahCTAHhXIozDNw/640?wx_fmt=jpeg&from=appmsg "")  
谷歌为其Chrome浏览器发布了一个关键的安全更新，解决了多个可能允许攻击者在用户系统上执行任意代码的高严重性漏洞。  
  
最新的稳定版更新，版本号为Windows和Mac的129.0.6668.89/.90以及Linux的129.0.6668.89，正在全球范围内向用户推出。  
# 关键漏洞披露  
  
此次更新中的四个安全修复中有三个是由外部安全研究人员报告的，这突显了协作努力在维护浏览器安全方面的重要性。最严重的漏洞包括：  
1. 布局中的整数溢出（CVE-2024-7025）：由Tashita Software Security发现，这一高严重性漏洞可能允许攻击者执行任意代码或导致拒绝服务。  
  
1. Mojo中的数据验证不足（CVE-2024-9369）：**由字节跳动旗下无恒实验室研究人员Xiantong Hou和Pisanbao 报告，这一Chrome IPC库中的漏洞可能导致敏感信息泄露或权限提升。** （中文名实在是没找到，大佬们太低调了，知道中文名的大佬麻烦评论一下）  
  
1. V8中的不当实现（CVE-2024-9370）：由STAR Labs SG Pte. Ltd.的研究人员发现，这一Chrome JavaScript引擎中的问题可能使恶意行为者能够操纵网页内容或执行任意代码。  
  
谷歌的Chrome漏洞奖励计划（VRP）在识别和解决这些安全问题方面发挥了重要作用。该计划已运行14年，为发现和报告关键漏洞的研究人员提供最高25万美元的奖励。  
  
为了鼓励更彻底的研究，谷歌最近更新了其奖励结构。例如，发现远程代码执行（RCE）漏洞现在可为研究人员带来最高25万美元的奖励，而发现受控写入漏洞则可获得最高9万美元的奖励。  
  
强烈建议Chrome用户立即更新他们的浏览器，以防范这些潜在威胁。虽然更新过程通常是自动的，但用户也可以通过导航到浏览器设置中的“关于Google Chrome”部分手动检查更新。  
  
由于这些漏洞的细节在大多数用户更新之前仍受到限制，因此用户及时行动以确保其系统免受潜在利用至关重要。  
  
> https://chromereleases.googleblog.com/2024/10/stable-channel-update-for-desktop.html  
  
  
  
  
  
