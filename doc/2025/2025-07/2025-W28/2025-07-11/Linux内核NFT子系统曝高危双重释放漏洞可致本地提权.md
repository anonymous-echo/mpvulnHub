> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324803&idx=3&sn=a328e0d32ba8414355872528a04b0823

#  Linux内核NFT子系统曝高危"双重释放"漏洞可致本地提权  
 FreeBuf   2025-07-11 10:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibB6c57w7TYCsC97JxXoqaKM8vEQx04zY5wdDF32x8atw2GAqKhCLsCSLW2JlmK6gEDBLmrbujbMQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Linux内核的NFT（netfilter）子系统中的pipapo集合模块被发现存在严重的"双重释放"（double-free）漏洞。该高危安全缺陷允许低权限攻击者通过特制的netlink消息触发内核内存破坏，最终实现本地权限提升。  
  
  
**Part01**  
## 漏洞核心要点  
  
  
1. Linux内核NFT子系统（5.6-rc1至6.13-rc3版本）存在双重释放漏洞，可导致本地提权  
  
  
2. 当CONFIG_INIT_STACK_ALL_ZERO配置禁用时，nft_add_set_elem函数中的未初始化栈变量会引发内存破坏  
  
  
3. 攻击者发送特制netlink消息，通过先删除集合元素再删除整个集合的方式触发双重释放  
  
  
4. 启用CONFIG_INIT_STACK_ALL_ZERO配置并应用netfilter补丁可正确初始化易受攻击的数据结构  
  
  
**Part02**  
## 漏洞技术分析  
  
  
该漏洞位于net/netfilter/nf_tables_api.c文件中的nft_add_set_elem函数，未初始化的栈变量struct nft_set_elem elem成为安全缺陷的根源。  
  
  
根据SSD安全公告，当CONFIG_INIT_STACK_ALL_ZERO配置选项被禁用时，栈上的未初始化数据会在处理过程中污染元素键值。漏洞代码路径处理用户提供的NFTA_SET_ELEM_KEY数据时，仅初始化了密钥长度（klen）范围内的内存，导致缓冲区剩余内容保留未初始化的栈数据。这些未初始化内存通常包含先前内核函数调用的指针，当pipapo集合尝试删除元素时就会触发双重释放条件。  
  
  
漏洞利用过程涉及复杂的堆利用技术，可实现KASLR绕过并建立任意写入原语。攻击者可通过以下步骤触发漏洞：  
  
- 初始设置：创建具有特定字段配置的netfilter表和pipapo集合，生成未初始化的填充字节  
  
- 首次释放：删除集合元素，导致首次释放elem->priv，而该元素仍保留在pipapo集合引用中  
  
- 二次释放：删除整个集合，触发对同一内存区域的二次释放  
  
**Part03**  
## 影响范围与配置要求  
  
  
该漏洞影响Linux内核5.6-rc1至6.13-rc3版本，需要特定的内核配置组合：  
  
- CONFIG_NETFILTER=y  
  
- CONFIG_NF_TABLES=y  
  
- CONFIG_USER_NS=y  
  
- 关键条件：CONFIG_INIT_STACK_ALL_ZERO=n  
  
漏洞利用利用了elem->priv结构大小可在32-256字节间变化的特性，为kmalloc缓存目标选择提供了灵活性。  
  
  
**Part04**  
## 缓解措施  
  
  
该漏洞提供了可靠的双重释放原语，可被用于本地权限提升，安全风险极高。攻击者通过暴力破解技术识别触发漏洞的最佳密钥长度，使攻击具有高度稳定性。  
  
  
有效的缓解策略包括：  
  
- 启用CONFIG_INIT_STACK_ALL_ZERO内核编译选项，将局部变量初始化为零值，防止未初始化数据污染  
  
- 应用netfilter开发团队提供的补丁，从根源上修复问题——正确初始化elem结构  
  
该漏洞与CVE-2023-4004的相似性凸显了内核内存管理问题的重复模式，强调了在内核开发中正确初始化变量和全面堆栈保护机制的重要性。  
  
  
**参考来源：**  
  
Critical Linux Kernel’ Double Free Vulnerability Let Attackers Escalate Privileges  
  
https://cybersecuritynews.com/linux-kernel-double-free-vulnerability/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324737&idx=1&sn=8f0843cf1d51ac50bd1eae4a5f0e4c87&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
   
  
