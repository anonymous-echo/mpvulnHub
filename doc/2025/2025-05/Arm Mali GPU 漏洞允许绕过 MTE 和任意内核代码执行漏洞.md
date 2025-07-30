#  Arm Mali GPU 漏洞允许绕过 MTE 和任意内核代码执行漏洞   
 网安百色   2025-05-27 11:32  
  
在 Arm Mali GPU 驱动程序中发现了一个被确定为 CVE-2025-0072 的严重漏洞，该漏洞对采用命令流前端 （CSF） 架构的较新 Mali GPU 的设备构成重大威胁，包括 Google 的 Pixel 7、Pixel 8 和 9 系列。  
  
该漏洞由安全研究人员于 2024 年 12 月 12 日报告给 Arm，随后在 2025 年 5 月 2 日发布的 Mali 驱动程序版本 r54p0 中进行了修补，作为 Android 2025 年 5 月安全更新的一部分，它允许恶意 Android 应用程序绕过内存标记扩展 （MTE） 并实现任意内核代码执行。  
  
此漏洞利用在启用了内核 MTE 的 Pixel 8 上成功测试，凸显了即使实施了高级硬件保护，在保护低级内存作方面也存在持续的挑战。  
## 新增 CVE-2025-0072 漏洞  
  
该漏洞利用了 Mali GPU 驱动程序中对 CSF 队列的处理，特别是通过通过 ioctl 管理的对象和结构的交互，例如 和 。kbase_queuekbase_queue_groupKBASE_IOCTL_CS_QUEUE_BINDKBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE  
  
通过仔细编排队列的绑定和终止，攻击者可以纵该字段以指向新分配的 GPU 内存页面，同时保持与以前释放的页面的用户空间映射。queue->phys  
  
这将创建一个释放后使用方案，在该方案中，释放的内存页仍可通过用户空间映射进行访问。  
## 利用 CSF 队列  
  
该漏洞利用进一步利用了这一点，将释放的页面重新用作 GPU 上下文的页表全局目录 （PGD），使攻击者能够映射和重写内核内存，包括内核代码，从而实现对系统的完全控制。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo6RCdcUP6h79lk8gl6oesdUlve3u7yT4lpZ32225wGGlbJYYPBvUmMB6qS3aKWhYSqqCk3aIuC2kQ/640?wx_fmt=png&from=appmsg "")  
  
  
一个漏洞利用的想法  
  
  
根据 GitHub 报告，此过程还允许纵进程凭据以获得 root 访问权限并禁用 SELinux，从而有效地破坏了设备的安全模型。  
  
使该漏洞特别令人担忧的是它能够绕过 MTE，MTE 是 Arm v8.5a 架构中一项基于硬件的安全功能，旨在通过标记内存指针和块来检测内存损坏问题，例如释放后使用。  
  
与之前通过 GPU作访问释放的内存的 Mali GPU 漏洞 （CVE-2023-6241） 不同，CVE-2025-0072 通过驱动程序使用如下函数创建的用户空间映射访问释放的内存。mgm_vmf_insert_pfn_prot  
  
这种将页帧直接插入到用户空间页表中的做法似乎避免了内核级的取消引用，从而避免了 MTE 的标签检查机制，即使页面返回到内核的伙伴分配器也是如此。  
  
这一发现凸显了 MTE 保护范围中的一个关键差距，因为当前硬件和软件保护措施仍未检查用户通过驱动程序创建的映射对释放内存的访问。  
  
CVE-2025-0072 揭示了在面对自定义内存池和特定于驱动程序的映射中的漏洞时，即使是像 MTE 这样的复杂内存安全机制的局限性。  
  
此漏洞不仅使攻击者能够对受影响的 Android 设备进行内核级控制，而且还清楚地提醒人们，需要在系统架构的各个级别进行全面的安全审计和缓解措施。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
