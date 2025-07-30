#  Windows 部署服务中发现新漏洞   
 网安百色   2025-05-06 11:31  
  
在 Microsoft 的 Windows 部署服务 （WDS） 中新发现的身份验证前拒绝服务 （DoS） 漏洞会通过恶意 UDP 数据包使企业网络立即面临系统崩溃的风险。  
  
被称为“0-click”缺陷，攻击者可以在没有用户交互的情况下远程利用它，耗尽服务器内存，直到关键服务出现故障。  
  
虽然人们的注意力都集中在远程代码执行错误上，但基于 UDP 的服务（如 WDS）中的内存耗尽漏洞构成了被低估的风险。  
  
这些缺陷允许攻击者通过迫使系统分配过多资源来压垮系统，从而以最小的努力使服务器崩溃。  
  
WDS 是企业 IT 基础设施的支柱，它说明了这些弱点如何危及 Internet 规模的运营。  
  
WDS 支持跨组织对 Windows作系统映像进行基于网络的部署，具体取决于：  
- PXE 引导：客户端通过 Preboot Execution Environment 引导以获取作系统映像。  
  
- TFTP/多播传输：高效分发 Windows PE 引导文件和安装映像。  
  
- 无人值守安装：使用答案文件自动进行设置。  
  
WDS 广泛用于企业网络、数据中心和学术机构。  
## UDP 漏洞利用：一个简单的缺陷如何使系统崩溃  
  
WDS 使用端口 69/UDP 进行 TFTP 通信。研究人员发现，每个连接请求都会创建一个 CTftpSession 对象，该对象无限制地存储在 EndpointSessionMapEntry 中。  
  
攻击者可以使用随机的源 IP 和端口来欺骗 UDP 数据包，迫使 WDS 创建无休止的会话，直到内存耗尽。  
  
**概念验证：模拟攻击**  
  
伪代码片段演示了漏洞利用的简单性：  
```
void fake_send(const char *dst_ip, int dst_port) {  for (unsigned int i = 0x4000000; i < 0xffffffff; i++) {    char src_ip[16];    int_to_ip(i, src_ip); // Generate random spoofed IP    for (int port = 0x4000; port < 0xe000; port++) {      udp_send(src_ip, port, dst_ip, dst_port, malicious_data); // Flood server    }  }}
```  
  
在测试中，当内存使用率达到 15GB 时，具有 8GB RAM 的 Windows Server 在 7 分钟后崩溃。多线程攻击可能会以指数级方式加速这一过程。  
  
企业的关键要点  
1. 监视 WDS 服务器：监视端口 69 上的异常 UDP 流量。  
  
1. 限制网络暴露：限制 WDS 对受信任子网的访问。  
  
1. 向 Microsoft 施压：倡导修补被低估的 DoS 风险。  
  
此缺陷凸显了基于 UDP 的服务的脆弱性，以及对系统性内存管理保护措施的迫切需求。在 Microsoft 解决这一问题之前，企业仍然容易受到破坏性、低工作量的攻击。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
