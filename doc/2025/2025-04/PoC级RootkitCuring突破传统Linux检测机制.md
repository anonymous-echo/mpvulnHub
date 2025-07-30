#  PoC级Rootkit"Curing"突破传统Linux检测机制   
鹏鹏同学  黑猫安全   2025-04-29 01:29  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce9CKoqLh9Guwat7ACs5OCHA3NKl1JgGx1IZvvvrUvjfHOgoBCwX8BClTTibYh4uhPD3p1mgn5Rd4Iw/640?wx_fmt=png&from=appmsg "")  
  
该概念验证型Rootkit利用Linux异步I/O机制io_uring实现无系统调用攻击，成功规避主流安全监测方案。研究团队在GitHub披露："Curing通过io_uring执行各类操作而无需触发系统调用，使依赖syscall监控的安全工具完全失效。其命名灵感源自38C3黑客大会（C与io_uring的组合）"  
  
**技术突破性**  
1. **攻击原理**  
  
- 利用2019年Linux 5.1内核引入的io_uring API  
  
- 通过用户态与内核态共享的环形缓冲区实现零系统调用操作  
  
- 当前支持61种关键操作（含网络/文件系统访问）  
  
1. **对抗效果**  
  
- 成功绕过Falco/Tetragon等运行时检测系统  
  
- 对Microsoft Defender仅触发基础文件完整性告警  
  
- SentinelOne成为少数可检测该攻击的商业方案  
  
**检测盲区分析**  
  
c  
  
  
复制  
  
  
下载  
```
```  
```
```  
```
```  
```
```  
```
```  
```
```  
```
```  
```
```  
```
```  
```
```  
```
```  
  
**行业影响评估**  
1. **现有方案缺陷**  
✓ 多数Linux EDR无法监控io_uring活动  
✓ Falco计划通过LSM钩子增强检测（当前版本存在盲区）  
✓ Tetragon需手动配置Kprobes才能发现异常  
  
1. **防御建议**  
  
- 优先部署支持LSM（Linux安全模块）的检测方案  
  
- 在eBPF程序中强制添加io_uring操作审计点  
  
- 对/proc/[pid]/io_uring实施强制访问控制  
  
**未来挑战**  
报告指出："尽管行业正转向eBPF探针开发，但其验证器的严格限制导致难以全面监控io_uring。如何平衡安全性与性能，将成为下一代Linux安全方案的核心挑战。"  
  
  
