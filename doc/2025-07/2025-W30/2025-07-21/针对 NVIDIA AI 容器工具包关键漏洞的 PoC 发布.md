> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0NzE4ODk1Mw==&mid=2652096406&idx=2&sn=6471c0f86eb9b15e01ed8ae126826dee

#  针对 NVIDIA AI 容器工具包关键漏洞的 PoC 发布  
 网安百色   2025-07-21 10:58  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo4mS9sicLyicYfX99g84XN1vVoOvHabhicrhcs1I7Gj7Bez7cS46jF6pqu90AB38IeNbEmJFpVXr1sAA/640?wx_fmt=jpeg&from=appmsg "")  
  
NVIDIA 容器工具包中出现了一个严重的容器逃逸漏洞，威胁着全球人工智能基础设施的安全基础。  
  
该缺陷被称为“NVIDIAScape”，跟踪为 CVE-2025-23266，CVSS 最高得分为 9.0，是迄今为止发现的基于云的人工智能服务面临的最严重威胁之一。  
  
该漏洞允许恶意行为者摆脱容器隔离，并实现对运行 GPU 加速工作负载的主机系统的完全根级控制。  
  
该漏洞的毁灭性简单性使其有别于传统的复杂攻击媒介。  
  
研究人员已经证明，仅仅三行 Dockerfile 就可以将此漏洞武器化，使攻击者能够绕过所有容器安全边界。  
  
恶意负载利用 Linux LD_PRELOAD 环境变量在容器初始化期间将代码注入特权进程，将本应隔离的工作负载转变为破坏系统的威胁。  
  
Wiz.io 分析师发现，该漏洞源于 NVIDIA 容器工具包处理开放容器计划 （OCI） 挂钩的方式中的一个根本缺陷。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo4mS9sicLyicYfX99g84XN1vVmNb0yZdIMdibPIqG3kUtgWqb7iaEia4licxmBC7kkjDw0PYS4K9RGxv8Hg/640?wx_fmt=png&from=appmsg "")  
  
加载任意图像（来源 – Wiz.io）  
  
  
该工具包作为容器化 AI 应用程序和 NVIDIA GPU 之间的关键桥梁，在 createContainer 钩子执行阶段无意中从容器映像继承了环境变量。  
  
这会创建一个攻击面，恶意环境变量可以影响特权主机进程，从而导致系统完全受损。  
## 攻击的技术过程  
  
攻击媒介利用容器运行时与 NVIDIA 容器工具包的信任关系。  
  
当恶意容器映像包含环境变量时，该工具包的特权挂钩进程会直接从容器文件系统加载并执行攻击者的共享库文件。漏洞利用代码演示了这种技术：-
```
LD_PRELOAD=/proc/self/cwd/poc.so
```

  

```
FROM busybox
ENV LD_PRELOAD=/proc/self/cwd/poc.so
ADD poc.so /
```

  
这种看似简单的有效负载允许对底层主机系统的即时 root 访问权限，绕过所有容器隔离机制。  
  
该漏洞影响 v1.17.7 之前的所有 NVIDIA 容器工具包版本，并对客户在共享 GPU 基础设施上部署自定义容器映像的多租户 AI 云环境构成系统性风险。  
  
使用主要云提供商的托管人工智能服务的组织立即面临风险，因为单个恶意容器可能会危及整个主机系统并访问属于多个租户的敏感数据。  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
