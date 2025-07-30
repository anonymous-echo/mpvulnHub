#  安全研究员发现漏洞群，允许黑客逃离 Docker 和 runc 容器   
 安全客   2024-02-06 15:13  
  
Snyk 安全研究员   
Rory McNamara 和 Snyk 安全实验室团队在核心容器  
基础设施组件  
发现了四个统称为 “Leaky Vessels “的漏洞群，这些漏洞允许容器逃逸。攻击者可以利用这些容器逃逸从容器内获得对底层主机操作系统的未经授权的访问。一旦攻击者获得对底层主机操作系统的访问权限，他们就有可能访问系统上的任何数据，包括敏感数据（凭据、客户信息等），并发起进一步的攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Ok4fxxCpBb7ibCMcNC6m457mmCmsLuS0hA4Cg1GKSJTSjibaPMIC2EC2gOxDpBDVtUFo2y0WoNKRrkicMzN02NdvQ/640?wx_fmt=jpeg&from=appmsg "")  
  
在发现和验证后，安全实验室团队启动了负责任地披露漏洞的流程，首先通知 Docker，Docker 在审核后将其中一个漏洞转发给开源安全组runc。值得一提的是，安全研究员没有发现泄漏容器漏洞在野外被积极利用的迹象，但是还是建议所有受影响的系统管理员尽快应用可用的安全更新。  
## 安全漏洞影响范围广泛，危害极大  
  
容器是打包到一个文件中的应用程序，包含运行应用程序所需的所有运行时依赖项、可执行文件和代码，一般由 Docker 和 Kubernetes 等平台执行，这些平台在与操作系统隔离的虚拟化环境中运行应用程序。  
  
当威胁攻击者或恶意应用程序脱离隔离的容器环境，未经授权访问主机系统或其他容器时，就会发生容器逃逸。Snyk 团队发现四个统称为 “Leaky Vessels “的漏洞，主要影响了 runc 和 Buildkit 容器基础架构和构建工具，可能允许威胁攻击者在各种软件产品上执行容器逃逸。  
  
由于多种流行的容器管理软件（如 Docker 和 Kubernetes）都在使用 runc 或 Buildkit，因此安全漏洞造成的网络完全风险显得尤为严重。  
  
”Leaky Vessels “漏洞概述如下：  
> CVE-2024-21626：该漏洞源于 runc 中 WORKDIR 命令的操作顺序漏洞，允许威胁攻击者逃离容器的隔离环境，对主机操作系统进行未经授权的访问，并可能危及整个系统；  
> CVE-2024-23651：Buildkit 的挂载缓存处理中的竞赛条件导致不可预测的行为，可能允许威胁攻击者操纵进程进行未经授权的访问或破坏正常的容器操作；  
> CVE-2024-23652：允许在 Buildkit 的容器拆卸阶段任意删除文件或目录的漏洞，可能导致拒绝服务、数据损坏或未经授权的数据操作；  
> CVE-2024-23653：该漏洞源于 Buildkit 的 GRPC 接口权限检查不足，可能允许威胁攻击者执行超出其权限的操作，导致权限升级或未经授权访问敏感数据。  
  
## “Leaky Vessels “安全漏洞群的补救措施  
  
鉴于 Buildkit 和 runc 被 Docker 等流行项目和多个 Linux 发行版广泛使用，因此 Snyk 安全研究团队、受影响组件（runc 和 Buildkit）的维护者以及更广泛的容器基础架构社区需要采取协调一致的行动，立刻修补 “Leaky Vessels “漏洞群。  
  
2024 年 1 月 31 日，Buildkit 在 0.12.5 版本中修复了安全漏洞，runc 在 1.1.12 版本中解决了影响它的安全漏洞问题。Docker 也在同一天发布了 4.27.0 版，在其 Moby 引擎中纳入了组件的安全版本 25.0.1 和 24.0.8。  
  
随后，亚马逊网络服务、谷歌云和 Ubuntu 相继发布了安全公告，指导用户采取适当步骤解决其软件和服务中的安全漏洞。最后，CISA 还发布了一份警报，敦促云系统管理员采取适当措施，确保其系统免受潜在攻击。  
  
  
**来**  
  
**领**  
  
**资**  
  
**料**  
  
**【免费领】**  
**网络安全专业入门与进阶学习资料，轻松掌握网络安全技能！**  
  
****![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb5zfVHMK8vJ8zic6ibgeibGEWYYPXYX3hmApQCWbJxhyeUWjAQgCqgfROhlRQRunSZX39mJbudrqGoZA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
