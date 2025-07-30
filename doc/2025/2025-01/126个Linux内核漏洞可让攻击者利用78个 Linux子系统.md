#  126个Linux内核漏洞可让攻击者利用78个 Linux子系统   
何威风  祺印说信安   2025-01-21 16:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rTibWNx9ARWnuoSW8vkOrDrWjBnQjSNrgKhH2T0YaBODom9ic9bjwEELb4BF2P9LlibQO2omvnZ5uWnQicVY91jy8A/640?wx_fmt=png&from=appmsg "")  
  
Canonical 发布了一个重要的安全补丁，以解决Xilinx ZynqMP  
处理器  
的 Linux 内核中的几个严重漏洞，建议 Ubuntu 22.04 LTS 用户立即更新他们的系统。  
  
Xilinx Zynq UltraScale+ MPSoC (ZynqMP) 的 Linux 内核是 Linux 内核的一个专门版本，专门用于支持 Xilinx Zynq UltraScale+ MPSoC 系列处理器的功能和硬件。  
  
这些处理器结合了四核 ARM Cortex-A53（64 位）应用处理器、双核 ARM Cortex-R5（32 位）实时处理器、ARM Mali-400 GPU 和可编程逻辑 (FPGA)。  
  
Linux 内核为这些设备上的嵌入式和通用应用程序提供了坚实的基础。  
  
如果不进行修补  
，这些漏洞可能会让攻击者破坏系统，从而可能导致未经授权的访问或破坏。  
  
“Linux 内核中发现了几个安全问题。攻击者可能会利用这些问题来破坏系统”。  
  
该补丁解决了数百个 CVE，涵盖子系统、架构、驱动程序和协议中的漏洞。官方安全通知中提供了已解决 CVE 的完整列表。  
## Linux 内核更新带来安全修复和增强功能  
  
最新的 Linux 内核更新为多个子系统提供了关键的安全补丁和性能改进：  
- **架构：**  
 ARM32、x86、RISC-V 和 S390 的更新。  
  
- **文件系统：**  
增强了 BTRFS、Ext4、GFS2、Ceph、NFS、JFS 和 F2FS 的安全性和性能。  
  
- **驱动程序：**  
修复 GPU、USB、蓝牙、GPIO、以太网绑定和 InfiniBand 驱动程序。  
  
- **网络：**  
 TCP、SCTP、IPv4、IPv6、Netfilter 等的改进。  
  
- **安全框架：**  
 SELinux 和访问控制模块的更新。  
  
- **核心组件：**  
内存管理和跟踪基础设施的优化。  
  
以下是更新后的表格，其中包含每个相关 CVE 的链接：  
  
<table><thead style="border-bottom: 3px solid;"><tr><th style="padding: 2px 8px;text-align: left;border-color: initial;word-break: break-word;"><strong>类别/子系统</strong></th><th style="padding: 2px 8px;text-align: left;border-color: initial;word-break: break-word;"><strong>细节</strong></th><th style="padding: 2px 8px;text-align: left;border-color: initial;word-break: break-word;"><strong>相关 CVE</strong></th></tr></thead><tbody><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>架构</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">ARM32、RISC-V、S390、x86</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49938</span><span style="vertical-align: inherit;">、</span><span style="vertical-align: inherit;">CVE-2024-49966</span><span style="vertical-align: inherit;">、</span><span style="vertical-align: inherit;">CVE-2024-50013</span><span style="vertical-align: inherit;">、</span><span style="vertical-align: inherit;">CVE-2024-50093</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>块层子系统</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">存储块层管理</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49944</span><span style="vertical-align: inherit;">、</span><span style="vertical-align: inherit;">CVE-2024-50046</span><span style="vertical-align: inherit;">、</span><span style="vertical-align: inherit;">CVE-2024-50096</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>ACPI 驱动程序</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">高级配置和电源接口</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49985</span><span style="vertical-align: inherit;">和</span><span style="vertical-align: inherit;">CVE-2024-50040</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>驱动核心</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">跨子系统的核心驱动程序</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49924</span><span style="vertical-align: inherit;">和</span><span style="vertical-align: inherit;">CVE-2024-49981</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>以太网 ATA (AOE)</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">以太网上的 ATA 协议</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49877</span><span style="vertical-align: inherit;">和</span><span style="vertical-align: inherit;">CVE-2024-49975</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>TPM 设备驱动程序</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">可信平台模块</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49902</span><span style="vertical-align: inherit;">和</span><span style="vertical-align: inherit;">CVE-2024-49903</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>时钟框架和驱动程序</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">定时和同步驱动程序</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-50062</span><span style="vertical-align: inherit;">和</span><span style="vertical-align: inherit;">CVE-2024-49997</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>EFI 核心</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">可扩展固件接口核心功能</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49977</span><span style="vertical-align: inherit;">和</span><span style="vertical-align: inherit;">CVE-2024-50024</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>GPU 驱动程序</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">图形处理单元驱动程序</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-50038</span><span style="vertical-align: inherit;">和</span><span style="vertical-align: inherit;">CVE-2024-50008</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>文件系统</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">Ext4、BTRFS、Ceph、NFS（客户端/服务器/超级块）、NILFS2、GFS2、F2FS、JFS</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49936</span><span style="vertical-align: inherit;">、</span><span style="vertical-align: inherit;">CVE-2024-49892</span><span style="vertical-align: inherit;">、</span><span style="vertical-align: inherit;">CVE-2024-50049</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>网络核心</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">IPv4、IPv6、CAN、多路径 TCP、MAC80211</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49863</span><span style="vertical-align: inherit;">、</span><span style="vertical-align: inherit;">CVE-2024-50033</span><span style="vertical-align: inherit;">、</span><span style="vertical-align: inherit;">CVE-2024-50015</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>USB 驱动程序</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">USB 设备类，USB Type-C 端口控制器</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-50019</span><span style="vertical-align: inherit;">和</span><span style="vertical-align: inherit;">CVE-2024-50059</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>蓝牙子系统</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">蓝牙协议栈</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49913</span><span style="vertical-align: inherit;">和</span><span style="vertical-align: inherit;">CVE-2024-50044</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>内核安全</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">SELinux，简化强制访问控制内核框架</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49948</span><span style="vertical-align: inherit;">和</span><span style="vertical-align: inherit;">CVE-2024-50095</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>媒体驱动程序</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">Amlogic Meson SoC 驱动程序、AudioScience HPI、USB 声音</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49973</span><span style="vertical-align: inherit;">和</span><span style="vertical-align: inherit;">CVE-2024-50038</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>内存管理</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">内核级内存管理</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49871</span><span style="vertical-align: inherit;">和</span><span style="vertical-align: inherit;">CVE-2024-50001</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>性能事件</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">性能监视事件</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49967</span><span style="vertical-align: inherit;">、</span><span style="vertical-align: inherit;">CVE-2024-49954</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><strong>追踪基础设施</strong></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">内核跟踪框架</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49995</span><span style="vertical-align: inherit;">、</span><span style="vertical-align: inherit;">CVE-2024-49957</span></td></tr></tbody></table>  
除了子系统更新之外，Ubuntu 还发布了安全更新，以解决影响其他系统的漏洞。  
  
以下是更新后的表格，其中嵌入了 CVE 标识符的链接：  
  
<table><thead style="border-bottom: 3px solid;"><tr><th style="padding: 2px 8px;text-align: left;border-color: initial;word-break: break-word;"><strong>缺失的 CVE</strong></th><th style="padding: 2px 8px;text-align: left;border-color: initial;word-break: break-word;"><strong>受影响区域</strong></th></tr></thead><tbody><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49907</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">内核内存管理子系统</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-50062</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">时钟框架和驱动程序</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-36893</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">ACPI 驱动程序</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49903</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">TPM 设备驱动程序</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49886</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">USB 驱动程序</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-50180</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">以太网绑定驱动程序</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-47757</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">网络核心</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49938</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">体系结构（x86）</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-47709</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">网络流量控制</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49884</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">媒体驱动程序</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49977</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">电喷核心</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-47734</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">InfiniBand 驱动程序</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49963</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">GPU 驱动程序</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-47747</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">蓝牙子系统</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-50008</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">GPU 驱动程序</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-47696</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">文件系统（Ceph、NFS）</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-50038</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">GPU 驱动程序</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-46695</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">USB Type-C 端口控制器管理器</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-47705</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">媒体驱动程序</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49957</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">追踪基础设施</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-38538</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">IPv6 网络</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-50019</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">USB 驱动程序</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-38544</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">IPv4 网络</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-50003</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">SELinux 安全模块</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-50095</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">简化的强制访问控制内核框架</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-50000</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">文件系统基础设施</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49981</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">驱动核心</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49863</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">网络核心</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-47710</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">IPv4 网络</span></td></tr><tr><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">CVE-2024-49983</span></td><td style="padding: 2px 8px;border-color: initial;word-break: break-word;"><span style="vertical-align: inherit;">多路径 TCP</span></td></tr></tbody></table>  
这些漏洞影响 Linux 内核中的多个子系统和组件，凸显了问题的复杂性和广泛性。如需查看完整列表，请访问  
Ubuntu 安全通知 (USN-7166-4)  
。  
  
Canonical 已针对这些问题提供了针对性的内核更新。受影响的软件包为linux-xilinx-zynqmp  
，更新版本为**5.15.0-1039.43**  
。建议用户检查当前版本并立即升级，以确保系统安全。  
  
要应用更新，用户应在其终端中执行以下命令：  
```
sudo apt update
sudo apt upgrade
sudo reboot
```  
  
重新启动至关重要，以确保应用所有修复并使用新更新的内核。  
  
此补丁对应用程序二进制接口 (ABI) 进行了更改，需要重新编译和重新安装任何第三方内核模块。  
  
然而，对于大多数没有手动删除标准内核元包（例如linux-generic  
）的用户，此过程将在升级期间自动完成。  
  
此次更新是 Canonical 持续致力于确保其开源操作系统的安全性和稳定性的一部分。  
  
鉴于漏洞的严重性和范围，强烈建议 Ubuntu 用户尽快更新系统，以避免潜在的攻击。  
  
**—END—**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWhJou9CCpqmibD6ldgHL2ONAnycCV5yOcv7NiccibzQb5oMWLVmYhwK6jQaSapdQNKVoTAePYIKqmmicA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
[精彩回顾：祺印说信安2024之前](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103882&idx=1&sn=fe68b43898a872f40e66a8cdb720d7d7&chksm=8bbccef3bccb47e5bd52249ff6490fe17df9696568053776e4124ef70d790a5ed06f2d3c6809&scene=21#wechat_redirect)  
  
  
[祺印说信安2024年一年回顾](https://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652113685&idx=1&sn=d3320d1235049cfe41884d009ec597cc&scene=21#wechat_redirect)  
  
  
**——等级保护**  
  
河南省新规定测评与密评预算再调低  
  
四川省等级测评与商密评估预算计算方法  
  
[广西壮族自治区等级测评与商密评估预算为几何？](https://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652113803&idx=1&sn=f9bbfaf9193865b0419628a0c7d349ef&scene=21#wechat_redirect)  
  
  
**——数据安全**  
  
[《网络数据安全管理条例》解读](https://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652113680&idx=1&sn=86da41ae8e79d457e121599e64b266f3&scene=21#wechat_redirect)  
  
  
**——错与罚**  
  
江苏涟水农村商业银违反网络安全与数据安全管理规定等被罚114.5万  
  
江苏灌南农商行因违反数据安全管理规定等被罚97.5万  
  
网安企业“内鬼”监守自盗，窃取个人信息2.08亿条  
  
**郑州3家公司未履行网络安全保护义务被网信部门约谈**  
  
**25年郑州新增两家公司违反《网络安全法》被市网信办行政处罚**  
  
**驻马店市委网信办就网络安全问题依法约谈相关责任单位**  
  
[](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103528&idx=1&sn=fef657b5a0e1982eff81b5c92f33db57&chksm=8bbcc951bccb4047211ef41c22541966c1c25dbee9f79c45e1e429fb485f675b706babdcf347&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652100366&idx=1&sn=27d04d1abc7a02a6b731322416805a1a&chksm=8bbcfd37bccb7421ab6f679bd83b34e02c930e2beca304844ee59a8843d5b18df1bf52d4e032&scene=21#wechat_redirect)  
  
