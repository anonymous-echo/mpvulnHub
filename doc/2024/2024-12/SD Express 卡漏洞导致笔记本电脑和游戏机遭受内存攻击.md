#  SD Express 卡漏洞导致笔记本电脑和游戏机遭受内存攻击   
原创 很近也很远  网络研究观   2024-12-07 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxNWn8DsOGyU1TicyI7LK0icuwK7r2dsINvnTvYJ3r1dib3LUk1yyf8CmrVWFggNJ4ULJaZZ7UAIF8xAg/640?wx_fmt=png&from=appmsg "")  
  
Positive Technologies 最近发布的一份报告揭示了一个名为 DaMAgeCard 的新漏洞，攻击者可以利用该漏洞利用 SD Express 内存卡直接访问系统内存。  
  
该漏洞利用了 SD Express 中引入的直接内存访问 (DMA) 功能来加速数据传输速度，但也为对支持该标准的设备进行复杂的攻击打开了大门。  
  
研究人员演示了经过修改的 SD Express 卡如何绕过 IOMMU 等系统保护措施，对游戏机、笔记本电脑和其他高速媒体设备构成了重大威胁。  
### 了解 DaMAgeCard  
###   
  
由嵌入式系统研究人员领导的Positive Technologies 公司在对 SD Express 进行例行调查时发现了该漏洞。  
# 新招数，老把戏：DaMAgeCard 攻击直接通过 SD 卡读卡器攻击内存  
#   
# https://swarm.ptsecurity.com/new-dog-old-tricks-damagecard-attack-targets-memory-directly-thru-sd-card-reader/  
#   
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxNWn8DsOGyU1TicyI7LK0icuwNGr2TYQSILPrwMIicOwiaM7UiasCxIOtvsvwibJtA3tiaOt5J5ZPwt3JeRg/640?wx_fmt=png&from=appmsg "")  
  
该标准于 2018 年首次推出，随着采用基于 PCIe 的数据传输功能以实现更快速度的设备而受到关注。  
  
尽管 SD Express 在高速应用方面具有潜力，但该团队发现业界在保护其 DMA 功能方面存在差距。  
  
通过自定义硬件修改，研究人员演示了在 MSI 游戏笔记本电脑和 AYANEO Air Plus 手持控制台等系统上成功的内存访问，揭示了在 SDIO（传统 SD 协议）和 PCIe 模式之间转换的设备缺乏足够的安全措施。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxNWn8DsOGyU1TicyI7LK0icuwSLqUQricibapdZq2tGJAdh9e5gJ5P9f9CrkK0bxFFLGMZSRWiaOo1FTrw/640?wx_fmt=png&from=appmsg "")  
  
主机与 SD 卡在协议层面的数据交换  
  
SD Express由 SD 协会设计，将传统的 SD 技术与 PCIe 和 NVMe 协议相结合，实现高达 985 MB/s 的传输速率。  
  
这种性能提升对于管理大型媒体文件至关重要，它引入了 PCIe 总线控制，该功能允许 SD 卡直接访问系统内存。  
  
虽然该实现旨在绕过 CPU 瓶颈来提高速度，但未能充分限制未经授权的内存访问。  
  
Realtek RTS5261 主机控制器和类似组件允许 SD Express 卡在连接后作为 PCIe NVMe 设备运行。  
  
这种转变正是 DaMAgeCard 的优势所在：攻击者可以利用实施不当的控件来操纵设备并访问敏感内存区域。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/yvLFKBRPQxNWn8DsOGyU1TicyI7LK0icuwI6Leo1N6iayG7RkPv09CicMtbFLLSGbicyKQn5IYdjQarurdj7R0ics92Q/640?wx_fmt=jpeg&from=appmsg "")  
  
通用适配器展示头位配置  
### 受影响的系统和风险  
###   
  
SD Express 的采用仍然相对有限，但正在增长，高端笔记本电脑、游戏机和媒体设备都采用了该标准。  
  
可能受影响的系统如下所列：  
- 1. AYANEO Air Plus 等游戏机缺乏 IOMMU 保护，允许未经过滤的内存访问。  
-   
- 2. 笔记本电脑，甚至包括像 MSI 游戏笔记本电脑这样带有 IOMMU 的高端系统，都可能被操纵，以允许通过修改后的 SD Express 卡进行未经授权的 DMA 访问。  
-   
- 3. 基于 PCIe 的外部读取器。  
-   
- 4. 摄影设备、摄像机和其他需要高速数据处理的嵌入式系统，其中 SD Express 是首选标准。  
-   
![](https://mmbiz.qpic.cn/mmbiz_jpg/yvLFKBRPQxNWn8DsOGyU1TicyI7LK0icuwcUbwnicTia6hdztb93vnzsLSjYME0xmUTATpu6APoJ86c1wiaW9MFMXhw/640?wx_fmt=jpeg&from=appmsg "")  
  
带有 Pi Pico 板载设置的 SD Express 适配器  
  
为了防范 DaMAgeCard 和类似的基于DMA 的攻击，Positive Technologies 建议采取以下措施：  
- 1. 确保 IOMMU 在所有支持 PCIe 的设备上处于活动状态。  
-   
- 2. 配置系统以限制仅对受信任的设备进行直接内存访问。  
-   
- 3. 应用最新的固件更新，以便强制 SDIO 和 PCIe 模式之间的安全转换，或在授予 DMA 权限之前通过加密签名验证 SD Express 卡。  
-   
- 4. 如果不需要，请禁用热插拔以防止未经授权的设备连接。  
-   
- 5. 避免在敏感系统中使用不熟悉的 SD 卡或外部读取器。  
-   
- 6. 定期检查设备是否被篡改，特别是在共享环境中。  
-   
DaMAgeCard 漏洞凸显了在 SD Express 等现代外设标准中平衡性能与安全性的挑战。随着采用率的提高，设备制造商必须优先实施针对基于 DMA 的威胁的强大保护措施。  
  
在此之前，用户应保持警惕，更新系统并限制接触未经验证的设备。  
  
