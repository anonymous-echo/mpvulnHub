> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0NzE4ODk1Mw==&mid=2652096397&idx=2&sn=e7fec28c9a1dbdde9d1dde9ddb08c222

#  NVIDIA 容器工具包允许攻击者执行特权代码漏洞  
 网安百色   2025-07-18 11:08  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo4zZIrHfCdnbS1vApXib9F4ULyc912wmfYIFhVe7GYgjVEBs8VNuDoBzAdShNjZyFIuXWycByicPMUw/640?wx_fmt=jpeg&from=appmsg "")  
  
NVIDIA 发布了关键安全更新，解决了其容器工具包和 GPU作员中的两个重大漏洞，这些漏洞可能允许攻击者以提升的权限执行任意代码。  
  
这些漏洞于 2025 年 7 月发现，影响 1.17.7 之前的所有 Container Toolkit 版本和 25.3.0 之前的 GPU Operator 版本，促使这家图形巨头立即发布安全补丁和缓解建议。  
## 已发现严重安全漏洞  
  
最严重的漏洞被跟踪为 CVE-2025-23266，其关键 CVSS 评分为 9.0，并影响所有平台上容器工具包中的初始化挂钩。  
  
该缺陷使攻击者能够以提升的权限执行任意代码，从而可能通过权限升级、数据篡改、信息泄露和拒绝服务攻击导致系统完全受损。  
  
该漏洞利用了容器初始化过程中的弱点，使其对于容器化环境特别危险。  
  
第二个漏洞 CVE-2025-23267 的严重性评级很高，CVSS 评分为 8.5。此缺陷会影响 update-ldcache 钩子，并允许攻击者使用特制的容器镜像执行链接跟踪攻击。  
  
虽然不如第一个漏洞严重，但它仍然会带来重大风险，包括数据篡改和拒绝服务攻击。  
  
<table><thead><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="7326319" msthash="41" style="box-sizing: border-box;font-weight: bold;"><span leaf="">CVE 编号</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="6157333" msthash="42" style="box-sizing: border-box;font-weight: bold;"><span leaf="">描述</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="7089264" msthash="43" style="box-sizing: border-box;font-weight: bold;"><span leaf="">CVSS 分数</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="4044495" msthash="44" style="box-sizing: border-box;font-weight: bold;"><span leaf="">严厉</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="23218" msthash="45" style="box-sizing: border-box;font-weight: bold;"><span leaf="">CWE</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="4085822" msthash="46" style="box-sizing: border-box;font-weight: bold;"><span leaf="">冲击</span></strong></td></tr></thead><tbody><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">CVE-2025-23266 漏洞</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">容器初始化钩子中的任意代码执行</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">9.0</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">危急</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">CWE-426型</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">权限提升、数据篡改、信息泄露、拒绝服务</span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">CVE-2025-23267</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">update-ldcache 钩子中的链接关注漏洞</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">8.5</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">高</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">CWE-59型</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">数据篡改、拒绝服务</span></section></td></tr></tbody></table>  
**受影响的产品和更新**  
  
这两个漏洞都会影响所有平台上的 NVIDIA 容器工具包安装以及 Linux 系统上的 GPU Operator。  
  
运行 Container Toolkit 版本高达 1.17.7 或 GPU Operator 版本高达 25.3.0 的组织容易受到攻击，应立即升级到已修补的版本：Container Toolkit 1.17.8 和 GPU Operator 25.3.1。  
  
虽然永久修复需要更新到最新版本，但 NVIDIA 为无法立即升级的组织提供了临时缓解措施。  
  
用户可以通过修改配置文件或环境变量来禁用 enable-cuda-compat 钩子。对于 Container Runtime 用户，这涉及编辑 config.toml 文件以将 disable-cuda-compat-lib-hook 功能标志设置为 true。  
  
GPU Operator 用户可以通过在 Helm 安装或升级期间向环境变量添加 disable-cuda-compat-lib-hook 标志来实现类似的保护。  
  
鉴于这些漏洞的严重性及其在容器化环境中被利用的可能性，安全专家建议立即实施可用补丁。  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
