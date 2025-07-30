> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247533745&idx=2&sn=a176b8fa0297f6d311e87c46b62a9f49

#  荐读丨工信部：AI绘图工具ComfyUI多个安全漏洞已被用于实施网络攻击  
 工业安全产业联盟平台   2025-06-20 09:11  
  
[](https://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247533368&idx=1&sn=d541bea83288feda781e5a7a02c397c9&scene=21#wechat_redirect)  
  
  
近日，工业和信息化部网络安全威胁和漏洞信息共享平台（NVDB）监测发现，ComfyUI工具存在任意文件读取、远程代码执行等5个安全漏洞，已被用于实施网络攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FpQm8QaW5l6XPgWUZN76LqNOwBpzcUVZUBBbnBmeibLPibVQU9P8XrliaIWAOeDYxrq3IzHd1BjCBSy1jxN2nUOQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
ComfyUI是一款开源的人工智能绘图工具，用于人工智能驱动的图像生成、视频制作、3D建模与音频创作等。由于其组件存在代码注入、任意文件读取、跨站脚本、远程代码执行等安全漏洞，可被攻击者利用执行远程恶意代码，获取服务器权限，进而窃取系统数据。受影响的ComfyUI组件包括ComfyUI-Ace-Nodes、Comfyanonymous/comfyui、ComfyUI-Bmad-Node、ComfyUI-Impact-Pack、ComfyUI-Manager。  
  
  
**上述漏洞均已修复，链接如下：**  
  
****  
**1.**  
 ComfyUI-Ace-Nodes链接：  
  
https://github.com/hay86/ComfyUI_AceNodes/blob/5ba01db8a3b7afb8e4aecfaa48823ddeb132bbbb/nodes.py#L1193。  
  
  
**2.**  
 Comfyanonymous/comfyui链接：  
  
https://github.com/comfyanonymous/ComfyUI/pull/6034。  
  
  
**3.**  
 ComfyUI-Bmad-Node链接：  
  
https://github.com/bmad4ever/comfyui_bmad_nodes/blob/392af9490cbadf32a1fe92ff820ebabe88c51ee8/cv_nodes.py#L1814。  
  
  
**4.**  
 ComfyUI-Impact-Pack链接：  
  
https://github.com/ltdrdata/ComfyUI-Impact-Pack/commit/a43dae373e648ae0f0cc0c9768c3cea6a72acff7。  
  
  
**5.**  
 ComfyUI-Manager链接：  
  
https://github.com/ltdrdata/ComfyUI-Manager/commit/ffc095a3e5acc1c404773a0510e6d055a6a72b0e。  
  
  
建议相关单位和用户立即开展全面排查，及时升级至最新安全版本，通过限制互联网访问、设置IP白名单、增强身份验证机制等方式做好类似人工智能应用的安全加固，防范网络安全风险。  
  
**· end ·**  
  
  
  
来源 |   
网络安全威胁和漏洞信息共享平台  
  
责任编辑 | 赫敏  
  
  
声明：本文由工业安全产业联盟平台微信公众号（微信号：ICSISIA）转发，如有版权问题，请联系删除。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/4FpQm8QaW5kiaicHTUwSf9sId0er1ytR3D1Sc1RPfDpmk8FiciciadlBic9jSUbt1ciaE3G3aKiaicickE5ficq81KuYplgow/640?wx_fmt=png "")  
  
  
  
**如需合作或咨询，请联系工业安全产业联盟平台小秘书微信号：ICSISIA20140417**  
  
  
  
**往期荐读**  
  
# 重磅 | 《自动化博览》2025年第一期暨《工业控制系统信息安全专刊（第十一辑）》上线  
# 2025两会必看丨这些工业信息安全精华提案将改写行业规则  
# 工信部丨关于防范针对DeepSeek本地化部署实施网络攻击的风险提示  
# 干货丨长输油气管网工控安全防护：策略、实践与展望  
  
**DeepSeek分析丨**  
[零信任安全架构在工业领域的发展现状与未来展望](https://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247532379&idx=1&sn=1603721f3f669d1fe6c5773b5fb55489&scene=21#wechat_redirect)  
  
# 白皮书丨东北大学：2024工业控制网络安全态势白皮书（附下载）  
# 荐读丨即将过气的五大网络安全技术  
# 干货丨工业可编程控制系统加密技术研究  
# 荐读 | 安全人视角的DeepSeek洞察与思考  
# 工信部丨2024年我国信息安全领域收入2290亿元  
# 关注丨网络关键设备安全检测结果（第19批）  
# 电力安全｜2024年新型电力系统安全建设指南报告（附下载）  
# 工信部等十三部门丨2024年网络安全技术应用典型案例项目名单  
# 关注丨国家发展改革委、国家数据局等六部门联合印发《关于完善数据流通安全治理 更好促进数据要素市场化价值化的实施方案》  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4FpQm8QaW5kl2a8G7lfZTXQ65jPLzCdpyKsyPqcbQnzEqbmYSDib90bZicWWGDc7kFPbaRiaVzC16MXUp4T0FY8cA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FpQm8QaW5kl2a8G7lfZTXQ65jPLzCdpMs8tAvMDjxib9jwveZic6lrGG8K5iaoRIibBzbMEOZ1iay9MmF0aJtvicHmQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4FpQm8QaW5kl2a8G7lfZTXQ65jPLzCdpQrnsLdgPsjvdBHkvnibporOYKicPv4aBgHkEw0tLgNnDuOTOOAia2tPug/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4FpQm8QaW5kl2a8G7lfZTXQ65jPLzCdpgJgfShwDlZNGBxX5EkH8XMYawAfotAVmiaoD9icCOE7l306nqjCsuibCw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4FpQm8QaW5kl2a8G7lfZTXQ65jPLzCdp1IQNNBb9Hm4vRAiaKFBY2gMMDZB2IBvpkaCEetNoQvPFnwv2Tb13PuA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
