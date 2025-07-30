> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzA5Nzc4Njg1NA==&mid=2247489260&idx=1&sn=51ba3d6560441abb6d16005aa88ecc6d

#  关于防范人工智能绘图工具ComfyUI多个安全漏洞的风险提示  
NVDB  网络安全威胁和漏洞信息共享平台   2025-06-13 08:38  
  
    近日，工业和信息化部网络安全威胁和漏洞信息共享平台（  
NVDB  
）监测发现，  
ComfyUI  
工具存在任意文件读取、远程代码执行等  
5  
个安全漏洞，已被用于实施网络攻击。  
  
    ComfyUI  
是一款开源的人工智能绘图工具，用于人工智能驱动的图像生成、视频制作、  
3D  
建模与音频创作等。由于其组件存在代码注入、任意文件读取、跨站脚本、远程代码执行等安全漏洞，可被攻击者利用执行远程恶意代码，获取服务器权限，进而窃取系统数据。受影响的  
ComfyUI  
组件包括  
ComfyUI-Ace-Nodes  
、  
Comfyanonymous/comfyui  
、  
ComfyUI-Bmad-Node  
、  
ComfyUI-Impact-Pack  
、  
ComfyUI-Manager  
。  
  
    上述漏洞均已修复，链接如下：  
  
    1.  
ComfyUI-Ace-Nodes  
链接：  
https://github.com/hay86/ComfyUI_AceNodes/blob/5ba01db8a3b7afb8e4aecfaa48823ddeb132bbbb/nodes.py#L1193  
。  
  
    2.  
Comfyanonymous/comfyui  
链接：  
https://github.com/comfyanonymous/ComfyUI/pull/6034  
。  
  
    3.  
ComfyUI-Bmad-Node  
链接：  
https://github.com/bmad4ever/comfyui_bmad_nodes/blob/392af9490cbadf32a1fe92ff820ebabe88c51ee8/cv_nodes.py#L1814  
。  
  
    4.  
ComfyUI-Impact-Pack  
链接：  
https://github.com/ltdrdata/ComfyUI-Impact-Pack/commit/a43dae373e648ae0f0cc0c9768c3cea6a72acff7  
。  
  
    5.  
ComfyUI-Manager  
链接：  
https://github.com/ltdrdata/ComfyUI-Manager/commit/ffc095a3e5acc1c404773a0510e6d055a6a72b0e  
。  
  
    建议相关单位和用户立即开展全面排查，及时升级至最新安全版本，通过限制互联网访问、设置  
IP  
白名单、增强身份验证机制等方式做好类似人工智能应用的安全加固，防范网络安全风险。  
  
  
