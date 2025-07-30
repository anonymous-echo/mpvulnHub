#  Windows 11高危漏洞：300毫秒即可提权至管理员   
 FreeBuf   2025-04-17 10:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38icATbzGX97j2YbGeTvf8RwHoY990lEyqaOWuwViceI5OIYK7AJibWiaVD1lnXM8HCEJQGxmaX4DGRzA/640?wx_fmt=png&from=appmsg "")  
  
  
  
Windows 11 存在一个严重漏洞，攻击者可在短短 300 毫秒内从低权限用户提升至系统管理员权限。  
  
  
该漏洞编号为 CVE-2025-24076，通过精密的 DLL 劫持技术利用 Windows 11“移动设备”功能的缺陷。安全研究人员于 2024 年 9 月发现此漏洞，并于 2025 年 4 月 15 日公开披露，其攻击目标是 Windows 11 摄像头功能加载的 DLL 文件。  
  
  
研究人员发现，位于用户可修改目录 %PROGRAMDATA%\CrossDevice\ 下的 CrossDevice.Streaming.Source.dll 文件会先由普通用户进程加载，随后被高权限系统进程加载。  
  
  
Compass Security 公司的 John Ostrowski 表示：“这个漏洞是典型的 DLL 劫持场景，但包含极具挑战性的时间控制因素，攻击窗口期极短——仅有 300 毫秒，但我们开发了可靠的技术手段实现稳定利用。”  
  
  
**01**  
  
  
  
**Windows 11 权限提升漏洞技术细节**  
  
  
漏洞利用过程面临多项技术挑战。研究人员最初使用 PrivescCheck 工具进行自动化扫描，发现非特权用户对 COM 服务器模块文件具有修改权限：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38icATbzGX97j2YbGeTvf8RwgsgjIdGeMY4c8DI0eClFGaXaT2viczJGjLCt0H3ricuuBwSYvtgq1ewA/640?wx_fmt=png&from=appmsg "")  
  
  
为克服短暂的时间窗口，研究人员采用机会锁（Opportunistic Locks）技术在关键时刻暂停程序执行。通过微软 Detours 库，他们拦截了专门针对 GetFileVersionInfoExW 的 Windows API 调用，以确定可靠替换文件的时机。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38icATbzGX97j2YbGeTvf8RwsiazNT5OFiaHs696412dnNgxltvSicYGB8I3jOu4vQTCYHW4YW3825eMw/640?wx_fmt=png&from=appmsg "")  
  
  
研究人员创建了恶意 DLL 文件，该文件在保留原有功能的同时添加了未授权命令：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38icATbzGX97j2YbGeTvf8RwjWaw8qQaJqADOgTdxaiczt0Zeje6A1xcbMS6Z3tmhf2UOvVEAz4JT2A/640?wx_fmt=png&from=appmsg "")  
  
  
当高权限进程加载该 DLL 时，恶意代码将以 SYSTEM 权限执行。为确保被替换的 DLL 保持原有功能，研究人员实现了代理机制，将函数调用转发至原始 DLL：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38icATbzGX97j2YbGeTvf8RwzRcUvugGwuY5hYqgXB8bWk0knBkN1yg8gJC0mib9TvhO2uHV9Jg0ZOA/640?wx_fmt=png&from=appmsg "")  
  
  
**02**  
  
  
  
**漏洞缓解措施**  
  
  
该漏洞影响启用了“移动设备”功能的 Windows 11 系统，该功能允许用户将手机链接为网络摄像头使用。微软已在 2025 年 3 月的安全更新中发布补丁。  
  
  
此发现凸显了在特权进程中实施严格文件访问控制和签名验证的重要性。即使在没有可用补丁的情况下，端点检测与响应（EDR）解决方案也能通过行为监控检测此类攻击。  
  
  
研究人员建议 ：“虽然保持系统更新至关重要，但用户还可采取额外防护措施，使用 EDR 解决方案可以主动检测异常行为，识别可疑活动。”  
  
  
微软将主系统级权限提升漏洞编号为 CVE-2025-24076，同一功能中的相关用户间攻击向量编号为 CVE-2025-24994。强烈建议用户安装最新的 Windows 安全更新以修复这些漏洞。  
  
  
该漏洞利用案例表明，即使是现代操作系统，在新功能实现中也可能受到长期存在的攻击技术威胁，特别是当熟练的攻击者利用时间差和竞争条件时。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1y91mvSZuxibf3Q3g2rJ32FNzoYfx4yaBmWbfwcRaNicuMo3AxIck2bCw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651318673&idx=1&sn=fc4885839a5fa2d029e0e95474e9432b&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651317804&idx=2&sn=3d017ae8749aa67775bcd2302b38931b&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651317737&idx=1&sn=99fed7dcc16d21127eb031fd187b35f5&scene=21#wechat_redirect)  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1uEIoRxNoqa17tBBrodHPbOERbZXdjFvNZC5uz0HtCfKbKx3o3XarGQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5KDnCKUfVLVQGsc9BiaQTUsrwzfcianumzeLVcmibOmm2FzUqef2V6WPQQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38mFMbqsUOVbBDicib7jSu7FfibBxO3LTiafGpMPic7a01jnxbnwOtajXvq5j2piaII2Knau7Av5Kxvp2wA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
