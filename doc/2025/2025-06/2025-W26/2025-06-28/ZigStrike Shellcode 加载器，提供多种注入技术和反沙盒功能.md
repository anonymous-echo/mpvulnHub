> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247531429&idx=2&sn=4e0ea50e85df429d670264285c4ebb2b

#  ZigStrike Shellcode 加载器，提供多种注入技术和反沙盒功能  
 Ots安全   2025-06-28 11:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
ZigStrike 是一款基于 Zig 开发的强大 Shellcode 加载器，提供多种注入技术和反沙盒功能。它利用编译时功能实现高效的 Shellcode 分配，并已证明能够成功绕过高级安全解决方案。ZigStrike 包含一个自定义 Payload 构建器，允许用户通过 Python 构建的 Web 应用程序轻松选择和构建 Payload。  
  
功能（2.0 版）  
  
多次注射技术：  
- 本地线程  
  
- 局部映射  
  
- 远程映射  
  
- 远程线程劫持  
  
- 早期级联注射  
  
反沙盒保护：  
- TPM 存在检查。  
  
- 域加入检查。  
  
- 运行时保护。  
  
输出格式：  
- XLL（Excel 插件）  
  
- 动态链接库  
  
- CPL  
  
高级功能：  
- Shellcode 高级配置。  
  
- 有效载荷运行时保护；防止模拟和沙盒动态分析。  
  
- 绕过常见的检测规则。  
  
前端增强：  
- 添加了新页面来查看生成的有效载荷。  
  
- 每个创建的有效载荷的详细信息。  
  
- 修复 flask 问题以支持上传大型 shellcode。  
  
条件环境  
- Zig 0.14.0  
  
- Ubuntu / Debian  
  
- Python 3.x (for the web interface)  
  
- Flask  
  
文章  
  
以下文章针对 ZigStrike 进行了发布，重点介绍了其功能并展示了绕过高级安全解决方案的能力。  
  
https://kpmg.com/nl/en/home/insights/2024/12/zig-strike-the-ultimate-toolkit-for-payload-creation-and-evasion.html  
  
项目地址  
  
https://github.com/0xsp-SRD/ZigStrike  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
