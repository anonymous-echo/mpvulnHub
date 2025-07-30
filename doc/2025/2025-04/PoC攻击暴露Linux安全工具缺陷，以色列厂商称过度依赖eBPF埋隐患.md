#  PoC攻击暴露Linux安全工具缺陷，以色列厂商称过度依赖eBPF埋隐患   
 信息安全大事件   2025-04-26 08:46  
  
以色列云安全公司Armo近日通过新型概念验证（PoC）rootkit成功绕过多款主流Linux运行时安全工具，该案例揭示了当前安全产品存在的技术局限。这款名为"Curing"的PoC工具名称融合了"治愈"概念与Linux内核接口io_uring，后者正是实现攻击绕过的关键技术。  
  
三款安全工具集体失守  
  
测试显示，Curing能不同程度地绕过三款Linux安全产品：由Sysdig开发、现属云原生计算基金会（CNCF）的Falco，Isovalent公司（已被思科收购）的Tetragon，以及微软Defender。其中：  
- Falco完全无法检测Curing活动  
  
- Defender既未能识别Curing，也无法发现其他常见恶意软件  
  
- Tetragon虽能通过Kprobes和LSM钩子检测io_uring活动，但这些功能默认处于关闭状态  
  
Armo安全研究主管Amit Schendel指出，这些产品的共性问题在于过度依赖基于扩展伯克利包过滤器（eBPF）的代理技术，这些代理通过监控系统调用来获取威胁可见性。"系统调用并非总是必然触发，io_uring就能完全绕过它们。这凸显了构建健壮eBPF安全代理时面临的设计复杂度权衡。"  
  
io_uring接口的双刃剑特性  
  
自2019年Linux 5.1版本引入以来，io_uring接口旨在解决原生异步I/O（libaio）性能低下的问题。其核心机制允许程序通过环形缓冲区向内核提交多个I/O请求，实现非阻塞操作。但Armo的Curing rootkit证明，该接口也可能成为攻击者进入内核的"高速公路"——自问世以来，io_uring接口已持续曝出多个CVE级别漏洞。  
  
Armo开发此rootkit主要出于两个目的：其一，尽管io_uring技术已存在至少两年，但Linux安全厂商尚未有效应对相关风险；其二，揭示主流安全工具存在的深层次架构缺陷。"我们想强调当前监控方案缺乏前瞻性设计，这些方案应该兼容Linux内核新特性并应对新技术。"Schendel解释道。  
  
厂商回应现分歧  
  
各厂商对Armo发现的反应呈现明显差异：  
- Falco维护者承认问题并承诺开发新插件提升可见性  
  
- 微软始终未予回应  
  
- Isovalent首席开源官Liz Rice则反驳称，Tetragon通过eBPF可挂钩内核多个区域（包括Linux安全模块API），并非仅依赖系统调用监控  
  
值得注意的是，此次回应Armo的均为开源项目（Falco、Tetragon），而商业软件代表微软保持沉默。虽然Armo自身作为安全厂商存在商业立场，但其提出的检测策略——如监控io_uring异常使用、部署内核运行时安全检测（KRSI）等——仍具参考价值。正如Schendel所强调："若从未使用io_uring的应用突然启用该接口，就是明确的危险信号。"  
  
文字来源：FreeBuf  
   
  
  
  
  
**推荐阅读**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/JqliagemfTA6nncddCe33WjV627ibFia38auDQkibdTRUBKcPcOUb7hLTTomkGxJUCzyoPUxiaUsS6tcwgetRSDMcpg/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**1**  
  
[江苏国骏网络安全服务业务全景](https://mp.weixin.qq.com/s?__biz=MzkzNjIzMjM5Ng==&mid=2247490721&idx=2&sn=6a12cec92cbb74648773060c6255aa01&scene=21#wechat_redirect)  
  
  
**2**  
  
[网络安全等级保护服务业务](https://mp.weixin.qq.com/s?__biz=MzkzNjIzMjM5Ng==&mid=2247490721&idx=3&sn=3f899eb539b719a60dfb541f8120e32d&scene=21#wechat_redirect)  
  
  
**3**  
  
[勒索病毒专项防护工作业务](https://mp.weixin.qq.com/s?__biz=MzkzNjIzMjM5Ng==&mid=2247490721&idx=4&sn=c64426bef9775eecf37bfc0f4cbb8a7c&scene=21#wechat_redirect)  
  
  
  
