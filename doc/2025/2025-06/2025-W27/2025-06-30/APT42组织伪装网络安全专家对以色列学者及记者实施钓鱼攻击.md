> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3OTc0NDcyNQ==&mid=2247494128&idx=3&sn=6c847c613e01833a1a057a22a66d5ad3

#  APT42组织伪装网络安全专家对以色列学者及记者实施钓鱼攻击  
鹏鹏同学  黑猫安全   2025-06-29 23:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceibYCGPMPtiaaftjkVuTguBnc1sT7bNwYOYOYfRsaJ9uPOAib25xAxdrM1BjB44Fz68fdxvKhia2VA24g/640?wx_fmt=png&from=appmsg "")  
  
网络安全公司Check Point最新报告披露，伊朗背景黑客组织APT42（又称"Educated Manticore"、"Charming Kitten"）正针对以色列记者、网络安全专家及学者发起精密钓鱼攻击。该组织通过伪装成安全从业人员，系统性窃取邮箱凭证及双重认证(2FA)代码，其攻击活动呈现高度专业化特征。  
  
【攻击技术解剖】  
1. **身份伪造体系**  
  
- 深度伪造Check Point、Palo Alto Networks等企业安全专家身份  
  
- 使用AI生成专业级钓鱼话术（含技术术语与会议引用）  
  
- 通过WhatsApp建立信任后转入钓鱼阶段（规避初期链接触发警报）  
  
1. **钓鱼工具链**  
  
- 采用React构建的单页面应用(SPA)钓鱼套件  
  
- 实时网络套接字(WebSocket)传输窃取数据  
  
- 动态路由技术隐藏恶意代码（规避静态检测）  
  
- 预填受害者邮箱的伪造Gmail登录页（提升可信度）  
  
1. **基础设施网络**  
  
- 注册超过130个钓鱼域名（主要通过NameCheap）  
  
- 使用Google Sites托管伪造会议邀请（利用可信域名）  
  
- 部分IP与GreenCharlie子组织重叠（归属Educated Manticore分支）  
  
【典型攻击链示例】  
① 冒充安全研究员通过WhatsApp联系目标  
② 发送伪造的Google Meet会议邀请（实际为Google Sites钓鱼页面）  
③ 诱导访问React构建的实时钓鱼SPA  
④ 窃取输入的凭证及2FA代码（含键盘记录功能）  
⑤ 通过WebSocket实时传输至攻击者服务器  
  
【战术演进分析】  
■ 2025年1月：出现Outlook/Yahoo钓鱼套件变种  
■ 2025年6月：新增AI生成个性化话术  
■ 当前阶段：结合线下会面邀约实施复合式社工攻击  
  
（注：报告特别指出，该组织攻击目标多处于敏感信任环境，如学术合作与国际调查记者网络，这种定位与其地缘政治诉求高度吻合。）  
  
【防御建议】  
1. 关键人员应启用FIDO2物理安全密钥替代短信2FA  
  
1. 对跨平台会议邀约实施"二次确认"流程  
  
1. 部署AI生成内容检测工具识别伪造消息  
  
1. 监控NameCheap新注册相似域名  
  
