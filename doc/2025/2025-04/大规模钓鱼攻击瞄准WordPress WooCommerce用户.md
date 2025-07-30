#  大规模钓鱼攻击瞄准WordPress WooCommerce用户   
鹏鹏同学  黑猫安全   2025-04-29 01:29  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce9CKoqLh9Guwat7ACs5OCHAb3oZGP0OzEVrXicI3IR9lKgia7DnUd6l0ga6LNs8biabibib0XEhcia0U4uw/640?wx_fmt=png&from=appmsg "")  
  
Patchstack安全团队近日曝光一起针对WordPress WooCommerce用户的大规模钓鱼活动。攻击者伪装成官方团队发送虚假安全警报，诱骗用户下载植入后门的"关键补丁"。  
  
**攻击手法分析**  
1. **钓鱼诱饵**  
：  
  
1. 谎称存在"未授权管理访问漏洞"（实际不存在）  
  
1. 模仿2023年12月同类攻击手法（当时虚构CVE-2023-45124 RCE漏洞）  
  
1. 使用国际化域名（IDN）仿冒woocommerce官网（如woocommėrce[.]com）  
  
1. **恶意载荷**  
：  
  
1. 压缩包authbypass-update-31297-id.zip伪装成正规插件  
  
1. 激活后通过WordPress钩子隐藏恶意行为  
  
1. 每分钟执行隐藏WP Cron任务：  
✓ 创建隐蔽管理员账户  
✓ 将凭证外传到攻击者服务器  
✓ 下载P.A.S.-Fork/p0wny/WSO等混淆PHP网页壳  
  
1. **攻击能力**  
：  
  
1. 广告注入/流量劫持  
  
1. 支付数据窃取  
  
1. 发起DDoS攻击  
  
1. 部署勒索软件  
  
**威胁指标(IoCs)**  
- **异常账户**  
：8位随机字符用户名  
  
- **可疑任务**  
：如mergeCreator655定时任务  
  
- **恶意目录**  
：  
✓ wp-content/plugins/authbypass-update  
✓ wp-content/uploads/wp-cached-<随机8字符>  
  
- **C2域名**  
：  
woocommerce-services[.]com  
woocommerce-api[.]com  
woocommerce-help[.]com  
  
**安全建议**  
Patchstack警告称，随着攻击曝光，攻击者可能更换基础设施。建议用户：  
1. 核查所有"安全补丁"邮件的真实性  
  
1. 检查服务器是否存在上述异常特征  
  
1. 立即扫描wp-content/uploads目录中的可疑PHP文件  
  
