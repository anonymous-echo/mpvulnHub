#  WordPress插件WPForms惊现高危漏洞，数百万网站面临退款风险！   
原创 技术修道场  技术修道场   2024-12-11 00:38  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wWBwsDOJT49cImASiaicFessRlbKbFJUUgbPhNetYj1Q4DLGWLkh7gGaFe5eicBSfruFC8bBP0eu1oKbpFGxS4Ekw/640?wx_fmt=png&from=appmsg "")  
## WordPress插件WPForms惊现高危漏洞，数百万网站面临退款风险！  
  
**科技圈速报**  
  就在刚刚，安全研究人员披露了流行 WordPress 插件 WPForms 中的一个高危漏洞，该漏洞可能允许攻击者在数百万个网站上随意进行 Stripe 退款或取消订阅。  
  
**漏洞详情**  
- **漏洞编号:**  
 CVE-2024-11205  
  
- **受影响版本:**  
 WPForms 1.8.4 至 1.9.2.1  
  
- **安全版本:**  
 WPForms 1.9.2.2  
  
- **漏洞描述:**  
 由于 WPForms 错误地使用wpforms_is_admin_ajax()  
 函数来判断请求是否为管理员 AJAX 调用，导致任何已认证用户，即使是最低权限的订阅者，都可以调用敏感的 AJAX 函数，例如执行 Stripe 退款的ajax_single_payment_refund()  
 和取消订阅的ajax_single_payment_cancel()  
。  
  
- **潜在危害:**  
  网站所有者可能面临巨大的经济损失、业务中断以及客户信任危机。  
  
**专家提醒**  
  
Wordfence 安全研究员 "vullu164" 发现了此漏洞，并向 Wordfence 的漏洞赏金计划报告了该漏洞。WPForms 开发商 Awesome Motive 已于 11 月 18 日发布了修复版本 1.9.2.2。  
  
据统计，大约一半使用 WPForms 的网站尚未升级到最新版本，这意味着至少 300 万个网站仍然处于危险之中。 尽管目前尚未发现该漏洞被 actively 利用，但强烈建议所有 WPForms 用户**立即升级到 1.9.2.2 版本或禁用该插件**  
，以避免潜在风险。  
  
**关于 WPForms**  
  
WPForms 是一款用户友好的 WordPress 表单构建器，拥有超过 600 万活跃用户，用于创建联系表单、反馈表单、订阅表单和支付表单等，并支持 Stripe、PayPal、Square 等支付平台。  
  
**科技圈作者点评**  
  
此次 WPForms 漏洞事件再次提醒我们，及时更新软件版本和加强安全意识至关重要。 对于网站所有者来说，应密切关注安全公告，并采取必要的措施来保护自己的网站和用户数据安全。  
  
