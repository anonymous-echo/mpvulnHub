#  黑客利用 OttoKit WordPress 插件漏洞添加管理员帐户   
Rhinoer  犀牛安全   2025-05-29 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlkqb2UwXDnXb0MYfKajE4r654So3n3kN3v92pSksrwB7aO2zU1bljbUricXvXzdCicvxv1KbQz1MKw/640?wx_fmt=png&from=appmsg "")  
  
黑客正在利用 OttoKit WordPress 插件中一个严重的未经身份验证的权限提升漏洞，在目标网站上创建恶意管理员帐户。  
  
OttoKit（以前称为 SureTriggers）是一款 WordPress 自动化和集成插件，已在超过 100,000 个网站中使用，允许用户将其网站连接到第三方服务并自动化工作流程。  
  
2025 年 4 月 11 日，Patchstack 收到了研究员丹佛·杰克逊 (Denver Jackson) 提交的有关 OttoKit 中一个严重漏洞的报告。  
  
该漏洞的标识符为 CVE-2025-27007，攻击者可以利用“create_wp_connection”函数中的逻辑错误，通过插件的 API 获得管理员访问权限，在未设置应用程序密码时绕过身份验证检查。  
  
供应商第二天就收到了通知，并于 2025 年 4 月 21 日发布了补丁，OttiKit 版本为 1.0.83，增加了对请求中使用的访问密钥的验证检查。  
  
截至 2025 年 4 月 24 日，大多数插件用户已被强制更新至修补版本。  
  
如今已被用于攻击  
  
Patchstack 于 2025 年 5 月 5 日发布了其报告，但新的更新警告称，漏洞利用活动在公开披露后大约 90 分钟就开始了。  
  
攻击者试图通过瞄准 REST API 端点、发送模仿合法集成尝试的请求、使用“create_wp_connection”以及猜测或暴力破解的管理员用户名、随机密码以及虚假访问密钥和电子邮件地址来利用该漏洞。   
  
一旦初始攻击成功，攻击者就会向“/wp-json/sure-triggers/v1/automation/action”和“？rest_route=/wp-json/sure-triggers/v1/automation/action”发出后续 API 调用，包括有效载荷值：“type_event”：“create_user_if_not_exists”。  
  
在存在漏洞的安装中，这会默默创建新的管理员帐户。  
  
Patchstack 建议：“如果您正在使用 OttoKit 插件，强烈建议您尽快更新您的网站，并检查您的日志和网站设置中是否存在这些攻击和泄露指标。”  
  
这是自 2025 年 4 月以来黑客利用的 OttoKit 中的第二个严重漏洞，前一个是另一个被追踪为CVE-2025-3102 的身份验证绕过漏洞。  
  
该漏洞的利用始于漏洞披露的同一天，攻击者试图使用随机用户名、密码和电子邮件地址创建恶意管理员帐户，这表明存在自动化尝试。  
  
  
信息来源：B  
leepingComputer  
  
