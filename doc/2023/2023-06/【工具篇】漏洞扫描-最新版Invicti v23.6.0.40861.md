#  【工具篇】漏洞扫描-最新版Invicti v23.6.0.40861   
 渗透测试网络安全   2023-06-17 20:30  
  
由于微信公众号推送机制改变了，快来星标不再迷路，谢谢大家！![](https://mmbiz.qpic.cn/mmbiz_png/ewSxvszRhM4Cs3BCYY8FQ8y77hyEgv1M5ibpUUiaD0k5K0c4TibNufZG8bCyhx8peDo5VnRqibhRgKVzwunDTpk5HA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
0x01 Invicti介绍Invicti可以全自动、极其准确并且是易于使用的 Web 应用程序安全扫描程序，可自动查找您的网站、Web 应用程序和 Web 服务中的安全漏洞。0x02 Invicti本次更新介绍  
本次  
Invicti 更新新增漏洞检查如下：  
- 添加了对基于布尔值的 MongoDB 注入的检查。  
  
- 添加了对 MongoDB 运算符注入器的检查。  
  
- 已实现 IAST 的 XML 外部实体检查。  
  
- 添加了 ISO/IEC27001：2022 分类。  
  
- 将报告模板和攻击模式添加到带外 RCE。  
  
- 添加了对 Lua 的被动检查。  
  
- 添加了安全检查以检测公共 Docker 文件。  
  
- 实现了一个新的引擎来识别WordPress主题和插件。  
  
- 为 SAML 添加了新的安全检查。  
  
- 添加了对 IT 命中 WebDAV 服务器 .Net 版本披露的安全检查。  
  
- 添加了对 MS Exchange 版本披露的安全检查。  
  
- 为命令注入添加了新的有效负载。  
  
- 添加了对 PopperJS 的支持。  
  
- 添加了对 CanvasJS 的支持。  
  
- 为 SQLite 数据库检测添加了新的安全检查。  
  
- 为标头注入添加了新的有效负载。  
  
- 为弹簧启动执行器检测添加了新的安全检查。  
  
- 添加了对 NodeJS 堆栈跟踪泄露的安全检查。  
  
- 添加了对 SailsJS 和 ActionHero Identification 的安全检查。  
  
- 添加了对 JetBrains .idea 检测到的安全检查。  
  
- 添加了对 GraphQL 堆栈跟踪披露的安全检查。  
  
- 添加了对 Javascript 库的安全检查。  
  
- 添加了对 Web 应用程序指纹程序引擎的安全检查。  
  
- 为 WordPress Hello Elementor 主题检测添加了新的安全检查。  
  
- 为 WordPress Twenty Twenty-Three主题检测添加了新的安全检查。  
  
- 为 WordPress Twenty Twenty-Twenty-Theme Detection 添加了新的安全检查。  
  
- 为 WordPress Astra 主题检测添加了新的安全检查。  
  
- 为 WordPress Twenty Twenty-One 主题检测添加了新的安全检查。  
  
- 为 WordPress Twenty Twenty Theme Detection 添加了新的安全检查。  
  
- 为 WordPress OceanWP 主题检测添加了新的安全检查。  
  
- 为 WordPress Twenty Seventeen 主题检测添加了新的安全检查。  
  
- 为 WordPress Kadence 主题检测添加了新的安全检查。  
  
- 为 WordPress Twenty-Sixteen 主题检测添加了新的安全检查。  
  
- 为 WordPress Twenty Nineteen 主题检测添加了新的安全检查。  
  
- 为 WordPress PopularFX 主题检测添加了新的安全检查。  
  
- 为 WordPress GeneratePress 主题检测添加了新的安全检查。  
  
- 添加了针对WordPress Inspiro主题检测的新安全检查。  
  
- 为 WordPress Go 主题检测添加了新的安全检查。  
  
- 为WordPress粉碎气球社交照片提要插件检测添加了新的安全检查。  
  
- 为 WordPress Contact Form 7 插件检测添加了新的安全检查。  
  
- 为 WordPress Yoast SEO 插件检测添加了新的安全检查。  
  
- 为WordPress Elementor Website Builder Plugin Detection添加了新的安全检查。  
  
- 为 WordPress Classic Editor Plugin Detection 添加了新的安全检查。  
  
- 为 WordPress Akismet 垃圾邮件保护插件检测添加了新的安全检查。  
  
- 为WordPress WooCommerce插件检测添加了新的安全检查。  
  
- 通过WPForms插件检测为WordPress联系表单添加了新的安全检查。  
  
- 为WordPress真正简单的SSL插件检测添加了新的安全检查。  
  
- 为 WordPress Jetpack 插件检测添加了新的安全检查。  
  
- 为WordPress多合一WP迁移插件检测添加了新的安全检查。  
  
- 为 WordPress Wordfence 安全插件检测添加了新的安全检查。  
  
- 添加了WordPress Yoast重复发布插件检测的新安全检查。  
  
- 为 WordPress WordPress 导入器插件检测添加了新的安全检查。  
  
- 为WordPress LiteSpeed Cache Plugin Detection添加了新的安全检查。  
  
- 为 WordPress UpdraftPlus WordPress Backup Plugin Plugin Detection 添加了新的安全检查。  
  
- 为 EZProxy 已识别添加了新的安全检查。  
  
0x03 Invicti支持扫描的漏洞- SQL 注入  
  
- XSS（跨站脚本）  
  
- DOM XSS  
  
- 命令注入  
  
- 盲命令注入  
  
- 本地文件包含和任意文件读取  
  
- 远程文件包含  
  
- 远程代码注入/评估  
  
- CRLF / HTTP 标头注入 / 响应拆分  
  
- 打开重定向  
  
- 帧注入  
  
- 具有管理员权限的数据库用户  
  
- 漏洞 - 数据库（推断的漏洞）  
  
- ViewState 未签名  
  
- ViewState 未加密  
  
- 网络后门  
  
- TRACE / TRACK 方法支持已启用  
  
- 禁用 XSS 保护  
  
- 启用 ASP.NET 调试  
  
- 已启用 ASP.NET 跟踪  
  
- 可访问的备份文件  
  
- 可访问的 Apache 服务器状态和 Apache 服务器信息页面  
  
- 可访问的隐藏资源  
  
- 易受攻击的 Crossdomain.xml 文件  
  
- 易受攻击的 Robots.txt 文件  
  
- 易受攻击的谷歌站点地图  
  
- 应用程序源代码公开  
  
- Silverlight 客户端访问策略文件易受攻击  
  
- CVS、GIT 和 SVN 信息和源代码披露  
  
- PHPInfo() Pages Accessible 和 PHPInfo() Disclosure in other Pages  
  
- 敏感文件可访问  
  
- 重定向响应 BODY 太大  
  
- 重定向响应 BODY 有两个响应  
  
- HTTP 上使用的不安全身份验证方案  
  
- 通过 HTTP 传输的密码  
  
- 通过 HTTP 提供的密码表单  
  
- 暴力破解获得的认证  
  
- 通过 HTTP 获得的基本身份验证  
  
- 弱凭证  
  
- 电子邮件地址披露  
  
- 内部知识产权披露  
  
- 目录列表  
  
- 版本披露  
  
- 内部路径披露  
  
- 访问被拒绝的资源  
  
- MS Office 信息披露  
  
- 启用自动完成  
  
- MySQL 用户名披露  
  
- 默认页面安全  
  
- 未标记为安全的 Cookie  
  
- 未标记为 HTTPOnly 的 Cookie  
  
- 堆栈跟踪披露  
  
- 编程错误信息披露  
  
- 数据库错误信息披露  
  
0x04 获取下载  
> **免责声明**  
> 由于传播、利用本公众号渗透测试网络安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号渗透测试网络安全及作者不为此承担任何责任，一旦造成后果请自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
  
**进交流群 请添加管理员 号**  
  
备注：进群，将会自动  
邀请您  
加入 渗透测试网络安全 技术 官方 交流群  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ewSxvszRhM5SJ83c3U4h64KVQHNPn19OZzhVVkks3UtLDDy0zraY4FmJAqbF8iamU01XUV7WQgWRIJ6qMStM3ZQ/640?wx_fmt=png "")  
  
  
好文分享收藏赞一下最美点在看哦  
  
