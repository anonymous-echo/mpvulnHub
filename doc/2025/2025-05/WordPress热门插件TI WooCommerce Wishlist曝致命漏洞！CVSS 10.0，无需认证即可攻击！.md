#  WordPress热门插件TI WooCommerce Wishlist曝致命漏洞！CVSS 10.0，无需认证即可攻击！   
原创 Hankzheng  技术修道场   2025-05-31 09:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wWBwsDOJT48V3K35lTlmZAibiaMgPfhdKQHUPeITC24JCjVlE1fOcZWNiaX2FFFia3Oo5ZCEsT9vxZs3KC8NmMiaMOw/640?wx_fmt=png&from=appmsg "")  
  
一款广受欢迎的WordPress电商愿望清单插件——TI WooCommerce Wishlist（活跃安装量超过10万）近日被爆出存在一个极其严重的未修补安全漏洞。该漏洞被评为**CVSS 10.0级（最高危）**  
，编号为CVE-2025-47577。尤为关键的是，**攻击者无需任何身份验证（Unauthenticated Attack）**  
 即可利用此漏洞上传任意文件，最终可能导致服务器被完全控制，引发远程代码执行（RCE）的灾难性后果。  
## 漏洞核心技术探析：  
  
此漏洞源于TI WooCommerce Wishlist插件（版本2.9.2及更早版本，发布于2024年11月29日）内部一个名为 tinvwl_upload_file_wc_fields_factory  
 的文件上传处理函数。该函数在设计上调用了WordPress的**核心标准文件上传函数 wp_handle_upload**  
。  
  
wp_handle_upload  
 函数本身是WordPress处理文件上传的常规机制，其安全性高度依赖于调用时传入的参数配置。问题在于，TI WooCommerce Wishlist插件的 tinvwl_upload_file_wc_fields_factory  
 函数在调用 wp_handle_upload  
 时，错误地将关键的覆盖参数 test_type  
 设置为了 false  
。  
- **test_type => false 的致命缺陷**  
test_type  
 参数的正常作用是检查上传文件的MIME（多用途互联网邮件扩展类型）类型，确保其符合预设的安全规范（例如，只允许图片类型）。一旦该参数被设为 false  
，WordPress将**完全跳过文件类型的验证**  
。这相当于为攻击者打开了方便之门，允许其上传包括恶意PHP脚本（如webshell）在内的任何类型文件。  
  
- 另一个参数 test_form  
 也被设置为 false  
，它用于验证 $_POST['action']  
 参数，虽然在此漏洞中，test_type  
 的设置是导致任意文件上传的直接和主要原因，但双双设置为 false  
 进一步削弱了安全校验的完整性。  
  
攻击者一旦成功上传恶意PHP文件，只需通过浏览器直接访问该文件的URL，便可在服务器上执行任意指令，进而实现对网站服务器的远程代码执行（RCE）。获得RCE权限后，攻击者便可为所欲为，例如：**窃取数据库中敏感的用户订单信息与支付详情，篡改网站首页内容以植入非法广告或钓鱼链接，甚至将您的服务器纳入其僵尸网络，用于发起DDoS攻击、进行加密货币挖矿或散播恶意软件等。**  
## 漏洞利用前提条件：  
  
需要指出的是，此高危漏洞的利用并非无条件触发。存在漏洞的函数 tinvwl_upload_file_wc_fields_factory  
 是通过 tinvwl_meta_wc_fields_factory  
 或 tinvwl_cart_meta_wc_fields_factory  
 这两个特定的WordPress钩子（hook）函数来调用的。这些钩子函数仅在用户的WordPress网站**同时安装并激活了另一个名为“WC Fields Factory”的插件，并且在TI WooCommerce Wishlist插件的设置中启用了与WC Fields Factory的集成功能时**  
，才处于可用状态。  
  
据了解，**WC Fields Factory 插件通常用于为WooCommerce电子商务系统的产品页面、购物车或结账页面添加自定义字段（如文本框、下拉选项等），以收集更丰富的订单信息或产品定制需求。**  
 尽管存在这一依赖关系，鉴于WordPress生态中插件组合使用的普遍性以及WC Fields Factory插件为其特定用户群提供了必要功能，这一前置条件并不能完全排除大量网站面临的风险。  
## 当前风险与影响总结：  
- **受影响插件版本：**  
 TI WooCommerce Wishlist 2.9.2版及所有更早版本。  
  
- **漏洞修补状态：**  
 截至2025年5月30日，**官方尚未发布任何安全补丁**  
。  
  
- **核心风险：**  
 综上所述，此漏洞通过禁用关键的文件类型校验（test_type => false  
），使得未经身份验证的远程攻击者能够直接上传恶意脚本（如PHP webshell）至目标服务器。结合TI WooCommerce Wishlist插件的庞大用户基数以及其与WC Fields Factory插件的潜在组合使用场景，构成了极为严峻且广泛的安全威胁，可直接导致服务器被入侵和完全控制。  
  
## 紧急安全响应与防护建议：  
1. **立即排查：**  
 请所有WordPress网站管理员迅速检查是否安装了TI WooCommerce Wishlist插件以及WC Fields Factory插件。  
  
1. **确认版本与集成状态：**  
 若TI WooCommerce Wishlist已安装，务必核实其版本号（2.9.2及更早版本受影响）。同时，检查是否启用了与WC Fields Factory插件的集成。  
  
1. **果断处置——停用并删除：**  
 鉴于漏洞的严重性、CVSS 10.0的评级以及暂无补丁的现状，最安全有效的措施是**立即停用并从您的网站中彻底删除TI WooCommerce Wishlist插件**  
。  
  
1. **开发者警示：**  
 插件开发者在代码审计和安全开发生命周期（SDL）中，当使用WordPress的 wp_handle_upload()  
 函数时，应严格审查并正确配置其参数。尤其是要**避免将 test_type 参数设置为 false**  
，除非有绝对必要并已实现其他可靠的补充验证机制，例如：**实施严格的文件扩展名白名单校验（而非仅仅依赖黑名单进行不完整的防护）、对上传文件的内容进行深度扫描以识别潜在的恶意代码片段或已知恶意文件的签名/特征码等。**  
  
1. **保持警惕与更新：**  
 持续关注TI WooCommerce Wishlist插件官方的最新动态以及权威安全信息渠道（如CVE数据库、Wordfence、Patchstack等），一旦安全补丁发布，应在测试环境验证其兼容性与有效性后尽快部署到生产环境。  
  
网络安全防线刻不容缓，任何疏忽都可能导致灾难性后果。请各位站长和开发者高度重视此次高危预警，**立即行动，刻不容缓**  
，全面排查并采取果断措施，确保网站资产与用户数据的绝对安全！  
  
