#  30,000个WordPress网站因文件上传漏洞暴露于攻击风险   
 网安百色   2025-02-14 11:29  
  
 ![图片](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5Jjch2wQj7HFiaWvjHSr59wibaxKOK8Zp2djXvDkSskcQUpKjjAdJIZtuHxynX5LDAuF1nJW4a74cw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
“安全与恶意软件扫描CleanTalk”插件中的一个严重安全漏洞使3万多个WordPress网站暴露于漏洞攻击。  
  
该漏洞被标识为CVE-2024-13365，允许未经身份验证的攻击者进行任意文件上传，有可能导致远程代码执行（RCE）。  
  
该缺陷被赋予CVSS 9.8分（严重），影响所有版本的插件，包括2.149。强烈建议用户立即更新到补丁版本2.150。  
## 技术概述  
  
这个漏洞源于插件处理ZIP文件上传的方式，主要是通过有漏洞的UploadChecker类的checkUploadedArchive（）函数。  
  
当插件扫描上传的ZIP文件以寻找恶意软件时，它会在没有进行充分身份验证检查的情况下，将存档解压到WordPress上传文件夹中的一个公开可访问目录。  
  
这个缺陷在于插件的文件检查机制（spbc_is_user_logged_in()）只验证了“wordpress_logged_in”cookie的存在。  
  
这种不充分的身份验证检查允许攻击者绕过限制并上传恶意文件，即使是在未经身份验证的情况下。  
  
一旦提取出来，攻击者可以在ZIP文件中包含恶意PHP脚本，从而在服务器上执行任意命令。  
  
此外，这些提取文件的目标路径是使用wp_get_upload_dir（）函数确定的，从而使恶意文件可以公开访问。  
  
这为攻击者打开了部署webshell或其他后门的大门，使他们能够完全控制被入侵的网站。  
## 风险与开采  
  
这个问题特别危险，因为它允许任何攻击者（无需身份验证或管理访问）：  
1. 上传包含数千个假的。txt文件和一个恶意的。php文件的大型ZIP文件。  
  
1. 利用服务器的资源提取和处理这些文件，压倒服务器。  
  
1. 远程访问恶意的.php文件，触发RCE并获得对网站的完全控制。  
  
根据攻击者的目标，这种攻击可能导致整个站点的泄露、数据泄露，甚至是服务器级的漏洞利用。  
  
发现该漏洞的安全研究员Lucio Sá与CleanTalk合作，发布了修补过的插件版本（2.150）。  
  
使用这个插件的WordPress管理员必须立即升级到这个版本以降低风险。  
  
为了加强保护，建议网站所有者利用WordPress防火墙，如Wordfence，启用“禁用代码执行上传目录”选项。  
  
这可以阻止恶意文件从上传文件夹执行，增加了额外的防御层。  
  
这次事件凸显了WordPress网站上定期更新插件和健全安全措施的重要性。  
  
30,000个暴露于文件上传漏洞的WordPress网站强调了未修补插件的风险。  
  
网站管理员应该迅速采取行动，更新插件并再次检查所有安全设置，以减少未来的攻击面。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
