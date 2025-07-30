#  9万个WordPress站点面临本地文件包含漏洞攻击   
AI小蜜蜂  FreeBuf   2025-02-21 11:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
WordPress的Jupiter X Core插件存在严重安全漏洞，使得超过9万个网站面临本地文件包含（LFI）和远程代码执行（RCE）攻击的风险。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icKwLMcanFbC55QibEQZcicWzZFaWkEs2RUQqQx06sn8VOqL3c0uJlXtDBzyHqNmvbS6ASxnaiasc18A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该漏洞被追踪为CVE-2025-0366，CVSS评分为8.8（高危），允许具有贡献者权限的攻击者上传恶意的SVG文件并在受影响的服务器上执行任意代码。  
  
  
该漏洞利用了Jupiter X Core（一款与高级Jupiter X主题配套的插件）中的两个连锁弱点。  
  
  
**1. SVG文件上传不受限制**  
  
  
插件的upload_files()  
函数（属于Ajax_Handler  
类）允许贡献者上传SVG文件，但未对文件内容进行适当验证。  
  
  
虽然文件名通过PHP的uniqid()  
函数进行了随机化处理，但由于依赖于服务器微时间戳，如果攻击者知道上传时间，就能预测文件名。此漏洞使得包含嵌入式PHP代码的恶意SVG文件得以上传，例如：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icKwLMcanFbC55QibEQZcicWzD3trTicblEatsylV4JoMXiaFby9xhI69I5uSxmkWbf3YicMXrBdAtDqSA/640?wx_fmt=jpeg&from=appmsg "")  
##   
## 2. 通过get_svg()实现本地文件包含  
  
****  
插件Utils  
类中的get_svg()  
方法未对用户输入进行适当过滤，导致路径遍历漏洞。攻击者可以通过操纵$file_name  
参数包含任意文件：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icKwLMcanFbC55QibEQZcicWzeNWfhmrVrURtNx7mp6NmdqoqNgAhbn66AkGwVbX39KE1QicH1hjQXsg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
通过上传恶意SVG文件并强制通过精心构造的请求使其被包含，攻击者能够实现远程代码执行（RCE）。值得注意的是，研究人员stealth copter通过Wordfence的漏洞赏金计划发现了此漏洞，并获得了782美元的奖励。  
  
  
该漏洞的严重性在于其利用门槛较低：  
- **权限提升**：通常权限较低的贡献者用户可能获得服务器的完全控制权。  
  
- **数据泄露**：攻击者可以访问敏感文件，如_wp-config.php_  
或数据库凭据。  
  
- **持久化**：通过植入Webshell，攻击者可以实现长期访问。  
  
##   
## 3. 缓解措施与补丁  
  
  
插件开发商Artbees已于2025年1月29日发布了修复版本（4.8.8），主要修复内容包括：  
- **严格的文件验证**：限制SVG文件的上传权限仅授予可信用户，并清理文件内容。  
  
- **路径清理**：在get_svg()  
中实现realpath  
检查，防止目录遍历攻击。  
  
  
因此，建议用户更新至Jupiter X Core 4.8.8及以上版本，审核用户角色以尽量减少贡献者账户，并配置支持LFI/RCE规则集的Web应用防火墙（WAF）。  
  
  
此外，还应检查自定义主题/插件是否存在类似的文件处理漏洞，特别是在SVG/XML解析器中。鉴于WordPress驱动了全球43%的网站，主动的漏洞管理仍至关重要。  
  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651312407&idx=1&sn=60289b6b056aee1df1685230aa453829&token=1964067027&lang=zh_CN&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
