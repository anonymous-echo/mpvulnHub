#  韩国黑客利用WPS零日漏洞开展大规模间谍活动   
GoUpSec  商密君   2024-08-31 19:50  
  
近日，ESET安全研究人员发现韩国网络间谍组织APT-C-60利用WPS Office Windows版本中的一个零日代码执行漏洞（CVE-2024-7262），在东亚地区的目标系统中安装了名为SpyGlace的后门程序。  
  
  
WPS Office是中国金山软件公司开发的一款生产力套件，在亚洲地区拥有广泛的用户基础，全球活跃用户超过5亿。  
  
  
**WPS零日漏洞被野外利用超过半年**  
  
  
此次曝光的CVE-2024-7262漏洞，涉及WPS Office对自定义协议处理程序（如'ksoqing://'）的处理方式不当，使攻击者能够通过恶意URL在文档中执行外部应用程序。这一漏洞自2024年2月下旬以来已在野外被利用，影响了从2023年8月发布的12.2.0.13110版本到2024年3月发布的12.1.0.16412版本。  
  
  
APT-C-60在攻击中使用了恶意超链接，隐藏在图片下方，诱使用户点击。点击后，会执行特定插件（promecefpluginhost.exe），加载恶意DLL文件（ksojscore.dll），最终下载并执行SpyGlace后门程序。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhva4Q6uibx3rceb7icibFvb0qOp8bCHlGia00ESSNDA8IoeViayvhYia2J1SfgR8CjkM6SLS0kR6ia7B5T5Ow/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
APT-C-60攻击路径 来源：ESET  
  
  
SpyGlace是一个后门程序，根据Threatbook此前的分析报告，APT-C-60曾在攻击人力资源和贸易相关组织时使用过SpyGlace。  
  
  
**补丁不完善导致新的漏洞**  
  
  
更为严重的是，ESET的研究人员在调查APT-C-60的攻击时，还发现了另一个相关的任意代码执行漏洞（CVE-2024-7263）。这个漏洞是由于金山软件对CVE-2024-7262修补不完全导致的，某些参数如'CefPluginPathU8'未得到充分验证，攻击者可能利用这一漏洞再次执行恶意代码。（此漏洞可以在本地或通过网络共享进行利用）  
  
  
尽管研究人员尚未观察到APT-C-60或其他攻击者利用CVE-2024-7263在野外发动攻击，但这个漏洞的存在意味着在足够的时间内，攻击者可能会发现并利用这一安全缺口。  
  
  
**漏洞披露时间线**  
  
  
以下为ESET官方博客（按照其与金山协调的漏洞披露政策）公布的自武器化文档上传到 VirusTotal至今的时间线：  
  
- 2024-02-29：CVE-2024-7262的漏洞利用文档上传至VirusTotal。  
  
- 2024-03-??：金山发布了一个更新，悄悄修补了CVE-2024-7672漏洞，因此 2024-02-29披露的漏洞不再有效。这是通过分析2024-03至2024-04之间所有可访问的WPS Office 版本后得出的结论，因为金山在尝试修复此漏洞时并未特别提供其操作的精确细节。  
  
- 2024-04-30：ESET分析了来自VirusTotal的恶意文档，发现它正在积极利用 CVE-2024-7262，这是文档首次使用时的一个零日漏洞。ESET还发现WPS的静默补丁仅解决了部分错误代码，其余有缺陷的代码仍然可被利用。  
  
- 2024-05-25：ESET联系了金山软件，报告了发现。虽然第一个漏洞已经修复，但ESET询问金山软件是否可以创建CVE条目和/或公开声明，就像对CVE-2022-24934所做的那样。  
  
- 2024-05-30：金山软件承认了这些漏洞并告诉ESET会及时更新信息。  
  
- 2024-06-17：ESET要求更新。  
  
- 2024-06-22：金山软件告诉ESET开发团队仍在努力解决这个问题，并计划在即将推出的版本中修复这个问题。  
  
- 2024-07-31：根据后续测试，ESET发现CVE-2024-7263已被悄悄修复，ESET告知金山软件已预留并正在准备CVE-2024-7262和CVE-2024-7263。  
  
- 2024-08-11：DBAPPSecurity团队独立发布了其调查结果。  
  
- 2024-08-15：CVE-2024-7262和CVE-2024-7263发布。  
  
- 2024-08-16：ESET要求金山软件进行另一次更新。  
  
- 2024-08-22：金山软件承认已于5月底修复了CVE-2024-7263，这与该公司在2024-06-22声称其开发团队“仍在努力解决该问题”的说法相矛盾。  
  
- 2024-08-28：金山软件已承认这两个漏洞，并已修复。但是，该公司表示无意公开CVE-2024-7262的野外利用情况，因此ESET决定发布博客文章警告金山软件的客户：由于CVE-2024-7262漏洞野外利用的第三方披露（会增加漏洞被利用的可能性），他们应紧急更新WPS Office。  
  
  
  
**应对措施与建议**  
  
  
目前，ESET强烈建议WPS Office用户尽快更新到最新版本，至少升级到12.2.0.17119版本，以解决这两个代码执行漏洞。ESET在报告中警告：“这个漏洞非常狡猾，足以诱使任何用户点击看似合法的电子表格，攻击成功率极高。”  
  
  
**结语**  
  
  
WPS零日漏洞攻击事件再次提醒我们，在使用流行办公软件时，仍需保持警惕，及时更新软件以防范潜在的安全威胁。此外，APT-C-60的攻击活动表明，针对东南亚地区的目标，网络间谍组织正在不断寻找新的漏洞和更高效的攻击手段。  
  
  
有关APT-C-60活动的详细入侵指标（IoCs）列表，可以访问ESET在GitHub上的项目页面获取。  
  
  
编辑：陈十九  
  
审核：商密君  
  
**征文启事**  
  
大家好，为了更好地促进同业间学术交流，商密君现开启征文活动，只要你对商用密码、网络安全、数据加密等有自己的独到见解和想法，都可以积极向商密君投稿，商密君一定将您的声音传递给更多的人。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXNcXmbiaiaCljdXpwzOEQ9QTBXMibM6rZTOnbTSwTmCXncQLria2vuLGxn8QPtznzBc0as8vBxWIjrWxQ/640?wx_fmt=jpeg "")  
  
来源：GoUpSec  
  
注：内容均来源于互联网，版权归作者所有，如有侵权，请联系告知，我们将尽快处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXOdeQx0thlyozF2swQTEN9iaaBNDG0jTKfAgqgdesve8x5IEWNvYxjF6sAWjO1TPCZVsWd0oiaDn3uw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMyyClGk1cttkSBbJicAn5drpXEbFIeChG9IkrslYEylRF4Z6KNaxNafDwr5ibcYaZXdnveQCNIr5kw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaMcJkA69QYZ9T4jmc3fdN6EA7Qq9A8E3RWcTKhxVEU1QjqOgrJMu2Qg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点分享  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaiaRXdw4BFsc7MxzkVZaKGgtjWA5GKtUfm3hlgzsBtjJ0mnh9QibeFOGQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaeiaNlRO9954g4VS87icD7KQdxzokTGDIjmCJA563IwfStoFzPUaliauXg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点在看  
  
