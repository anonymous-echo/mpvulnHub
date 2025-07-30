#  iOS 和 macOS 惊现 TCC 绕过漏洞！ TCC符号链接攻击手法深度解析   
原创 Hankzheng  技术修道场   2024-12-17 12:49  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wWBwsDOJT49bv6ywduoukCohdN0lonhJT4aGzRD2ia6DuX0XKyWezrw3cTCqt64ZXK7T7vz2ia97xOR8G8nl9AFQ/640?wx_fmt=png&from=appmsg "")  
  
**漏洞速递**  
  近日，Jamf Threat Labs  安全研究人员披露了一个  iOS  和  macOS  系统中存在的  TCC (Transparency, Consent, and Control) 框架绕过漏洞 (CVE-2024-44131)。该漏洞利用符号链接 (symlink)  的验证缺陷，允许恶意应用程序绕过  TCC  机制， unauthorized access 用户敏感信息，例如  iCloud  备份数据、健康数据、麦克风、摄像头等。  
  
**TCC 框架：苹果安全基石**  
  
TCC  框架是苹果设备上的一个关键安全机制，旨在保护用户隐私和数据安全。它通过弹窗等方式，让用户明确授权应用程序访问敏感信息，例如位置信息、通讯录、照片等。TCC  框架的有效性，直接关系到  iOS  和  macOS  系统的安全性。  
  
**符号链接攻击：隐蔽而致命**  
  
符号链接 (symlink)  是指向文件或目录的特殊文件，类似于 Windows  系统中的快捷方式。攻击者可以利用符号链接的特性，诱骗操作系统或应用程序访问 unintended 的文件或目录。  
  
在本例中，攻击者利用  FileProvider  组件对符号链接验证不充分的漏洞，在用户使用  Files  应用复制或移动文件时，将文件重定向到攻击者控制的目录，从而绕过  TCC  框架的限制， unauthorized access  用户敏感信息。  
  
**漏洞的技术细节**  
- **漏洞触发条件:**  
  用户使用  Files  应用在恶意应用程序可访问的目录下复制或移动文件。  
  
- **攻击手法:**  
  恶意应用程序利用  fileproviderd  守护进程的高权限，通过操作符号链接，将文件重定向到攻击者控制的目录。  
  
- **漏洞影响:**  
  攻击者可 unauthorized access  iCloud  备份数据、健康数据、麦克风、摄像头等敏感信息，具体取决于目标进程的权限。  
  
**漏洞修复与安全建议**  
  
苹果已在  iOS 18、iPadOS 18  和  macOS Sequoia 15  中修复了该漏洞。建议用户及时更新系统，并谨慎安装未知来源的应用程序，以保护个人信息安全。  
  
**安全圈作者点评**  
  
该漏洞的发现，再次凸显了操作系统安全机制的复杂性和脆弱性。攻击者往往能够找到一些意想不到的途径，绕过安全防护机制， unauthorized access  用户数据。安全研究人员和软件厂商需要不断努力，加强安全研究和漏洞修复，提升系统的安全性。  
  
**对安全趋势的思考**  
  
近年来，随着移动设备和云服务的普及，用户数据安全面临着越来越严峻的挑战。攻击者不断发明新的攻击技术，利用系统漏洞和用户疏忽，窃取敏感信息。TCC  框架绕过漏洞的出现，也提醒我们，安全防护需要不断进化，才能应对日益 sophisticated 的攻击手段。  
  
