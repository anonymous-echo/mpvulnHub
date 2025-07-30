#  关于调用安卓FileProvider组件的移动应用程序存在高危漏洞的风险提示   
NVDB  网络安全威胁和漏洞信息共享平台   2024-05-17 21:29  
  
近日，工业和信息化部网络安全威胁和漏洞信息共享平台（  
NVDB  
）监测发现，多个  
调用安卓操作系统  
FileProvider  
组件的移动互联网应用程序（以下简称  
APP  
）存在路径遍历高危漏洞，可被恶意利用实施网络攻击。  
  
FileProvider  
组件是美国谷歌公司推出的安卓操作系统中的一个组件，为应用程序间提供文件共享。如果调用该组件的  
APP  
没有正确处理服务器应用程序提供的文件名，  
攻击者可利用该漏洞覆盖客户端  
APP  
中特定存储位置的文件  
，绕过应用程序主目录中的读写限制，甚至导致恶意代码执行，控制  
APP  
所在设备，多个调用  
FileProvider  
组件的安卓  
APP  
已被发现存在该漏洞。  
  
目前，安卓官方已经发布了修补该漏洞的安全开发指南  
(https://developer.android.com/privacy-and-security/risks/untrustworthy-contentprovider-provided-filename)  
，  
建议相关  
APP  
主办者排查自身  
APP  
漏洞，参考安卓官方安全开发指南修改  
APP  
源代码，发布升级后的  
APP  
，消除漏洞风险。建议移动终端用户及时更新  
APP  
至最新版本，仅安装来源可信的  
APP  
，避免潜在的恶意应用程序。  
  
  
