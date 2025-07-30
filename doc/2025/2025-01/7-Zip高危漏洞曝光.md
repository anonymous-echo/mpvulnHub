#  7-Zip高危漏洞曝光   
原创 Norsea  泷羽Sec-Norsea   2025-01-24 15:07  
  
               短发萧骚襟袖冷，稳泛沧浪空阔。                 
  
  
> 免责声明          
  
  
本系列工具仅供安全专业人员进行已授权环境使用，此工具所提供的功能只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用工具中的功能对任何计算机系统进行入侵操作。利用此工具所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。     
  
  
工具合集：后台回复“合集”即可获取。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/IkpoxULsr9fkE8yibrNOpJddDUOwLdGq35e7KwHwlHl5HwL0z4VPpVFVgJHiaF3dLgxG9KicLpvGwIgzrm71FibuSw/640?wx_fmt=jpeg&from=appmsg "")  
#### 摘要  
  
近日，7-Zip文件压缩工具被曝存在高危漏洞CVE-2025-0411，允许攻击者绕过Windows的“Web来源标记”（Mark of the Web，简称MotW）安全机制，进而在用户计算机上执行恶意代码。  
  
此漏洞会影响从嵌套压缩包中提取的文件，导致提取后的文件未附带MotW标记，从而规避系统的安全提示。  
  
官方已在版本24.09修复该漏洞，但由于7-Zip缺乏自动更新功能，未及时更新的用户仍处于潜在风险之中。  
#### 漏洞详情  
  
7-Zip自2022年6月支持MotW功能，通过在提取的文件中添加特殊标记（“Zone.Id”），提醒操作系统和应用程序文件可能来自不可信来源。当用户尝试打开带有MotW标记的文件时，系统会弹出警告，并可能限制宏的运行或以受保护模式打开文件，从而降低恶意行为的风险。  
  
然而，Trend Micro在最新公告中指出，7-Zip在处理嵌套压缩包时存在漏洞，当从标记有MotW的压缩包中提取文件时，未将该标记传播至提取文件。攻击者可利用此漏洞执行任意代码，进而危及用户设备安全。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/IkpoxULsr9fkE8yibrNOpJddDUOwLdGq3ibfLf6oL4mGXsaH8W4FYEW62CVlWUyoBWsWVichar4iaN42RXrvYr4xFA/640?wx_fmt=jpeg&from=appmsg "")  
#### 风险影响  
  
此漏洞的危害在于：  
- **绕过系统提示**：用户在无感知的情况下运行了恶意文件；  
  
- **代码执行**：攻击者可通过精心构造的压缩包实现远程代码执行；  
  
- **传播难以控制**：由于7-Zip无自动更新机制，易被未更新的用户忽视。  
  
#### 官方修复  
  
7-Zip开发者Igor Pavlov已于2024年11月30日发布版本24.09，修复了该漏洞。他表示，该问题出现在嵌套压缩包的文件提取逻辑中，更新版本已完善相关机制，确保MotW标记得以正常传播。  
#### 漏洞利用趋势  
  
历史上，MotW绕过漏洞多次被用于恶意软件传播，例如：  
1. **DarkGate恶意软件**：利用CVE-2024-38213漏洞，通过伪装为合法软件（如iTunes、NVIDIA驱动）绕过SmartScreen保护，植入恶意代码；  
  
1. **DarkMe远程访问木马**：利用CVE-2024-21412漏洞，针对股票和外汇交易论坛用户，传播恶意程序。  
  
#### 安全建议  
  
为避免此类漏洞带来的安全隐患，建议广大用户立即采取以下措施：  
1. **更新版本**：下载并安装7-Zip最新版本（24.09或更高）；  
  
1. **关注安全公告**：及时跟进开源工具的安全更新；  
  
1. **谨慎操作未知文件**：即使无安全警告，提取和运行文件时仍需注意文件来源。  
  
#### FreeBuf帮会  
  
推荐加入我们的帮会，专为红队实战打造！帮会定期分享网上找不到的珍贵资源，特殊限时提供的安卓远控工具（7.4版）等。此外，还有大量Poc、渗透工具、课程资源以及实战案例，帮助你快速提升渗透技能。前100位仅需 99元就可以享受终身使用，人多后价格会上涨，机会难得，别错过！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/IkpoxULsr9dEclFnKnAAurt1AlnO1HBLiaRymULG1ibJJhXlNjMH1rd1SgQQWIyFBVTRMteWWfiby3FCWfpB7n2oA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IkpoxULsr9fu7k87GWyAbdEWHSUB8pN4fRff5E9c935lEmryJWQEZCd9Op28RqrUpslw73GrrPibshicArzEzzgw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IkpoxULsr9fu7k87GWyAbdEWHSUB8pN41653CVUrOcaDjpKpzpj0PKqiaJktVlibmPjpzRUGuYdoD8QbicnPuQaWQ/640?wx_fmt=png&from=appmsg "")  
#### 学习交流群  
  
刚加入网络安全行业的小白，可以加入学习交流群，大家一起互相学习，互相进步，不会的难题大家一起学习，一起攻克。  
  
想要进学习交流群的师傅们，可以扫描下方二维码添加好友，我再拉你进群（Ps：防止广告进群）。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/IkpoxULsr9eqEfdABzE2OY90qYNH40o4TmbcRV72bzGJExxAO9pibPc7yI0AxwJevFIAUzOickTsz9KbhG50pOkw/640?wx_fmt=jpeg&from=appmsg "")  
  
**你花了****·  来阅读**  
  
**点个**  
**再走吧~**  
****  
  
  
  
