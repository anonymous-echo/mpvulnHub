#  某代理商管理系统存在RCE漏洞   
原创 狐狸  狐狸说安全   2025-04-15 01:01  
  
**免责声明**  
  
由于传播、利用本公众号狐狸说安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号  
狐狸说安全  
及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉，谢谢！  
### 0x01 概述  
  
由于此代理商管理系统使用Struts2开发框架组件，均存在历史遗留漏洞，可直接利用Struts2的Nday漏洞进行渗透攻击即可  
### 0x02 正文  
  
**FOFA语法：body="AgentSyste代理商管理系统"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwbM7uS6ezW1wQhP9GPziak6wNEZ0Gns8AMua3Gvpat5hTZr3Y6jGA236wwySmtRb3Q0wicgHNM4WJHQ/640?wx_fmt=png&from=appmsg "")  
  
执行whoami命令：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwbM7uS6ezW1wQhP9GPziak6wpHJE9f70yP8ufXcngy1WdQfWUTNhFC4EurFDD0iaQzMdzPs1I6I4aIg/640?wx_fmt=png&from=appmsg "")  
  
执行ifconfig命令：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwbM7uS6ezW1wQhP9GPziak6wzO2u0pGPspgWgOLZwLiahJGAQEnj9mfbxh1zjYI25CHIQ1gCfdyTJJA/640?wx_fmt=png&from=appmsg "")  
  
工具检索：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwbM7uS6ezW1wQhP9GPziak6wSgDdY1MN82ms5OnTPV9CUtAQNicZiaJRbVRYic7oEz4Krgjg3qgrvVMIg/640?wx_fmt=png&from=appmsg "")  
  
**0x03结尾**  
  
这次就不写POC脚本了，直接拿工具打吧，只作为研究参考以及学习使用，请不要违法哦！  
  
  
**0x04内部圈子**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/pH5fZ5lvwwbM7uS6ezW1wQhP9GPziak6woD7xzFKuEG72rDEibsU53Fu2clLuLButQJkJv7zdhR7cZU73SVwdia4w/640?wx_fmt=jpeg&from=appmsg "")  
  
