#  我的首个 AI 智能体，一键关联漏洞 POC ！   
原创 xazlsec  信安之路   2025-03-13 08:30  
  
AI 真是个好东西，不仅能帮我写 POC，还能帮我一键检测网站指纹并进行漏洞匹配，不信你看：  
  
![image-20250312170821641](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfdH9Ypsv4tkwV7J9wrWnia0Nnd0qgibt7PaghlZOj4Xg5IHjWkmQO3TL9N2mhkSz6SOUACzP4zL2CiaQ/640?wx_fmt=png&from=appmsg "")  
  
任何人都可以在信安之路的微信公众号回复想要探测的网站地址，AI 都会帮大家一一探测，目前刚发布，可能会存在各种问题，不过这条路是可行的，可以为大家带来更多玩法。  
  
当然，AI 不仅仅是这个功能，你可以提任何问题，把它当作一个 AI 聊天窗口也是可以的，欢迎试用。  
  
你可能会关心，背后是如何实现的，其实原理一点都不难，重点是工具平台，我使用的是字节的 coze 创建的智能体：  
  
![image-20250312171128246](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfdH9Ypsv4tkwV7J9wrWnia0Nf94duVIvnMxrYYw6TUxib0B7jIatWoiaR7YG0wgKIXicez5Ceicb4ibu3KA/640?wx_fmt=png&from=appmsg "")  
  
其中网站探测部分用到了信安之路 POC 管理系统的 API，通过创建工作流，编写 python 脚本来进行交互，从而实现网站与 POC 的关联。  
  
最后由 AI 将所查询到的 POC 根据名称一一介绍 POC 相关内容，在对某个网站做渗透测试之前，先来问问 AI，确实是一个不错的选择。  
  
使用很简单，公众号后台对话框输入内容就可与该智能体进行对话，方便快捷！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfc1ibbG6mEdqV5Xpw0yu9UxtIoLlhiazxU4NakInEiam1mOnHHYw4pVq3nrrCc8tpnn5ictdhmNLUaHuA/640?wx_fmt=png&from=appmsg "")  
  
