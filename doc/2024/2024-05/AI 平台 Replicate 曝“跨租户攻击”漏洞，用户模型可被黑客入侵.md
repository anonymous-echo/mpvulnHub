#  AI 平台 Replicate 曝“跨租户攻击”漏洞，用户模型可被黑客入侵   
安世加  安世加   2024-05-30 18:13  
  
5 月 28 日消息，安全公司 Wiz 近日发布报告，宣称开源 AI 模型共享平台 Replicate 存在重大漏洞，黑客可通过恶意模型进行“跨租户攻击”（注：即利用存在于多租户环境中的安全漏洞访问 / 干扰其他租户的数据资源），从而导致平台用户训练的 AI 模型内部机密数据泄露。  
  
  
安全公司声称，Replicate 平台出现“跨租户攻击”漏洞的主要原因是该平台为提升 AI 模型推论（inference）效率推出的模型容器化格式 Cog，虽然相关格式能够显著改善模型与效率，不过 Replicate 平台忽略了 Cog 格式中的安全隔离机制。  
  
  
获悉，黑客可以将经过训练后的恶意模型打包成 Cog 容器，并通过 Replicate 的用户操作界面与容器互动，最终成功进行了一系列远程执行代码（RCE）攻击测试，获得了容器的 root 权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/UZ1NGUYLEFhiaB65WsOMzT2yQ85joyjV4dJNCdSmpzjd4NGtB9Ofbwib5mafsS5b6ympicLiaFL6OtYUEusBSSwVAA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
此后，研究人员还对 Replicate 平台的基础设施进一步调查，利用当前容器的 TCP 连接成功访问到另一台容器，并通过名为 rshijack 的工具将特定数据成功注入至 TCP 连接中，从而绕过了平台的身份验证步骤，成功访问到其他用户的 AI 模型。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/UZ1NGUYLEFhiaB65WsOMzT2yQ85joyjV4tFMTROmmckHiaib86Fh1icAI34Xtcf633NXqicuD8waXWpsfoKTMHQ6KDQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
研究人员指出，黑客可以利用相关漏洞轻松获取其他用户自用的 AI 模型，能够自由从相关模型问答记录中提取用户隐私数据，还能够自由下载 / 修改用户模型内容，对平台存在严重危害。  
  
  
IReplicate 平台在接到 Wiz 通报后已迅速修复相关漏洞，并表示目前没有检测到有用户 AI 模型外流的迹象。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/UZ1NGUYLEFhiaB65WsOMzT2yQ85joyjV468AFTYkxQk9Ij2eM7aeu6lWOM6EvzTRfBxCARyTpkNH3RYY2BnOQxQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
本公众号发布的文章均转载自互联网或经作者投稿授权的原创，文末已注明出处，其内容和图片版权归原网站或作者本人所有，并不代表安世加的观点，若有无意侵权或转载不当之处请联系我们处理！  
  
文章来源  
（  
IT之家）  
  
  
推荐阅读  
   
  
[](http://mp.weixin.qq.com/s?__biz=MzU2MTQwMzMxNA==&mid=2247537105&idx=1&sn=ece854138fdc1b84f85af0156d94429a&chksm=fc7b550ccb0cdc1a62a117937a891f8dfa6ac50e785f7faf9cf3cd2a62462df6579392d2eed0&scene=21#wechat_redirect)  
  
  
