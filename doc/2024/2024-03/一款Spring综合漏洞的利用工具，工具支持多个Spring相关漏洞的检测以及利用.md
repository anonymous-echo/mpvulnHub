#  一款Spring综合漏洞的利用工具，工具支持多个Spring相关漏洞的检测以及利用   
charonlight  无影安全实验室   2024-03-15 20:45  
  
免责声明：  
由于传播、利用本公众号无影安全实验室所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号无影安全实验室及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把  
**无影安全实验室**  
“**设为星标**  
”，  
这样更新文章也能第一时间推送  
！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3GHDOauYyUGbiaHXGx1ib5UxkKzSNtpMzY5tbbGdibG7icBSxlH783x1YTF0icAv8MWrmanB4u5qjyKfmYo1dDf7YbA/640?&wx_fmt=gif "")  
  
  
安全工具  
  
  
  
工具介绍  
  
01  
  
  
工具目前支持Spring Cloud Gateway RCE(CVE-2022-22947)、Spring Cloud Function SpEL RCE (CVE-2022-22963)、Spring Framework RCE (CVE-2022-22965) 的检  
测以及利用。。  
  
  
工具展示  
  
02  
  
  
  
  
单个检测&&批量检测  
  
工具支持单个漏洞单个目标检测，也支持多个目标检测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERVoTgNAlnYIPIDoZpryYz8j3abEoGYnyo56ic5ePzuPMrWic0x72ibSOKicEFoiar5WwFI5gkInGpy7xw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERVoTgNAlnYIPIDoZpryYz8bkQibiarEgjM7XOOJU7ibjeZXoQltFEXVsfuALJCvDe675Zs99rrFqttQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERVoTgNAlnYIPIDoZpryYz86mLBiaP3Yb4473Z46vZ0iciaaHmwicErq3D8ZtkKIKb5gIE13iaxtgJrsLQ/640?wx_fmt=png&from=appmsg "")  
  
漏洞利用  
  
Spring Cloud Gateway RCE(CVE-2022-22947) 目前支持命令执行、一键反弹shell、哥斯拉内存马注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERVoTgNAlnYIPIDoZpryYz8BykxiakenNeIZ0YgnzXx22qpy3811HjNfnicGyrPgricQbH6ujabibzSeg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERVoTgNAlnYIPIDoZpryYz8XcmOTohoLZmwE3bibgQ3cibGynho68VqqXDvazMXe6L2GqDAJXpicjbdg/640?wx_fmt=png&from=appmsg "")  
  
Spring Cloud Function SpEL RCE (CVE-2022-22963)目前支持一键反弹shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERVoTgNAlnYIPIDoZpryYz8mmxnmnORm0USibr1OpNbDEUicibmHLFibaGeAhPqVhLElbyYLrYicA5dgOQ/640?wx_fmt=png&from=appmsg "")  
  
Spring Framework RCE (CVE-2022-22965) 目前支持命令执行，通过写入webshell实现的，后续会继续实现写入ssh公钥、计划任务等利用方式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERVoTgNAlnYIPIDoZpryYz8yC91W6MJxtfcIPpzf5hABnS1b7r2EgXSQQrX2vgR4QVHzYxChUZJ6A/640?wx_fmt=png&from=appmsg "")  
  
  
工具下载  
  
03  
  
  
**点击关注下方名片****进入公众号**  
  
**回复关键字【240315****】获取**  
**下载链接**  
  
  
  
