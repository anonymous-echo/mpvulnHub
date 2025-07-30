#  sqlmap_gui是一款图形界面化的 SQL 注入漏洞测试工具   
suqianjue  无影安全实验室   2025-02-21 12:46  
  
免责声明：  
本篇文章仅用于技术交流，  
请勿利用文章内的相关技术从事非法测试  
，  
由于传播、利用本公众号无影安全  
实验室所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号无影安全实验室及作者不为此承担任何责任，一旦造成后果请自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把"**无影安全实验室**  
"设为星标，这样更新文章也能第一时间推送！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3GHDOauYyUGbiaHXGx1ib5UxkKzSNtpMzY5tbbGdibG7icBSxlH783x1YTF0icAv8MWrmanB4u5qjyKfmYo1dDf7YbA/640?&wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
安全工具  
  
  
  
## 0x01 工具简介  
  
SQLMap 是一款自动化的 SQL 注入漏洞测试工具，它能帮助安全研究人员、渗透测试员和网络安全专家识别、利用和修复SQL注入漏洞。为了更方便用户操作和理解其工作流程，我们推出  
了 SQLMap 可  
视化工具，使得SQLMap的操作更加简单直观，尤其适合没有命令行经验的用户。该工具将 SQLMap 命令行工具进行图形化，提供更加直观、易于操作的界面，让用户可以轻松进行 SQL 注入测试。  
## 0x02 主要特点  
- 🎯 **图形化界面**  
：  
告别繁琐的命令行输入，通过可视化的界面进行操作。  
  
- 🚀 **快速扫描**  
：  
简单设置，轻松启动扫描，节省您的时间。  
  
- 🛠️ **高级功能**  
：  
支持 SQLMap 的所有高级功能，如自定义 payload、数据库信息泄露、Web 应用程序防护绕过等。  
  
## 0x03 环境要求  
- 🖥️ **操作系统**  
：  
Windows  
  
- ⚙️ **Java 版本**  
：  
1.8+ 版本  
  
- 🧑‍💻 **SQLMap**  
：  
确保本地已经安装并配置好 SQLMap 工具  
  
## 0x04 工具截图  
  
双击jar包打开程序如图所示，会在当前文件夹生成一个config.txt文件  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERN6Ocz4qj9WbYeCzszlU5mz0yj9aZ0RrBKwFtf4DArC8icwIicX2nzmZ9ibylNTNQKAloKm6CDYGcjg/640?wx_fmt=png&from=appmsg "")  
  
config.txt文件里面记录的是sqlmap路径和代理信息，可在工具中导入，也可手动填写  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERN6Ocz4qj9WbYeCzszlU5m7KiaJlt065qLicpbyBzgHsKVkdUuwGmT3nqU81K9viaQEuZxXtwBdp9Jw/640?wx_fmt=png&from=appmsg "")  
  
  
文件->导入sqlmap，选择sqlmap文件夹就可以了(不用选择具体文件)  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERN6Ocz4qj9WbYeCzszlU5m8uj2mKslptkUwdXnQnS15ouZTTcvxV6sTFtqNeCy2Y0LOFViby5Hj2A/640?wx_fmt=png&from=appmsg "")  
  
设置->代理，可以挂代理，工具自带测试代理是否可用功能  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERN6Ocz4qj9WbYeCzszlU5m9psvR84azSu9FCh2Py4rLAib6uWYP49TfiaRcyxA5jwkWvtsgF9tTuIg/640?wx_fmt=png&from=appmsg "")  
  
脚本文件会自动获取sqlmap文件中tamper文件夹，也可以手动添加脚本到里面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERN6Ocz4qj9WbYeCzszlU5m3EdPGfMEOgyVfscuQQMBExVT6ibUfxRuqpjukl0rEbejNqicLDPkgX8g/640?wx_fmt=png&from=appmsg "")  
  
自定义参数在GET请求下就是sqlmap的 -p id ，POST请求就是sqlmap的 -data id=1，GET/POST请求可在url那一行最左边选 测试级别、风险级别、线程数、库、表、列都可以自定义，还有一些可自选的功能项 选择完后点击预览按钮，则会生成sqlmap语句在预览框中显示，可以自定义调整，修改、删除、添加 然后点击start就是开始运行 **注：必须先点预览，预览框中出现了命令才能点start运行**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERN6Ocz4qj9WbYeCzszlU5msF0DaTl3H2P8MfWveXXwNerxCNCrk3okp1g95ZxAjNy7TLDSFQibicOA/640?wx_fmt=png&from=appmsg "")  
  
**关于抓包跑，可直接在burp抓包，复制请求包粘贴到文本框中，在需要测试的地方加上 * 点击start即可 其他地方不需要改，可以选择需要的脚本和一些功能项等等 注：当预览框和抓包跑文本框都有信息时，优先会运行预览框命令**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERN6Ocz4qj9WbYeCzszlU5m7MGgGP3Oxg9my9apcyohYulyHwPbRqBcD4T51mH22vS4TCkEcClnicw/640?wx_fmt=png&from=appmsg "")  
  
## 0x05 工具下载  
  
**点****击关注**  
**下方名片****进入公众号**  
  
**回复关键字【250221****】获取**  
**下载链接**  
  
  
最后推荐一下小密圈，干货满满，物超所值，**内部圈子每增加100人，价格将上涨20元，越早进越优惠！！！**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/awCdqJkJFERvgmiaRWOkaOT8aCVKhAf4Yab5X63k4NpTL9CzAmhw61VKGWrkCzd8LZIdEgUrlfhU8ib65tVG6EiaQ/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
