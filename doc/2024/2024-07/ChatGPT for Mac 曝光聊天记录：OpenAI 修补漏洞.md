#  ChatGPT for Mac 曝光聊天记录：OpenAI 修补漏洞   
flyme  独眼情报   2024-07-06 10:38  
  
上个月，OpenAI 宣布 ChatGPT for Mac 可供所有用户使用。使用官方 ChatGPT 客户端，用户可以快速进行文本对话、生成图像、读取屏幕截图或文件以及搜索对话。然而，即使是像 OpenAI 这样规模的公司，其安全性也存在  
漏洞  
。ChatGPT for Mac 将所有用户对话以纯文本形式存储在本地磁盘上。  
  
这意味着在 Mac 上运行的任何应用程序、进程或恶意软件都可以在未经授权的情况下直接访问完整的聊天记录，从而可能导致私人数据泄露。自 2018 年发布 macOS Mojave 10.14 以来，Apple 引入了新的安全功能，以防止未经授权的应用程序访问私人数据，并在需要此类访问时提示用户同意。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnT2Hd8FygKjSibgppmcceQnSoQcv8xZOW2zUJlfzA8zqXGcqVatesKPPZ4c8YW3aXgibibwALU65TTxQ/640?wx_fmt=png&from=appmsg "")  
  
在开发 Mac 版 ChatGPT 的过程中，OpenAI 并未采用 Apple 推荐的设置将用户数据存储在沙盒中。相反，OpenAI 将其存储在不受保护的路径中：~/Library/Application Support/com.openai.chat/conve…{uuid}/  
  
将数据存储在不受保护的路径中已经够成问题了，但 OpenAI 还未能加密用户数据，这使得任何人都可以轻易窃取完整的聊天记录。  
  
技术爱好者 Pedro Jose  
发现了  
这个问题，并在 Meta Threads 上发布了一个演示视频。根据用户的反馈，OpenAI 迅速发布了更新版本来解决这个问题。  
  
在最新版本的 ChatGPT for Mac 中，OpenAI 现在已经对本地存储的数据进行了加密。虽然它仍然没有被放置在沙盒中，但文件现在已经被加密，在一定程度上增强了安全性。  
  
建议ChatGPT for Mac用户立即升级到最新版本以确保安全，您可以从  
OpenAI网站  
下载最新的安装包。  
  
  
