#  【2025-02-09】黑客新闻摘要——黑客新招数！利用pickle文件漏洞，Hugging Face平台被攻陷？   
知机安全  知机安全   2025-02-09 10:01  
  
### 1. Hugging Face冒出两份恶意机器学习模型，巧妙利用pickle文件避开检测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QGibgZhUnjfODDnEWJh2p4QcnljNgfuibfut5nlHQBcYBiaIuVaGNnD4mhoq4W5LaGKVfXKIt1xHniad2ddgd2yB5w/640?wx_fmt=png "")  
  
网络安全研究人员在Hugging Face platform上发现了两份利用奇特的“损坏”pickle文件技术的恶意机器学习模型，这种策略被称为nullifAI，目的是绕过现有的安全检查标准。这些模型试图通过压缩的PyTorch格式和7z格式的7z压缩，成功地隐藏在官方检测工具Picklescan之外。尽管Picklescan未能检测到，但模型仍能部分执行，导致安全风险。Hugging Face已经更新了其检测工具以修复这一漏洞。  
  
  
【标签】#  
Machine Learning  
 #  
Malware  
 #  
Pickle files  
 #  
Hugging Face  
 #  
Security  
  
  
【来源】https://thehackernews.com/2025/02/malicious-ml-models-found-on-hugging.html  
  
  
**关注我们**  
  
        欢迎来到我们的公众号！我们专注于全球网络安全和精选资讯，为您带来最新的资讯和深入的分析。在这里，您可以了解世界各地的网络安全事件，同时通过我们的新闻，获取更多的行业知识。感谢您选择关注我们，我们将继续努力，为您带来有价值的内容。  
  
  
