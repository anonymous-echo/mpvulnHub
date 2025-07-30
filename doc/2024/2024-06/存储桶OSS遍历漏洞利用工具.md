#  存储桶OSS遍历漏洞利用工具   
 黑白之道   2024-06-16 09:12  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
**1、工具介绍**  
  
  
由于经常遇到  
存储桶遍历漏洞  
，直接访问文件是下载，不方便预览，且甲方要求证明该存储桶的危害，因此该工具应运而生。该工具由**jdr2021**师傅编写。  
  
  
**2、技术工具**  
  
  
使用javafx做图形化，kkFileView做文件预览接口。  
  
  
**3、工具使用**  
  
  
直接运行  
OSSFileBrowse-1.0-SNAPSHOT.jar  
  
  
**命令行运行**  
```
java -jar OSSFileBrowse-1.0-SNAPSHOT.jar
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/GzdTGmQpRic3UVuxlvn0aEYA9wD12NWicv3va0QRkVbyLhaS2PN1UPvFiacU6WlYpeLRslosobugUdHuVRZaU9vibw/640?wx_fmt=jpeg&wxfrom=13 "")  
  
先点击**加载**按钮，此时会爬取存储桶上的全部资源，等待几秒后，左边的**webView**将会通过**kkFilewView**去渲染文件资源。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/GzdTGmQpRic3UVuxlvn0aEYA9wD12NWicvfibKI70aJatuZfwSQKFZibwICeicMx2MFYNzvUbd7wiacsmbT9XHdKuhKQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
按钮**下一个**将会切换到下一个存储桶资源、按钮**上一个**将会返回到上一个资源。  
  
  
**4、注意**  
  
****  
  
在**config.properties**中  
  
  
修改**allow.extensions**的值，即可添加可支持的文件类型进行预览。  
  
  
修改**kkFileView_URL**的值，即可将**kkFileView**修改成自己的**kkfileview**。默认是使用官方的**kkfileview**地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/GzdTGmQpRic3UVuxlvn0aEYA9wD12NWicvYgU4HDUKkv3KBIziboCvSiaIak9J93XcUfoficebqJLHyZccIg466lD5w/640?wx_fmt=jpeg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**工具下载**  
  
****  
**https://github.com/jdr2021/OSSFileBrowse**  
  
> **文章来源：HACK之道**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
