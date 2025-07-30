#  记录某次APP漏洞挖掘案例   
原创 知名小朋友  进击安全   2025-02-06 01:01  
  
 一、前言  
  
     记录一下最近的一个漏洞，是针对app进行测试的一个漏洞。  
  
二、挖掘记录  
  
    
  在进行测试短信相关功能点漏洞的时候发现，存在相关的sign值，并且在URL当中发现了存在相关的时间。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWXa2bmh8exIyr6WJdykfO9JyD7d6lIibibj74dibOO5FYEdNUA2uRIXCYicNe4aunMs3ia0KGicXcQPYag/640?wx_fmt=png&from=appmsg "")  
  
    其中相关的参数如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWXa2bmh8exIyr6WJdykfO9ibvsgEEyS700CsANqYCd61rwtqopOOLJRcwekkDLZwQAGSYT3E6QVmw/640?wx_fmt=png&from=appmsg "")  
  
    可以看到参数mobile为我们的手机号，并且存在一个参数为timestamp为时间相关时间戳，这里对接口再次进行调用发现回显如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWXa2bmh8exIyr6WJdykfO9tOOsbzhz9mNLRKIh86h4MTJcUpNabibU0AZ5Qs5gNuvCKK16FaD03hg/640?wx_fmt=png&from=appmsg "")  
  
    这里猜想，是否时间戳来进行控制时间判断是否在一分钟之内，在修改时间戳之后进行重新发包发现。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWXa2bmh8exIyr6WJdykfO9jDd1wiaicMicL3qsfiaen1cHOvrxgibNNAgGKU6RqANib3zZhHG77UBKoLGw/640?wx_fmt=png&from=appmsg "")  
  
    这里可以很明显的发现，存在相关字符串为sign，这里需要运用到我们的逆向知识了，先来查看文件是否存在加固。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWXa2bmh8exIyr6WJdykfO9hHl8n0qXrgiapTWnguZrT42MDS6dcWANA0DTqCyXlzXKia146dqGfLxQ/640?wx_fmt=png&from=appmsg "")  
  
    这里可以看到存在数字加固，我们需要进行脱壳，在经历一系列脚本小子的操作之后，脱壳内容如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWXa2bmh8exIyr6WJdykfO9e6jxES18c2YtMtleo83204O0vwd8ETbEibmzSpAjMxtLsmp7bIrEicKQ/640?wx_fmt=png&from=appmsg "")  
  
      
我们来载入相关jadx尝试进行逆向相关签名值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWXa2bmh8exIyr6WJdykfO9jPXwPJRtoWHNbHZXy5wIleGAIGic4GZMOOo9gmuyhuLFaOICjZ8jJAQ/640?wx_fmt=png&from=appmsg "")  
  
      
最终定位到代码如下，发现就是对相关参数进行编辑排版到一起之后进行双层md5加密，使用AI帮我们编辑相关脚本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWXa2bmh8exIyr6WJdykfO9T9lNFVXBzhvP6eMPn0UperRRiccEfuOFPNYqhicpEURIU2oxicmPeU2EA/640?wx_fmt=png&from=appmsg "")  
  
      
可以看到成功编写出来相关的签名生成脚本，这里我们尝试进行变换时间戳进行利用，我们将时间戳更改为111111。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWXa2bmh8exIyr6WJdykfO9BprZXUQqSXY7M5yvwatIFrKPrDiaZyTN8aKPf4pdpQcVeb3XfDKjeRQ/640?wx_fmt=png&from=appmsg "")  
  
     
 进行访问尝试。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWXa2bmh8exIyr6WJdykfO9wubm0NzwL71s8EOtMmNdkEKibBJCibSvbzhVgJliasgicz6pbT6vsiaCTibg/640?wx_fmt=png&from=appmsg "")  
  
发送成功，表明签名正确，剩下的就是不停的变换时间戳进行发包，成功水到一个低危。  
  
三、完结  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg "")  
  
  
  
