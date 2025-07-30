#  【漏洞复现】Ruby On Rails   
 菜鸟小新   2024-03-28 07:59  
  
#############################  
  
免责声明：本文仅作收藏学习之用，亦希望大家以遵守《网络安全法》相关法律为前提学习，切勿用于非法犯罪活动，对于恶意使用造成的损失，和本人及作者无关。  
  
##############################  
  
Ruby On Rails在开发环境下使用Sprockets作为静态文件服务器，Ruby On Rails是著名Ruby Web开发框架，Sprockets是编译及分发静态资源文件的Ruby库。  
  
Sprockets 3.7.1及之前版本中，存在一处因为二次解码导致的路径穿越漏洞，攻击者可以利用%252e%252e/来跨越到根目录，读取或执行目标服务器上任意文件。  
  
版本 <=Sprockets 3.7.1利用手法 %252e%252e/ 不断返回上级目录，从而读取任意文件  
  
1.先尝试目录穿越 http://your-ip/assets/file:///etc/passwd  会报错，这是一位内/etc/passwd不在当前目录下  
  
  
2.所以我们把通过编码后的../../../../路径穿越到根目录，然后进行读取passwd文件内容，也就是%252e%252e/  %252e%252e/ ，这里…/…/需url编码为%2e,然后二次编码，才能读取到用户信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQShlQyto4FTjg53zenhJKEBAeHfPGxW8Qmml3otlPJ0v3UaSUBK7iaskyJjgMb6vZye44JvVdZqCAYQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
