> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU1NTQ5MDEwNw==&mid=2247485124&idx=1&sn=c383ddce288763dc639bca3094109066

#  HydraCrypt/UmbreCrypt勒索病毒  
原创 Enginge  Enginge   2025-06-14 14:30  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/SEdvtYR5JaYI00RAa1ZTy35yKKkZEN7ElLsNgz8ts6yTA4cMcHfnGFJotpTGKt04nQBy5H1nAkTOUzZ0AqpdKg/640?wx_fmt=jpeg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/7QRTvkK2qC7JrnsdoLClToqibt8hpbOMria1A1ulmEwmia8svO8Ck3XazRt4c0UCwBicDxLDib8NccJYKIUMA8bf7UQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&tp=webp "")  
  
长风萧萧渡水来，归雁连连映天没。——《南北朝 · 卢思道》  
  
  
HydraCrypt/UmbreCrypt勒索病毒  
  
HydraCrypt 和 UmbreCrypt勒索病毒可被大部分解密。这两个家族都与2015年源代码泄露到 PasteBin 的 CrypBoss 勒索软件家族密切相关。但都更改了加密方案中的一些实现细节。  
  
HydraCrypt/UmbreCrypt勒索病毒会导致文件末尾多达 15 个字节的损坏无法恢复。但是，对于大多数文件格式，最后的尾随字节并不重要，或者只需打开并保存文件即可相对容易地修复。对于其他文件格式，可能有专用的修复和恢复工具可用。  
  
快速识别其是否为该勒索病毒，其加密后的每个文件都重命名为以下格式：  

```
*.hydracrypt* 
*.umbrecrypt* 
```

  
解密方式，请查找加密的 PNG 文件并从 Internet 上获取任何随机的 PNG 图像（或本机未被加密的PNG文件）。选择，然后将未加密和加密的文件同时拖放到解密器可执行文件上。如下操作：  
  
![Just drag and drop either an encrypted file and its unencrypted version or an encrypted PNG file and any PNG image onto the decrypter.](https://mmbiz.qpic.cn/sz_mmbiz_gif/SEdvtYR5JaZjibLicbgYrn8uBSWaZXFR96dX71lpHjThtvO1EPiay3Wf7ibvoiaK2ia2NB8kmuvlqFicgiaiaXLOvWULGNQ/640?wx_fmt=gif&from=appmsg "")  
  
只需将加密文件及其未加密版本或加密的 PNG 文件和任何 PNG 图像拖放到解密器上即可。  
  
此过程可能相当耗时，并且根据您的 CPU 和系统可能需要长达几天的时间。  
  
确定解密密钥后，您将收到如下消息：  
  
![The message you receive after the decrypter determined the correct key for your system.](https://mmbiz.qpic.cn/sz_mmbiz_png/SEdvtYR5JaZjibLicbgYrn8uBSWaZXFR96H1jg9Wx5AQ8hB1A0avryumRiaIp2BXibOibje8q1aSmRq3zmVx6dtVQsg/640?wx_fmt=png&from=appmsg "")  
  
解密器确定系统的正确密钥后收到的消息。  
  
如果您收到错误消息，可能是此解密器尚不支持的新变体的目标。  
  
找到密钥后，可添加到文件夹，所选文件夹的子文件夹中的文件也将被解密。  
  
解密地  
址方法以  
及工具的最新地址：  

```
https://decrypter.emsisoft.com/download/hydracrypt
```

  
  
