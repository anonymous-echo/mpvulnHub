#  emlog2.5.3代码审计（后台文件上传漏洞）   
 船山信安   2025-04-25 16:00  
  
## 前言  
  
前几天在学代码审计，翻cnvd看到一个emlog的新漏洞，想着自己复现一下  
  
![1744853339_6800595b1144d0be1bf60.png!small?1744853337814](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicPYASmDyLTIiaH9YEE1iagXarWoicWzgJg4BNUwcLUiaNzPdAMJoQKQlfbr3w8DTicCRASLH8Ms1Gvgl5g/640?wx_fmt=jpeg&from=appmsg "")  
## 搭建  
  
访问官网找到对应版本下载即可  
  
https://www.emlog.net/  
  
解压到phpstudy的www目录下  
  
访问install.php即可安装  
## 审计  
  
该漏洞需要登录到后台，因此先进行登录  
  
![1744792019_67ff69d3550693d0bf024.png!small?1744792019000](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicPYASmDyLTIiaH9YEE1iagXar3lUO2SfwoXSkhkAMic570yhqwaodfnXKZAiaZ8tbtYYhNRLIzhCAibFdA/640?wx_fmt=jpeg&from=appmsg "")  
  
进入后台，来到插件这，可以看到有一个安装插件，即上传功能  
  
分析相应的代码  
```
```  
  
重点为以下两个部分  
  
![1744792093_67ff6a1dc746ad585ee04.png!small?1744792093344](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicPYASmDyLTIiaH9YEE1iagXarGDkO1vO0TS1fjPaABtrx5GH23FAjMibrGTLjvmpZ5T44j3lrVttJNwg/640?wx_fmt=jpeg&from=appmsg "")  
  
1.emUnZip  
```
```  
  
重点为以上加粗的两部分  
  
1.1  
  
![1744792183_67ff6a77d464b9c34ea31.png!small?1744792183344](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicPYASmDyLTIiaH9YEE1iagXarUv1fWEU1fH8TRG5KOKCYIv4eEj39zRNO1nQ334GAISdcq6vQ8QgXDQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744792389_67ff6b4544be6bd4117fb.png!small?1744792388753](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicPYASmDyLTIiaH9YEE1iagXarYdqYuGJKk4XMGiarBhKCcttTqgbF59SYPKsDUG34uWIKdIEA7b2hUbg/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744792404_67ff6b541850066e3a7ec.png!small?1744792403545](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicPYASmDyLTIiaH9YEE1iagXarq4rfsg9BoJ6X5TF9vYfnFo3XCPfRToyDKNEzDzZUAlTmVoNDnF669Q/640?wx_fmt=jpeg&from=appmsg "")  
  
使用 ZipArchive::getNameIndex(0) 获取 ZIP 文件中第一个文件的完整路径。  
  
使用 explode 函数将路径按 / 分割，取第一个部分作为目录名（$dir），并确保其以 / 结尾。  
  
这里的 $dir 是 ZIP 文件中第一个文件所在的目录，用于后续的文件检查  
  
2.  
  
由于传参是“plugin”，所以主要是这一部分  
  
![1744792204_67ff6a8cc97109460c98f.png!small?1744792205533](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicPYASmDyLTIiaH9YEE1iagXar5pN05G3Z2JlwV8aFfaxuLK3Wb0CySP1gDvOviaaeibC8qCricE3oicXotA/640?wx_fmt=jpeg&from=appmsg "")  
![1744792452_67ff6b84ef585a227a58e.png!small?1744792452487](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicPYASmDyLTIiaH9YEE1iagXarfqE5fpzj6icICibBhSJdehNwTz515ndAliaSGe72wYVr5UXxxox8ahIbg/640?wx_fmt=jpeg&from=appmsg "")  
  
要让re不为false  
  
则$dir和$plugin_name需要相同  
  
因此zip目录结构如下  
  
phpinfo/phpinfo.php  
  
即目录要和最后的文件名相同  
  
![1744792226_67ff6aa206b4299decbb1.png!small?1744792226301](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicPYASmDyLTIiaH9YEE1iagXariapg3QKQKa9QFOElibyJDeUHPhV0Wc1mibTtJic9aichniaGQZy36HYzZN1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
上传后访问路径为  
  
![1744792288_67ff6ae06bbe0d507e620.png!small?1744792291965](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicPYASmDyLTIiaH9YEE1iagXarvy3jjoe2yqGJbre2FYqAWog6a78xeqmcvZVpd0YPEOsA5qJcWCfjMA/640?wx_fmt=jpeg&from=appmsg "")  
  
因此访问../content/plugins/phpinfo/phpinfo.php  
  
![1744792291_67ff6ae36a1ad285e8a15.png!small?1744792291966](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicPYASmDyLTIiaH9YEE1iagXarfRzTcQ3LKnkMfjG0uhsV4r0qqTibFEJiaBzWRAAMnrmWV2GnuDCIl9qw/640?wx_fmt=jpeg&from=appmsg "")  
  
来源：  
https://www.freebuf.com/ 感谢【  
鸡你太美666】  
  
