#  内网漏洞自动化扫描工具 -- P1soda   
P001water/P1soda  网络安全者   2025-01-25 16:01  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。  
0x01 工具介绍  
P1soda （苏打水）是一款常规内网渗透场景下的全方位漏洞扫描工具。  
0x02 安装与使用  
单个、多个目标探测，支持CIDR网段输入  
```
P1soda.exe -t 192.168.110.235 // 单个目标
P1soda.exe -t 192.168.110.2-235 // 多个目标
P1soda.exe -t 192.168.110.143,192.168.110.251 // 多个目标
P1soda.exe -t 192.168.110.235/24 // 扫描110 C段
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccx9oAltSoP61c7jwFZIOJicGx5n8hB7SwTWYR4DmKxtujCFk9Qbw8vrrfLmPBqNrZm2X9GxibId1oMg/640?wx_fmt=png&from=appmsg "")  
  
内网网段探测  
```
.\P1soda.exe -plg netspy -cidr 192.168.0.0/16
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccx9oAltSoP61c7jwFZIOJicG9sibkMGQamw7TmH5HzAibibP1tYLFf8lqbTbZcjPG045l527S2CSsVicNw/640?wx_fmt=png&from=appmsg "")  
  
指定用户名密码爆破  
```
.\P1soda.exe -t 127.0.0.1 -br -user root,admin -pwd 123456 // -br 开启爆破模式，默认情况不开启
```  
```

```  
  
输出保存文件  
```
.\P1soda.exe -t 127.0.0.1 -br -nc -o // -br开启爆破模式, -o输出重定向到p1.txt, -nc取消颜色输出
```  
```

```  
  
针对url的检测  
  
单个url目标  
```
.\P1soda.exe -u http://192.168.110.251
```  
```

```  
  
多个目标  
```
.\P1soda.exe -uf .\targets.txt
```  
```

```  
  
Debug 测试信息  
```
.\P1soda.exe -u http://192.168.110.143:8888 -dbg
```  
```
debug显示一些poc信息，http请求信息
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccx9oAltSoP61c7jwFZIOJicGiae1yGuWkvkhTeRtBKAwo6d532pK1mZmsYq2ekf9Ie6VTQbWr7Ld1Cw/640?wx_fmt=png&from=appmsg "")  
  
****  
**0x03 下载链接**  
  
不要问，问就是百度！不要问，问就是百度！不要问，问就是百度！  
  
  
  
  
  
  
**·****今 日 推 荐**  
**·**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccx9oAltSoP61c7jwFZIOJicGhz30pNWW9u15OnGVWPTPsw5NgOkibxvAwPiaJrpVia2RtR1TiadEiaG2RrQ/640?wx_fmt=png&from=appmsg "")  
  
  
