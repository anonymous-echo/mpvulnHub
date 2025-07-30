> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NzUyNTI1Nw==&mid=2247497447&idx=1&sn=bcc588c3c8ac5d3f6fbbcef7b0a88061

#  网络摄像头漏洞扫描工具 | Ingram  
jorhelp  无影安全实验室   2025-07-15 11:39  
  
免责声明：  
本篇文章仅用于技术交流，  
请勿利用文章内的相关技术从事非法测试  
，  
由于传播、利用本公众号无影安全  
实验室所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号无影安全实验室及作者不为此承担任何责任，一旦造成后果请自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把"**无影安全实验室**  
"设为星标，这样更新文章也能第一时间推送！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3GHDOauYyUGbiaHXGx1ib5UxkKzSNtpMzY5tbbGdibG7icBSxlH783x1YTF0icAv8MWrmanB4u5qjyKfmYo1dDf7YbA/640?&wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
安全工具  
  
  
  
## 0x01 工具介绍  
  
主要针对网络摄像头的漏洞扫描框架，目前已集成海康、大华、宇视、dlink等常见设备。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFETWfUyeen9l1iaxha3HFjPrHIMVaCglmBnP1FssOicVPDqm3k9DuhakYJyO33mlFiazibXV9iczoVD90FQ/640?wx_fmt=png&from=appmsg "")  
## 0x02 工具安装  
  
  
**请在 Linux 或 Mac 系统使用，确保安装了3.8及以上版本的Python，尽量不要使用3.11，因为对许多包的兼容不是很好**  
- 克隆该仓库:  
  

```
git clone https://github.com/jorhelp/Ingram.git
```

- 进入项目目录，创建一个虚拟环境，并激活该环境：  
  

```
cd Ingram
pip3 install virtualenv
python3 -m virtualenv venv
source venv/bin/activate
```

- 安装依赖:  
  

```
pip3 install -r requirements.txt
```

  
至此安装完毕！  
## 0x03 工具使用  
- 由于是在虚拟环境中配置，所以，每次运行之前，请先激活虚拟环境：
```
source venv/bin/activate
```

  
  
- 你需要准备一个目标文件，比如 targets.txt，里面保存着你要扫描的 IP 地址，每行一个目标，具体格式如下：  
  

```
# 你可以使用井号(#)来进行注释

# 单个的 IP 地址
192.168.0.1

# IP 地址以及要扫描的端口
192.168.0.2:80

# 带 '/' 的IP段
192.168.0.0/16

# 带 '-' 的IP段
192.168.0.0-192.168.255.255

```

- 有了目标文件之后就可直接运行:  
  

```
python3 run_ingram.py -i 你要扫描的文件 -o 输出文件夹

```

- 端口： 如果target.txt文件中指定了目标的端口，比如: 192.168.6.6:8000，那么会扫描该目标的8000端口  
  
否则的话，默认只扫描常见端口(定义在 
```
Ingram/config.py
```

  
 中)，若要批量扫描其他端口，需自行指定，例如：  

```
python3 run_ingram.py -i 你要扫描的文件 -o 输出文件夹 -p 80 81 8000

```

- 默认并发数目为 300，可以根据机器配置及网速通过 
```
-t
```

  
 参数来自行调控：  
  

```
python3 run_ingram.py -i 你要扫描的文件 -o 输出文件夹 -t 500

```

- 支持中断恢复，不过并不会实时记录当前运行状态，而是间隔一定时间，所以并不能准确恢复到上次的运行状态。如果扫描因为网络或异常而中断，可以通过重复执行上次的扫描命令来继续扫描  
  
- 所有参数：  
  

```
optional arguments:
  -h, --help            show this help message and exit
  -i IN_FILE, --in_file IN_FILE
                        the targets will be scan
  -o OUT_DIR, --out_dir OUT_DIR
                        the dir where results will be saved
  -p PORTS [PORTS ...], --ports PORTS [PORTS ...]
                        the port(s) to detect
  -t TH_NUM, --th_num TH_NUM
                        the processes num
  -T TIMEOUT, --timeout TIMEOUT
                        requests timeout
  -D, --disable_snapshot
                        disable snapshot
  --debug
```

  
  
## 0x04 端口扫描器  
  
  
- 我们可以利用强大的端口扫描器来获取活动主机，进而缩小 Ingram 的扫描范围，提高运行速度，具体做法是将端口扫描器的结果文件整理成 
```
ip:port
```

  
 的格式，并作为 Ingram 的输入  
  
- 这里以 masscan 为例简单演示一下（masscan 的详细用法这里不再赘述），首先用 masscan 扫描 80 或 8000-8008 端口存活的主机：
```
masscan -p80,8000-8008 -iL 目标文件 -oL 结果文件 --rate 8000
```

  
  
- masscan 运行完之后，将结果文件整理一下：
```
grep 'open' 结果文件 | awk '{printf&#34;%s:%s\n&#34;, $4, $3}' > targets.txt
```

  
  
- 之后对这些主机进行扫描：
```
python run_ingram.py -i targets.txt -o out
```

  
  
## 0x05 扫描结果  

```
.
├── not_vulnerable.csv
├── results.csv
├── snapshots
└── log.txt

```

- 
```
results.csv
```

  
 里保存了完整的结果, 格式为: 
```
ip,端口,设备类型,用户名,密码,漏洞条目
```

  
:  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2V4qLgKdCT8wyMrZtPqLexSxibsPcghibDoT2ZbGBJfZyz30XUz6jk5W7OUVPK8zGibDeOw4Sg9eMjmQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
- 
```
not_vulnerable.csv
```

  
 中保存的是没有暴露的设备  
  
- 
```
snapshots
```

  
 中保存了部分设备的快照:  
  
![Ingram](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFETWfUyeen9l1iaxha3HFjPrHotzRK5rGvQ6bic3ZDS57KFkGWhibCveaG99UZsEF1f9ibs4eWnXK3l2bg/640?wx_fmt=png&from=appmsg "")  
  
  
## 0x06 实时预览(由于部分原因已移除)  
  
- 可以直接通过浏览器登录来预览  
  
- 如果想批量查看，我们提供了一个脚本 show/show_rtsp/show_all.py，不过它还有一些问题:  
  
![Ingram](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFETWfUyeen9l1iaxha3HFjPrHR3HVIea6hmQCvCicrnnwZw378HSGibVxo4XtwWiat4mC6vWiaEY4uo1Kzw/640?wx_fmt=png&from=appmsg "")  
  
## 0x07 工具下载  
  
**点****击关注**  
**下方名片****进入公众号**  
  
**回复关键字【250715****】获取**  
**下载链接**  
  
  
  
最后推荐一下内部  
小  
密圈，干货满满，物超所值，**内部圈子每增加100人，价格将上涨20元，越早进越优惠！！！**  
  
****  
