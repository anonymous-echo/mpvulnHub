> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NzUyNTI1Nw==&mid=2247497402&idx=1&sn=05b670092bd72cf9491c07b871a8aa6f

#  Wavely | 高效便捷的图形化Nuclei GUI POC管理工具  
perlh  无影安全实验室   2025-06-15 02:00  
  
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
  
Wavely 是一款专为 Nuclei POC 管理设计的图形化工具，可以方便快捷地对  
Nuclei POC进行增删改查和精准漏洞扫描  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFER1ldWvdqudtuAyFAibScqGgW831yD5YAVuA85SJSK9qc2KjhRmiatWMaLCwd1IavhfhXuVN1IwjpBw/640?wx_fmt=png&from=appmsg "")  
## 0x02 主要功能  
  

```
实现对nuclei模板的添加、删除、查询以及修改操作。
兼容MacOS、Windows和Linux操作系统。
实现选择多个POC、多个扫描任务以及多目标的并行扫描功能。
支持自定义DNSLOG服务器，自定义扫描速率，同时支持http代理（http、https、socks5）。
支持查看 POC 匹配到的请求包与响应包。
支持 POC 编辑器的主题切换。
支持nuclei模板一键导入(选择POC文件夹即可导入，可实现nuclei模版去重导入，基于template id)。
支持国际化，已广泛覆盖大部分区域。
支持手动停止扫描任务，便于灵活控制扫描进程。
支持配置持久化，确保用户配置信息持久化保存。
支持 API 扫描，包括带目录扫描（如：http://target.com/api）。
支持图形化生成简单poc，降低 poc 生成门槛。
```

  
## 0x03 工具使用  
  
3.1 注册  
  
依次点击设置 -> 注册，在注册页面按提示获取设备 ID，完成证书申请后上传证书，即可注册成功。  
  
3.2 导入方法  
  
在 App 中导入 POC（具备去重功能）  
- 点击
```
从文件夹中导入POC
```

  
按钮，选择存放
```
nuclei poc
```

  
文件的目录。  
  
- 系统将自动识别并导入所选目录内的所有 POC 文件，导入过程实时显示进度与文件数量，若存在基于 template id 的重复 POC，系统将自动去重，完成后弹窗告知导入结果。  
  
![alt text](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFER1ldWvdqudtuAyFAibScqGg0KGAbnbRHTLs2oobHWsur7ylx3e1o0xSzVaNAVE5ia8IWFTDbtuLBOw/640?wx_fmt=png&from=appmsg "")  
  
3.3 创建扫描任务流程  
  
任务发起操作  
- 选择指定POC后，点击顶部扫描按钮即可启动扫描。  
  
- 若未选择 POC，系统将对搜索结果执行全扫描；  
  
- 若已选择 POC，则仅针对所选 POC 进行扫描。  
  
- 此外，点击扫描按钮前，可在任务设置区域自定义扫描速率等参数。  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFER1ldWvdqudtuAyFAibScqGgPG8Bs76t0XmJ7bgib1tqibXGJSphbibZ1s0Gx6oPePTARPN6917C7TamQ/640?wx_fmt=png&from=appmsg "")  
  
扫描结果查看  
- 扫描完成后，点击
```
POC ID
```

  
可直接跳转到` POC 编辑界面，方便进一步分析与调整。  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFER1ldWvdqudtuAyFAibScqGgeL6cNhxRNia4K5icp1Ad4rhGMic1g0dMneu584leDk8VKFu0udKsFUZwg/640?wx_fmt=png&from=appmsg "")  
  
2.4 Nuclei 模版编辑 / 添加操作  
  
编辑poc  
  
##### 查看请求 / 响应包（需检测匹配成功）  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFER1ldWvdqudtuAyFAibScqGgyIVwRJSnfMXYiaGP7M7RPiaPkt9xP6cJ0p1ZmsT431h3fAxLIjee5kibg/640?wx_fmt=png&from=appmsg "")  
##### 图形化生成 POC  
- **表单形式请求包**  
：通过直观的表单填写方式。  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFER1ldWvdqudtuAyFAibScqGg3VH9zib3zicWj8jXgsNnUbykQH65VV8e0Rpc3b8iaLNstyOFQyPgtPwgA/640?wx_fmt=png&from=appmsg "")  
- **raw 格式请求包**  
：支持以 raw 格式编辑和生成请求包。  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFER1ldWvdqudtuAyFAibScqGg97nc7bzMDzJMmuyBU274QGQWg79m3kF0EjpTj7ib8tPg7VHvsLWfMrw/640?wx_fmt=png&from=appmsg "")  
  
- **测试功能**  
：生成 POC 后，可点击测试按钮快速验证其有效性。  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0fllln5icf8pDd2horQvfT3YzKlkvwy8CU4aprY4Q4nHJlMfZUaDrpM9FO0Z4yFXbbbiaYicp6rX8NIic6ZHQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
## 0x04 工具下载  
  
**点****击关注**  
**下方名片****进入公众号**  
  
**回复关键字【250615****】获取**  
**下载链接**  
  
  
  
最后推荐一下内部  
小  
密圈，干货满满，物超所值，**内部圈子每增加100人，价格将上涨20元，越早进越优惠！！！**  
  
****  
