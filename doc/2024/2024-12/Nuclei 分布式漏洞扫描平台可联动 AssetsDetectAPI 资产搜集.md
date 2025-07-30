#  Nuclei 分布式漏洞扫描平台可联动 AssetsDetectAPI 资产搜集   
evilc0deooo  夜组安全   2024-12-16 00:01  
  
免责声明  
  
由于传播、利用本公众号夜组安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号夜组安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
**所有工具安全性自测！！！VX：**  
**baobeiaini_ya**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把  
**夜组安全**  
“**设为星标**  
”，  
否则可能就看不到了啦！  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WrOMH4AFgkSfEFMOvvFuVKmDYdQjwJ9ekMm4jiasmWhBicHJngFY1USGOZfd3Xg4k3iamUOT5DcodvA/640?wx_fmt=png&from=appmsg "")  
  
  
**01**  
  
**工具介绍**  
  
Nuclei 分布式漏洞扫描平台可联动 AssetsDetectAPI 资产搜集。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2XqMeAJKjT2UicPNhia8CCIGewIB9lUP4Xua2XFHF7l5qTHqnYpNLtEyic7TavBU6ulKaklibWJuCKGzA/640?wx_fmt=png&from=appmsg "")  
  
  
**功能设计逻辑**  
  
NucleiPlatform 扫描模块 —> 逻辑设计简单，随时添加目标资产，针对大量资产进行无脑扫描。—> 支持对资产进行项目分组。—> 至少两至三台机器去做 Nuclei 分布式扫描。—> 支持对节点状态，扫描队列的查询。  
  
  
AssetsDetectAPI 资产收集模块 —> 支持 celery 分布式任务调度。—> 支持对资产进行项目分组，主要功能流程域名收集（域名爆破和网络测绘）、端口扫描、站点查询、指纹识别、服务识别、证书信息、站点截图、目录扫描。  
  
**02**  
  
**项目部署**  
  
修改控制文件描述符限制  
  
```
#!/bin/bash

# 系统
echo 'fs.file-max = 65535' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 用户 cat /etc/security/limits.conf
sudo tee -a /etc/security/limits.conf << EOF
*               hard    nofile          65535
*               soft    nofile          65535
root            hard    nofile          65535
root            soft    nofile          65535
*               soft    nproc           65535
*               hard    nproc           65535
root            soft    nproc           65535
root            hard    nproc           65535
*               soft    core            unlimited
*               hard    core            unlimited
root            soft    core            unlimited
root            hard    core            unlimited
EOF

# Systemd  
# cd /etc/systemd/
# grep -rn -F "DefaultLimitNOFILE"
sudo sed -i '/DefaultLimitNOFILE/c DefaultLimitNOFILE=65535' /etc/systemd/*.conf
sudo systemctl daemon-reexec
```  
  
  
创建启动 Redis 容器  
```
docker pull redis:latest
docker run -d --name redis -p 6379:6379 redis:latest --requirepass "redis_password"
```  
  
  
创建启动 Mongo 容器  
```
docker pull mongo
docker run -d \
  --name mongodb \
  -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=mongo_password \
  mongo
```  
  
  
启动 Web  
```
screen python3 app.py
```  
  
运行 Scan Agent  
```
screen python3 nuclei_agent.pyscreen python3 zombie_agent.py
```  
  
  
**03**  
  
**工具下载**  
  
**点击关注下方名片****进入公众号**  
  
**回复关键字【241216****】获取**  
**下载链接**  
  
  
**04**  
  
**往期精彩**  
  
[ 一款后渗透免杀工具，助力每一位像我这样的脚本小子快速实现免杀，支持bypass 360 火绒 Windows Defender ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247492959&idx=1&sn=bfaedc1fde06af5264a7be8d453a2158&chksm=c36ba1a7f41c28b1bbed8f255d13c0bca37977b60f2ab6b49db3b3862f2640d761445e6f53f4&scene=21#wechat_redirect)  

						  
  
  
[ XXE 漏洞检测工具 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247492955&idx=1&sn=394994faf4a919f7d1520e437498c6ea&chksm=c36ba1a3f41c28b56e5aae8d5cf82d8896736b79c17d565bbbbc543206b9865849110cdb73a7&scene=21#wechat_redirect)  

						  
  
  
[ 双12渗透攻防武器库 | 12个名额 秒了 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247492954&idx=1&sn=4d558e1c4f0a7beef64bd62bba63a1d3&chksm=c36ba1a2f41c28b400efe4322f95523c04301f69f50f96911b1822ec6b3fff5b1d8eb1589830&scene=21#wechat_redirect)  

						  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAmMqjhMehrtxRQaYnbrvafmXHe0AwWLr2mdZxcg9wia7gVTfBbpfT6kR2xkjzsZ6bTTu5YCbytuoshPcddfsNg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&random=0.8399406679299557 "")  
  
