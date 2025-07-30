#  Nuclei分布式漏洞扫描平台 -- NucleiPlatform   
evilc0deooo  Web安全工具库   2024-12-24 16:00  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
NucleiPlatform 扫描模块 —> 逻辑设计简单，随时添加目标资产，针对大量资产进行无脑扫描。—> 支持对资产进行项目分组。—> 至少两至三台机器去做 Nuclei 分布式扫描。—> 支持对节点状态，扫描队列的查询。  
  
AssetsDetectAPI 资产收集模块 —> 支持 celery 分布式任务调度。—> 支持对资产进行项目分组，主要功能流程域名收集（域名爆破和网络测绘）、端口扫描、站点查询、指纹识别、服务识别、证书信息、站点截图、目录扫描。  
0x02 安装与使用  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibv76gVuhTtuATPVib98K8MTk60khNl4pCn23BdAUbVYcrm46xhibPSclU1wJg7nvO8opLLdI5GwxaoA/640?wx_fmt=png&from=appmsg "")  
  
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
screen python3 nuclei_agent.py
screen python3 zombie_agent.py
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibv76gVuhTtuATPVib98K8MTkdsF1uvdn7BNiaxnEBzCSr3QmiaukgRGibeSuyI8Vzb7rkSE66Kfz6iaCsw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 项目链接下载**  
  
1、点击阅读原文，从原项目地址下载。  
  
2、网盘下载链接  
：https://pan.quark.cn/s/fd9a33722ccc  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibv76gVuhTtuATPVib98K8MTkZhia2kU7WgIxqGhdNddUPCc1zSIAsTWWIFmbjhz9kPXibLEicWTiaMy3vg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**·****今 日 推 荐**  
**·**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibv76gVuhTtuATPVib98K8MTkVWWVMq63VSibDrEVjKDAS1mlTyGt1wTdI0Byic5yj6XubcrM6gyE3QEg/640?wx_fmt=png&from=appmsg "")  
  
  
