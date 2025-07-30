#  Nuclei-Scan分布式漏洞扫描平台-可联动 AssetsDetectAPI 资产搜集|漏洞探测   
漏洞挖掘  渗透安全HackTwo   2024-12-25 16:00  
  
0x01 工具介绍   
NucleiPlatform 一个分布式漏洞扫描系统，支持基于 Nuclei 的多节点任务调度和自动化资产扫描。可分组管理资产，集成域名收集、端口扫描、指纹识别等功能，支持 Redis 和 Mongo 数据库，适合大型安全测试场景。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4NMvHns8ycIRBQ8qibSk8kRAL4FVIPyN0BjiadqrS9eatpAKBIJQKM89TdPCicVD53db0ne2YjF8pRA/640?wx_fmt=png&from=appmsg "")  
  
  
**下载地址在末尾**  
  
0x02 功能简介功能逻辑设计NucleiPlatform 扫描模块 —> 逻辑设计简单，随时添加目标资产，针对大量资产进行无脑扫描。—> 支持对资产进行项目分组。—> 至少两至三台机器去做 Nuclei 分布式扫描。—> 支持对节点状态，扫描队列的查询。AssetsDetectAPI 资产收集模块 —> 支持 celery 分布式任务调度。—> 支持对资产进行项目分组，主要功能流程域名收集（域名爆破和网络测绘）、端口扫描、站点查询、指纹识别、服务识别、证书信息、站点截图、目录扫描。Demo0x03更新说明支持 celery 分布式任务调度支持对资产进行项目分组支持漏洞批量探测0x04 使用介绍项目部署修改控制文件描述符限制#!/bin/bash# 系统echo 'fs.file-max = 65535' | sudo tee -a /etc/sysctl.confsudo sysctl -p# 用户 cat /etc/security/limits.confsudo tee -a /etc/security/limits.conf << EOF*               hard    nofile          65535*               soft    nofile          65535root            hard    nofile          65535root            soft    nofile          65535*               soft    nproc           65535*               hard    nproc           65535root            soft    nproc           65535root            hard    nproc           65535*               soft    core            unlimited*               hard    core            unlimitedroot            soft    core            unlimitedroot            hard    core            unlimitedEOF# Systemd  # cd /etc/systemd/# grep -rn -F "DefaultLimitNOFILE"sudo sed -i '/DefaultLimitNOFILE/c DefaultLimitNOFILE=65535' /etc/systemd/*.confsudo systemctl daemon-reexec创建启动 Redis 容器docker pull redis:latestdocker run -d --name redis -p 6379:6379 redis:latest --requirepass "redis_password"创建启动 Mongo 容器docker pull mongodocker run -d \  --name mongodb \  -p 27017:27017 \  -e MONGO_INITDB_ROOT_USERNAME=admin \  -e MONGO_INITDB_ROOT_PASSWORD=mongo_password \  mongo启动 Webscreen python3 app.py运行 Scan Agentscreen python3 nuclei_agent.pyscreen python3 zombie_agent.py  
0x05 内部星球VIP介绍-V1.3（福利）        如果你想学习更多渗透挖洞技术/技巧欢迎加入我们内部星球可获得内部工具字典和享受内部资源，每周一至五周更新1day/0day漏洞(2024POC更新至2500+)，包含网上一些付费工具BurpSuite漏洞检测插件，Fofa高级会员，CTFshow等各种账号会员共享。详情直接点击下方链接进入了解，需要加入的直接点击下方链接了解即可，觉得价格高的师傅可后台回复" 星球 "有优惠券名额有限先到先得！内部包含了网上需付费的0day/1day漏洞库，后续资源会更丰富在加入还是低价！👉点击了解加入-->>内部VIP知识星球福利介绍V1.3版本-星球介绍-1day/0day漏洞库每日更新  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20241226获取下载地址**  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
> **彩蛋🌟内部星球新增1day/0day漏洞及资源:(每日更新中...)**  
  
  
```
博斯外贸管理软件V6.0 loginednew.jsp 存在SQL注入漏洞
网上阅卷系统存在弱口令漏洞
当虹科技-Arcvideo-Live存在文件上传漏洞
卓软计量业务管理平台 image.ashx 任意文件读取漏洞
WordPress File Upload 插件存在任意文件读取漏洞
车联网漏洞分析与挖掘技术
漏洞挖掘自动化赏金技巧手册（全干货）
CobaltStrike4.9.1中文免杀魔改版
新增Xray最新企业版
SRC资产表
```  
  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.3版本-‍星球介绍(新增推送0day)**  
  
**2. 最新Nessus2024.10.7版本主机漏洞扫描下载**  
  
**3. 最新BurpSuite2024.7.3专业版中英文版下载**  
  
[4. 最新xray1.9.11高级版下载Windows/Linux](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483882&idx=1&sn=e1bf597eb73ee7881ae132cc99ac0c8e&chksm=cf16a75af8612e4c73eda9f52218ccfc6de72725eb37aff59e181435de095b71e653b446c521&scene=21#wechat_redirect)  
  
  
[5. 最新HCL AppScan Standard 10.2.128273破解版下载](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483850&idx=1&sn=8fad4ed1e05443dce28f6ee6d89ab920&chksm=cf16a77af8612e6c688c55f7a899fe123b0f71735eb15988321d0bd4d14363690c96537bc1fb&scene=21#wechat_redirect)  
  
  
  
###### 渗透安全HackTwo  
  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜欢的朋友可以点赞转发支持一下  
  
  
