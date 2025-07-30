#  0day预警 | 已复现Github公开nacos rce的exp（小白友好）   
原创 永恒之锋实验室  Eonian Sharp   2024-07-15 21:01  
  
### 声明  
  
该公众号分享的安全工具和项目均来源于网络，仅供学术交流，请勿直接用于任何商业场合和非法用途。如用于其它用途，由使用者承担全部法律及连带责任，与工具作者和本公众号无关。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hvMQKkLOqzPckGibrN9YiaPeJe7tyD8jiaLvzgtk3ictnTr0QGhLUgMic9HldfsPO0CnjAwhziadq4V2YiaMSzkQAUzjQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
# 介绍  
  
Nacos是一个更易于构建云原生应用的动态服务发现、配置管理和服务管理平台，支持多种开箱即用的以服务为中心的架构特性，无缝支持Kubernetes和Spring Cloud，具备企业级SLA的开源产品  
  
永恒之锋第一时间监测到Github公开了Nacos 0day的情报（目前不知何原因公开），并进行了成功的复现。我注意到很多人卡在搭建环境中，故写了一篇相对详细的教程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hvMQKkLOqzM0QEjxZC2ib3Jx8Z8TbzCNAGn6DJwuBnKy4tFSaicAdznatYibUgtdibbAyN0TRB22J3JzQvOvYPqa4Q/640?wx_fmt=png&from=appmsg "")  
  
影响版本：nacos2.3.2、nacos2.4.0  
# POC下载  
  
  
https://github.com/enomothem/nacos-poc  
  
或关注公众号发送"**715**"获取EXP文件  
# 复现过程  
### 使用Docker搭建Nacos环境  
  
由于国内禁用了Docker源，导致很多人在这一环节出现问题，这里给出成功复现的Docker源  
```
https://hub.uuuadc.top", "https://docker.anyhub.us.kg", "https://dockerhub.jobcher.com", "https://dockerhub.icu", "https://docker.ckyl.me", "https://docker.awsl9527.cn"

```  
  
放入文件（如果没有则创建）vim /etc/docker/daemon.json  
```
{
        "registry-mirrors": [   
                "https://hub.uuuadc.top", "https://docker.anyhub.us.kg", "https://dockerhub.jobcher.com", "https://dockerhub.icu", "https://docker.ckyl.me", "https://docker.awsl9527.cn"
        ]
}

```  
  
重启一下Docker  
```
systemctl restart docker.server
```  
  
克隆Nacos环境并进入到项目目录中启动，Docker会自动拉取环境。  
```
git clone https://github.com/nacos-group/nacos-docker.git
cd nacos-docker
docker-compose -f example/standalone-derby.yaml up
```  
  
玩Docker一定要有耐心，我观察到很多人起开后就立马访问，发现自己环境没启开，就着急以为自己的步骤错了，如果在虚机操作需要一定的缓冲时间，多等待并刷新几下。如果还不行可以重启docker再试。  
### 攻击侧  
  
这里仍然使用同一台机器作为攻击，克隆0day脚本  
```
git clone https://github.com/ayoundzw/nacos-poc
cd nacos-poc
```  
  
安装需要的库  
```
python -m pip install -r requirements.txt  -i https://mirrors.tencent.com/help/pypi.html
```  
  
使用python指定pip安装的库是好习惯，避免pip版本混乱。给大家指定了一个腾讯云的源，避免python没有配置源的同学下载慢。  
  
然后起一个POC里面带的服务  
  
python service.py   
  
另外开一个窗口进行攻击（python里的默认命令和ip地址可以微调一下，也可以执行的时候根据情况填写）  
```
python exploit.py 
```  
  
成功执行命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hvMQKkLOqzM0QEjxZC2ib3Jx8Z8TbzCNAbCHrsDOEFpWRZWz9Kbj91Ed2XqDia7yjq4icrW4Gvd2kzcnvJPqt2hUg/640?wx_fmt=png&from=appmsg "")  
  
查看访问记录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hvMQKkLOqzM0QEjxZC2ib3Jx8Z8TbzCNAOyRFh1A5AJeo2mYrItLuckQ9B7X2dXx4XnILPcwH8aNPGPibeib81z1A/640?wx_fmt=png&from=appmsg "")  
### 防范  
1. 1. 更新最新版本（虽然目前没有安全版本，主要是为了修复一个历史漏洞）  
  
1. 2. 缓解措施：不要公开在外网。  
  
1. 3. 等待官方最新安全版本  
  
如果还是有问题，可加入永恒之锋团队交流群询问大佬们  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hvMQKkLOqzM0QEjxZC2ib3Jx8Z8TbzCNAaMNUe4A2qGrZKNSsicc6ARNP1yDfFjkoFiadJb7Uzd8TaWccxOBmI0nA/640?wx_fmt=png&from=appmsg "")  
  
  
  
