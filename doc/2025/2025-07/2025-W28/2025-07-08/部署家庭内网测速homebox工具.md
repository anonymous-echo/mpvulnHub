> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyMDY4MTc2Ng==&mid=2247484320&idx=1&sn=9e6a39504961b296e09691bb19778060

#  部署家庭内网测速homebox工具  
 爱唠叨的Nil   2025-07-08 00:05  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Lm4IarPJiaOMZkeX3Z0HHDffkyB9gB8qic5HMjVkjTQ5biaTmiazD10tRrcSicmhMDExgHUue3DvPROFgLLxLT9nic9w/640?wx_fmt=png "")  
# 1.背景  
  
上次教程已经与大家分享了网页版的speedtest工具的部署，大多数据朋友有在NAS上使用homebox的内网测速工具，因此本次分享在普通Linux服务器上安装部署homebox的教程。  
## 2.搭建  
  
使用docker-compose来搭建，首先新建一个目录  

```
mkdir -p /opt/docker/homebox

```

  
创建一个docker-compose.yml文件，将以下内容放入文件中。  

```
version: '3'
services:
  homebox:
    image: xgheaven/homebox:latest
    container_name: homebox
    restart: unless-stopped
    volumes:
      - ./config:/config  # 挂载配置目录
      - /etc/localtime:/etc/localtime:ro  # 同步宿主机时间
    ports:
      - &#34;3300:3300&#34;  # 映射端口，根据需要修改
    environment:
      - TZ=Asia/Shanghai

```

  
如图存放所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Lm4IarPJiaOPtHqHOZG9jlqtW05Y99YuUesQoxN1B98L7HJwvG4se942v50iaoGmsQcziawfQ1PEsE9xm5NuDJ59A/640?wx_fmt=png&from=appmsg "")  
  
大家可以根据自己的需求，放在合适的目录下使用。  
  
放行端口3300 tcp。  

```
firewall-cmd --add-port=3300/tcp --permanent
firewall-cmd --reload

```

## 3.访问  
  
访问http://ip:3300，ip修改为部署服务的ip地址，然后在浏览器里访问网页。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Lm4IarPJiaOPtHqHOZG9jlqtW05Y99YuUOiaVXrRrl6ibUpghZz4ibb5WZxhyE8fmfTD6CzxD9Tx9qxA4JfE923cEw/640?wx_fmt=png&from=appmsg "")  
  
点击Start，开始网络测速。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Lm4IarPJiaOPtHqHOZG9jlqtW05Y99YuUfrDia4m77MqlVS7fa2HqTZTrBy2JoJQzM3uZ2eGFxteMaDYHicwrcAuQ/640?wx_fmt=png&from=appmsg "")  
  
从网页上可以看到明确的上传和下载速度，也可以根据需要选择Mb和MB单位大小。  
  
在高级设置中，还可以设置包大小。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Lm4IarPJiaOPtHqHOZG9jlqtW05Y99YuUsMfWjWYJZkXNBPpVL7ISvTMN9qk9DRVp8jFibicaym5oFM3llWj6e9aw/640?wx_fmt=png&from=appmsg "")  
  
测试速度直观，还挺好用！  
  
  
  
