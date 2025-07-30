#  【必刷靶场】JavaSecLab-Java漏洞平台   
ChinaRan404  知攻善防实验室   2024-11-09 15:18  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vqA2icF6gYLSeESv5UzLfnHty3DbxYcLEgDfjRDkHHRiaJuqyDXj6sqqFOHMvBj7WClWt9tV36EPyjQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vqA2icF6gYLSeESv5UzLfnHtZhoyphCKwN1ibrKibwID3F4iaibvUo6no2vqrZCUUbiboDG4ialJWRlibWRQw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vqA2icF6gYLSeESv5UzLfnHtUpXM7SuWIK2X0TibVEiadpAAsw9CkRhQwZUQDUJxRrXVOfVXGqEjdrTw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vqA2icF6gYLSeESv5UzLfnHtYxT68WTwhnuicGVGQVt3ItnaGVTROIgJWTf85yHsZ4XCSyVXKz2zhfA/640?wx_fmt=png&from=appmsg "")  
  
docker搭建：  
  
```
git clone https://github.com/whgojp/JavaSecLab.git3
mvn clean package -DskipTests
docker-compose -p javaseclab up -d
```  
  
  
如因网络问题，docker用不了，可以使用我做好的Vmware虚拟机镜像，即开即用  
  
VM镜像  
  
打开后直接终端执行  
  
sudo docker start c27a2ccdc2c7  
  
sudo docker start 31ec50ea1ef8  
  
即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vqA2icF6gYLSeESv5UzLfnHtecIKCutKvx0MsicicJZic22c76gThHJ74j0icS1sYsFvX9Mcuj1XLtqofA/640?wx_fmt=png&from=appmsg "")  
  
获取方式，后台回复“  
JavaSecLab”  
  
  
