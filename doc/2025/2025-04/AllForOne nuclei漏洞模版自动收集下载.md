#  AllForOne nuclei漏洞模版自动收集下载   
原创 qife  网络安全技术点滴分享   2025-04-05 09:28  
  
AllForOne通过读取配置中收集到的nuclei漏洞模版后，git clone到本地保存。这样当收集到新增的nuclei模版资源，只需将链接添加到配置文件后，再次运行程序，即可自动收集到本地。  
  
一、下载、安装、运行AllForOne  
```
git clone https://github.com/AggressiveUser/AllForOne.git
cd AllForOne #进入AllForOne目录
pip install -r requirements.txt #安装依赖模块
python AllForOne.py #更新nuclei模板库
```  
  
项目中已经配置了一些收集到的nuclei模版项目，如下所示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/meR9vVNE209M56qkdmoOgzm6XibYxxUxHzUFlQTCchBgAFicuQFWKVuP154NRFD73nFYyBibHq7zn94pM2QJZAlicw/640?wx_fmt=png&from=appmsg "")  
  
运行的结果如下所示，开始下载templates到本地，我们可以将自己收集到的新的templates项目加到配置文件中即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/meR9vVNE209M56qkdmoOgzm6XibYxxUxH9uuvM2eia85I7jW1DcTh84R8En3DSVAt9rYevPedAT5DXezq9WKEzYA/640?wx_fmt=png&from=appmsg "")  
  
类似的更新自动templates的项目还有下面所示：  
  
https://github.com/lianqingsec/NucleiPocGather.git  
  
https://github.com/Gorebox-Networks/GetNucleiTemplates.git  
  
