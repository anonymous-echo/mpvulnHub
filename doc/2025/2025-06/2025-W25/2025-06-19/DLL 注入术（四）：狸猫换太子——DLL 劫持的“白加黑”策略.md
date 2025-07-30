> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyNTUyNTA5OQ==&mid=2247485562&idx=1&sn=229b7474e7e7ef67de827e2020339a48

#  DLL 注入术（四）：狸猫换太子——DLL 劫持的“白加黑”策略  
原创 仇辉攻防  仇辉攻防   2025-06-19 14:01  
  
📌   
**免责声明**  
：本系列文章仅供网络安全研究人员在合法授权下学习与研究使用，严禁用于任何非法目的。违者后果自负。  
  
同上篇一样，首先找一个白程序作为目标，这里拿Edge浏览器来举例  
  
一、确定劫持对象  
  
使用ProcessMonitor工具或者火绒，查看exe加载的DLL   
  
1、先用过滤器筛选  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFIydvP1TDf9ZbSD3A3ZFia3Z6Ow2SKyZ0y7nzZ5R2GfEicrwGj63x3Bbg6xceqmxhef5PWGx55qa3Ow/640?wx_fmt=png&from=appmsg "")  
  
2、选中进程，右击或者Ctrl+P打开属性页，如图查看加载的DLL  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFIydvP1TDf9ZbSD3A3ZFia3ZHDyJsYF3r6K3iazRBX0kaeHLsdIMySl8ArMSLkicLrfwvmdDeEmxKXCg/640?wx_fmt=png&from=appmsg "")  
  
3、这里就以ffmpeg.dll为例，打开路径，找到该文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFIydvP1TDf9ZbSD3A3ZFia3ZvOdBibTFyZ3ZyF0kZv7l1rfoZ1zz9BQaqiclDeHKgGdBaZMQrheJw3Rw/640?wx_fmt=png&from=appmsg "")  
  
二、获取必要信息  
  
使用vs自带dumpbin工具  
  
