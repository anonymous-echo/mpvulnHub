#  Centos添加漏洞扫描   
原创 网络安全菜鸟  安全孺子牛   2025-05-17 01:51  
  
点击蓝字  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2gG5sygYR7bDd0JXWSSDDkicic7pAUE2boBJuPPCeYI3oOn66YHgfKqHg8IT81VoeMGIB9sGmHZrt8wTRSWh3j1Q/640?wx_fmt=png&from=appmsg "")  
  
  
关注我们  
  
  
1.查询当前系统版本  
```
sqlite3 /var/ossec/queue/db/global.db "SELECT OS_NAME, OS_MAJOR FROM AGENT WHERE ID = 004;"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2gG5sygYR7bDd0JXWSSDDkicic7pAUE2boDQtp5khw1zn92mOkbmtbUKZm6qHRFLIabMEyv9iaexY64dVDicZdfD3g/640?wx_fmt=png&from=appmsg "")  
  
2.修改代理配置文件  
```
  <vulnerability-detector>
     <enabled>yes</enabled>
     <interval>5m</interval>
     <min_full_scan_interval>6h</min_full_scan_interval>
     <run_on_start>yes</run_on_start>
   
   <provider name="redhat">
      <enabled>yes</enabled>
      <os allow="CentOS Linux-7">7</os>
      <update_interval>1h</update_interval>
   </provider>
   
   <provider name="nvd">
      <enabled>yes</enabled>
      <update_interval>1h</update_interval>
   </provider>
  </vulnerability-detector>
```  
  
3.重启服务  
```
systemctl restart wazuh-agent
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2gG5sygYR7bDd0JXWSSDDkicic7pAUE2bo8fSibbXtaiavM2qhMSzG2rmC5Dtnn3oHPPCbVo4xEF4n7NcDKLiaelYlg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2gG5sygYR7bDd0JXWSSDDkicic7pAUE2bo4uTVKpLjFyKx5m946UDZBWhdt5Y7TYLIVe52gY9veJKQFKRhwzjCYA/640?wx_fmt=png&from=appmsg "undefined")  
  
扫码关注  
  
关注小助理微信，入群交流成长  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/2gG5sygYR7bDd0JXWSSDDkicic7pAUE2bo7jrGFILiaqcVwvF5OWFOfxalFibh2Qy2iaw0CauibG3HQTBVgyqHrJhQdw/640?wx_fmt=gif&from=appmsg "")  
  
  
  
  
