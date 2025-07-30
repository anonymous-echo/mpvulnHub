#  【漏洞预警】泛微 E-Cology 任意文件写入漏洞   
cexlife  飓风网络安全   2024-07-22 22:37  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01TZWypqXHWlXwwRuzCgStJDZflKhvU1IME8rA5yQmwXrCTL4HXxn6s7vx8nPcvstajRzcoCaiatZA/640?wx_fmt=png&from=appmsg "")  
  
**漏洞详情:**近日,泛微网络发布2024年7月安全紧急更新,修复了影响Ecology8.0和Ecology9.0的一处任意文件写入漏洞,建议受影响用户尽快升级至最新版本。**修复方案:**厂商已发布补丁修复漏洞,用户请尽快更新至安全版本:**安全版本:**升级安全补丁包至10.65及以上版本**升级方法:****方法1：**等待安全包自动更新**方法2:**用sysadmin登录oa系统,访问/security/monitor/Monitor.jsp,点击【环境信息】,如果看到【下载并应用更新】,可以直接点击,然后等待几分钟后即可实现在线更新,该更新不需要重启服务。**方法3:**手工停止服务打包。以上漏洞涉及的安全补丁包可在下方页面中点击下载:https://www.weaver.com.cn/cs/security/edm20240719_kdielfrovkewpiiuyrtewtw.html**备注:**1.如果当前系统中安全补丁版本是10.63,则可以直接使用《基于10.63的增量补丁》进行升级；如果不能确认当前版本，则可以使用全量补丁。2.10.62及以上补丁包中新增了一项防护规则，针对长时间不使用的接口（40-45天未被访问）进行收集。收集完成后，重保期间，可以启用拦截模式进行拦截，以减少接口暴露面。具体使用方法，可以升级本补丁包后，用sysadmin登录系统，访问/security/monitor/Monitor.jsp，然后点击【日志拦截详情】->【历史接口防护】，输入sysadmin的密码后进入拦截页面->【开启拦截-点击查看防护描述】，了解该功能后，可决定是否要开启防护。（护网期间，建议启用）。与此同时，请做好资产自查以及预防工作，以免遭受黑客攻击。参考链接:https://www.weaver.com.cn/cs/security/edm20240719_kdielfrovkewpiiuyrtewtw.html  
  
