#  【漏洞预警】Argo Events权限管理不当漏洞   
cexlife  飓风网络安全   2025-04-16 10:22  
  
漏洞描述:  
  
Kubernetes的事件驱动工作流自动化框架Argo Events中存在一个权限管理不当漏洞,该漏洞源于Argo Events对EventSource和Sensor自定义资源的处理方式不正确,攻击者可通过创建或修改某些资源获得对主机系统和集群的特权访问,并通过定制spec.template和spec.template.container来利用,该漏洞可能会破坏租户隔离、让非管理员用户获得主机和集群访问,Argo团队已发布补丁版本修复此漏洞,建议受影响用户及时升级到安全版本。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00S9IdBjBTlDxWzpqzbUqBTZjicgpIWLGT241r3DfVktxMNfj4xyniaeaiaKjNCwriaoSM9PRFP2KNbJQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00S9IdBjBTlDxWzpqzbUqBTBEfKMwePgEI3xQvjSDUaC9icav2YtM4iaXkk7DdFvxJaCzslMaXOewdg/640?wx_fmt=png&from=appmsg "")  
  
修复建议:  
  
正式防护方案:  
  
针对此漏洞,官方已经发布了漏洞修复版本,请立即更新到安全版本:  
  
Argo Events >= v1.9.6  
  
下载链接:  
  
https://github.com/argoproj/argo-events/releases  
  
安装前,请确保备份所有关键数据,并按照官方指南进行操作。安装后,进行全面测试以验证漏洞已被彻底修复,并确保系统其他功能正常运行。  
  
  
  
