#  利用SSRF漏洞读取云服务元数据   
原创 安全工程师实录  安全工程师实录   2024-07-27 09:41  
  
关于SSRF漏洞原理就不过多赘述了，我们只需要理解攻击者可以将漏洞点当做一台跳板机来读取内网里的数据。如果目标资产部署在云上的话，其实我们可以有新的玩法----读取元数据。本次漏洞利用思路以阿里云为例（其他云平台之后有空再写）。  
  
在阿里云的语境中，“元数据地址”通常指的是 ECS (Elastic Compute Service) 实例的元数据服务（Metadata 
Service）所提供的访问地址。这是一个特殊的服务，允许ECS实例安全地查询与实例本身相关的信息，而无需提供额外的身份验证凭证。阿里云ECS实例的元数据服务为每个实例提供了有关该实例及其配置的信息。这些信息包括但不限于实例ID、私有IP地址、公有IP地址、安全组、实例类型等。元数据服务通常通过一个特定的HTTP地址提供这些信息，这个特定的HTTP地址为：http://100.100.100.200/latest/meta-data/   
话不多说，上实战案例：1、确认存在SSRF漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iayIJuw3yD7pxETZkuMvJmyBDNRViazH0bzBgYm7S1WXTMEDvF1Sc6iaXwZzRic1MDUVkOOVocmG1a8CkPObplbkaA/640?wx_fmt=png&from=appmsg "")  
  
2、直接读取阿里云元数据地址查看响应信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iayIJuw3yD7pxETZkuMvJmyBDNRViazH0bY5Hb19TvvC87sR1Eqf6eJ5BbWuxG9MAZGOI5pd3643iaibGtVaBewv3w/640?wx_fmt=png&from=appmsg "")  
  
从响应信息中可以看到在上文中提到的实例ID、私有IP地址、公有IP地址等，获取的方法只需要拼接在元数据地址之后访问就可以，我们主要关注两个点：private-ipv4、ram；读取ipv4地址为之后的云上内网横向渗透做准备  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iayIJuw3yD7pxETZkuMvJmyBDNRViazH0bDNHn7sjDhGas1mFkmU7e1iasBibN1MM5vjRdIpiaTbxsK8iaPIOKVia2jaw/640?wx_fmt=png&from=appmsg "")  
  
而ram则可以帮助我们获取到主机开放的临时凭证，前提是存在ram，  
我们先访问  
http://100.100.100.200/latest/meta-data/ram/security-credentials/来获取角色名称，获取之后拼接在后面：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iayIJuw3yD7pxETZkuMvJmyBDNRViazH0bhkBIgy5na3V8ic6RDgbFwHjm54XmvnWibU7FVUryy8wEQhCEW5urSc4w/640?wx_fmt=png&from=appmsg "")  
  
如果RAM角色没有被授权，哪怕拿到了临时凭证也没有任何作用反过来，只要RAM角色的权限足够大，即使他只是个STS凭证，也能够造成足够威力的破坏。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iayIJuw3yD7pxETZkuMvJmyBDNRViazH0bOdO9NVcpmDO4Xia6y8qMEsL1NyGOtUMwO7uuUFYdKOG3aIm4M8x0BTA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iayIJuw3yD7pxETZkuMvJmyBDNRViazH0bU0ib4WTDf6iaeYpLzo9vQaVwGAAlFRSes4CKkWFhibOGUOpKl5g30G5Mg/640?wx_fmt=png&from=appmsg "")  
  
  
