#  【漏洞通告】Nacos 集群Raft反序列化漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-06-06 20:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yLJtEP6HkELh93nzGibKQw8w6BHNicFjfKia3Z34nGgibBbae7GvbudRarlNWkfW5NZ5roxibmfzgcWFw/640?wx_fmt=gif "")  
  
**漏洞名称：**  
  
Nacos 集群Raft反序列化漏洞  
  
**组件名称：**  
  
Alibaba Nacos  
  
**影响范围：**  
  
1.4.0 ≤ Alibaba Nacos < 1.4.6  
  
2.0.0 ≤ Alibaba Nacos < 2.2.3  
  
**漏洞类型：**  
  
反序列化漏洞  
  
**利用条件：**  
  
1、用户认证：未知  
  
2、前置条件：默认配置  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：未知。  
  
<综合评定威胁等级>：高危，能造成代码执行。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yLJtEP6HkELh93nzGibKQw8fdiaT8uDnKkUTcJHAyW284VebJ5TEoT7hGhjrQaNFm3ric6zOynibiaQpQ/640?wx_fmt=gif "")  
  
**组件介绍**  
  
Alibaba Nacos是一个更易于构建云原生应用的动态服务发现、配置管理和服务管理平台。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yLJtEP6HkELh93nzGibKQw8fdiaT8uDnKkUTcJHAyW284VebJ5TEoT7hGhjrQaNFm3ric6zOynibiaQpQ/640?wx_fmt=gif "")  
  
**漏洞简介**  
  
2023年6月6日，深信服安全团队监测到一则Alibaba Nacos组件存在反序列化漏洞的信息，漏洞威胁等级：高危。  
  
**攻击者可利用该漏洞在未授权的情况下，构造恶意Jraft请求，利用hessian进行反序列化攻击，最终造成服务器敏感性信息泄露或代码执行。**  
  
  
**影响范围**  
  
目前受影响的版本：  
  
1.4.0 ≤ Alibaba Nacos < 1.4.6  
  
2.0.0 ≤ Alibaba Nacos < 2.2.3  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yLJtEP6HkELh93nzGibKQw8fdiaT8uDnKkUTcJHAyW284VebJ5TEoT7hGhjrQaNFm3ric6zOynibiaQpQ/640?wx_fmt=gif "")  
  
**官方修复建议**  
  
  
当前官方已发布最新版本，建议受影响的用户及时更新升级到最新版本。链接如下：  
  
https://github.com/alibaba/nacos/releases  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yLJtEP6HkELh93nzGibKQw8fdiaT8uDnKkUTcJHAyW284VebJ5TEoT7hGhjrQaNFm3ric6zOynibiaQpQ/640?wx_fmt=gif "")  
  
**深信服解决方案**  
  
  
**1.风险资产发现**  
  
支持对Apache OFBiz的主动检测，可**批量检出**业务场景中该事件的**受影响资产**情况，相关产品如下：  
  
**【深信服主机安全检测响应平台CWPP】**已发布资产检测方案。  
  
**【深信服云镜YJ】**已发布资产检测方案。  
  
  
**参考链接**  
  
https://github.com/alibaba/nacos/releases/tag/2.2.3  
  
  
**时间轴**  
  
  
  
**2023/6/6**  
  
深信服监测到Nacos集群Raft反序列化漏洞的漏洞信息。  
  
  
**2023/6/6**  
  
深信服千里目安全技术中心发布漏洞通告。  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yLJtEP6HkELh93nzGibKQw8ZMm6XytROpNicCxgPq1hdk59R9PBM42k7PK6pXPGdD7biaoOx7ibva1Lg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5yLJtEP6HkELh93nzGibKQw8nfiaicarHAN0MPAD458d47VOQE3OhiaFfuY3sAIqgvSSyBgqf9MomDUPg/640?wx_fmt=jpeg "")  
  
  
  
