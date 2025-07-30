#  FortiWLM 曝关键漏洞，攻击者可获得管理员权限   
天唯科技  天唯信息安全   2024-12-23 02:08  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNbU68NXCNH8sw9R1wBYiaT6icvH7moZbnkDB7UPWcP57YnEr5sDNDh6pssbCmuxvzQERZeMhN6Dknw/640?wx_fmt=png "")  
  
****  
Fortinet 披露了 Fortinet Wireless Manager （FortiWLM） 中的一个严重漏洞，该漏洞允许远程攻击者通过特制的 Web 请求执行未经授权的代码或命令来接管设备。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR389GQon9kaib6xcIzm7t0JKib8U98Q3eop7c9gpx74rlU2PRa4FIjLicqbmkeh1HKO0JGTudpsHxyy3g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
FortiWLM 是一种集中式管理工具，用于监控、管理和优化无线网络，被政府机构、医疗保健组织、教育机构和大型企业使用。  
  
  
该漏洞被跟踪为 CVE-2023-34990，是一个相对路径遍历缺陷，评分高达 9.6。Horizon3 研究员 Zach Hanley 于 2023 年 5 月发现并披露了该漏洞。但在数月后仍未修复。于是 Hanley 决定于 2024 年 3 月 14 日在一篇关于他发现的其他 Fortinet 漏洞的技术文章中披露相关信息和 POC。尽管研究人员公开警告，但缺少 CVE编号以及安全公告意味着大多数用户没有充分意识到风险。  
  
  
该漏洞会影响 FortiWLM 8.6.0 到 8.6.5 和 8.5.0 到 8.5.4 版本 。当 'op_type' 设置为 'upgradelogs' 时，通过在 'imagename' 参数中使用目录遍历技术，攻击者可以从系统中读取敏感的日志文件。这些日志通常包含管理员会话 ID，可用于劫持管理员会话并获得特权访问权限，从而允许威胁行为者接管设备。  
  
  
根据12月18日发布的安全公告，漏洞已在 2023 年 9 月底发布的 FortiWLM 版本 8.6.6 和 8.5.5 中修复。但Fortinet直到最近才正式发布该漏洞的安全通告。  
  
  
换言之，该漏洞作为零日漏洞持续了大约四个月的时间，鉴于 FortiWLM 部署在关键环境中，可能成为攻击者的目标，通过远程入侵导致整个网络中断和敏感数据泄露。因此，强烈建议 FortiWLM 管理员在可用更新可用时应用所有可用更新。  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNbU68NXCNH8sw9R1wBYiaT6icvH7moZbnkDB7UPWcP57YnEr5sDNDh6pssbCmuxvzQERZeMhN6Dknw/640?wx_fmt=png "")  
  
  
天唯科技专注于大型组织信息安全领域及IT基础设施解决方案的规划、建设与持续运维服务。帮助客户提高IT基础设施及信息安全管控水平和安全运营能力，使客户在激烈的市场环境中保持竞争力。  
  
我们一直秉承“精兵强将，专业专注”的发展理念。  
先后在江门、深圳成立分公司，在武汉、长沙成立办事处以及成立广州的服务支撑中心。公司已获得高新技术企业认证、已通过IS09001、IS027001、CCRC信息安全集成服务、CCRC信息安全风险评估、CCRC信息安全应急处理等认证。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNRytkPMNOKYRW452LxR5Ez5Wee8X6KlbhoUMt9XyhhbRxHafKcCLWJic3ib0umJiaH3fl6sOx8KMBiaQ/640?wx_fmt=png "盾牌单图.png")  
  
**END**  
  
  
  
**往期推荐:**  
  
  
  
  
  
[2024年11月国内数据泄露及勒索事件汇总](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247503191&idx=1&sn=b526ad6c6672c2aa49f13bedf127126c&scene=21#wechat_redirect)  
  
  
  
[从台湾到韩国：TIDRONE威胁者以ERP软件为目标](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247503191&idx=2&sn=17effaf41ece1d595a2e412f02274226&scene=21#wechat_redirect)  
  
  
  
[国家网络安全通报中心：重点防范境外恶意网址和恶意IP](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247503165&idx=1&sn=9811a34eece0757b910dc31e2f731c21&scene=21#wechat_redirect)  
  
  
  
**征文通道:**  
  
  
  
  
  
[发钱！征文！让真诚的分享更有价值](http://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247490310&idx=1&sn=db4b524d1d9f5aabb4af2184dd831de3&chksm=c25ed7a6f5295eb053d3f90e2dc8cd22a2d8ce1a62561ffa62966340ee563734cd4fd32045f3&scene=21#wechat_redirect)  
  
  
