#  Sirius 一款开源通用漏洞扫描器（Docker版）|漏洞探测   
makoto56  渗透安全HackTwo   2025-05-29 16:01  
  
0x01 工具介绍  
  
  
天狼星（Sirius）是一款高效的开源漏洞扫描工具，支持Docker快速部署，提供Web界面、API接口和自动化扫描功能。适用于企业安全团队、渗透测试人员及开发者，帮助发现并修复系统漏洞，快速检测SQL注入、XSS、弱口令等常见漏洞。5分钟搭建你的专属扫描平台！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq73b6mMDrSsibcNOibke44MwuEeGrWuzIYYp3J0nOKSpPyIrtZ0aWlvibuzlP4XkXyibPn9N9OPiaOGWicQ/640?wx_fmt=png&from=appmsg "")  
  
  
**注意：**  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
**渗透安全HackTwo**  
"**设为****星标⭐️**  
"  
**否****则可能就看不到了啦！**  
  
**下载地址在末尾#渗透安全HackTwo**  
  
0x02   
功能简介  
  
  
界面导览  
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq73b6mMDrSsibcNOibke44Mwu5eGcqJPyIyukqiak5FqQGPWTVghvlsP7icRGrkZLNG0W7Bb36p7XXLXw/640?wx_fmt=png&from=appmsg "")  
### 仪表板  
###   
  
仪表板作为您的中央指挥中心，提供：  
- 实时扫描活动和进度  
- 最新漏洞发现和趋势  
- 系统性能指标  
- 常见操作的快速访问控件  
### 扫描接口  
###   
  
您可以在扫描页面控制漏洞评估：  
- 用于自定义工作流程的可视化模块编辑器  
- 实时扫描进度监控  
- 自动扫描计划  
- 精细调整扫描参数  
- 自定义扫描配置文件和模板  
### 漏洞导航器  
###   
  
用于管理已发现漏洞的综合平台：  
- 实时更新的动态漏洞列表  
- 高级搜索和过滤功能  
- 多种视图选项（列表、网格、基于严重性）  
- 详细的漏洞报告包括：  
- CVE/CPE 映射  
- CVSS 评分细目  
- 分步补救说明  
### 环境概述  
###   
  
全面了解您的基础设施：  
- 完整的主机库存管理  
- 风险评分和安全指标  
- 交互式网络拓扑可视化  
- 详细系统信息  
- 服务枚举和版本跟踪  
### 主机详细信息  
###   
  
各个系统的详细视图：  
- 完整的系统规格  
- 端口和服务枚举  
- 漏洞按严重程度计数  
- 历史扫描结果  
- 安全风险指标  
### 终端接口  
###   
  
直接访问 Sirius 后端：  
- 用于高级操作的 PowerShell 环境  
- 自定义脚本执行  
- 代理部署和管理  
- 系统诊断  
- 批量操作支持  
## 系统架构  
## Sirius 通过多种微服务运行：  
服务描述港口Sirius UIWeb 界面 (Next.js)3000（HTTP）、3001（开发）Sirius API后端 API 服务9001天狼星引擎扫描引擎5174Sirius RabbitMQ消息代理5672（AMQP），15672（管理）sirius-postgres数据库5432天狼星瓦尔基键值存储6379  
  
0x03 更新说明  
  
```
漏洞库升级 - 新增1000+漏洞检测规则，覆盖最新CVE漏洞
性能优化 - 扫描速度提升40%，内存占用降低30%
UI改进 - 全新仪表盘设计，数据可视化更直观
API增强 - 提供更丰富的REST API接口
Docker支持 - 优化容器部署体验
修复问题 - 解决20+已知bug
```  
  
  
0x04 使用介绍  
  
📦  
快速入门指南  
  
**条件**  
```
Docker 引擎 20.10.0+
Docker Compose V2
最低 4GB RAM
10GB可用磁盘空间
```  
  
**安装**  
```
cd website
# Start all services
docker compose up -d
# Access the web interface
open http://localhost:3000
```  
  
**登录**  
```
用户名:
admin
密码：
password
```  
  
  
就这样！您的 Sirius Scan 实例现已运行。  
### 服务状态  
  
```
# Check all services
docker compose ps
# View logs
docker compose logs
# Check specific service
docker compose logs sirius-api
```  
  
### 常见问题  
### 服务启动失败  
  
```
检查日志：
docker compose logs <service-name>
验证端口：
netstat -tuln
检查系统资源
```  
  
### 数据库连接问题  
  
```
验证 PostgreSQL：
docker compose ps sirius-postgres
检查日志：
docker compose logs sirius-postgres
验证凭证
```  
  
### 消息队列问题  
  
```
检查 RabbitMQ：http://localhost:15672
查看日志：
docker compose logs sirius-rabbitmq
```  
  
###   
  
  
**0x05 内部VIP星球介绍-V1.4（福利）**  
  
        如果你想学习更多**渗透测试技术/应急溯源/免杀/挖洞赚取漏洞赏金/红队打点**  
欢迎加入我们**内部星球**  
可获得内部工具字典和享受内部资源和  
内部交流群，**每1-2天更新1day/0day漏洞刷分上分****(2025POC更新至3900+)**  
**，**  
包含网上一些**付费****工具及BurpSuite自动化漏****洞探测插件，AI代审工具等等**  
。shadon\Quake\  
Fofa高级会员，CTFShow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复"   
**星球**  
 "有优惠券名额有限先到先得！全网资源  
最新  
最丰富！**（🤙截止目前已有1800多位师傅选择加入❗️早加入早享受）**  
  
****  
  
**👉****点击了解加入-->>内部VIP知识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
****  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250530获取下载**  
  
# 最后必看-免责声明  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.4（AI自动化工具）**  
  
**2.CS4.8-CobaltStrike4.8汉化+插件版**  
  
**3.最新BurpSuite2025.2.1专业版（新增AI模块）**  
  
**4. 最新xray1.9.11高级版下载Windows/Linux**  
  
**5. 最新HCL AppScan Standard**  
  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
[全面资产收集流程及方法解析 万字长文窥探信息收集|挖洞技巧](https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247491574&idx=1&sn=48d865c82a228bd135a035419c765e94&scene=21#wechat_redirect)  
  
  
