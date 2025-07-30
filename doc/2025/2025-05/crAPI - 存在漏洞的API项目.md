#  crAPI - 存在漏洞的API项目   
原创 qife  网络安全技术点滴分享   2025-05-26 00:35  
  
# crAPI 是一个OWASP提供的故意设计存在漏洞的API项目，通过这个项目，可以安全地运行并训练自己识别和利用API中的安全漏洞。  
## 项目概述  
  
crAPI 模拟了一个汽车维修服务的B2C应用，采用微服务架构构建。用户可以通过Web界面进行注册、管理车辆、联系技师、购买配件以及在社区中互动。  
## 主要功能  
- **用户认证系统**  
：包含注册、登录、密码重置等功能，故意设计存在认证漏洞  
  
- **车辆管理**  
：添加车辆、查看车辆位置、联系技师维修  
  
- **在线商店**  
：购买汽车配件，使用优惠券，管理订单  
  
- **社区功能**  
：发布帖子、评论互动  
  
- **漏洞挑战**  
：内置15+个安全挑战，涵盖OWASP API安全十大风险  
  
## 技术架构  
  
crAPI 采用微服务架构，包含以下组件：  
  
<table><thead><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><th style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;font-weight: bold;background-color: #f0f0f0;min-width: 85px;"><section><span leaf="">服务名称</span></section></th><th style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;font-weight: bold;background-color: #f0f0f0;min-width: 85px;"><section><span leaf="">技术栈</span></section></th><th style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;font-weight: bold;background-color: #f0f0f0;min-width: 85px;"><section><span leaf="">功能描述</span></section></th></tr></thead><tbody><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">web</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">OpenResty</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">主入口服务，Web界面</span></section></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: #F8F8F8;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">identity</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">Java</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">用户认证和授权管理</span></section></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">community</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">Go</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">社区博客和评论功能</span></section></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: #F8F8F8;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">workshop</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">Python</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">车辆维修工单管理</span></section></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">mailhog</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">-</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">邮件模拟服务</span></section></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: #F8F8F8;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">mongo</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">MongoDB</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">NoSQL数据库</span></section></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">postgres</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">PostgreSQL</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;min-width: 85px;"><section><span leaf="">SQL数据库</span></section></td></tr></tbody></table>  
## 结构图如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/meR9vVNE208P8kgeFOkWVc0ibYpsuoCPSrTQRy7aJX9cnLnoaEVpt6oQqnljsWFibusykcgwzytRIxnUQbKvTvIA/640?wx_fmt=png&from=appmsg "")  
## 安装指南  
### 系统要求  
- Docker 和 docker-compose (版本1.27.0或更高)  
  
- 推荐配置：t2.micro机器(1 CPU, 1GB内存)  
  
### 快速启动  
  
使用预构建镜像：  
```
# Linux
curl -o /tmp/crapi.zip https://github.com/OWASP/crAPI/archive/refs/heads/main.zip
unzip /tmp/crapi.zip
cd crAPI-main/deploy/docker
docker compose pull
docker compose -f docker-compose.yml --compatibility up -d

# Windows
curl.exe -o crapi.zip https://github.com/OWASP/crAPI/archive/refs/heads/main.zip
tar -xf .\crapi.zip
cd crAPI-main\deploy\docker
docker compose pull
docker compose -f docker-compose.yml --compatibility up -d
```  
### 配置覆盖  
  
可以通过修改.env  
文件或直接在命令中设置环境变量来覆盖默认配置：  
```
LISTEN_IP="0.0.0.0" docker compose -f docker-compose.yml --compatibility up -d
```  
## 使用说明  
1. 访问Web界面：http://localhost:8888  
  
1. 注册新账户  
  
1. 探索各项功能并尝试发现漏洞  
  
### 示例API调用  
  
获取用户车辆信息：  
```
curl -X GET "http://localhost:8888/identity/api/v2/user/dashboard" \
-H "Authorization: Bearer YOUR_JWT_TOKEN"
```  
## 漏洞挑战  
  
crAPI 内置了多个安全挑战，涵盖以下漏洞类型：  
1. **BOLA (Broken Object Level Authorization)**  
  
1. 访问其他用户的车辆详情  
  
1. 查看其他用户的维修报告  
  
1. **认证漏洞**  
  
1. 重置其他用户密码  
  
1. JWT令牌伪造  
  
1. **数据过度暴露**  
  
1. 查找泄露敏感信息的API端点  
  
1. 发现视频的内部属性  
  
1. **速率限制**  
  
1. 通过"联系技师"功能实施DoS攻击  
  
1. **BFLA (Broken Function Level Authorization)**  
  
1. 删除其他用户的视频  
  
完整挑战列表请参阅挑战文档(  
challenges.md)  
  
项目链接地址：  
https://github.com/OWASP/crAPI.git  
  
