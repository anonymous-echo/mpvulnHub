#  AscensionPath一个基于Docker容器化技术的漏洞环境管理系统   
 黑白之道   2025-04-23 02:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
## 工具介绍  
  
**AscensionPath**  
一个基于Docker容器化技术的漏洞环境管理系统全栈漏洞环境管理系统，提供漏洞环境全生命周期管理，基于Docker容器技术实现安全隔离的实验环境。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2X95Uxo9GwTtUyj0DUJgVEEebH4qpbu12weibpPj5jB3sia6A5UyiaV66KhIKQdlqJvz34wiaqBz03xUQ/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
## 功能特性  
- **环境管理**  
  
✅ 镜像批量上传  ✅ 容器编排  ✅ 端口映射  ✅ 自动回收  
  
- **权限控制**  
  
🔒 RBAC权限模型  🔒 JWT认证  🔒 操作审计  
  
👨💻 普通用户环境隔离  👨💻 Admin全局管理  
  
- **开发支持**  
  
🛠️ Docker API集成  🛠️ Docker Compose多环境部署  🛠️ 端口智能映射  
  
📊 资源消耗统计  📊 实验时长分析  
  
- **安全机制**  
🔐 文件上传验证  🔐 容器沙箱隔离  🔐 路径穿越防护 🔐 会话加密     🔐 操作日志追踪  
  
## 环境部署  
### 开发环境  
```
# 前端cd frontendpnpm installnpm run dev# 后端cd backendgo mod tidygo run ./cmd/app/main.go
```  
### 生产部署  
```
cd frontendnpm run buildcd ../backend/cmd/app/go build main.go# 端口可选，默认8080./main [-port xxxx]# 在浏览器打开即可
```  
  
默认账号密码：admin:123456  
## 使用说明  
### 镜像  
  
在当前的系统中可以上传**镜像列表.json**  
文件，也可以上传**Docker compose项目**  
的压缩包。但要注意的是，列表**.json**有以下格式要求：  
- rank：对该漏洞的评分  
  
```
[    {        "image_name": "镜像名称(拉取地址)",        "image_vul_name": "漏洞镜像环境的名称(可自定义)",        "image_desc": "对于该漏洞镜像环境的描述(可自定义)",        "rank": 1,        "degree": {            "HoleType": [                "命令执行","SQL注入","..."            ],            "devLanguage": [                "Java","..."            ],            "devClassify": [                "Gin","..."            ],            "DevDatabase": [                "MYSQL","..."            ]        },        "from": "镜像来源(可自定义)"    }]
```  
  
也可以直接在机器上拉取镜像，系统会自动读取本地已有的镜像。  
>   
> 笔者已经整理好了Vulfocus的相关镜像，部署成功后上传即可。  
  
### Docker compose  
  
**Docker compose**  
项目的压缩包就比较自由了，只需要上传ZIP压缩包即可。系统会自动解压到 ./storeate  
目录下并自动寻找该目录下所有的 docker-compose.yml  
文件进行加载，docker-compose.yml  
文件在的目录名会自动作为漏洞环境的名称。在上传的时候要注意多次上传ZIP压缩包内容的相对路径最好别相同防止覆盖。  
  
系统并没有对ZIP进行任何限制，你甚至可以将**Vulhub**  
项目打包上传。  
### Pull image  
  
拉取镜像与系统默认的docker源有关，由于国内的网络条件，请注意调整网络网络环境。  
### 创建一个实例  
1. 拉取镜像 或 上传**Docker compose**  
压缩包  
  
1. 创建漏洞环境  
  
1. 创建实例  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2X95Uxo9GwTtUyj0DUJgVEESazbhfc0iah7PoWCw4oic5dDgKLu1icHibicGLoibPgN6C7Hicu7p61XlJGNg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2X95Uxo9GwTtUyj0DUJgVEE9I6VVvDsEvF6juQoA5uBvvE5iaFdo1POAUezzcMeb2bmQ1a2ficmhDpQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icZ1W9s2Jp2X95Uxo9GwTtUyj0DUJgVEEPGrsJgC418XD2btDIbFOUmcHuKm5hwMYbFnjGp5gQsia5XdB4aEsrtg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 权限管理  
  
<table><thead><tr><th style="color: rgb(66, 75, 93);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">角色</span></section></th><th style="color: rgb(66, 75, 93);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">权限说明</span></section></th><th style="color: rgb(66, 75, 93);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">功能范围</span></section></th></tr></thead><tbody><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">Admin</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">系统管理员</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">用户管理/镜像审核/全局监控</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">User</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">普通实验用户</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">实例操作/个人空间</span></section></td></tr></tbody></table>  
## 安全设计  
  
<table><thead><tr><th style="color: rgb(66, 75, 93);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">安全特性</span></section></th><th style="color: rgb(66, 75, 93);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">实现方式</span></section></th></tr></thead><tbody><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">Token加密</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">HS256签名算法 + 动态密钥管理</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">会话安全</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">18小时自动过期机制 + 服务端状态校验</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">防篡改机制</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">签名验证 + 标准Claim校验</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">密钥管理</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">uuid随机密钥 + 每天凌晨2点自动刷新</span></section></td></tr></tbody></table>  
  
  
## 工具获取  
  
  
  
https://github.com/xm6nb/AscensionPath  
  
  
> **文章来源：夜组安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
