#  【技术干货】2022-29464 WSO2 API Manager 任意文件上传、远程代码执行漏洞   
 星阑科技   2022-06-10 11:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Cc8QqLUKOeiaFHTFtiatmEIxZQcXOHfyr6GOBM88IeMm28ybjSAHEJKicuQxPxN5L5NFZ5mza2NOnuokf9ant2fUQ/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1NSkNgX8voWSJmuSUlcQtsLKWSxBUmsxRCOqbNibhhXFuhtfXiak5ibYGMcEGD9yzzIy4qVq1Q5a63IQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1NSkNgX8voWSJmuSUlcQtsLgZE9TXJrsxHuabVS0UbocSyplzJJ0pxtQQZpAzIBdZwlByjZ3qUUAQ/640?wx_fmt=png "好看的图.png")  
  
**arp**  
  
**@PortalLab实验室**  
  
  
**漏洞描述**  
  
某些WSO2产品允许不受限制地上传文件，从而执行远程代码。以WSO2 API Manager 为例，它是一个完全开源的 API 管理平台。它支持API设计，API发布，生命周期管理，应用程序开发，API安全性，速率限制，查看API的统计信息，以及连接API，API产品和端点。  
  
**漏洞版本**  
  
WSO2 API Manager 2.2.0 及以上版本  
  
WSO2 Identity Server 5.2.0 及以上  
  
版本WSO2 Identity Server Analytics 5.4.0、5.4.1、5.5.0、5.6.0WSO2  
  
Identity Server as Key Manager 5.3.0 及更高版本  
  
WSO2 Enterprise Integrator 6.2.0 及更高版本  
  
WSO2 Open Banking AM 1.4.0 及更高版本  
  
WSO2 Open Banking KM 1.4.0 及更高  
  
**环境搭建**  
  
采用Dockerfile搭建  wso2/wso2am - Docker Image | Docker Hub  
  
版本：WSO2 API Manager  4.0.0  
```
# ------------------------------------------------------------------------
#
# Copyright 2018 WSO2, Inc. (http://wso2.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License
#
# ------------------------------------------------------------------------
# set base Docker image to AdoptOpenJDK CentOS Docker image
FROM adoptopenjdk/openjdk11:x86_64-centos-jdk-11.0.10_9
LABEL maintainer="WSO2 Docker Maintainers <dev@wso2.org>" \
      com.wso2.docker.source="https://github.com/wso2/docker-apim/releases/tag/v4.0.0.1"
# set Docker image build arguments
# build arguments for user/group configurations
ARG USER=wso2carbon
ARG USER_ID=802
ARG USER_GROUP=wso2
ARG USER_GROUP_ID=802
ARG USER_HOME=/home/${USER}
# build arguments for WSO2 product installation
ARG WSO2_SERVER_NAME=wso2am
ARG WSO2_SERVER_VERSION=4.0.0
ARG WSO2_SERVER_REPOSITORY=product-apim
ARG WSO2_SERVER=${WSO2_SERVER_NAME}-${WSO2_SERVER_VERSION}
ARG WSO2_SERVER_HOME=${USER_HOME}/${WSO2_SERVER}
ARG WSO2_SERVER_DIST_URL=https://github.com/wso2/${WSO2_SERVER_REPOSITORY}/releases/download/v${WSO2_SERVER_VERSION}/${WSO2_SERVER}.zip
# build argument for MOTD
ARG MOTD='printf "\n\
Welcome to WSO2 Docker resources.\n\
------------------------------------ \n\
This Docker container comprises of a WSO2 product, running with its latest GA release \n\
which is under the Apache License, Version 2.0. \n\
Read more about Apache License, Version 2.0 here @ http://www.apache.org/licenses/LICENSE-2.0.\n\n"'

# create the non-root user and group and set MOTD login message
RUN \
    groupadd --system -g ${USER_GROUP_ID} ${USER_GROUP} \
    && useradd --system --create-home --home-dir ${USER_HOME} --no-log-init -g ${USER_GROUP_ID} -u ${USER_ID} ${USER} \
    && echo ${MOTD} > /etc/profile.d/motd.sh
# copy init script to user home
COPY --chown=wso2carbon:wso2 docker-entrypoint.sh ${USER_HOME}/
# install required packages
RUN \
    yum -y update \
    && yum install -y \
        nc \
        unzip \
        wget \
    && rm -rf /var/cache/yum/*
# add the WSO2 product distribution to user's home directory
RUN \
    wget -O ${WSO2_SERVER}.zip "${WSO2_SERVER_DIST_URL}" \
    && unzip -d ${USER_HOME} ${WSO2_SERVER}.zip \
    && chown wso2carbon:wso2 -R ${WSO2_SERVER_HOME} \
    && mkdir ${USER_HOME}/wso2-tmp \
    && bash -c 'mkdir -p ${USER_HOME}/solr/{indexed-data,database}' \
    && chown wso2carbon:wso2 -R ${USER_HOME}/solr \
    && cp -r ${WSO2_SERVER_HOME}/repository/deployment/server/synapse-configs ${USER_HOME}/wso2-tmp \
    && cp -r ${WSO2_SERVER_HOME}/repository/deployment/server/executionplans ${USER_HOME}/wso2-tmp \
    && rm -f ${WSO2_SERVER}.zip
# set the user and work directory
USER ${USER_ID}
WORKDIR ${USER_HOME}
# set environment variables
ENV WORKING_DIRECTORY=${USER_HOME} \
    WSO2_SERVER_HOME=${WSO2_SERVER_HOME}
# expose ports
EXPOSE 9763 9443 9999 11111 8280 8243 5672 9711 9611 9099
# initiate container and start WSO2 Carbon server
ENTRYPOINT ["/home/wso2carbon/docker-entrypoint.sh"]
```  
  
运行docker run命令 搭建docker环境。  
```
docker run -it -p 8280:8280 -p 8243:8243 -p 9443:9443 --name api-manager wso2/wso2am:4.0.0
```  
  
搭建完成后，访问 https://localhost:9943  默认用户名 密码 admin admin。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYyS87kNXRk2BF1iac6Z3J7h66Krweb9NialpWQjX5OvKcicDFnZkabAWgicg/640?wx_fmt=jpeg "")  
  
**漏洞复现**  
## 漏洞原理  
  
补丁diff记录（https://github.com/wso2/carbon-kernel/pull/3152/commits/13795df0a5b6a2206fd0338abfff057a7b99e1bb）   
Remove Unnecessary file uploader classes and improve parent path validation. by bhagyasakalanka · Pull Request #3152 · wso2/carbon-kernel (github.com)  
  
查看diff记录、在创建file对象时会先对上传文件的路径做校验。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYyzAzNIktxKO1CjqZkwfWRMyxI2BqsPe8anHEF6gxgM2Pp4ibaBCTVbDg/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYy48hgicxjQCwqicXicC5Gje5mfpAHnBkgjB3GbpPuFyb4hwTPGrWib8iaWcg/640?wx_fmt=jpeg "")  
  
carbon-kernel/FileUploadServlet.java at 4.4.x · wso2/carbon-kernel (github.com)  
  
开启docker镜像调试模式，在idea上使用远程调试。  
```
docker run -it -p 8280:8280 -p 8243:8243 -p 9443:9443 -p 5005:5005 --name another-api-manager wso2/wso2am:4.0.0 -debug *:5005
```  
  
/fileupload 会在服务器启动期间被注册。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYya4KX3qwoAAAMAHt9ibARdeic8SWxrEECZxAs3qJMIzfBZSIj2dAEKQuw/640?wx_fmt=jpeg "")  
  
在使用文件上传时，会调用/org/wso2/carbon/ui/transports/FileUploadServlet.java 。  
  
构造函数FileUploadServlet 会将类内部定义的私有属性进行修改。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYywicy9tVW0UtIGtt5lqp78GGYYP9RZQ5PlJDKJrxJpcIw7BgUbcINZ2w/640?wx_fmt=jpeg "")  
  
使用POST方法时，会调用doPost(),接着调用**fileUploadExecutorManager**  
.execute()  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYymQIoaJl4TvLwxjE8dvLB5557XCpeWj3UxAogvicNI3ibNjapibic6qLWwg/640?wx_fmt=jpeg "")  
  
因此我们将断点打到/org/wso2/carbon/ui/transports/fileupload/FileUploadExecutorManager.java#execute，正如上面描述所说、当收到一个文件上传请求，这个方法会被调用。它接受的两个参数：http request、https response，会返回布尔值。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYyPuTy9ZjHGJPFOHkiaLGapia3yNVdmia0HLpJqmEUBPvRVbnfwUecPGwtQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYy1DhiaOofNKjbMf33nX0RG4hvmOf65ISJwL5UStLlkUd8MZ5Gf1tTXSg/640?wx_fmt=jpeg "")  
  
CarbonConstants类包含Carbon所有重要常数  
  
然后对CarbonConstants的cookie、**webContext、**SERVER_URL、进行操作。向下走，通过对requestURI的截取获得actionString。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYyIADe97cBM0IPsJWaz1pBSAjc76E4NibInzlknOoaweapHRGMZjLsOfw/640?wx_fmt=jpeg "")  
  
在下面的代码中会注册execution handlers、首先会创建execHandlerManager对象 ，接下来会加上ExecHandler链条 。FileUploadExecutionHandlerManager => CarbonXmlFileUploadExecHandler=>OSGiFileUploadExecHandler=>AnyFileUploadExecHandler。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYyGibGhTich390IZYyWBcxValDONzA008wzKtYLwdibW9tOlZI8juib0QIxg/640?wx_fmt=jpeg "")  
  
进入startExec() 会调用/org/wso2/carbon/ui/transports/fileupload/FileUploadExecutorManager.java# execute() 在for循环中匹配到 toolsAny。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYyavJlibS4znOQkf9MQDhNQtqBjQXNE1dzAmI6XdBd0EUVSS9PdzRuApg/640?wx_fmt=jpeg "")  
  
然后进入/org/wso2/carbon/ui/transports/fileupload/AbstractFileUploadExecutor.java# executeGeneric() ，然后调用parseRequest(request) 获取request 参数。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYyy4EibXVEKKRhcLbAFQomrOomaCVMcLNPCEmhnobSIVkIQpxUn36YynQ/640?wx_fmt=jpeg "")  
  
/org/wso2/carbon/ui/transports/fileupload/AbstractFileUploadExecutor.java#parseRequest()  
  
将断点打到该位置，继续调试。它首先确保 POST 请求是分段 POST 请求，然后提取上传的文件，确保 POST 请求至少包含上传的文件，并根据最大文件大小对其进行验证。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYyicJ7DxbKbKfzb7ewOVSg8XfEzhd490QXr7VUQR34FXGhezlax0wUSbg/640?wx_fmt=jpeg "")  
  
走了很长一串之后，进入到/org/wso2/carbon/ui/transports/fileupload/ToolsAnyFileUploadExecutor.java# execute()  
  
这是错误所在，该方法容易受到路径遍历vulenerabulity的影响，因为它信任用户在POST请求中给出的文件名。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYybOcpDq3B0mhRBIBARJhsicTYsEEEppeRw1a3ypkibJOick0DdxYgxCbgw/640?wx_fmt=jpeg "")  
  
在该方法下，会返回一个 uuid 是由系统时间和随机数组成。在uploadeFile中可以看到存放上传文件的路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYyvyE4v99adjiaqQgs4rD4YWTTYcZ9lysTqQ02lEzE5gicXg7YLGq8Y1cQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYyJsSQOw2CfbuBJyVCuaLdzsgic20Y2niaiaiblpAFhbVibW0PJ9jDUQ3OZWw/640?wx_fmt=jpeg "")  
## 漏洞测试  
  
运行以下命令：  
```
python3 exploit.py https://127.0.0.1:9443/ shell.jsp
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYyjjVgyjjbjxAFFXRYGcbp4EmqqAibSRHmibkBNJgiaMSdzkZrvgEQcyjSw/640?wx_fmt=jpeg "")  
  
在网页中打开以下链接。在输入框中输入命令 ls 。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wfFYMXc5G1Nf05aTtkLkaoU2pOgY1OYyibr4WEE8PfyewsM7YE98lv1CzoclQp9nibpSSTL5qjCRrtOJgBKPglTQ/640?wx_fmt=jpeg "")  
  
**修复建议**  
  
如果最新版本未列在受影响的产品列表下，则可以迁移到产品的最新版本。否则，您可以根据以下公开修复程序将相关修复程序应用于产品：  
- https://github.com/wso2/carbon-kernel/pull/3152  
  
- https://github.com/wso2/carbon-identity-framework/pull/3864  
  
- https://github.com/wso2-extensions/identity-carbon-auth-rest/pull/167  
  
临时缓解措施：  
<table><tbody style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><tr style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td width="260" valign="top" style="margin: 0px;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 1px;border-style: solid;border-color: rgb(221, 221, 221);max-width: 100%;overflow-wrap: break-word !important;box-sizing: border-box !important;"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;"><strong style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">产品版本</strong></span></p></td><td width="260" valign="top" style="margin: 0px;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 1px;border-style: solid;border-color: rgb(221, 221, 221);max-width: 100%;overflow-wrap: break-word !important;box-sizing: border-box !important;"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;"><strong style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">临时缓解步</strong></span></p></td></tr><tr style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td width="260" valign="top" style="margin: 0px;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 1px;border-style: solid;border-color: rgb(221, 221, 221);max-width: 100%;overflow-wrap: break-word !important;box-sizing: border-box !important;"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">WSO2 API 管理器 2.6.0、2.5.0、2.2.0 及更早版本</span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">WSO2 身份服务器 5.8.0、5.7.0、5.6.0、5.5.0、5.4.1、5.4.0、5.3.0、5.2.0 和更早版本</span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">作为密钥管理器的 WSO2 身份服务器 5.7.0、5.6.0、5.5.0、5.3.0 和更早版本</span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">WSO2 IS 分析 5.6.0、5.5.0、5.4.1、5.4.0 及更早版本</span></p></td><td width="260" valign="top" style="margin: 0px;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 1px;border-style: solid;border-color: rgb(221, 221, 221);max-width: 100%;overflow-wrap: break-word !important;box-sizing: border-box !important;"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">删除</span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;"><strong style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">&lt;product_home&gt;/repository/conf/carbon</strong></span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">中</span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;"><strong style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">FileUploadConfig</strong></span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">标记内定义的所有映射.xml</span></p></td></tr><tr style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td width="260" valign="top" style="margin: 0px;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 1px;border-style: solid;border-color: rgb(221, 221, 221);max-width: 100%;overflow-wrap: break-word !important;box-sizing: border-box !important;"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">WSO2 API 管理器 4.0.0、3.2.0、3.1.0、3.0.0</span></p></td><td width="260" valign="top" style="margin: 0px;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 1px;border-style: solid;border-color: rgb(221, 221, 221);max-width: 100%;overflow-wrap: break-word !important;box-sizing: border-box !important;"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">将以下配置添加到 <strong style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">&lt;product_home&gt;/repository/conf/deployment.toml</strong></span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;"><strong style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">deployment.toml</strong></span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">[[resource.access_control]]context=&#34;(.*)/fileupload/resource(.*)&#34;secure=falsehttp_method = &#34;all&#34; [[resource.access_control]]context=&#34;(.*)/fileupload/(.*)&#34;secure=truehttp_method = &#34;all&#34;permissions = [&#34;/permission/protected/&#34;]</span></p></td></tr><tr style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td width="260" valign="top" style="margin: 0px;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 1px;border-style: solid;border-color: rgb(221, 221, 221);max-width: 100%;overflow-wrap: break-word !important;box-sizing: border-box !important;"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">SO2 企业集成商 6.6.0、6.5.0、6.4.0、6.3.0、6.2.0</span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">及更早版本</span></p></td><td width="260" valign="top" style="margin: 0px;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 1px;border-style: solid;border-color: rgb(221, 221, 221);max-width: 100%;overflow-wrap: break-word !important;box-sizing: border-box !important;"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">于 EI 配置文件，请从&lt;<strong style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">文件上传</strong>配置&gt;部分中删除&lt;product_home&gt;<strong style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">/conf/carbon</strong>.xml 文件中的以下映射。</span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">对于业务流程/代理和分析配置文件，分别在以下位置对 <strong style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">carbon.xml</strong> 文件应用相同的更改。</span></p><ul start="1" class="list-paddingleft-1" style="margin: 0px;padding: 0px 0px 0px 1.5em;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><li style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">&lt;product_home&gt;/wso2/broker/conf/carbon.xml</span></p></li></ul><ul start="1" class="list-paddingleft-1" style="margin: 0px;padding: 0px 0px 0px 1.5em;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><li style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">&lt;product_home&gt;/wso2/业务流程/conf/carbon.xml</span></p></li></ul><ul start="1" class="list-paddingleft-1" style="margin: 0px;padding: 0px 0px 0px 1.5em;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><li style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">&lt;product_home&gt;/wso2/analytics/conf/carbon.xml</span></p></li></ul><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;"><strong style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">deployment.toml</strong></span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">&lt;Mapping&gt;    &lt;Actions&gt;        &lt;Action&gt;keystore&lt;/Action&gt;        &lt;Action&gt;certificate&lt;/Action&gt;        &lt;Action&gt;*&lt;/Action&gt;    &lt;/Actions&gt;    &lt;Class&gt;org.wso2.carbon.ui.transports.fileupload.AnyFileUploadExecutor&lt;/Class&gt;&lt;/Mapping&gt; &lt;Mapping&gt;    &lt;Actions&gt;        &lt;Action&gt;jarZip&lt;/Action&gt;    &lt;/Actions&gt;    &lt;Class&gt;org.wso2.carbon.ui.transports.fileupload.JarZipUploadExecutor&lt;/Class&gt;&lt;/Mapping&gt; &lt;Mapping&gt;    &lt;Actions&gt;        &lt;Action&gt;tools&lt;/Action&gt;    &lt;/Actions&gt;    &lt;Class&gt;org.wso2.carbon.ui.transports.fileupload.ToolsFileUploadExecutor&lt;/Class&gt;&lt;/Mapping&gt; &lt;Mapping&gt;    &lt;Actions&gt;        &lt;Action&gt;toolsAny&lt;/Action&gt;    &lt;/Actions&gt;    &lt;Class&gt;org.wso2.carbon.ui.transports.fileupload.ToolsAnyFileUploadExecutor&lt;/Class&gt;&lt;/Mapping&gt;</span></p></td></tr><tr style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td width="260" valign="top" style="margin: 0px;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 1px;border-style: solid;border-color: rgb(221, 221, 221);max-width: 100%;overflow-wrap: break-word !important;box-sizing: border-box !important;"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">WSO2 身份服务器 5.11.0、5.10.0、5.9.0</span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">作为密钥管理器的 WSO2 身份服务器 5.10.0、5.9.0</span></p></td><td width="260" valign="top" style="margin: 0px;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 1px;border-style: solid;border-color: rgb(221, 221, 221);max-width: 100%;overflow-wrap: break-word !important;box-sizing: border-box !important;"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">将以下配置添加到 <strong style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">&lt;product_home&gt;/repository/conf/deployment.toml</strong></span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;"><strong style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">deployment.toml</strong></span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">[[resource.access_control]]context=&#34;(.*)/fileupload/service(.*)&#34;secure=falsehttp_method = &#34;all&#34; [[resource.access_control]]context=&#34;(.*)/fileupload/entitlement-policy(.*)&#34;secure=falsehttp_method = &#34;all&#34; [[resource.access_control]]context=&#34;(.*)/fileupload/resource(.*)&#34;secure=falsehttp_method = &#34;all&#34; [[resource.access_control]]context=&#34;(.*)/fileupload/(.*)&#34;secure=truehttp_method = &#34;all&#34;permissions = [&#34;/permission/protected/&#34;]</span></p></td></tr><tr style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td width="260" valign="top" style="margin: 0px;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 1px;border-style: solid;border-color: rgb(221, 221, 221);max-width: 100%;overflow-wrap: break-word !important;box-sizing: border-box !important;"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">基于 WSO2 碳核 4 版本的其他不受支持的产品/版本</span></p></td><td width="260" valign="top" style="margin: 0px;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 1px;border-style: solid;border-color: rgb(221, 221, 221);max-width: 100%;overflow-wrap: break-word !important;box-sizing: border-box !important;"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">删除</span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;"><strong style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">&lt;product_home&gt;/repository/conf/carbon</strong></span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">中</span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;"><strong style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">FileUploadConfig</strong></span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">标记内</span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">定义的所有映射</span></p><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;">.xml</span></p></td></tr></tbody></table>  
  
**参考材料**  
  
1. 安全公告 WSO2-2021-1738 - WSO2 平台安全性 - WSO2 文档：  
https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2021-1738  
  
2. 关键概念 - WSO2 API 管理器文档 4.1.0：https://apim.docs.wso2.com/en/latest/get-started/key-concepts/  
  
3. hakivvi/CVE-2022-29464：WSO2 RCE （CVE-2022-29464） 漏洞利用和写入。(github.com)：https://github.com/hakivvi/CVE-2022-29464  
  
  
**更多技术干货，欢迎关注“星阑PortalLab”公众号**  
  
****  
  
  
**关于Portal Lab**  
  
星阑科技 Portal Lab 致力于前沿安全技术研究及能力工具化。主要研究方向为API 安全、应用安全、攻防对抗等领域。实验室成员研究成果曾发表于BlackHat、HITB、BlueHat、KCon、XCon等国内外知名安全会议，并多次发布开源安全工具。未来，Portal Lab将继续以开放创新的态度积极投入各类安全技术研究，持续为安全社区及企业级客户提供高质量技术输出。  
  
  
**往期 · 推荐**  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247492888&idx=1&sn=219ad26c37836f5cdefc5f41dea620c0&chksm=c0074884f770c192f60f651f3e0c6a0f293b38a59d9499a89cd1b9c2e2d8cbc4dd4620783ed1&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247492771&idx=1&sn=5bc86cbf62a83db69b1b1919ad86273b&chksm=c007493ff770c0290f199daef6b03bd09f9f85e35c5179c3ca8fe062623ecc27522b45850f0a&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247492691&idx=1&sn=7f4fdf863953280d024c2ae7144badff&chksm=c00749cff770c0d98d9848f5415e2c7b395add84d39e4ab51172549c024d36cfc80af23ad43e&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247492617&idx=1&sn=103b4a185c02f1435ddcc1778bd038e6&chksm=c0074995f770c08374efe7cda4e53a8991a867e2b1b73fe05f0f4a32335756a56c77483ee75f&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Cc8QqLUKOehwcHoxicoOah5mxDjLHMZ9RHUxNeibERphRXOj3AEupxt7JyOt3LF1RmmWQibYmicTv2DxM93iaEJhLxw/640?wx_fmt=gif "")  
