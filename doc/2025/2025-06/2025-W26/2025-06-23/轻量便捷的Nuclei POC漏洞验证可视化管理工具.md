> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyOTQyOTk3Mg==&mid=2247485333&idx=1&sn=40853a58fa3f469387da554b208318a7

#  轻量便捷的Nuclei POC漏洞验证可视化管理工具  
海底天上月  海底天上月   2025-06-23 05:01  
  
> 免责声明：  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，海底生残月及文章作者不为此承担任何责任。  
  
  
**0x01 工具介绍**  
  
          
轻量便捷的 Nuclei POC 漏洞验证可视化管理工具  
  
功能一览：  
- POC 模板管理：支持对 nuclei POC 模板的增删查改操作  
  
- 跨平台兼容：已支持 MacOS 和 Windows 系统，Linux 版本测试中  
  
- 多任务扫描：支持多 POC、多目标批量扫描  
  
-  高级配置：支持自定义 DNSLOG 服务器、扫描速率控制及多协议网络代理（http/https/socks5）  
  
-  请求分析：支持查看 POC 匹配时的完整请求/响应数据包  
  
-  编辑器优化：POC 编辑器支持主题切换和字体大小调整  
  
-  模板导入：支持一键导入 nuclei 模板，基于 template id 自动去重  
  
-  任务控制：支持手动停止扫描任务，灵活掌控测试流程  
  
-  配置持久化：自动保存用户配置，下次启动无需重复设置参数  
  
-  API 测试：支持对 API 接口及带目录路径的目标进行扫描  
  
-  POC 生成：提供图形化界面辅助生成简单 POC  
  
-  扫描进度实时显示：提供可视化进度条展示当前扫描状态  
  
-  扫描结果导出：支持将扫描结果导出为Excel格式文件  
  
**0x02 工具功能**  
#### MacOS 安装步骤  
- 将
```
Wavely.app
```

  
拖移至
```
Applications
```

  
文件夹中。在终端执行：  
  

```
sudo xattr -d com.apple.quarantine /Applications/Wavely.app 
```

#### Windows 安装步骤  
- 下载对应压缩包并解压，执行Wavely-xxx-installer.exe安装程序  
  
#### DNSLOG 设置说明  
- 系统默认采用 Nuclei 默认 DNSLOG 服务。  
  
#### 注册  
- 依次点击设置 -> 注册，在注册页面按提示获取设备 ID，完成证书申请后上传证书，即可注册成功。  
  
#### 导入 POC  
- 点击
```
从文件夹中导入POC
```

  
按钮，选择存放
```
nuclei poc
```

  
文件的目录。  
  
#### 添加/测试 POC  
- ##### 编辑poc  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/fYSUHibFMoaLicib7jx3mm4KOKTcgny6RQXHeJYXKLGmAToBp2GJN8H567CLbocqm8PDNm6ZqQtdufTTmickbQbG8A/640?wx_fmt=png&from=appmsg "")  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/fYSUHibFMoaLicib7jx3mm4KOKTcgny6RQXOUwSicnkibOaaARXWO6awWPBUE6bDEaYSSPVbZHS7ibOPl6YqWMHXyfOQ/640?wx_fmt=png&from=appmsg "")  
## 常见问题  
#### Windows 启动时闪现命令框  
  
此为正常现象，不会对 App 功能产生任何影响，可放心使用。  
#### Macos 无法打开App  
  
因未使用 Apple 证书签名 App，可能出现解除安全验证提示，如**软件显示禁止符号**  
 、 **无法验证软件身份**  
 或 **提示已损坏故不能正常打开**  
 ，可参考以下方案解决：  
##### 方案1  
  
在终端执行命令：  

```
sudo xattr -d com.apple.quarantine /Applications/Wavely.app
```

  
##### 方案2  
##### 执行命令：  

```
chmod 755 /Applications/Wavely.app/Contents/MacOS/Wavely
```

  
**0x04 工具下载**  
  
**点击关注下方名片****进入公众号**  
  
**回复关键字【Wavely**  
**】获取****下载链接**  
  
  
  
