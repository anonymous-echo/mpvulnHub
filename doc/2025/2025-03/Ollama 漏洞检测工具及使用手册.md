#  Ollama 漏洞检测工具及使用手册   
 网络安全等保与关保   2025-03-03 22:27  
  
   
  
# Ollama 漏洞检测工具使用手册  
  
## 简介  
  
Ollama 漏洞检测工具是一个用于检测本地 Ollama 服务是否存在已知安全漏洞的 Python 脚本。该工具可以检测路径遍历漏洞、未授权访问、模型注入攻击和本地文件包含等安全问题。  
  
**作者**  
: 牛仔帽(niuzaimao)  
## 系统要求  
- • Python 3.6 或更高版本  
  
- • 网络连接（用于连接本地或远程 Ollama 服务）  
  
- • 运行中的 Ollama 服务（默认地址：http://localhost:11434）  
  
## 安装步骤  
### 1. 下载检测工具  
- • 将 ollama_vulnerability_scanner.py  
 文件下载到您的计算机上。  
  
- • 下载地址：https://www.alipan.com/s/kScrKbEgNeY  
  
### 2. 创建并激活虚拟环境（推荐）  
  
在 macOS/Linux 上：  
```
# 创建虚拟环境python3 -m venv ollama-env# 激活虚拟环境source ollama-env/bin/activate
```  
  
在 Windows 上：  
```
# 创建虚拟环境python -m venv ollama-env# 激活虚拟环境ollama-env\Scripts\activate
```  
### 3. 安装依赖  
  
在激活的虚拟环境中安装所需的依赖：  
```
pip install requests
```  
## 使用方法  
### 基本用法  
  
确保 Ollama 服务正在运行，然后执行以下命令：  
```
python ollama_vulnerability_scanner.py
```  
  
这将使用默认设置（连接到 http://localhost:11434）扫描您的 Ollama 服务。  
### 扫描远程 Ollama 服务  
  
如果您的 Ollama 服务运行在不同的主机或端口上，可以使用 --host  
 参数：  
```
python ollama_vulnerability_scanner.py --host http://your-server-ip:11434
```  
### 查看帮助信息  
```
python ollama_vulnerability_scanner.py --help
```  
## 扫描结果解读  
  
扫描完成后，工具会生成一份报告，包含以下信息：  
1. 1. **Ollama 版本信息**  
：显示检测到的 Ollama 版本号  
  
1. 2. **漏洞列表**  
：列出所有发现的漏洞，包括：  
  
1. • 漏洞名称  
  
1. • 严重性级别（高/中/低）  
  
1. • 漏洞描述  
  
1. • 修复建议  
  
如果没有发现漏洞，工具会显示 "[+] 未发现漏洞" 的信息。  
## 检测的漏洞类型  
  
该工具可以检测以下类型的漏洞：  
1. 1. **路径遍历漏洞 (CVE-2023-48022)**  
  
1. • 严重性：高  
  
1. • 影响：攻击者可以访问服务器上的任意文件  
  
1. • 修复：升级到 Ollama 0.1.15 或更高版本  
  
1. 2. **未授权 API 访问**  
  
1. • 严重性：中  
  
1. • 影响：任何能访问 Ollama 端口的人都可以使用 API  
  
1. • 修复：配置防火墙限制访问，或使用反向代理添加认证  
  
1. 3. **模型注入漏洞**  
  
1. • 严重性：中  
  
1. • 影响：模型可能容易受到提示注入攻击  
  
1. • 修复：更新模型配置，添加更强的安全边界  
  
1. 4. **本地文件包含漏洞**  
  
1. • 严重性：高  
  
1. • 影响：攻击者可以读取服务器上的本地文件  
  
1. • 修复：升级到最新版本的 Ollama  
  
## 常见问题解决  
### 无法连接到 Ollama 服务  
  
如果出现 "无法连接到 Ollama 服务器" 的错误：  
1. 1. 确认 Ollama 服务是否正在运行  
  
1. 2. 检查连接地址和端口是否正确  
  
1. 3. 确认没有防火墙阻止连接  
  
### ModuleNotFoundError: No module named 'requests'  
  
如果出现此错误，说明缺少 requests 库：  
```
pip install requests
```  
### 权限问题  
  
如果脚本无法执行，可能需要添加执行权限：  
```
chmod +x ollama_vulnerability_scanner.py
```  
## 安全建议  
  
如果检测到漏洞，建议采取以下措施：  
1. 1. 升级到最新版本的 Ollama  
  
1. 2. 限制 Ollama API 的网络访问，只允许可信来源访问  
  
1. 3. 考虑使用反向代理添加认证层  
  
1. 4. 定期检查更新和安全公告  
  
## 免责声明  
  
此工具仅用于安全评估和教育目的。请在获得适当授权的情况下使用，不要用于未经授权的系统测试。  
## 卸载  
  
如果您不再需要此工具，可以简单地删除脚本文件和虚拟环境：  
```
# 退出虚拟环境deactivate# 删除虚拟环境和脚本rm -rf ollama-envrm ollama_vulnerability_scanner.py
```  
  
希望这个使用手册能帮助您顺利运行 Ollama 漏洞检测工具。如有任何问题，请参考上述故障排除部分或联系作者获取支持。  
  
   
  
  
