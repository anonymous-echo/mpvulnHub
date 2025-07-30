#  HVV2024POC漏洞核查思路   
原创 数据安全合规交流部落  数据安全合规交流部落   2024-09-02 20:08  
  
       2024HVV已告一段，互联网上已经有网友整理好包含今年hvv期间暴露出来的283个漏洞的POC合集，在这个过程中，不少安全运营者肯定想对自己管理的资产进行相关测试确定有没有受影响的漏洞。  
  
    下面将介绍如何使用Python脚本，结合基于路径的指纹库，实现WEB指纹识别与漏洞检测。后面内容包括指纹库的生成、批量目标的检测以及实际操作中的细节处理。  
        
## 1. 生成基于路径的指纹库  
  
首先，我们通过解析PDF文件中收集的283个漏洞POC，生成一个JSON格式的指纹库文件fingerprint_db.json。以下是Python脚本的核心步骤：  
  
import re  
  
import json  
  
import fitz  # PyMuPDF  
  
  
def extract_poc_from_pdf(pdf_path):  
  
    doc = fitz.open(pdf_path)  
  
    text = ""  
  
    for page in doc:  
  
        text += page.get_text()  
  
    doc.close()  
  
    return text  
  
  
def parse_poc(text):  
  
    vulnerabilities = []  
  
    pattern = re.compile(r'(\d+)\.(.*?)\n(POST|GET)\s+([^\s]+)\s+HTTP/1\.1')  
  
    matches = pattern.findall(text)  
  
      
  
    for match in matches:  
  
        index, system_description, method, path = match  
  
          
  
        parts = system_description.split(' ', 1)  
  
        if len(parts) == 2:  
  
            system_name, description = parts  
  
        else:  
  
            system_name = system_description  
  
            description = "描述未提供"  
  
          
  
        vulnerabilities.append({  
  
            "name": system_name.strip(),  
  
            "paths": [path.strip()],  
  
            "description": description.strip()  
  
        })  
  
      
  
    return vulnerabilities  
  
  
def main():  
  
    pdf_path = "path_to_your_pdf.pdf"  # 替换为你的PDF文件路径  
  
    text = extract_poc_from_pdf(pdf_path)  
  
    vulnerabilities = parse_poc(text)  
  
      
  
    fingerprint_db = {  
  
        "vulnerabilities": vulnerabilities  
  
    }  
  
      
  
    with open('fingerprint_db.json', 'w', encoding='utf-8') as f:  
  
        json.dump(fingerprint_db, f, ensure_ascii=False, indent=4)  
  
      
  
    print("指纹库已生成并保存为 fingerprint_db.json")  
  
  
if __name__ == "__main__":  
  
    main()  
  
{  
  
  "vulnerabilities": [  
  
    {  
  
      "name": "用友 U8 CRM",  
  
      "paths": ["/crmtools/tools/import.php?DontCheckLogin=1&issubmit=1"],  
  
      "description": "用友 U8 CRM import.php 任意文件上传漏洞"  
  
    },  
  
    {  
  
      "name": "赛蓝企业管理系统",  
  
      "paths": ["/BaseModule/ReportManage/DownloadBuilder?filename="],  
  
      "description": "赛蓝企业管理系统 GetJSFile 任意文件读取漏洞"  
  
    }  
  
    // 更多条目...  
  
  ]  
  
}  
## 2. 批量目标检测  
  
在实际操作中，漏洞检测不仅针对单一目标，还可能需要批量处理多个目标。为此，我们可以编写一个Python脚本，从url.txt文件中读取多个目标URL，并对每个目标执行检测。  
  
import json  
  
import requests  
  
  
with open('fingerprint_db.json', 'r', encoding='utf-8') as f:  
  
    fingerprint_db = json.load(f)  
  
  
def check_vulnerability(url):  
  
    for vulnerability in fingerprint_db['vulnerabilities']:  
  
        for path in vulnerability['paths']:  
  
            target_url = url + path  
  
            try:  
  
                response = requests.get(target_url, timeout=5)  
  
                if response.status_code in [200, 403]:  
  
                    print(f"[+] 可能存在漏洞: {vulnerability['description']} 在 {target_url} (HTTP状态码: {response.status_code})")  
  
                else:  
  
                    print(f"[-] {target_url} 返回状态码: {response.status_code}, 不存在或无响应")  
  
            except requests.exceptions.RequestException as e:  
  
                print(f"[!] 请求失败: {e}")  
  
  
def main():  
  
    with open('url.txt', 'r') as file:  
  
        targets = file.read().splitlines()  
  
  
    for target in targets:  
  
        print(f"\n[+] 开始检测目标: {target}")  
  
        check_vulnerability(target)  
  
  
if __name__ == "__main__":  
  
    main()  
  
  
3. 处理特殊HTTP状态码  
  
在实际检测中，目标路径可能返回403（Forbidden）状态码，这通常意味着路径存在但访问受限。因此，我们在脚本中增加对403状态码的处理，以便更准确地识别潜在的漏洞。  
  
  
  
