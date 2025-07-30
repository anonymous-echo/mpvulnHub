#  OA-EXPTOOL漏洞综合利用框架   
LittleBear4  七芒星实验室   2024-05-28 18:11  
  
**项目介绍**  
  
OA-EXPTOOL是一款  
OA综合利用工具，集合将近20款OA漏洞批量扫描****  
  
**使用方式**  
- 第一次使用脚本请运行pip3 install -r requirements.txt  
  
- 面板是所有参数了致远就输入 zyscan tab键有补全命令的功能  
  
- 进入后help就可以查看，操作和msf一样  
  
- 批量使用先进行set type file 改变对象类型 然后set value 文件名  
  
### 使用实例  
  
加载已定义的模块  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicnMlJEyliaXgyAOUiaFDSpRFWgO2MU54iclHb9S12nNhEWsFSEbXDr2gw2RiaGd9JCicRNBJPgLnRgIA1Q/640?wx_fmt=png&from=appmsg "")  
  
在主界面用set xxx 来加载book中自义定文件夹中的yaml文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicnMlJEyliaXgyAOUiaFDSpRFWhKdDCR9hEYTBfRztKMyeGib8FUILQvmFiaJzpPJW3R06G6QsMyBZDpnA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicnMlJEyliaXgyAOUiaFDSpRFWnmCoQdTHtW7iavQ5y3KoeOqhibgXOr9kTzQvkoVib6DlYo1xA7hSD8jIQ/640?wx_fmt=png&from=appmsg "")  
  
**YAML模板**  
```
id: xxx                                             #漏洞名称:必选项
time: 'xxx'                                         #纰漏时间:可选项

info:                                                   #这里主要是漏洞的信息：都是可选项
  name: xxxxx                                           #名称
  author: xxxxx                                         #作者
  severity: high                                        #漏洞等级
  description: xxxxxxx                                  #描述信息
  reference: xxxx                                       #参考链接

http:                                                   编辑请求
  - method: 
      - POST                                            #第一次请求方式 以此类推
      - GET                                             #第二次请求方式
    path:
      - "{{BaseURL}}/xxxxxxxxxxx"                       #第一次请求路径  跟请求方式对应
      - "{{BaseURL}}/xxxxxx"                            #第二次请求路径
    body:
      - |
        "xxxxxxxxx"                                     #有post是必选项 第一次post请求的主体
    Rheader:
      - Content-Type:application/x-www-form-urlencoded & Accept-Enco   #第一次POST请求时的请求头，&分隔开，可选项
    Gheader:
      - Cookie:session & Content-Type:application & Accept-Encoding:deflate  # 第一次GET 请求头，&分隔开，可选项
    
    matchers-condition: and                                        #在最后一次请求后进行验证 所有条件为and或者or
    matchers:                                                           
      - type: word                                                 #key值 必选项
        part: body                                                 #验证的部分 可选项也可以是header和nuclei通用
        words:                                                     #key对应的内容
          - "当前已登录了一个用户，同一窗口中不能登录多个用户"
          - "<a href='/seeyon/main.do?method=logout'"

      - type: status                       #这里对应的是请求的响应                                        
        status:
          - 200     

    extractors:                                                    #提取器 
      - name:                          
          - session                                               #Gheader 中的session 上边Gheader中
        part: 
          - Gheader                                               # 提取的部分和赋值给Gheader
        time:                                                     #在第几次请求中进行提取
          - 1
        regex:
          - 'JSESSIONID=(.*)'
```  
  
  
**免责声明**  
  
本  
开源工具是由作者按照开源许可证发布的，仅供个人学习和研究使用。作者不对您使用该工具所产生的任何后果负任何法律责任  
  
**下载地址**  
  
**点击下方名片进入公众号**  
  
**回复关键字【**  
**240528****】获取**  
**下载链接**  
  
