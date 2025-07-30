#  模糊测试：强制漏洞挖掘wfuzz   
原创 xxxxxx  渗透测试知识学习   2024-05-08 19:38  
  
# 本文章或工具仅供安全研究使用，请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任  
  
  
WFuzz是一款基于Python的Web安全模糊测试工具，主要用于发现Web应用程序的潜在漏洞和异常行为。  
  
WFuzz的功能与特点  
  
模糊测试：通过发送大量随机或半随机数据到目标系统，发现潜在漏洞和异常行为。多功能支持：支持多种HTTP方法、请求头、参数等，可定制模糊测试过程。  
  
  
使用方法：  
  
WFuzz 提供了许多选项来定制模糊测试：-z：定义自定义的有效载荷和范围。-H：添加自定义 HTTP 头。-X：指定 HTTP 请求方法（如 GET、POST 等）。--data：用于 POST 请求的数据。-c：继续执行，即使出现错误。--hc：指定 HTTP 响应码来过滤结果。-o：将输出保存到文件。--timeout：设置请求超时时间。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sqS9g7b8FY51SDp6n6WCvtH1f9KNLfNia3Lt1L68sFq2z4HhmXQyLSibgbXgHwXNXXzQoqUWRwicH1r8TPZCC9ibLA/640?wx_fmt=png "")  
​  
  
运行模糊测试使用以下基本命令格式来运行模糊测试：bashwfuzz -w <字典文件> -u <目标URL>-w 参数用于指定字典文件。-u 参数用于指定目标 URL，其中 FUZZ 是一个占位符，它将被字典中的每个值替换。例如，如果你有一个名为 words.txt 的字典文件，并且你想对 http://xxxxx.com/login.php?username=FUZZ 进行模糊测试，你可以运行：  
bash  
  
wfuzz -w words.txt -u http://xxxxx.comlogin.php?username=FUZZ  
  
如果你想使用 POST 方法发送数据，并且想过滤掉 HTTP 状态码为 200 的响应，你可以这样做：bashwfuzz -w words.txt -u http://xxxxx.com/login.php -X POST --data="username=FUZZ&password=pass" --hc 200WFuzz 会输出每个请求的详细信息，包括 URL、HTTP 状态码、响应大小等。通过分析这些信息，你可以识别出潜在的漏洞或异常行为。注意事项在进行模糊测试之前，请确保你有合法的权限对目标进行测试。模糊测试可能会生成大量的请求，这可能对目标服务器造成压力，因此请谨慎使用。遵循最佳实践和安全准则，不要滥用模糊测试工具。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sqS9g7b8FY51SDp6n6WCvtH1f9KNLfNianUC3vIUtrfoQibnPpN9dgDeYxFibk2UlEdziagqjImqCkrHwDNbpnX8yw/640?wx_fmt=jpeg "")  
​  
  
  
