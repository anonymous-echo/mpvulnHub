#  【DDDD二开】修复bug 新增指纹poc 新增功能   
 凯撒安全实验室   2025-05-28 00:52  
  
Sfd3n安全  
  
背景  
  
  
  
  
随着近年来网络攻防演练规模的持续扩大与实战化要求的不断提升，信息收集以及漏洞扫描依赖多个工具等需要手动执行，效率略低，在此背景下，由SleepingBag945师傅开发的dddd工具凭借其高效的信息收集、精准的指纹识别及灵活的漏洞探测能力应运而生，然而随着2024年6月后项目已经不再继续更新，原有POC与指纹库的已无法完全适配实战需求。  
  
  
  
Sfd3n安全  
  
概述  
  
  
随着攻防演练的常态化推进，越来越多的企事业单位被纳入实战化对抗场景。然而，对于多数安全服务与渗透的兄弟而言，受限于资源投入与技术积累，往往难以像专业实验室或头部企业那样建立并维护完善的内部漏洞库。这种差距导致在攻防演练中，团队常面临漏洞检测能力滞后、POC验证效率低下等挑战，难以高效应对实战化攻防场景的复杂需求。每次面对攻防演练巨量的信息资产收集和nday漏洞探测都会煞费苦心，费时费力，所以 为应对当前攻防演练中资产收集不足、漏洞探测滞后、于是基于dddd源码进行了二次开发。本次升级聚焦以下核心方向：  
- 新增部分poc  
：  
  
<table><tbody><tr><td data-colwidth="576"><p><span leaf="">- Vite-任意文件读取漏洞-CVE-2025-30208</span></p><p><span leaf="">- Vite-任意文件读取漏洞-CVE-2025-31125</span></p><p><span leaf="">- Vite-任意文件读取漏洞-CVE-2025-31486</span></p><p><span leaf="">- Vite-任意文件读取漏洞-CVE-2025-32395</span></p><p><span leaf="">- 用友时空KSOA-PrintZPZP-SQL延时注入</span></p><p><span leaf="">- 用友时空KSOA-fillKP-SQL延时注入</span></p><p><span leaf="">- 用友时空KSOA-PreviewKPQT-SQL延时注入</span></p><p><span leaf="">- 用友时空KSOA-PrintZPFB-SQL延时注入</span></p><p><span leaf="">- 用友时空KSOA-PrintZP-SQL延时注入</span></p><p><span leaf="">- 用友时空KSOA-PrintZPYG-SQL注入</span></p><p><span leaf="">- jeesite-默认密码</span></p><p><span leaf="">- ZZCMS-index-php-SQL延时注入漏洞-CVE-2025-0565</span></p><p><span leaf="">- 蓝凌OA-WebService-hrStaffWebService-任意文件读取漏洞</span></p><p><span leaf="">- 蓝凌OA-WebService-kmImeetingBookWebService-任意文件读取漏洞</span></p><p><span leaf="">- 蓝凌OA-WebService-kmImeetingResWebService-任意文件读取漏洞</span></p><p><span leaf="">- 蓝凌OA-WebService-loginWebserviceService-任意文件读取漏洞</span></p><p><span leaf="">- 蓝凌OA-WebService-sysFormMainDataInsystemWebservice-任意文件读取漏洞</span></p><p><span leaf="">- 蓝凌OA-WebService-sysNotifyTodoWebServiceEkpj-任意文件读取漏洞</span></p><p><span leaf="">- 蓝凌OA-WebService-sysNotifyTodoWebService-任意文件读取漏洞</span></p><p><span leaf="">- 蓝凌OA-WebService-sysSynchroGetOrgWebService-任意文件读取漏洞</span></p><p><span leaf="">- 蓝凌OA-WebService-sysTagWebService-任意文件读取漏洞</span></p><p><span leaf="">- 蓝凌OA-WebService-thirdImSyncForKKWebService-任意文件读取漏洞</span></p><p><span leaf="">- 蓝凌OA-WebService-wechatWebserviceService-任意文件读取漏洞</span></p><p><span leaf="">- 蓝凌OA-文件Copy导致远程代码执行漏洞-XVE-2023-18344</span></p><p><span leaf="">- 宏景eHR-uploadLogo-do-任意文件上传</span></p><p><span leaf="">- 宏景eHR-common_org_loadtree-SQL延时注入漏洞</span></p><p><span leaf="">- 宏景eHR-customreport_tree-SQL延时注入漏洞</span></p><p><span leaf="">- 宏景eHR-DownLoadCourseware-任意文件读取漏洞</span></p><p><span leaf="">- 宏景eHR-LoadOtherTreeServlet-SQL延时注入漏洞</span></p><p><span leaf="">- 宏景eHR-openFile任意文件读取漏洞</span></p><p><span leaf="">- 宏景eHR-OutputCode任意文件读取漏洞</span></p><p><span leaf="">- 宏景eHR-pos_dept_post-SQL延时注入漏洞</span></p><p><span leaf="">- 宏景eHR-sduty_getSdutyTree-SQL注入漏洞</span></p><p><span leaf="">- 宏景eHR-showmediainfo-SQL延时注入漏洞</span></p><p><span leaf="">- 赛蓝企业管理系统-System_FocusList_SubmitUploadify-任意文件上传漏洞</span></p><p><span leaf="">- 赛蓝企业管理系统-AuthToken_Index-身份认证绕过漏洞</span></p><p><span leaf="">- 赛蓝企业管理系统-DownloadBuilder-任意文件读取漏洞</span></p><p><span leaf="">- 赛蓝企业管理系统-EHR_Holidays_SubmitUploadify-任意文件上传漏洞</span></p><p><span leaf="">- 赛蓝企业管理系统-GetExcellTemperature-SQL注入漏洞</span></p><p><span leaf="">- 赛蓝企业管理系统-GetFieldJson-SQL注入漏洞</span></p><p><span leaf="">- 赛蓝企业管理系统-GetImportDetailJson-SQL延时注入漏洞 </span></p><p><span leaf="">- 用友U8-Cloud-MultiRepChooseAction-SQL延时注入漏洞</span></p><p><span leaf="">- 用友U8-Cloud-ReleaseRepMngAction-SQL延时注入漏洞-CNVD-2024-33023</span></p><p><span leaf="">- 用友U8-Cloud-RepAddToTaskAction-SQL延时注入漏洞</span></p><p><span leaf="">- 用友U8-Cloud-smartweb2_showRPCLoadingTip_d-XXE漏洞</span></p><p><span leaf="">- 用友U8-Cloud-uapbd-refdef-query-SQL注入漏洞</span></p><p><span leaf="">- 用友U8-Cloud-XChangeServlet-XXE漏洞</span></p><p><span leaf="">- 用友YonBIP-R5旗舰版-yonbiplogin-任意文件读取</span></p><p><span leaf="">- 泛微E-Cology9-QRcodeBuildAction-身份认证绕过导致SQL延时注入漏洞</span></p><p><span leaf="">- 泛微E-Cology9-WorkPlanService-前台SQL延时注入漏洞-XVE-2024-18112</span></p><p><span leaf="">- 泛微E-Cology10-appThirdLogin-身份认证绕过漏洞</span></p><p><span leaf="">- 泛微E-Cology-BlogService-SQL延时注入漏洞</span></p><p><span leaf="">- 泛微E-Cology-getFileViewUrl-SSRF漏洞</span></p><p><span leaf="">- 泛微E-Cology-WorkflowServiceXml-SQL注入漏洞</span></p><p><span leaf="">- 吉大正元身份认证网关-downTools-任意文件读取</span></p><p><span leaf="">- 易宝OA-ExecuteQueryForDataSetBinary-SQL延时注入漏洞</span></p><p><span leaf="">- 易宝OA-ExecuteQueryNoneResult-SQL延时注入漏洞</span></p><p><span leaf="">- 易宝OA-ExecuteSqlForDataSet-SQL延时注入漏洞</span></p><p><span leaf="">- 易宝OA-GetProductInv-SQL注入漏洞</span></p><p><span leaf="">- 易宝OA-getStockInRequestPrintDetail-SQL延时注入漏洞</span></p><p><span leaf="">- 易宝OA-GetUDEFStreamID-SQL延时注入</span></p><p><span leaf="">- FastAdmin后台开发框架-lang任意文件读取漏洞</span></p><p><span leaf="">- 九思OA-dl-jsp-任意文件读取</span></p><p><span leaf="">- 九思OA-WebServiceProxy-XXE漏洞</span></p><p><span leaf="">- 九思OA-workflowSync-getUserStatusByRole-dwr-SQL延时注入</span></p><p><span leaf="">- 章管家-listUploadIntelligent-SQL注入漏洞</span></p><p><span leaf="">- 章管家-saveUser-任意用户创建漏洞</span></p><p><span leaf="">- 联达动力OA-UpLoadFile-aspx-任意文件上传漏洞</span></p><p><span leaf="">- 联达动力OA-uploadImg-aspx-任意文件上传漏洞</span></p><p><span leaf="">- 联达动力OA-uploadLogo-aspx-任意文件上传漏洞</span></p><p><span leaf="">- BladeX企业级开发平台-code_list-SQL注入漏洞</span></p><p><span leaf="">- BladeX企业级开发平台-notice_list-SQL注入漏洞</span></p><p><span leaf="">- BladeX企业级开发平台-usual_list-SQL注入漏洞</span></p><p><span leaf="">- 亿赛通电子文档安全管理系统-NoticeAjax-SQL延时注入漏洞</span></p><p><span leaf="">- 亿赛通电子文档安全管理系统-CDGAuthoriseTempletService1-SQL注入漏洞-XVE-2024-19611</span></p><p><span leaf="">- 亿赛通电子文档安全管理系统-DeviceAjax-SQL延时注入漏洞</span></p><p><span leaf="">- 亿赛通电子文档安全管理系统-DocInfoAjax-SQL延时注入漏洞</span></p><p><span leaf="">- 亿赛通电子文档安全管理系统-FileFormatAjax-SQL延时注入漏洞</span></p><p><span leaf="">- 亿赛通电子文档安全管理系统-findByLockName-SQL延时注入漏洞</span></p><p><span leaf="">- 亿赛通电子文档安全管理系统-getAllUsers-信息泄露漏洞</span></p><p><span leaf="">- 亿赛通电子文档安全管理系统-LogicGroupAjax-SQL延时注入漏洞</span></p><p><span leaf="">- 亿赛通电子文档安全管理系统-MultiServerAjax-SQL延时注入漏洞</span></p><p><span leaf="">- 亿赛通电子文档安全管理系统-NavigationAjax-SQL延时注入漏洞</span></p><p><span leaf="">- 亿赛通电子文档安全管理系统-NetSecPolicyAjax-SQL延时注入漏洞</span></p><p><span leaf="">- jeecg-queryFieldBySql-rce-CVE-2023-4450</span></p><p><span leaf="">- jeecg-boot-getDictItemsByTable-sql</span></p><p><span leaf="">- JeecgBootgetTotalData-SQL-CVE-2024-48307</span></p><p><span leaf="">- jeecg-boot-jmreport-upload</span></p><p><span leaf="">- JeecgBoot-loadTableData-RCE</span></p><p><span leaf="">- JeecgBoot-onlDragDatasetHead_getTotalData-SQL注入漏洞-CVE-2024-48307</span></p><p><span leaf="">- JeecgBoot-passwordChange-任意用户密码重置漏洞</span></p><p><span leaf="">- jeecg-boot-queryTableData-sqli</span></p><p><span leaf="">- jeecg-boot-sqli</span></p><p><span leaf="">- JeecgBoot-testConnection-RCE</span></p><p><span leaf="">- JeecgBoot-权限绕过致AviatorScript表达式注入漏洞</span></p><p><span leaf="">- JeecgcommonController任意文件上传</span></p><p><span leaf="">- 用友U8-Cloud-AddTaskDataRightAction-SQL延时注入漏洞</span></p><p><span leaf="">- 用友U8-Cloud-approveservlet-SQL注入漏洞</span></p><p><span leaf="">- 用友U8-Cloud-BusinessRefAction-SQL延时注入漏洞</span></p><p><span leaf="">- 用友U8-Cloud-ExportUfoFormatAction-SQL延时注入漏洞-XVE-2024-4626</span></p><p><span leaf="">- 用友U8-Cloud-linkntbSQL注入漏洞</span></p><p><span leaf="">- 用友U8-Cloud-MeasQueryConditionFrameAction-SQL延时注入漏洞</span></p><p><span leaf="">- 用友U8-Cloud-MeasureQResultAction-SQL延时注入漏洞</span></p><p><span leaf="">- 用友U8-Cloud-MeasureQueryFrameAction-SQL延时注入漏洞</span></p><p><span leaf="">- 泛微-云桥e-Bridge-addTasteJsonp-SQL延时注入漏洞</span></p><p><span leaf="">- 泛微-云桥e-Bridge-checkMobile-SQL延时注入漏洞-XVE-2024-34435</span></p><p><span leaf="">- 用友U8-CRM-getufvouchdata-php-SQL注入漏洞</span></p><p><span leaf="">- 用友U8-CRM-import文件上传</span></p><p><span leaf="">- 用友U8-CRM-leadconversion-php-SQL延时注入</span></p><p><span leaf="">- 用友U8-CRM-relobjreportlist-php-SQL延时注入漏洞</span></p><p><span leaf="">- 用友U8-CRM-setremindtoold-php-SQL延时注入漏洞</span></p><p><span leaf="">- 用友U8CRM-uploadfile文件上传</span></p><p><span leaf="">- 用友U8-CRM-ajaxgetborrowdata-php-SQL延时注入-1</span></p><p><span leaf="">- 用友U8-CRM-ajaxgetborrowdata-php-SQL延时注入-2</span></p><p><span leaf="">- 用友U8-CRM-ajaxgetborrowdata-php-SQL延时注入-3</span></p><p><span leaf="">- 用友U8-CRM-ajaxgetborrowdata-php-SQL注入漏洞</span></p><p><span leaf="">- 用友U8-CRM-biztype-php-SQL延时注入</span></p><p><span leaf="">- 用友U8-CRM-chkService-php-SQL延时注入漏洞</span></p><p><span leaf="">- 用友U8-CRM-downloadfile-任意文件读取漏洞</span></p><p><span leaf="">- 用友U8-CRM-eventsetlist-php-SQL延时注入</span></p><p><span leaf="">- 用友U8-CRM-exportdictionary-php-SQL延时注入漏洞</span></p><p><span leaf="">- 用友U8-CRM-fillbacksetting-php-SQL延时注入漏洞</span></p><p><span leaf="">- 用友U8-CRM-fillbacksettingedit-php-SQL注入漏洞</span></p><p><span leaf="">- 用友U8-CRM-getufvouchdata-php-SQL延时注入</span></p><p><span leaf="">- 金和OA-C6-ApproveRemindSetExec-aspx-XXE漏洞-CNVD-2024-40568</span></p><p><span leaf="">- 金和OA-C6-DBModules-aspx-SQL延时注入漏洞</span></p><p><span leaf="">- 金和OA-C6-FileDownLoad任意文件读取漏洞</span></p><p><span leaf="">- 金和OA-C6-IncentivePlanFulfillAppprove-aspx-SQL延时注入漏洞</span></p><p><span leaf="">- 金和OA-C6-jQueryUploadify-ashx-SQL延时注入漏洞</span></p><p><span leaf="">- 金和OA-C6-SignUpload-ashx-SQL延时注入漏洞</span></p><p><span leaf="">- 金和OA-C6-UploadFileEditor-aspx-SQL延时注入漏洞</span></p><p><span leaf="">- 泛微E-Mobile-client-do-命令执行漏洞</span></p><p><span leaf="">- 泛微E-Mobile-client_cdnfile-任意文件读取漏洞</span></p><p><span leaf="">- 泛微E-Mobile-installOperate-SSRF漏洞</span></p><p><span leaf="">- 蓝凌EIS智慧协同平台-fi_message_receiver-aspx-SQL注入漏洞-CVE-2025-22214</span></p><p><span leaf="">- 用友GRP-U8-bx_dj_check-jsp-SQL延时注入漏洞-XVE-2024-10537</span></p><p><span leaf="">- 用友GRP-U8-dialog_moreUser_check-jsp-SQL延时注入漏洞-XVE-2024-10610</span></p><p><span leaf="">- 用友GRP-U8-userInfoWeb-SQL延时注入漏洞-XVE-2024-10539</span></p><p><span leaf="">- JeeWMS-cgAutoListController-do-SQL注入漏洞</span></p><p><span leaf="">- JeeWMS-cgFormBuildController-do-SQL注入漏洞-CVE-2025-0391</span></p><p><span leaf="">- JeeWMS-cgformTemplateController-do-任意文件读取漏洞-CVE-2024-27765</span></p><p><span leaf="">- JeeWMS-cgReportController-do-SQL注入漏洞-CVE-2024-57760</span></p><p><span leaf="">- JeeWMS-commonController-do-任意文件上传漏洞-CVE-2024-57761</span></p><p><span leaf="">- JeeWMS-graphReportController-do-SQL注入漏洞-CVE-2025-0392</span></p><p><span leaf="">- JeeWMS-iconController-do-任意文件上传漏洞</span></p><p><span leaf="">- 用友NC-checkekey-SQL注入漏洞-XVE-2024-37013</span></p><p><span leaf="">- 用友NC-Cloud-blobRefClassSearch-FastJson反序列化RCE</span></p><p><span leaf="">- 用友-NC-Cloud-importhttpscer-任意文件上传漏洞</span></p><p><span leaf="">- 用友NC-Cloud-queryPsnInfo-SQL注入漏洞</span></p><p><span leaf="">- 用友NC-Cloud-queryStaffByName-SQL注入漏洞</span></p><p><span leaf="">- 用友NC-down_bill-SQL延时注入-XVE-2024-9469</span></p><p><span leaf="">- 用友NC-downCourseWare-任意文件读取漏洞</span></p><p><span leaf="">- 用友NC-download-任意文件读取-XVE-2023-31829</span></p><p><span leaf="">- 用友NC-ECFileManageServlet-反序列化RCE</span></p><p><span leaf="">- 用友-NC-FileManager-任意文件上传漏洞</span></p><p><span leaf="">- 用友NC-files-反序列化RCE</span></p><p><span leaf="">- 用友NC-FormulaViewAction-SQL延时注入漏洞</span></p><p><span leaf="">- 用友NC-importPml-SQL延时注入漏洞-XVE-2023-29120</span></p><p><span leaf="">- 用友NC-isAgentLimit-SQL延时注入漏洞</span></p><p><span leaf="">- 用友NC-jiuqisingleservlet-反序列化RCE</span></p><p><span leaf="">- 用友NC-link_content-SQL延时注入漏洞</span></p><p><span leaf="">- 用友NC-ncmsgservlet-反序列化RCE</span></p><p><span leaf="">- 用友NC-pagesServletSQL延时注入漏洞-XVE-2024-13067</span></p><p><span leaf="">- 用友NC-PaWfm_open-SQL延时注入漏洞-XVE-2023-29119</span></p><p><span leaf="">- 用友NC-PaWfm2_open-SQL延时注入漏洞-XVE-2023-29119</span></p><p><span leaf="">- 用友NC-process-SQL注入漏洞</span></p><p><span leaf="">- 用友NC-registerServletJNDI-远程代码执行漏洞-XVE-2024-10248</span></p><p><span leaf="">- 用友NC-runStateServlet-SQL延时注入漏洞</span></p><p><span leaf="">- 用友NC-saveImageServlet-任意文件上传漏洞-XVE-2024-7471</span></p><p><span leaf="">- 用友-NC-saveXmlToFIleServlet-任意文件上传漏洞-XVE-2024-6507</span></p><p><span leaf="">- 用友NC-uploadFile任意文件上传</span></p><p><span leaf="">- 用友NC-yerfile_down-SQL延时注入漏洞-XVE-2024-34596</span></p><p><span leaf="">- 用友NC及NC-Cloud-show_download_content-SQL延时注入漏洞</span></p><p><span leaf="">- Apache-Solr-身份认证绕过导致任意文件读取漏洞-CVE-2024-45216</span></p><p><span leaf="">- Apache-Solr-身份认证绕过漏洞-CVE-2024-45216</span></p><p><span leaf="">- CVE-2021-29505</span></p><p><span leaf="">- Geoserver-property-rce</span></p><p><span leaf="">- Geoserver-ssrf</span></p><p><span leaf="">- Geoserver-XPath表达式注入致远程代码执行漏洞-CVE-2024-36401</span></p><p><span leaf="">- GeoServer-geoserverwms-RCE</span></p><p><span leaf="">- 海康威视综合安防管理平台-detection-前台RCE</span></p><p><span leaf="">- 海康威视综合安防管理平台-orgManagev1orgsdownload-任意文件读取漏洞</span></p><p><span leaf="">- 海康威视综合安防管理平台多处-FastJson反序列化RCE漏洞</span></p><p><span leaf="">- 海康威视综合安防管理平台-apiexternalreport任意文件上传</span></p><p><span leaf="">- 海康威视综合安防管理平台-applyCTfastjsonRCE</span></p><p><span leaf="">- 海康威视综合安防管理平台-artemis-port_alartemis_env信息泄露</span></p><p><span leaf="">- 海康威视综合安防管理平台-centerapifiles任意文件上传</span></p><p><span leaf="">- 海康威视综合安防管理平台-Centerlmapifiles任意文件读取</span></p></td></tr></tbody></table>  
- 新增指纹  
：增加了chainreactors师傅收集的指纹库内的指纹wappalyzer, fingerprinthub, ehole, goby 指纹，可能新增后的指纹和原来dddd指纹部分重复，后续我会不断修复精简。  
  
- 修改Nuclei对模板字段的限制  
：  
  
Nuclei对模板要求极其严格，所以很多朋友以前可能尝试给dddd添加漏洞但是发现无效可能就是这个原因，为了方便后续添加poc所以放宽了限制。  
  
- 支持-fofa -quake -hunter三平台联动  
：  
  
同时使用-fofa -quake -hunter时仅支持以下几种目标格式   
**公司名|域名|ip|CIDR**  
dddd会将目标拆解成-fofa -quake -hunter 对应的查询语句。  
  
- 修复mysql爆破失败的问题  
:  
  
由于mysql爆破模块与nuclei冲突所以将Mysql爆破提前至nuclei扫描前。  
  
- 修复部分原有模板的错误  
:  
  
通过实战发现部分原有模板存在一些错误于是进行修复。  
  
- 新增功能-gyl  
：  
  
攻防场景下获取同指纹网站权限，获取源码进行审计。  
  
- 新增功能-hw  
：  
  
这个功能适用于攻防快速打点抢分，需配合-fofa -quake -hunter同时使用,灵感来源于原dddd的低感知模式，现在同时支持fofa quake hunter，其功能类似于goby的fofa集成能力，即在不对目标进行主动探测扫描的情况下以针对指纹的数个poc直接探测漏洞，在ip被封禁之前便可探测漏洞，并且能够极短时间内对攻防演练的目标单位进行粗略攻击，快速抢分。  
  
  
  
  
Sfd3n安全  
  
用法  
  
  
本部分内容基于个人对工具功能的深入理解进行归纳，同时严格遵循原作者的设计逻辑与功能定位。通过结合实际应用场景与工具开发初衷，力求为用户提供清晰、精准的操作指南，确保用户既能掌握核心功能，又能贴合工具的设计目标实现高效应用。  
dddd很大一部分功能依赖fofa quake hunter 所以务必先配置相关api key（首次运行会在当前目录下新建config文件夹）  
- 常见参数与功能  
  
-t 指定目标可以是ip domain url ip:port domain:port 或者是文件例如targets.txt  
  
- 端口扫描  
  
这一步很多朋友都说dddd端口扫描速度太慢，其实并不是的，只是在windows上默认的tcp扫描模式特别慢，我个人使用习惯是在Linux上使用syn模式扫描，在普通4核4G10M的云服务器上可以10多分钟扫完整个C段全端口，基本一次攻防演练的目标单位ip资产基本也能在半天之内完成全端口扫描  
  
- 不同的使用场景  
**全部资产信息收集以及漏洞扫描（确保尽可能的全面）**  
**：**  
  
首先在云服务器上或者任linux服务器上下载masscan,dddd使用如下命令进行细致的全目标资产收集以及漏洞探测  
  
dddd -t targets.txt -sd -p 1-65535 -st syn -sst 150000  
  
这段命令是对所有资产的域名进行cdn识别保留真实ip以及初始填入的ip进行全端口扫描，识别指纹进行漏洞探测，对于部分只能域名访问的资产原作者也实现了域名绑定资产探测。  
  
-targets.txt中的内容为收集到全部单位的域名和ip资产例如：  
  
192.168.1.1  
  
172.16.1.0/24  
  
domain.com  
  
-st syn的前提是linux已经安装好了masscan  
  
-sst 150000这个参数需要使用者根据自身服务器带宽内存大小进行调试，调试方法就是下载masscan后使用masscan ip -p1-65535 --rate=150000，这个--rate就是指定扫描速度，选择一个已知开放端口数量的测试IP（如本地或公有测试靶机）验证在指定速率下，Masscan能否完整扫描目标所有开放端口，避免因速率过高导致数据包丢失或漏扫。  
  
**快速打点抢分：**  
  
dddd.exe -t targets.txt -fofa -quake -hunter -hw  
  
-tagets.txt  文件内为目标单位中文名，域名，ip，cidr等，例如 :  
  
xxxx公司  
  
192.168.1.1  
  
192.168.0.0/24  
  
domain.com  
  
这种模式下可实现在漏洞扫描之前零请求，仅需几个适应目标指纹的poc即可扫描结束。  
  
  
  
  
Sfd3n安全  
  
实战案例  
  
  
这里展示以下最近二开dddd在一次攻防演练中的实战效果：  
  
dddd.exe -t targets.txt -fofa -quake -hunter -hw-tagets.txt  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X1FGMiaWxGb2gstTEsCXN31DR31Fiaes7G9cmUVpIsGbBpRjOaEI7z28LSXXbGKMeCmo59NhlxlsW70393sPdsCw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X1FGMiaWxGb2gstTEsCXN31DR31Fiaes7GSa9bTrJ7BgXvl2D01GW7LDaySWw2ZE5HKiaoHmhOHUJjicMGRWm8IO5g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X1FGMiaWxGb2gstTEsCXN31DR31Fiaes7Gjbm05FP4VxGXlOAathHV1ur6gPXELtkHbClUMaMWbfFufE7DcVyKKA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X1FGMiaWxGb2gstTEsCXN31DR31Fiaes7Ge0ygOFGHxcb5GWW6nabC9icSQ3HXywFfzEtX5U8zWmlKGBibHicjsibNDQ/640?wx_fmt=png&from=appmsg "")  
  
  
dddd -t targets.txt -sd -p 1-65535 -st syn -sst 150000  
  
结果就不展示了，因为扫一半发现服务器流量异常被暂停了。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/X1FGMiaWxGb2gstTEsCXN31DR31Fiaes7G3sibpY6icRDEOOHkgwxyJezthQ2yvsz3OmAssH0BDalXKHh7VcibR4N9A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
Sfd3n安全  
  
后续计划  
  
- 后续每周抽  
时间更新最新公开  
po  
c  
  
- 针对攻防演练中常见可利用漏洞，需系统性梳理目标产品的poc，逐一修改Nuclei模板，并且添加多维度验证（关键字匹配以及oob验证）可以准确验证无  
回  
显漏洞  
  
- 后续增加资产导出功能，实现在工具扫描结束后全部资产将全部资产分类输入到excel中，方便后续进一步漏洞探测  
  
- 定期优化指纹  
  
- 修复其他bug  
  
- 实现用户提议  
  
- 继续优化维护hw模式  
  
Sfd3n安全  
  
工具获取  
  
  
关注公众号并添加vx群即可获取二开dddd，后续持续更新会在公众号和群中通知。  
  
  
  
vx群  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X1FGMiaWxGb2gstTEsCXN31DR31Fiaes7GHdQPBKXMicicMxJib98UfjoeySMhncTvYvDej1DvibsG0PB0VxflOy1ypQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
由于dddd比较依赖fofa hunter quake如果有hunter quake积分不够的小伙伴可以加vx联系本人  
  
**关注公众号   后台点击添加微信即可联系本人**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/X1FGMiaWxGb2gstTEsCXN31DR31Fiaes7GbZ3t9D0b0vxicfqQzAYFZ3UkfLiabUaOfFetSyaiaykW9ujZJnZibc07hQ/640?wx_fmt=gif&from=appmsg "")  
  
点击“阅读原文”  
  
