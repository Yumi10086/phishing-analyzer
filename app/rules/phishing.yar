/*
    钓鱼邮件 YARA 规则集
    用途：检测凭证钓鱼模板、恶意宏文档特征、HTML 钓鱼登录页。
    使用：需 yara-python（可选依赖），由 app/rules/loader.py 加载。
*/

rule Phish_Credential_Keywords
{
    meta:
        description = "正文包含凭证索取/紧急恐吓关键词组合"
        category = "phishing_template"
        severity = "medium"
    strings:
        $en_urgency = /(urgent|immediately|within\s+24\s+hours|action\s+required)/i
        $en_cred = /(verify\s+your\s+(account|identity)|confirm\s+your\s+password|update\s+your\s+billing)/i
        $zh_urgency = /(\xe7\xb4\xa7\xe6\x80\xa5|\xe7\xab\x8b\xe5\x8d\xb3|\xe5\x86\xbb\xe7\xbb\x93|\xe9\x80\x9f\xe8\xae\xb0)/
        $zh_cred = /(\xe9\xaa\x8c\xe8\xaf\x81\xe8\xb4\xa6\xe5\x8f\xb7|\xe8\xbe\x93\xe5\x85\xa5\xe5\xaf\x86\xe7\xa0\x81|\xe9\x87\x8d\xe7\xbd\xae\xe5\xaf\x86\xe7\xa0\x81)/
        $form = /<form[^>]*(action|method)/si
        $input_pass = /<input[^>]*type=[\"']?password/i
    condition:
        (1 of ($en_*) and 1 of ($en_cred, $form)) or
        (1 of ($zh_*) and 2 of ($en_cred, $form, $input_pass)) or
        (any of ($zh_cred) and $form)
}

rule Phish_HTML_Login_Page
{
    meta:
        description = "HTML 附件内嵌密码输入表单（钓鱼登录页常见特征）"
        category = "phishing_payload"
        severity = "high"
    strings:
        $doctype = /<(!doctype\s+)?html/i
        $pass = /<input[^>]*type=[\"']?password/i
        $submit = /(login|sign\s?in|verify|confirm)/i
    condition:
        $doctype and $pass and $submit
}

rule Malware_Macro_Office_Document
{
    meta:
        description = "Office 文档内嵌 VBA 宏特征（OLE 结构中含宏目录/自动执行）"
        category = "malware_document"
        severity = "high"
    strings:
        $zip_magic = { 50 4B 03 04 }
        $vba_proj = "vbaProject.bin"
        $autoexec = /(Auto_?Open|Document_Open|Workbook_Open|Auto_?Close)/
        $shell = /(Shell|CreateObject|WScript\.Shell|cmd\.exe|powershell)/i
    condition:
        $zip_magic at 0 and $vba_proj and (1 of ($autoexec, $shell))
}

rule Phish_Obfuscated_URL_Tactics
{
    meta:
        description = "正文包含 URL 混淆手段（hxxp、@ 符号、IP 直连）"
        category = "phishing_template"
        severity = "medium"
    strings:
        $hxxp = /h(x{2}|tt)p(s?):\/\//i
        $at_url = /https?:\/\/[^\s\/]+\@[^\s\/]+/i
        $ip_url = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
    condition:
        any of them
}
