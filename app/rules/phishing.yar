/*
*/

rule Phish_Credential_Keywords
{
    meta:
        category = "phishing_template"
        severity = "medium"
    strings:
        $en_urgency_1 = /(urgent|immediately|within\s+24\s+hours|action\s+required)/i
        $en_cred_1 = /(verify\s+your\s+(account|identity)|confirm\s+your\s+password|update\s+your\s+billing)/i
        $zh_urgency_1 = { E7 B4 A7 E6 80 A5 }   // jin-ji
        $zh_urgency_2 = { E7 AB 8B E5 8D B3 }   // li-ji
        $zh_urgency_3 = { E5 86 BB E7 BB 93 }   // dong-jie
        $zh_cred_1 = { E9 AA 8C E8 AF 81 E8 B4 A6 E5 8F B7 }   // yan-zheng-zhang-hao
        $zh_cred_2 = { E8 BE 93 E5 85 A5 E5 AF 86 E7 A0 81 }   // shu-ru-mi-ma
        $zh_cred_3 = { E9 87 8D E7 BD AE E5 AF 86 E7 A0 81 }   // zhong-zhi-mi-ma
        $form = /<form[^>]*(action|method)/is   // 修饰符顺序：/si 触发 yara 词法器怪癖（/is 合法）
        $input_pass = /<input[^>]*type=["']?password/i
    condition:
        (1 of ($en_urgency_*) and 1 of ($en_cred_1, $form)) or
        (1 of ($zh_urgency_*) and 2 of ($en_cred_1, $form, $input_pass)) or
        (any of ($zh_cred_*) and $form)
}

rule Phish_HTML_Login_Page
{
    meta:
        category = "phishing_payload"
        severity = "high"
    strings:
        $doctype = /<(!doctype\s+)?html/i
        $pass = /<input[^>]*type=["']?password/i
        $submit = /(login|sign\s?in|verify|confirm)/i
    condition:
        $doctype and $pass and $submit
}

rule Malware_Macro_Office_Document
{
    meta:
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
        category = "phishing_template"
        severity = "medium"
        note = "defanged hxxp / URL userinfo / IP literal only; plain http is normal"
    strings:
        // 只匹配"去毒化"写法（hxxp / hXXp / hxxps）。**不要**写成 /h(x{2}|tt)p.../：
        // 那个交替里含 tt，等价于同时匹配普通 http://，而附件里任何 http:// 都会命中——
        // 实测照片/截图 JPEG 的 XMP 元数据里就有 http://ns.adobe.com/xap/1.0/，
        // 使正常求职简历 docx（内嵌图片）命中本规则，拿满 12 分并进钓鱼强信号集。
        $hxxp = /hxxp(s?):\/\//i
        $at_url = /https?:\/\/[^\s\/]+\@[^\s\/]+/i
        $ip_url = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
    condition:
        any of them
}
