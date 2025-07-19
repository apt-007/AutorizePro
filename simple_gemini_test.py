#!/import json
import re

def extract_gemini_text(response_string):
    """使用 JSON 解析提取 Gemini 响应中的 text 内容"""
    try:
        # 直接解析 JSON 响应
        parsed = json.loads(response_string)
        
        # 导航到 text 字段
        if 'candidates' in parsed:
            for candidate in parsed['candidates']:
                if 'content' in candidate:
                    content = candidate['content']
                    if 'parts' in content:
                        for part in content['parts']:
                            if 'text' in part:
                                return part['text']
        return None
    except Exception as e:
        print("JSON 解析失败：", str(e))
        return Nonen/env python3
# -*- coding: utf-8 -*-

import json
import re

# 定义解析模式 - 修复：处理多行 JSON 和换行符
GEMINI_TEXT_PATTERN = re.compile(r'"text":\s*"([^"]*(?:\\.[^"]*)*)"', re.DOTALL)
RES_FIELD_PATTERN = re.compile(r'[\'\"]res[\'\"]:\s*[\'\"](\w+)[\'\"]', re.IGNORECASE)

# 测试响应 1
response1 = '''
{
    "candidates": [
        {
            "content": {
                "parts": [
                    {
                        "text": "分析结果：{\\"res\\":\\"true\\", \\"reason\\":\\"响应结构一致，判定越权成功\\"}"
                    }
                ]
            }
        }
    ]
}
'''

print("=== 完整测试流程 ===")
print("1. 查找 text 字段...")

gemini_text_match = GEMINI_TEXT_PATTERN.search(response1)
if gemini_text_match:
    text_content = gemini_text_match.group(1)
    print("2. 提取的 text 内容（原始）:", repr(text_content))
    
    # 解码转义字符
    text_content = text_content.replace('\\n', '\n').replace('\\\"', '\"').replace('\\\\', '\\')
    print("3. 解码后的 text 内容：", repr(text_content))
    
    # 搜索 res 字段
    res_in_text = RES_FIELD_PATTERN.search(text_content)
    if res_in_text:
        print("4. ✅ 找到 res 字段：", res_in_text.group(1))
        final_result = res_in_text.group(1).lower()
        print("5. 最终结果：", final_result)
    else:
        print("4. ❌ 未找到 res 字段")
        print("   尝试 JSON 解析...")
        
        if '{' in text_content and '}' in text_content:
            json_start = text_content.find('{')
            json_end = text_content.rfind('}') + 1
            json_str = text_content[json_start:json_end]
            print("   JSON 字符串：", repr(json_str))
            
            try:
                parsed = json.loads(json_str)
                if 'res' in parsed:
                    final_result = str(parsed['res']).lower()
                    print("5. ✅ JSON 解析成功，结果：", final_result)
                else:
                    print("5. ❌ JSON 中没有 res 字段")
            except Exception as e:
                print("5. ❌ JSON 解析失败：", str(e))
else:
    print("2. ❌ 未找到 text 字段")

print("\n=== 测试响应 2（简单格式）===")
response2 = '''
{
    "candidates": [
        {
            "content": {
                "parts": [
                    {
                        "text": "{"res":"false", "reason":"权限验证失败"}"
                    }
                ]
            }
        }
    ]
}
'''

gemini_text_match = GEMINI_TEXT_PATTERN.search(response2)
if gemini_text_match:
    text_content = gemini_text_match.group(1)
    print("提取的 text 内容：", repr(text_content))
    
    res_in_text = RES_FIELD_PATTERN.search(text_content)
    if res_in_text:
        print("✅ 找到 res 字段：", res_in_text.group(1))
    else:
        print("❌ 未找到 res 字段")
else:
    print("❌ 未找到 text 字段")
