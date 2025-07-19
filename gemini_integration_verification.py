#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
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
        return None

# 测试响应
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

response2 = '''
{
    "candidates": [
        {
            "content": {
                "parts": [
                    {
                        "text": "{\\"res\\":\\"false\\", \\"reason\\":\\"权限验证失败\\"}"
                    }
                ]
            }
        }
    ]
}
'''

# 定义解析模式
RES_FIELD_PATTERN = re.compile(r'[\'\"]res[\'\"]:\s*[\'\"](\w+)[\'\"]', re.IGNORECASE)

def extract_res_value_improved(response_string):
    """改进的 res 值提取函数"""
    try:
        # 步骤 1：使用 JSON 解析提取 text 内容
        text_content = extract_gemini_text(response_string)
        if not text_content:
            return ""
        
        print("提取的 text 内容：", repr(text_content))
        
        # 步骤 2：解码转义字符
        text_content = text_content.replace('\\n', '\n').replace('\\\"', '\"').replace('\\\\', '\\')
        print("解码后的 text 内容：", repr(text_content))
        
        # 步骤 3：搜索 res 字段
        res_match = RES_FIELD_PATTERN.search(text_content)
        if res_match:
            print("✅ 通过正则找到 res:", res_match.group(1))
            return res_match.group(1).lower()
        
        # 步骤 4：尝试 JSON 解析
        if '{' in text_content and '}' in text_content:
            json_start = text_content.find('{')
            json_end = text_content.rfind('}') + 1
            json_str = text_content[json_start:json_end]
            print("提取 JSON 字符串：", repr(json_str))
            
            try:
                parsed = json.loads(json_str)
                if 'res' in parsed:
                    print("✅ 通过 JSON 解析找到 res:", parsed['res'])
                    return str(parsed['res']).lower()
            except Exception as e:
                print("JSON 解析失败：", str(e))
        
        return ""
    except Exception as e:
        print("解析错误：", str(e))
        return ""

print("=== 测试响应 1 ===")
result1 = extract_res_value_improved(response1.strip())
print("最终结果：", result1)

print("\n=== 测试响应 2 ===")
result2 = extract_res_value_improved(response2.strip())
print("最终结果：", result2)
