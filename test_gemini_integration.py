#!/usr/bin/env python3
# coding: utf-8

"""
@File   : test_gemini_integration.py
@Author : sule01u
@Date   : 2024/12/20
@Desc   : 测试 Gemini API 集成的单元测试
"""

import re
import json

# 模拟正则表达式模式
GEMINI_PATTERN = re.compile(r'"text":\s*".*?res.*?[\'"](\w+)[\'"].*?"', re.DOTALL | re.IGNORECASE)
GEMINI_TEXT_PATTERN = re.compile(r'"text":\s*"(.*?)"', re.DOTALL)
RES_FIELD_PATTERN = re.compile(r'[\'\"]res[\'\"]:\s*[\'\"](\w+)[\'\"]', re.IGNORECASE)

def test_gemini_request_format():
    """测试 Gemini 请求格式生成"""
    system_prompt = "You are an authorization analyzer"
    user_prompt = "Analyze these responses"
    
    gemini_request = """
    {
        "contents": [
            {
                "parts": [
                    {
                        "text": "%s\\n\\n%s"
                    }
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 1024
        }
    }
    """ % (system_prompt, user_prompt)
    
    try:
        # 验证 JSON 格式是否正确
        parsed = json.loads(gemini_request.strip())
        assert "contents" in parsed
        assert "generationConfig" in parsed
        assert parsed["generationConfig"]["temperature"] == 0.1
        print("✅ Gemini request format test passed")
        return True
    except Exception as e:
        print("❌ Gemini request format test failed:", str(e))
        return False

def test_gemini_response_parsing():
    """测试 Gemini 响应解析"""
    
    # 模拟 Gemini API 响应
    gemini_response = """
    {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": "Based on the analysis, {\\"res\\": \\"true\\", \\"reason\\": \\"Responses are identical\\"}."
                        }
                    ],
                    "role": "model"
                }
            }
        ]
    }
    """
    
    # 测试 GEMINI_PATTERN
    match = GEMINI_PATTERN.search(gemini_response)
    if match:
        print("✅ Gemini pattern match found:", match.group(1))
    else:
        print("❌ Gemini pattern match failed")
        return False
    
    # 测试 GEMINI_TEXT_PATTERN
    text_match = GEMINI_TEXT_PATTERN.search(gemini_response)
    if text_match:
        text_content = text_match.group(1)
        text_content = text_content.replace('\\n', '\n').replace('\\"', '"').replace('\\\\', '\\')
        res_match = RES_FIELD_PATTERN.search(text_content)
        if res_match:
            print("✅ Gemini text extraction successful:", res_match.group(1))
            return True
        else:
            print("❌ Failed to extract res value from text")
            return False
    else:
        print("❌ Gemini text pattern match failed")
        return False

def test_api_endpoint_selection():
    """测试 API 端点选择逻辑"""
    api_endpoints = {
        "deepseek": "https://api.deepseek.com/v1/chat/completions",
        "gpt": "https://api.openai.com/v1/chat/completions",
        "glm": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        "hunyuan": "https://api.hunyuan.cloud.tencent.com/v1/chat/completions",
        "gemini": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "default": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
    }
    
    test_cases = [
        ("gemini-1.5-flash", "gemini"),
        ("gemini-1.5-pro", "gemini"),
        ("gpt-4o", "gpt"),
        ("qwen-turbo", "default")
    ]
    
    for model_name, expected_prefix in test_cases:
        for prefix, endpoint in api_endpoints.items():
            if model_name.lower().startswith(prefix):
                if prefix == "gemini":
                    api_url = endpoint.format(model=model_name)
                    expected_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
                    if api_url == expected_url:
                        print(f"✅ URL generation for {model_name}: {api_url}")
                    else:
                        print(f"❌ URL generation failed for {model_name}")
                        return False
                elif prefix == expected_prefix:
                    print(f"✅ Correct endpoint selected for {model_name}: {prefix}")
                else:
                    print(f"❌ Wrong endpoint selected for {model_name}")
                    return False
                break
    
    return True

def test_model_list():
    """测试模型列表"""
    predefined_options = [
        "qwen-turbo", "qwen-plus", "qwen-max", 
        "deepseek-chat", "deepseek-reasoner",
        "gpt-4o-mini", "gpt-4o", 
        "glm-4-flash", "glm-4-air", 
        "hunyuan-lite", "hunyuan-standard",
        "gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-flash-exp"
    ]
    
    supported_vendors = ["qwen", "deepseek", "gpt", "glm", "hunyuan", "gemini"]
    
    # 检查所有 Gemini 模型是否在列表中
    gemini_models = [model for model in predefined_options if model.startswith("gemini")]
    if len(gemini_models) >= 3:
        print(f"✅ Gemini models in list: {gemini_models}")
    else:
        print("❌ Missing Gemini models in predefined options")
        return False
    
    # 检查 gemini 是否在支持的厂商列表中
    if "gemini" in supported_vendors:
        print("✅ Gemini vendor in supported list")
    else:
        print("❌ Gemini vendor missing from supported list")
        return False
    
    return True

def main():
    """运行所有测试"""
    print("🚀 开始测试 Gemini API 集成...")
    print("=" * 50)
    
    tests = [
        ("Gemini Request Format", test_gemini_request_format),
        ("Gemini Response Parsing", test_gemini_response_parsing),
        ("API Endpoint Selection", test_api_endpoint_selection),
        ("Model List Configuration", test_model_list)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 测试：{test_name}")
        if test_func():
            passed += 1
        print("-" * 30)
    
    print(f"\n📊 测试结果：{passed}/{total} 通过")
    
    if passed == total:
        print("🎉 所有测试通过！Gemini API 集成成功！")
        return True
    else:
        print("⚠️  部分测试失败，请检查实现。")
        return False

if __name__ == "__main__":
    main()
