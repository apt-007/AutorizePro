#!/usr/bin/env python3
# coding: utf-8

"""
@File   : language_manager.py
@Author : sule01u
@Date   : 2024/10/10
@Desc   : 语言管理器，负责国际化文本的获取和语言切换
"""

class LanguageManager:
    """语言管理器类，负责加载不同语言的资源文件并提供文本获取接口"""
    
    def __init__(self):
        self.current_language = "en"  # 默认英文
        self.strings = {}
        self.load_language()
    
    def set_language(self, language_code):
        """设置当前语言
        
        Args:
            language_code: 语言代码，支持 "en"(英文) 和 "zh"(中文)
        """
        if language_code in ["en", "zh"]:
            self.current_language = language_code
            self.load_language()
            return True
        return False
    
    def load_language(self):
        """根据当前选择的语言加载对应的资源文件"""
        try:
            if self.current_language == "zh":
                from localization.strings_zh import STRINGS
            else:
                from localization.strings_en import STRINGS
            self.strings = STRINGS
        except ImportError:
            # 如果加载失败，使用默认的英文
            from localization.strings_en import STRINGS
            self.strings = STRINGS
    
    def get_text(self, key, default=""):
        """获取指定键的本地化文本
        
        Args:
            key: 文本资源键名
            default: 如果键不存在时返回的默认值
            
        Returns:
            本地化的文本字符串
        """
        text = self.strings.get(key, default)
        
        # 处理中文字符串在Jython环境中的编码问题
        if self.current_language == "zh":
            try:
                # 尝试将Unicode字符串解码为UTF-8，然后再编码为Java环境使用的字符集
                return self._fix_encoding(text)
            except Exception:
                pass
        return text
    
    def _fix_encoding(self, text):
        """处理中文字符串编码问题
        
        在Jython环境中，中文字符可能需要特殊处理以正确显示
        """
        try:
            # 尝试使用Java String方法确保正确编码
            from java.lang import String
            if isinstance(text, unicode):
                # 如果已经是unicode，直接转换为Java String
                return String(text)
            else:
                # 如果是str类型，先解码为unicode，再转换为Java String
                return String(text.decode('utf-8'))
        except ImportError:
            # 如果不在Jython环境中，直接返回原文本
            return text
        except Exception:
            # 处理过程中出现任何错误，返回原文本
            return text

# 创建全局语言管理器实例
_language_manager = LanguageManager()

def get_language_manager():
    """获取全局语言管理器实例"""
    return _language_manager

def get_text(key, default=""):
    """便捷函数，直接获取指定键的本地化文本"""
    return _language_manager.get_text(key, default) 