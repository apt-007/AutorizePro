#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
print("Python version:", sys.version)

try:
    from localization.ui_updater import update_main_ui, update_table_headers
    print("成功导入update_main_ui和update_table_headers函数")
except ImportError as e:
    print("导入错误:", e)

print("测试完成") 