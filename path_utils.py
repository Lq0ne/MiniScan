# -*- coding: utf-8 -*-
"""
路径工具模块
用于处理打包后的路径问题，确保config和tools文件夹可以被正确访问
"""
import os
import sys


def get_base_dir():
    """
    获取程序基础目录
    如果是打包后的exe，返回exe所在目录
    如果是开发环境，返回脚本所在目录
    """
    if getattr(sys, 'frozen', False):
        # 打包后的exe环境
        base_dir = os.path.dirname(sys.executable)
    else:
        # 开发环境
        base_dir = os.path.dirname(os.path.abspath(__file__))
    return base_dir


def get_config_path(filename="config.yaml"):
    """
    获取配置文件路径
    config文件夹应该位于exe同目录下
    """
    base_dir = get_base_dir()
    config_path = os.path.join(base_dir, "config", filename)
    return config_path


def get_tools_path(filename=""):
    """
    获取tools文件夹路径或文件路径
    tools文件夹应该位于exe同目录下
    """
    base_dir = get_base_dir()
    if filename:
        return os.path.join(base_dir, "tools", filename)
    return os.path.join(base_dir, "tools")


def get_relative_path(*paths):
    """
    获取相对于基础目录的路径
    """
    base_dir = get_base_dir()
    return os.path.join(base_dir, *paths)


def ensure_dir_exists(dir_path):
    """
    确保目录存在，如果不存在则创建
    """
    if not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)
    return dir_path

