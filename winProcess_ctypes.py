# coding=utf-8

'''
    python 修改内存
'''

import win32process  # 进程模块  需要安装 pywin32 包
import win32con  # 系统定义
import win32api  # 调用系统模块
import ctypes  # C语言类型
import win32gui  # 界面

PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)  # 一个常量，标识最高权限打开一个程序
window = win32gui.FindWindow('MainWindow', '植物大战僵尸中文版')  # 查找窗体
hid, pid = win32process.GetWindowThreadProcessId(window)  # 根据窗体抓取进程编号
phand = win32api.OpenProcess(PROCESS_ALL_ACCESS, False, pid)  # 用最高权限打开进程线程
date = ctypes.c_long()  # C语言的整数类型，读取数据
mydll = ctypes.windll.LoadLibrary('C:\\Windows\\System32\\kernel32.dll')  # 加载内核模块
mydll.ReadProcessMemory(int(phand), 405455088, ctypes.byref(date), 4, None)  # 读取内存（内存地址是:405455088）
print(date.value)
newdata = ctypes.c_long(10010)  # 修改内存数据为10010
mydll.WriteProcessMemory(int(phand), 405455088, ctypes.byref(newdata), 4, None)  # 修改内存地址
