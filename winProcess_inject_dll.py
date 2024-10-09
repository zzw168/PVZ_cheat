'''
    python 注入器
'''

import os
import sys

import psutil
from ctypes import *

import win32api
import win32event
import win32gui
import win32process
from win32gui import *

from PyQt5 import QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QWidget, QHeaderView, QAbstractItemView, \
    QTableWidgetItem, QPushButton

import Injector_ui
import Injector_exe_ui
import winProcess_get32Model


def is_number(s):
    try:  # 如果能运行float(s)语句，返回True（字符串s是浮点数）
        float(s)
        return True
    except ValueError:  # ValueError为Python的一种标准异常，表示"传入无效的参数"
        pass  # 如果引发了ValueError这种异常，不做任何事情（pass：不做任何事情，一般用做占位语句）
    try:
        import unicodedata  # 处理ASCii码的包
        unicodedata.numeric(s)  # 把一个表示数字的字符串转换为浮点数返回的函数
        return True
    except (TypeError, ValueError):
        pass
    return False


def inject_dll(pro_name, dll_path):
    if pro_name == "" or dll_path == "":
        return
    dll_path = bytes(dll_path, encoding="utf8")  # 注意！！一定要做ascii编码转换
    print(dll_path)

    dll_len = len(dll_path)
    # kernel32 = windll.kernel32
    kernel32 = windll.LoadLibrary("kernel32.dll")
    STANDARD_RIGHTS_REQUIRED = 0x000F0000
    SYNCHRONIZE = 0x00100000
    PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF)

    PAGE_EXECUTE_READWRITE = 0x00000040
    VIRTUAL_MEM = (0x1000 | 0x2000)

    print(type(pro_name))
    if is_number(pro_name):
        target_pid = int(pro_name)
    else:
        # 第一步用psutil获取整个系统的进程快照
        pids = psutil.pids()
        # 第二步在快照中去比对给定的进程名
        target_pid = None
        for pid in pids:
            try:
                p = psutil.Process(pid)
                if pro_name and p.name() == pro_name:
                    target_pid = pid
                    break
            except:
                continue
    if target_pid is None:
        print("无法找到名为 %s 的进程" % pro_name)
        ui.textBrowser_msg.append("无法找到名为 %s 的进程" % pro_name)

        return
    else:
        print("发现名为 %s 的进程，进程ID: %s" % (pro_name, target_pid))
        ui.textBrowser_msg.append("发现名为 %s 的进程，进程ID: %s" % (pro_name, target_pid))

    # 第三步用kernel32.OpenProcess 打开指定pid进程获取句柄
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(target_pid))
    if not h_process:
        print("无法获取目标进程的句柄，需要提升权限")
        ui.textBrowser_msg.append("无法获取目标进程的句柄，需要提升权限")
        return

    # 第四步 kernel32.VirtualAllocEx 在目标进程开辟内存空间（用于存放dll的路径）
    arg_adress = kernel32.VirtualAllocEx(h_process, None, dll_len, VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
    written = c_int(0)

    # 第五步用kernel32.WriteProcessMemory 在目标进程内存空间写入dll路径（ascii码）
    write_ok = kernel32.WriteProcessMemory(h_process, arg_adress, dll_path, dll_len, byref(written))
    if write_ok != 0:
        print("向目标进程写入 %d 字节成功\n内存地址: %#x" % (written.value, arg_adress))
        ui.textBrowser_msg.append("向目标进程写入 %d 字节成功\n内存地址: %#x" % (written.value, arg_adress))
    else:
        print("向目标进程写入失败，检查写入地址")
        ui.textBrowser_msg.append("向目标进程写入失败，检查写入地址")
        win32api.CloseHandle(h_process)
        return
    # 第六步获取 kernel32.dll 中 LoadLibraryA (注意对于所有应用程序 LoadLibraryA 的地址是一致的）

    h_kernel32 = win32api.GetModuleHandle("kernel32.dll")
    h_loadlib = win32api.GetProcAddress(h_kernel32, "LoadLibraryA")

    # 第七步用 kernel32.CreateRemoteThread 在目标进程中创建远程线程并用 LoadLibraryW 加载 dll
    thread_id = c_ulong(0)
    handle = kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib, arg_adress, 0, byref(thread_id))
    if handle != 0:
        print("创建远程线程成功， 句柄：%s ,线程id：%s" % (handle, thread_id))
        win32event.WaitForSingleObject(handle, 10)  # 等待线程信号10秒

        ui.textBrowser_msg.append("创建远程线程成功， 句柄：%s ,线程id：%s" % (handle, thread_id))
        show_model(pro_name)
    else:
        print("远程线程创建失败，请注意32/64位匹配")
        ui.textBrowser_msg.append("远程线程创建失败，请注意32/64位匹配")

    # 第八步关闭资源
    win32api.CloseHandle(h_process)
    win32api.CloseHandle(handle)

    return h_kernel32


# 卸载 DLL 模块
def free_dll(pro_name, dll_name):
    if pro_name == "" or dll_name == "":
        return

    kernel32 = windll.LoadLibrary("kernel32.dll")
    STANDARD_RIGHTS_REQUIRED = 0x000F0000
    SYNCHRONIZE = 0x00100000
    PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF)

    PAGE_EXECUTE_READWRITE = 0x00000040
    VIRTUAL_MEM = (0x1000 | 0x2000)

    print(type(pro_name))
    if is_number(pro_name):
        target_pid = int(pro_name)
    else:
        # 第一步用psutil获取整个系统的进程快照
        pids = psutil.pids()
        # 第二步在快照中去比对给定的进程名
        target_pid = None
        for pid in pids:
            try:
                p = psutil.Process(pid)
                if pro_name and p.name() == pro_name:
                    target_pid = pid
                    break
            except:
                continue
    if target_pid is None:
        print("无法找到名为 %s 的进程" % pro_name)
        ui.textBrowser_msg.append("无法找到名为 %s 的进程" % pro_name)

        return
    else:
        print("发现名为 %s 的进程，进程ID: %s" % (pro_name, target_pid))
        ui.textBrowser_msg.append("发现名为 %s 的进程，进程ID: %s" % (pro_name, target_pid))

    # 第三步用kernel32.OpenProcess 打开指定pid进程获取句柄
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(target_pid))
    if not h_process:
        print("无法获取目标进程的句柄，需要提升权限")
        ui.textBrowser_msg.append("无法获取目标进程的句柄，需要提升权限")
        return

    # 第四步，获取DLL模块的地址
    ModuleBaseAddr = winProcess_get32Model.GetProcessImageBase(target_pid, dll_name)
    if ModuleBaseAddr == 0:
        return
    print(hex(ModuleBaseAddr))

    # 第六步获取 kernel32.dll 中 FreeLibrary (注意对于所有应用程序 FreeLibrary 的地址是一致的）

    h_kernel32 = win32api.GetModuleHandle("kernel32.dll")
    h_loadlib = win32api.GetProcAddress(h_kernel32, "FreeLibrary")

    # 第七步用 kernel32.CreateRemoteThread 在目标进程中创建远程线程并调用 FreeLibrary 函数卸载 dll
    thread_id = c_ulong(0)
    handle = kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib, ModuleBaseAddr, 0, byref(thread_id))
    if handle != 0:
        print("创建远程线程成功， 句柄：%s ,线程id：%s" % (handle, thread_id))
        win32event.WaitForSingleObject(handle, 10)  # 等待线程信号10秒

        ui.textBrowser_msg.append("创建远程线程成功， 句柄：%s ,线程id：%s" % (handle, thread_id))
        show_model(pro_name)
    else:
        print("远程线程创建失败，请注意32/64位匹配")
        ui.textBrowser_msg.append("远程线程创建失败，请注意32/64位匹配")

    # 第八步关闭资源
    win32api.CloseHandle(h_process)
    win32api.CloseHandle(handle)

    return h_kernel32


titles = set()


def foo(hwnd, mouse):
    # 去掉下面这句就所有都输出了，但是我不需要那么多
    if IsWindow(hwnd) and IsWindowEnabled(hwnd) and IsWindowVisible(hwnd):
        titles.add(GetWindowText(hwnd))


def get_exe():
    EnumWindows(foo, 0)  # 枚举窗口
    lt = [t for t in titles if t]
    lt.sort()
    table = ui_child.tableWidget_exe
    table.setRowCount(0)
    for t in lt:
        print(t)
        handle = win32gui.FindWindow(None, t)
        pid = win32process.GetWindowThreadProcessId(handle)[1]
        print(pid)

        i = table.rowCount()
        num = i + 1
        table.setRowCount(num)

        exe_name = QTableWidgetItem(t)
        exe_name.setTextAlignment(Qt.AlignCenter)
        exe_name.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
        table.setItem(i, 1, exe_name)

        exe_pid = QTableWidgetItem(str(pid))
        exe_pid.setTextAlignment(Qt.AlignCenter)
        exe_pid.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
        table.setItem(i, 0, exe_pid)


def get_dll():
    download_file = QtWidgets.QFileDialog.getOpenFileName(
        caption='Select Dll File',
        directory=os.getcwd(),
        options=QFileDialog.DontUseNativeDialog,
        filter="dll(*.dll)")
    # print(type(download_path))
    s = download_file[0].replace('/', '\\')
    if s != "":
        print(s)
        ui.lineEdit_dll.setText(s)
        ui.textBrowser_msg.append(s)


def run_inject():  # 注入DLL
    pro_name = ui.lineEdit_exe.text()
    dll_path = ui.lineEdit_dll.text()
    inject_dll(pro_name, dll_path)


def run_free():  # 卸载DLL
    pro_name = ui.lineEdit_exe.text()
    dll_path = ui.lineEdit_dll.text()
    free_dll(pro_name, dll_path)


def show_model(pro_name):
    if is_number(pro_name):
        target_pid = int(pro_name)
    else:
        # 第一步用psutil获取整个系统的进程快照
        pids = psutil.pids()
        # 第二步在快照中去比对给定的进程名
        target_pid = None
        for pid in pids:
            try:
                p = psutil.Process(pid)
                if pro_name and p.name() == pro_name:
                    target_pid = pid
                    break
            except:
                continue
    if target_pid is None:
        print("无法找到名为 %s 的进程" % pro_name)
        ui.textBrowser_msg.append("无法找到名为 %s 的进程" % pro_name)

        return
    else:
        print("发现名为 %s 的进程，进程ID: %s" % (pro_name, target_pid))

    moduleMsg = winProcess_get32Model.GetModuleSnap(target_pid)
    print(moduleMsg)
    if moduleMsg == 'Error':
        return
    table = ui.tableWidget_model
    # table.clear()
    num = len(moduleMsg)
    table.setRowCount(num)
    for i in range(0, num):
        model_name = QTableWidgetItem(str(moduleMsg[i][0]))
        model_name.setTextAlignment(Qt.AlignCenter)
        model_name.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
        table.setItem(i, 1, model_name)

        model_pid = QTableWidgetItem(str(moduleMsg[i][1]))
        model_pid.setTextAlignment(Qt.AlignCenter)
        model_pid.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
        table.setItem(i, 0, model_pid)

        model_modBaseSize = QTableWidgetItem(str(moduleMsg[i][2]))
        model_modBaseSize.setTextAlignment(Qt.AlignCenter)
        model_modBaseSize.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
        table.setItem(i, 2, model_modBaseSize)

        data = str(moduleMsg[i][3])
        print(data)
        model_szExePath = QTableWidgetItem(data)
        model_szExePath.setTextAlignment(Qt.AlignCenter)
        model_szExePath.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
        table.setItem(i, 3, model_szExePath)


class My_Gui(Injector_ui.Ui_MainWindow):
    def __init__(self):
        super().__init__()

        # Custom output stream.

    def tw_dll_doubleclicked(self):
        table = self.tableWidget_model
        i = table.currentRow()
        s = table.item(i, 1).text()
        ui.lineEdit_dll.setText(s)
        ui.textBrowser_msg.append("卸载DLL名称: %s" % s)

    def setupUi(self, MainWindow):
        super().setupUi(MainWindow)

        p = psutil.Process(os.getpid())
        # 进程名称

        MainWindow.setWindowTitle(p.name())
        self.pushButton_exe.clicked.connect(self.show_child)

        table = self.tableWidget_model

        font = QFont('微软雅黑', 9)
        font.setBold(True)  # 设置字体加粗
        table.horizontalHeader().setFont(font)  # 设置表头字体
        # 为font设置的字体样式

        # table.setFrameShape(QFrame.NoFrame)  ##设置无表格的外框
        table.horizontalHeader().setFixedHeight(25)  ##设置表头高度
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)  # 设置第五列宽度自动调整，充满屏幕
        # table.horizontalHeader().setStretchLastSection(True)  ##设置最后一列拉伸至最大
        # table.setSelectionMode(QAbstractItemView.SingleSelection)  # 设置只可以单选，可以使用ExtendedSelection进行多选
        table.setSelectionBehavior(QAbstractItemView.SelectRows)  # 设置 不可选择单个单元格，只可选择一行。
        table.horizontalHeader().resizeSection(0, 120)  # 设置第一列的宽度为200
        table.horizontalHeader().resizeSection(1, 150)  # 设置第一列的宽度为200
        table.horizontalHeader().resizeSection(2, 100)  # 设置第一列的宽度为200
        table.setSortingEnabled(True)  # 设置表头可以自动排序
        self.tableWidget_model.doubleClicked.connect(self.tw_dll_doubleclicked)

    def show_child(self):
        Widget_Child.show()
        get_exe()


class Child(Injector_exe_ui.Ui_Form):
    def __init__(self):
        super().__init__()

    def tw_exe_doubleclicked(self):
        table = ui_child.tableWidget_exe
        i = table.currentRow()
        s = table.item(i, 0).text()
        ui.lineEdit_exe.setText(s)
        ui.textBrowser_msg.append("添加进程PID: %s" % s)
        show_model(s)
        Widget_Child.hide()

    def setupUi(self, Form):
        super().setupUi(Form)
        table = self.tableWidget_exe

        font = QFont('微软雅黑', 10)
        font.setBold(True)  # 设置字体加粗
        table.horizontalHeader().setFont(font)  # 设置表头字体
        # 为font设置的字体样式

        # table.setFrameShape(QFrame.NoFrame)  ##设置无表格的外框
        table.horizontalHeader().setFixedHeight(25)  ##设置表头高度
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)  # 设置第五列宽度自动调整，充满屏幕
        # table.horizontalHeader().setStretchLastSection(True)  ##设置最后一列拉伸至最大
        # table.setSelectionMode(QAbstractItemView.SingleSelection)  # 设置只可以单选，可以使用ExtendedSelection进行多选
        table.setSelectionBehavior(QAbstractItemView.SelectRows)  # 设置 不可选择单个单元格，只可选择一行。
        table.horizontalHeader().resizeSection(0, 100)  # 设置第一列的宽度为200
        table.setSortingEnabled(True)  # 设置表头可以自动排序

        self.tableWidget_exe.doubleClicked.connect(self.tw_exe_doubleclicked)


#
if __name__ == '__main__':
    # inject_dll("1234", "test_dll.dll")
    app = QApplication(sys.argv)
    MainWindow = QMainWindow()
    ui = My_Gui()
    ui.setupUi(MainWindow)
    MainWindow.show()

    Widget_Child = QWidget()
    ui_child = Child()
    ui_child.setupUi(Widget_Child)
    Widget_Child.hide()

    ui.pushButton_dll.clicked.connect(get_dll)
    ui.pushButton_inject.clicked.connect(run_inject)
    ui.pushButton_free.clicked.connect(run_free)

    sys.exit(app.exec_())
