# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Injector_exe_ui.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(341, 499)
        self.gridLayout = QtWidgets.QGridLayout(Form)
        self.gridLayout.setObjectName("gridLayout")
        self.tableWidget_exe = QtWidgets.QTableWidget(Form)
        self.tableWidget_exe.setObjectName("tableWidget_exe")
        self.tableWidget_exe.setColumnCount(2)
        self.tableWidget_exe.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget_exe.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget_exe.setHorizontalHeaderItem(1, item)
        self.gridLayout.addWidget(self.tableWidget_exe, 0, 0, 1, 1)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Exe窗口进程选择"))
        item = self.tableWidget_exe.horizontalHeaderItem(0)
        item.setText(_translate("Form", "PID"))
        item = self.tableWidget_exe.horizontalHeaderItem(1)
        item.setText(_translate("Form", "窗口名称"))
