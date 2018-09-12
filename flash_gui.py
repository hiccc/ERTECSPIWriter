# -*- coding: utf-8 -*-
"""
Author: Jie Ming
Date: 2018/08/24
"""

import time
import wx
import struct
import ctypes
import os
import ConfigParser

from pygdbmi.gdbcontroller import GdbController
from threading import Thread


class ExamplePanel(wx.Panel):
    def print_gdb_msg(self, list):
        for item in list:
            print(item['payload'])

    def file_size(self, fname):
        import os
        statinfo = os.stat(fname)
        return statinfo.st_size

    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.config = ConfigParser.ConfigParser()
        self.config.read('config.ini')
        self.gdbPath = self.config.get("basic", "gdb_file")
        self.filename = self.config.get("basic", "bin_file")

        self.labelGdb = wx.StaticText(self, label='GDB EXE:', pos=(20, 20))
        self.textGdb = wx.TextCtrl(self, value = self.gdbPath, pos=(120, 20), size=(400, -1))
        self.gdbButton = wx.Button(self, label='Browse', pos=(530, 17))
        self.Bind(wx.EVT_BUTTON, self.OpenGdbFile, self.gdbButton)
        self.textGdb.Disable()

        self.labelFile = wx.StaticText(self, label='Binary file:', pos=(20, 50))
        self.textFile = wx.TextCtrl(self, value=self.filename, pos=(120, 50), size=(400, -1))
        self.textFile.Disable()
        self.binButton = wx.Button(self, label='Browse', pos=(530, 47))
        self.Bind(wx.EVT_BUTTON, self.OpenFile, self.binButton)

        self.labelMACAddr = wx.StaticText(self, label='MAC Address:', pos=(20, 80))
        self.textMACAddr = wx.TextCtrl(self, value='80-20-cb-30-06-fc', pos=(120, 80), size=(140, -1))
        # 仅有1行的编辑控件
        self.labelIP = wx.StaticText(self, label='IP Address:', pos=(280, 80))
        self.textIPAddr = wx.TextCtrl(self, value='192.168.1.10', pos=(380, 80), size=(140, -1))

        self.labelMask = wx.StaticText(self, label='Subnet Mask:', pos=(20, 110))
        self.textSubMask = wx.TextCtrl(self, value='255.255.255.0', pos=(120, 110), size=(140, -1))

        self.labelMask = wx.StaticText(self, label='Default Router:', pos=(280, 110))
        self.textDefRouter = wx.TextCtrl(self, value='0.0.0.0', pos=(380, 110), size=(140, -1))

        # 一个按钮
        self.startButton = wx.Button(self, label='Start GDB', pos=(20, 150))
        self.Bind(wx.EVT_BUTTON, self.OnStartClick, self.startButton)

        self.flashButton = wx.Button(self, label='Flash', pos=(120, 150))
        self.Bind(wx.EVT_BUTTON, self.OnClick, self.flashButton)
        self.flashButton.Disable()

    def OnStartClick(self, event):
        self.gdbmi = GdbController(gdb_path=self.gdbPath,
                                   time_to_check_for_additional_output_sec=1)
        self.flashButton.Enable()
        self.gdbButton.Disable()
        self.binButton.Disable()
        self.startButton.Disable()

    def OnClick(self, event):
        self.flashButton.Disable()
        cmdList={}
        macStr = self.textMACAddr.GetValue()
        macSubStr = macStr.split('-', 6)
        valueStr1 = 'mon mww 0x200fffac 0x' + macSubStr[3] + macSubStr[2] + macSubStr[1] + macSubStr[0]
        valueStr2 = 'mon mww 0x200fffb0 0x0000' + macSubStr[5] + macSubStr[4]
        cmdList['mac1'] = valueStr1
        cmdList['mac2'] = valueStr2
        ipStr = self.textIPAddr.GetValue()
        ipSubStr = ipStr.split('.', 4)
        ipValue = int(ipSubStr[3])*256*256*256 + int(ipSubStr[2])*256*256
        ipValue = ipValue + int(ipSubStr[1]) * 256 + int(ipSubStr[0])
        valueStr3 = 'mon mww 0x200fffa8 0x' + "%08x" % ipValue
        cmdList['ip'] = valueStr3
        ipStr = self.textSubMask.GetValue()
        ipSubStr = ipStr.split('.', 4)
        ipValue = int(ipSubStr[3]) * 256 * 256 * 256 + int(ipSubStr[2]) * 256 * 256
        ipValue = ipValue + int(ipSubStr[1]) * 256 + int(ipSubStr[0])
        valueStr4 = 'mon mww 0x200fffa4 0x' + "%08x" % ipValue
        cmdList['mask'] = valueStr4
        ipStr = self.textDefRouter.GetValue()
        ipSubStr = ipStr.split('.', 4)
        ipValue = int(ipSubStr[3]) * 256 * 256 * 256 + int(ipSubStr[2]) * 256 * 256
        ipValue = ipValue + int(ipSubStr[1]) * 256 + int(ipSubStr[0])
        valueStr5 = 'mon mww 0x200fffa0 0x' + "%08x" % ipValue
        cmdList['router'] = valueStr5
        elfPath = os.path.join(os.path.dirname(__file__), 'ertec200p.elf')
        elfPathStr = elfPath.replace("\\","/")
        cmdList['elf'] = elfPathStr
        #print cmdList
        self.write_flash(cmdList)
        self.flashButton.Enable()
    def OpenGdbFile(self, event):
        print ('Open GDB exe file')
        file_exe = "exe file *.exe)|*.exe"
        dlg = wx.FileDialog(self, "Select GDB ...",
                            os.getcwd(), wildcard=file_exe)
        if dlg.ShowModal() == wx.ID_OK:
            self.gdbPath = dlg.GetPath()
            self.textGdb.SetValue(self.gdbPath)
            print self.gdbPath
            self.config.set("basic", "gdb_file",self.gdbPath)
            with open('config.ini','wb') as confFile:
                self.config.write(confFile)

    def OpenFile(self, event):
        print ('Open Binary file')
        file_binary = "Binary file **.bin)|*.bin"
        dlg = wx.FileDialog(self,"Open binary file...",
                            os.getcwd(),wildcard=file_binary)
        if dlg.ShowModal() == wx.ID_OK:
            self.filename = dlg.GetPath()
            self.textFile.SetValue(self.filename)
            print self.filename
            self.config.set("basic", "bin_file", self.filename)
            with open('config.ini','wb') as confFile:
                self.config.write(confFile)

    def write_flash(self, cmdlist):
        response = self.gdbmi.write('file ' + cmdlist['elf'])
        self.print_gdb_msg(response)
        self.gdbmi.write('target remote localhost:2331', timeout_sec=0.5)
        self.gdbmi.write('mon reset 0', timeout_sec=0.5)
        self.gdbmi.write('mon speed 30', timeout_sec=0.5)
        self.gdbmi.write('mon endian little', timeout_sec=0.5)
        self.gdbmi.write('mon reset', timeout_sec=0.5)
        self.gdbmi.write('mon reg cpsr = 0xd3', timeout_sec=0.5)
        self.gdbmi.write('mon speed 12000', timeout_sec=0.5)
        self.gdbmi.write('mon mww 0x4000f078 0x005fffff', timeout_sec=0.5)
        self.gdbmi.write('mon mww 0x10d00004 0x40000080', timeout_sec=0.5)
        self.gdbmi.write('mon mww 0x10d0000c 0x000003d0', timeout_sec=0.5)
        self.gdbmi.write('mon mww 0x10d00010 0x3ffffff1', timeout_sec=0.5)
        self.gdbmi.write('mon mww 0x10d00014 0x3ffffff1', timeout_sec=0.5)
        self.gdbmi.write('mon mww 0x10d00018 0x3ffffff1', timeout_sec=0.5)
        self.gdbmi.write('mon mww 0x10d0001c 0x3ffffff1', timeout_sec=0.5)
        self.gdbmi.write('mon mww 0x10d00020 0x01974700', timeout_sec=0.5)
        self.gdbmi.write('mon mww 0x10d00028 0x0', timeout_sec=0.5)
        self.gdbmi.write('mon mww 0x10d0002c 0x0', timeout_sec=0.5)
        self.gdbmi.write('mon mww 0x10d00030 0x42', timeout_sec=0.5)
        self.gdbmi.write('mon mww 0x10d00008 0x00002522', timeout_sec=0.5)
        self.gdbmi.write('mon mww 0x4000F030 0x00000001', timeout_sec=0.5)
        self.gdbmi.write(cmdlist['mac1'], timeout_sec=0.5)
        self.gdbmi.write(cmdlist['mac2'], timeout_sec=0.5)
        self.gdbmi.write(cmdlist['ip'], timeout_sec=0.5)
        self.gdbmi.write(cmdlist['mask'], timeout_sec=0.5)
        self.gdbmi.write(cmdlist['router'], timeout_sec=0.5)
        response = self.gdbmi.write('restore '+self.filename+' binary 0x20100000')
        time.sleep(20)
        self.print_gdb_msg(response)
        with open(self.filename, mode='rb') as binary_file:
            bin_size = self.file_size(self.filename)
            print("File size in bytes of a binary file: ", bin_size)
            binary_file.seek(bin_size - 2)
            szieFlashBoot0 = binary_file.read(1)
            szieFlashBoot1 = binary_file.read(1)
            byte0 = struct.unpack("B", szieFlashBoot1)
            byte1 = struct.unpack("B", szieFlashBoot0)
            cmdStr = "mon mww 0x200fffb8 0x%02x" % byte1
            cmdStr = cmdStr + "%02x" % byte0
            cmdStr = cmdStr + "5a00"
            print cmdStr
            self.gdbmi.write(cmdStr, timeout_sec=0.5)
            cmdStr = "mon mww 0x200fffb4 0x%08x" % (bin_size + 47)
            print cmdStr
            self.gdbmi.write(cmdStr, timeout_sec=0.5)
            binary_file.close()
        response = self.gdbmi.write('load')
        time.sleep(5)
        self.print_gdb_msg(response)
        response = self.gdbmi.write('cont')
        time.sleep(85)
        self.print_gdb_msg(response)
        #response = self.gdbmi.exit()

if __name__ == "__main__":
    app = wx.App(False)
    frame = wx.Frame(None, wx.ID_ANY, "ERTEC200P/200P-2 SPI Flash Writer",size=(700,250))
    panel = ExamplePanel(frame)
    frame.Show()
    app.MainLoop()
