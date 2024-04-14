import tkinter as tk
import tkinter.font as tkFont
import subprocess
import os
import signal 
class App:
    def __init__(self, root):
        #setting title
        root.title("NetPackt Vulnerability assesment tool")
        #setting window size
        width=600
        height=300
        screenwidth = root.winfo_screenwidth()
        screenheight = root.winfo_screenheight()
        alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        root.geometry(alignstr)
        root.resizable(width=False, height=False)

        GButton_255=tk.Button(root)
        GButton_255["bg"] = "#f0f0f0"
        ft = tkFont.Font(family='Times',size=10)
        GButton_255["font"] = ft
        GButton_255["fg"] = "#000000"
        GButton_255["justify"] = "center"
        GButton_255["text"] = "Start"
        GButton_255.place(x=70,y=230,width=144,height=52)
        GButton_255["command"] = lambda: self.start_button(0)

        GButton_863=tk.Button(root)
        GButton_863["bg"] = "#f0f0f0"
        ft = tkFont.Font(family='Times',size=10)
        GButton_863["font"] = ft
        GButton_863["fg"] = "#000000"
        GButton_863["justify"] = "center"
        GButton_863["text"] = "Stop"
        GButton_863.place(x=360,y=230,width=138,height=54)
        GButton_863["command"] = lambda: self.start_button(1)

        GLabel_639=tk.Label(root)
        ft = tkFont.Font(family='Times',size=10)
        GLabel_639["font"] = ft
        GLabel_639["fg"] = "#333333"
        GLabel_639["justify"] = "center"
        GLabel_639["text"] = "Status : "
        GLabel_639.place(x=70,y=60,width=70,height=25)

        GLabel_31=tk.Label(root)
        ft = tkFont.Font(family='Times',size=10)
        GLabel_31["font"] = ft
        GLabel_31["fg"] = "#333333"
        GLabel_31["justify"] = "center"
        GLabel_31["text"] = "Running"
        GLabel_31.place(x=210,y=60,width=70,height=25)

        GLineEdit_296=tk.Entry(root)
        GLineEdit_296["borderwidth"] = "1px"
        ft = tkFont.Font(family='Times',size=10)
        GLineEdit_296["font"] = ft
        GLineEdit_296["fg"] = "#333333"
        GLineEdit_296["justify"] = "center"
        GLineEdit_296["text"] = "Entry"
        GLineEdit_296.place(x=230,y=90,width=120,height=20)

        GLabel_159=tk.Label(root)
        ft = tkFont.Font(family='Times',size=10)
        GLabel_159["font"] = ft
        GLabel_159["fg"] = "#333333"
        GLabel_159["justify"] = "center"
        GLabel_159["text"] = "IP address : "
        GLabel_159.place(x=70,y=90,width=70,height=25)

    def start_button(self, status):
        s = subprocess.Popen(["python", "run.py"], shell=True)
        if status == 1:
             os.kill(s.pid, signal.SIGTERM)




if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
