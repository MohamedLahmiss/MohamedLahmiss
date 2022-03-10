from tkinter import *
from tkinter import ttk
from tkinter import messagebox
import sqlite3
import cv2

def Help():
    img = cv2.imread("helpSearch.png")
    cv2.imshow("Image Aide", img)


def Informations():
    root4=Tk()
    root4.title("Informations :")
    root4.mainloop()
def displayAll():
    db = sqlite3.connect("SniffDataBase.db")
    cur = db.cursor()
    cur.execute("select * from InfoTrame")
    trame = cur.fetchall()
    for i in trame:
        tv1.insert('', END, values=(i))
    db.close()
    messagebox.showinfo("confirmation :", "Done !!")
def displayDetail():
    db = sqlite3.connect("SniffDataBase.db")
    cur = db.cursor()
    cur.execute("select * from DetailTrame")
    trame = cur.fetchall()
    for i in trame:
        tv2.insert('', END, values=(i))
    db.close()
    messagebox.showinfo("confirmation :", "vous avez enregistrer ces trames spécifiquement !!")

def delete():
    root6=Tk()
    root6.title("personnaliser la suppression :")
    root6.geometry('300x100')
    root6.maxsize(300, 100)
    root6.minsize(300, 100)
    b1=Button(root6,text='    tout    ',font=("arial",12),command=remove_All,bg="#EC9241",bd=2)
    b1.place(x=30,y=30)
    b2 = Button(root6, text='selection', font=("arial", 12),command=remove_selection, bg="#75EB0C", bd=2)
    b2.place(x=180, y=30)

def remove_All():
    for record in tv1.get_children():
        tv1.delete(record)
    for records in tv2.get_children():
        tv2.delete(records)
    messagebox.showinfo("confirmation :","contenue supprimé !!")
def remove_selection():
    for i in tv1.selection():
        tv1.delete(i)
    for j in tv2.selection():
        tv2.delete(j)
    messagebox.showinfo("confirmation :", "selection supprimée !!")

def search():
    select="SELECT * FROM InfoTrame "
    Where="where "
    date1=str(e1.get())
    date2=str(e2.get())
    ver=str(Combo1.get())
    prot=str(Combo2.get())
    ipsrc=str(e4.get())
    ipdst=str(e5.get())
    macsrc=str(e6.get())
    macdst=str(e7.get())
    listWhere=[]
    if date1 and date2 :
        Where11="Date between "+"'"+date1+"'"+" and "+"'"+date2+"'"
        listWhere.append(Where11)
    elif date1:
        Where12 = "Date" + "=" +"'"+ date1+"'"
        listWhere.append(Where12)
    elif date2:
        Where21 = "Date" + "=" +"'"+ date2+"'"
        listWhere.append(Where21)
    if ver:
        Where1 =  "Ipversion" + "=" + ver
        listWhere.append(Where1)
    if prot:
        Where2 =  "Protocole" + "=" + "'"+prot+"'"
        listWhere.append(Where2)
    if ipsrc:
        Where3 =  "IpSrc" + "=" + "'"+ipsrc+"'"
        listWhere.append(Where3)
    if ipdst:
        Where4 =  "IpDst" + "=" + "'"+ipdst+"'"
        listWhere.append(Where4)
    if macsrc:
        Where5 =  "MacSrc" + "=" + "'"+macsrc+"'"
        listWhere.append(Where5)
    if macdst:
        Where6 =  "MacDst" + "=" + "'"+macdst+"'"
        listWhere.append(Where6)
    Where=Where+" and ".join(listWhere)


    db = sqlite3.connect("SniffDataBase.db")
    cur = db.cursor()
    if Where!="where ":
        requette = select + Where
    else:
        requette = select
    cur.execute(requette)
    trame = cur.fetchall()
    for i in trame:
        tv1.insert('', END, values=(i))
    db.close()
    messagebox.showwarning("Warning :", "Attention !!")




root1=Tk()
root1.title("Interface d'inspection :")
root1.geometry("1300x700")
root1.maxsize(1300,700)
root1.minsize(1300,700)
root1.iconbitmap("2170040.ico")

menuBar=Menu(root1)
menuFile=Menu(menuBar)
menuBar.add_cascade(label="Fichier",menu=menuFile)
menuFile.add_command(label="Qitter",command=root1.destroy)
menuRech=Menu(menuBar)
menuBar.add_cascade(label="Capture",menu=menuRech)
menuRech.add_command(label="Vers interface de capture")
menuHelp=Menu(menuBar)
menuBar.add_cascade(label="Help",menu=menuHelp)
menuHelp.add_command(label="Vers Aide",command=Help)
menuInfo=Menu(menuBar)
menuBar.add_cascade(label="Info",menu=menuInfo)
menuInfo.add_command(label="Vers Informations",command=Informations)
root1.config(menu=menuBar)

l1 = Label(root1, text='Date 1    :', font=('arial', 11))
l1.place(x=10, y=20)
e1 = Entry(root1, text="1er date", bd=2, width=35)
e1.place(x=80, y=23)
l2 = Label(root1, text='Date 2    :', font=('arial', 11))
l2.place(x=350, y=20)
e2 = Entry(root1, text="2eme date", bd=2, width=35)
e2.place(x=420, y=23)
l3 = Label(root1, text='version :', font=('arial', 11))
l3.place(x=10, y=50)
versions=[4,6]
Combo1 = ttk.Combobox(root1, values=versions, width=32)
Combo1.place(x=80, y=53)
l4 = Label(root1, text='protocole:', font=('arial', 11))
l4.place(x=350, y=50)
protocoles=['TCP','UDP','ARP','ICMP','ICMPv6']
Combo2 = ttk.Combobox(root1, values=protocoles, width=32)
Combo2.place(x=420, y=53)
l5 = Label(root1, text='Ip src   :', font=('arial', 11))
l5.place(x=10, y=80)
e4 = Entry(root1, text="Ipsrc", bd=2, width=35)
e4.place(x=80, y=83)
l6 = Label(root1, text='Ip dst   :', font=('arial', 11))
l6.place(x=350, y=80)
e5 = Entry(root1, text="Ipdst", bd=2, width=35)
e5.place(x=420, y=83)
l7 = Label(root1, text='Mac src  :', font=('arial', 11))
l7.place(x=10, y=110)
e6 = Entry(root1, text="Macsrc", bd=2, width=35)
e6.place(x=80, y=113)
l8 = Label(root1, text='Mac dst  :', font=('arial', 11))
l8.place(x=350, y=110)
e7 = Entry(root1, text="Macdst", bd=2, width=35)
e7.place(x=420, y=113)

butt1 = Button(root1, text='    display All    ', font=("arial", 12),command=displayAll,bg="#67EB0C", bd=2)
butt1.place(x=700, y=20)
butt2 = Button(root1, text='      Search       ', font=("arial", 12),command=search,bg="#63F094", bd=2)
butt2.place(x=700, y=60)
butt3 = Button(root1, text='      Delete       ', font=("arial", 12),command=delete, bg="#F04744", bd=2)
butt3.place(x=900, y=20)
butt4 = Button(root1, text='       close        ', font=("arial", 12),command=root1.destroy,bg="#EF8C34", bd=2)
butt4.place(x=900, y=60)
butt5 = Button(root1, text='  display detail ', font=("arial", 12),command=displayDetail,bg="#34D6EF", bd=2)
butt5.place(x=700, y=100)
butt6 = Button(root1, text='       !!!!!!!!       ', font=("arial", 12),command=Help,bg="#E9EF34", bd=2)
butt6.place(x=900, y=100)

frame1=Frame(root1,width=900,height=250,highlightbackground="grey",highlightthicknes=1)
frame1.grid(row=0,column=0,padx=10,pady=150)

scroll1=Scrollbar(frame1,orient="vertical")
scroll1.pack(side=RIGHT,fill="y")

xscroll1=Scrollbar(frame1,orient="horizontal")
xscroll1.pack(side=BOTTOM,fill="x")

style=ttk.Style()
style.configure("Treeview",
    background="#9FECE4",
    foreground="black",
    fieldbackground="#9FECE4"
)
style.map('Treeview',background=[('selected','blue')])

tv1=ttk.Treeview(frame1,columns=("Date","Time","Version","Ipsrc","Ipdst","protocole","Macsrc","Macdst","Summary"),xscrollcommand=xscroll1.set,yscrollcommand=scroll1.set,selectmode="extended")

tv1.column("#0",minwidth=10,width=10)
tv1.column("Date",minwidth=80,width=120)
tv1.column("Time",minwidth=80,width=120)
tv1.column("Version",minwidth=20,width=80)
tv1.column("Ipsrc",minwidth=100,width=160)
tv1.column("Ipdst",minwidth=100,width=160)
tv1.column("protocole",minwidth=30,width=90)
tv1.column("Macsrc",minwidth=100,width=160)
tv1.column("Macdst",minwidth=100,width=160)
tv1.column("Summary",minwidth=100)

tv1.heading("#0",text="")
tv1.heading("Date",text="Date")
tv1.heading("Time",text="Time")
tv1.heading("Version",text="Ip version")
tv1.heading("Ipsrc",text="Ip source")
tv1.heading("Ipdst",text="Ip destination")
tv1.heading("protocole",text="Protocole")
tv1.heading("Macsrc",text="Mac source")
tv1.heading("Macdst",text="Mac destination")
tv1.heading("Summary",text="Summary")


tv1.pack()
scroll1.config(command=tv1.yview)
xscroll1.config(command=tv1.xview)

frame2=Frame(root1,width=900,height=250,highlightbackground="grey",highlightthicknes=1)
frame2.place(x=10,y=400)

scroll2=Scrollbar(frame2,orient="vertical")
scroll2.pack(side=RIGHT,fill="y")

xscroll2=Scrollbar(frame2,orient="horizontal")
xscroll2.pack(side=BOTTOM,fill="x")

tv2=ttk.Treeview(frame2,columns=("details"),xscrollcommand=xscroll2.set,yscrollcommand=scroll2.set,selectmode="extended")

tv2.column("#0",minwidth=10,width=10)
tv2.heading("#0",text="")
tv2.column("details",minwidth=800,width=1250)
tv2.heading("details",text="Détail du Trame")

tv2.pack()

scroll2.config(command=tv2.yview)
xscroll2.config(command=tv2.xview)

root1.mainloop()

'''def Okkkk():
    list=[]
    proto=str(Combo.get())
    host="host "+str(entry1.get())
    port="port "+str(Combo1.get())
    if proto:
        list.append(proto)
    if str(entry1.get()):
        list.append(host)
    if str(Combo1.get()):
        list.append(port)
    filter=" and ".join(list)
    entry2.delete(0, END)
    entry2.insert(0, filter)
    return filter
def confirm():
    filter=Okkkk()


root5=Tk()
root5.title("Interface de filtrage :")
root5.geometry("500x400")
root5.maxsize(500,400)
root5.minsize(500,400)

l1=Label(root5,text='Protocole   :',font=('arial',12))
l1.place(x=20,y=50)
l2=Label(root5,text='Port             :',font=('arial',12))
l2.place(x=20,y=100)
l3=Label(root5,text='Host            :',font=('arial',12))
l3.place(x=20,y=150)
protocoles=["tcp","udp","icmp",'arp']
Combo=ttk.Combobox(root5,values=protocoles,width=50)
Combo.place(x=130,y=53)
ports=['http','https','ftp']
Combo1=ttk.Combobox(root5,values=ports,width=50)
Combo1.place(x=130,y=103)
entry1=Entry(root5,text="IP address",bd=2,width=53)
entry1.place(x=130,y=153)
ok=Button(root5,text='   Ok   ',font=("arial",12),command=Okkkk,bg="#95F685",bd=2)
ok.place(x=130,y=200)
entry2=Entry(root5,text="output",bd=2,width=70)
entry2.place(x=20,y=280)
Confirm=Button(root5,text='  confirmer  ',font=("arial",12),bg="#ABDDF2",bd=2)
Confirm.place(x=200,y=350)
Cancel=Button(root5,text='   Annuler   ',font=("arial",12),command=quit,bg="#EC9241",bd=2)
Cancel.place(x=350,y=350)


root5.mainloop()'''


"""def saveFile():
        myfile = open("output.txt", "a+")
        for (packet,date) in zip(capture,listDates):
            res = str(packet.show)
            myfile.write("----------------> date : " + date + "\n")
            myfile.write(res + "\n\n")
        myfile.close()

    saveRoot = Tk()
    saveRoot.title("personnaliser la sauvegarde :")
    saveRoot.geometry('300x100')
    saveRoot.maxsize(300, 100)
    saveRoot.minsize(300, 100)
    butt1 = Button(saveRoot, text='    cancel    ', font=("arial", 12), command=saveRoot.destroy, bg="#EC9241", bd=2)
    butt1.place(x=30, y=30)
    butt2 = Button(saveRoot, text=' save in file ', font=("arial", 12), command=saveFile, bg="#75EB0C", bd=2)
    butt2.place(x=180, y=30)"""