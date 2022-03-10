from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from scapy.all import *
import datetime
from scapy2dict import to_dict
import sqlite3
import cv2


def sniffAll():
    Nbr=int(nbrCombo.get())
    capture=sniff(count=Nbr)
    listDates=[]
    tupleDates=[]
    listVersion=[]
    listIPs=[]
    listSummary=[]
    listMacs=[]
    listProt=[]
    for packet in capture:
        dateT=str(datetime.datetime.now()).split(" ")
        DateTime=dateT[0]+"--"+dateT[1]
        listDates.append(DateTime)
        tupleDates.append((dateT[0],dateT[1]))
        data = to_dict(packet, strict=True)
        dataSummary=str(packet.summary())
        out = ""
        summar=""
        for l in dataSummary:
            if l!=" ":
                summar=summar+l
        listSummary.append(summar)

        for i in data:
            out += "###" + str(i) + "###"
            for j in data[i]:
                out += str(j) + "-->" + str(data[i][j]) + ","
        out1=""
        for k in out:
            if k!=" ":
                out1+=k
        tv2.insert('',END,values=(DateTime+"---->"+out1[:len(out1)-1]))
        tv2.insert('',END,values=("Summary"+"---->"+summar))
        layers = ""
        for i in packet.payload.layers():
            ALLlayer = str(i).split(".")
            Getlayer = ALLlayer[len(ALLlayer) - 1]
            layers = layers + Getlayer[:len(Getlayer) - 2] + '>'
        layerList=layers.split(">")
        if len(layerList)>2:
            listProt.append(str(layerList[1]))
        else:
            listProt.append(str(layerList[0]))

        if 'IP' in data:
            src = "4" + "=>" + str(data['IP']['src'])+"=>"+str(packet.sport)  # + "||" + str(data[protocol]['dport'])
            dst = "4" + "=>" + str(data['IP']['dst'])+"=>"+str(packet.dport)  # + "||" + str(data[protocol]['dport'])
            macSrc = str(packet.src)
            macDst = str(packet.dst)
            listVersion.append(4)
            listIPs.append((str(data['IP']['src']),str(data['IP']['dst'])))
            # print(src,dst,macSrc,macDst)
            # print(data)

        if 'IPv6' in data:
            src = "6" + "=>" + str(data['IPv6']['src'])
            dst = "6" + "=>" + str(data['IPv6']['dst'])
            macSrc = str(packet.src)
            macDst = str(packet.dst)
            listVersion.append(6)
            listIPs.append((str(data['IPv6']['src']),str(data['IPv6']['dst'])))
            # print(src,dst,macSrc,macDst)
            # print(data)

        if 'ARP' in data:
            src = str(data['ARP']['plen']) + "=>" + str(data['ARP']['psrc'])
            dst = str(data['ARP']['plen']) + "=>" + str(data['ARP']['pdst'])
            macSrc = str(packet.src)
            macDst = str(packet.dst)
            listVersion.append(int(data['ARP']['plen']))
            listIPs.append((str(data['ARP']['psrc']),str(data['ARP']['pdst'])))
            # print(src,dst,macSrc,macDst)
        tv1.insert('', END, values=((DateTime,src,dst,layers,macSrc+"->"+macDst)))
        listMacs.append((macSrc,macDst))

    def saveFile():
        myfile = open("output.txt", "a+")
        for (packet,date) in zip(capture,listDates):
            res = str(packet.show)
            myfile.write("----------------> date : " + date + "\n")
            myfile.write(str(packet.summary())+"\n")
            myfile.write(res + "\n\n")
        myfile.close()
        messagebox.showinfo("confirmation :", "contenue ajouté !!")

    saveRoot = Tk()
    saveRoot.title("personnaliser la sauvegarde dans fichier :")
    saveRoot.geometry('350x100')
    saveRoot.maxsize(350, 120)
    saveRoot.minsize(350, 120)
    labelSave=Label(saveRoot, text='voulez vous sauvegarder les trames ?', font=('arial', 12))
    labelSave.place(x=30,y=20)
    butt1 = Button(saveRoot, text='    cancel    ', font=("arial", 12), command=saveRoot.destroy, bg="#EC9241", bd=2)
    butt1.place(x=30, y=50)
    butt2 = Button(saveRoot, text=' save in file ', font=("arial", 12), command=saveFile, bg="#75EB0C", bd=2)
    butt2.place(x=180, y=50)

    def saveDatabase():
        db = sqlite3.connect("SniffDataBase.db")
        cur = db.cursor()
        for (packet, item,version,Ip,prot,Admac,suma) in zip(capture, tupleDates,listVersion,listIPs,listProt,listMacs,listSummary):
            valeurs = (item[0],item[1],version,Ip[0],Ip[1],prot,Admac[0],Admac[1],suma)
            insert = r"insert into InfoTrame values(?,?,?,?,?,?,?,?,?)"
            cur.execute(insert, valeurs)
            db.commit()
        db.close()
        messagebox.showinfo("confirmation :", "contenue ajouté !!")


    saveDB = Tk()
    saveDB.title("personnaliser la sauvegarde dans la database :")
    saveDB.geometry('450x120')
    saveDB.maxsize(450, 150)
    saveDB.minsize(450, 120)
    labelSaveBD = Label(saveDB, text='voulez vous sauvegarder les trames dans la database ?', font=('arial', 12))
    labelSaveBD.place(x=30, y=20)
    butt4 = Button(saveDB, text='    cancel    ', font=("arial", 12), command=saveDB.destroy, bg="#EC9241",bd=2)
    butt4.place(x=30, y=50)
    butt5 = Button(saveDB, text=' save in database ', font=("arial", 12),command=saveDatabase,bg="#ABDDF2", bd=2)
    butt5.place(x=220, y=50)
    saveDB.mainloop()
    saveRoot.mainloop()


def SearchInterface():

    def HelpS():
        img = cv2.imread("helpSearch.png")
        cv2.imshow("Image Aide", img)


    def displayAll():
        db = sqlite3.connect("SniffDataBase.db")
        cur = db.cursor()
        cur.execute("select * from InfoTrame")
        trame = cur.fetchall()
        for i in trame:
            tv1S.insert('', END, values=(i))
        db.close()
        messagebox.showinfo("confirmation :", "Done !!")

    def displayDetail():
        db = sqlite3.connect("SniffDataBase.db")
        cur = db.cursor()
        cur.execute("select * from DetailTrame")
        trame = cur.fetchall()
        for i in trame:
            tv2S.insert('', END, values=(i))
        db.close()
        messagebox.showinfo("confirmation :", "vous avez enregistrer ces trames spécifiquement !!")

    def delete():
        root6 = Tk()
        root6.title("personnaliser la suppression :")
        root6.geometry('300x100')
        root6.maxsize(300, 100)
        root6.minsize(300, 100)
        b1 = Button(root6, text='    tout    ', font=("arial", 12), command=remove_All, bg="#EC9241", bd=2)
        b1.place(x=30, y=30)
        b2 = Button(root6, text='selection', font=("arial", 12), command=remove_selection, bg="#75EB0C", bd=2)
        b2.place(x=180, y=30)

    def remove_All():
        for record in tv1S.get_children():
            tv1S.delete(record)
        for records in tv2S.get_children():
            tv2S.delete(records)
        messagebox.showinfo("confirmation :", "contenue supprimé !!")

    def remove_selection():
        for i in tv1S.selection():
            tv1S.delete(i)
        for j in tv2.selection():
            tv2S.delete(j)
        messagebox.showinfo("confirmation :", "selection supprimée !!")

    def search():
        select = "SELECT * FROM InfoTrame "
        Where = "where "
        date1 = str(e1.get())
        date2 = str(e2.get())
        ver = str(Combo1.get())
        prot = str(Combo2.get())
        ipsrc = str(e4.get())
        ipdst = str(e5.get())
        macsrc = str(e6.get())
        macdst = str(e7.get())
        listWhere = []
        if date1 and date2:
            Where11 = "Date between " + "'" + date1 + "'" + " and " + "'" + date2 + "'"
            listWhere.append(Where11)
        elif date1:
            Where12 = "Date" + "=" + "'" + date1 + "'"
            listWhere.append(Where12)
        elif date2:
            Where21 = "Date" + "=" + "'" + date2 + "'"
            listWhere.append(Where21)
        if ver:
            Where1 = "Ipversion" + "=" + ver
            listWhere.append(Where1)
        if prot:
            Where2 = "Protocole" + "=" + "'" + prot + "'"
            listWhere.append(Where2)
        if ipsrc:
            Where3 = "IpSrc" + "=" + "'" + ipsrc + "'"
            listWhere.append(Where3)
        if ipdst:
            Where4 = "IpDst" + "=" + "'" + ipdst + "'"
            listWhere.append(Where4)
        if macsrc:
            Where5 = "MacSrc" + "=" + "'" + macsrc + "'"
            listWhere.append(Where5)
        if macdst:
            Where6 = "MacDst" + "=" + "'" + macdst + "'"
            listWhere.append(Where6)
        Where = Where + " and ".join(listWhere)

        db = sqlite3.connect("SniffDataBase.db")
        cur = db.cursor()
        if Where != "where ":
            requette = select + Where
        else:
            requette = select
        cur.execute(requette)
        trame = cur.fetchall()
        for i in trame:
            tv1S.insert('', END, values=(i))
        db.close()
        messagebox.showwarning("Warning :", "Attention !!")

    rootS = Tk()
    rootS.title("Interface d'inspection :")
    rootS.geometry("1300x700")
    rootS.maxsize(1300, 700)
    rootS.minsize(1300, 700)
    rootS.iconbitmap("2170040.ico")

    menuBar = Menu(rootS)
    menuFile = Menu(menuBar)
    menuBar.add_cascade(label="Fichier", menu=menuFile)
    menuFile.add_command(label="Quitter", command=rootS.destroy)
    menuRech = Menu(menuBar)
    menuBar.add_cascade(label="Capture", menu=menuRech)
    menuRech.add_command(label="Vers interface de capture")
    menuHelp = Menu(menuBar)
    menuBar.add_cascade(label="Help", menu=menuHelp)
    menuHelp.add_command(label="Vers Aide", command=HelpS)
    menuInfo = Menu(menuBar)
    menuBar.add_cascade(label="Info", menu=menuInfo)
    menuInfo.add_command(label="Vers Informations", command=Informations)
    rootS.config(menu=menuBar)

    l1 = Label(rootS, text='Date 1    :', font=('arial', 11))
    l1.place(x=10, y=20)
    e1 = Entry(rootS, text="1er date", bd=2, width=35)
    e1.place(x=80, y=23)
    l2 = Label(rootS, text='Date 2    :', font=('arial', 11))
    l2.place(x=350, y=20)
    e2 = Entry(rootS, text="2eme date", bd=2, width=35)
    e2.place(x=420, y=23)
    l3 = Label(rootS, text='version :', font=('arial', 11))
    l3.place(x=10, y=50)
    versions = [4, 6]
    Combo1 = ttk.Combobox(rootS, values=versions, width=32)
    Combo1.place(x=80, y=53)
    l4 = Label(rootS, text='protocole:', font=('arial', 11))
    l4.place(x=350, y=50)
    protocoles = ['TCP', 'UDP', 'ARP', 'ICMP', 'ICMPv6']
    Combo2 = ttk.Combobox(rootS, values=protocoles, width=32)
    Combo2.place(x=420, y=53)
    l5 = Label(rootS, text='Ip src   :', font=('arial', 11))
    l5.place(x=10, y=80)
    e4 = Entry(rootS, text="Ipsrc", bd=2, width=35)
    e4.place(x=80, y=83)
    l6 = Label(rootS, text='Ip dst   :', font=('arial', 11))
    l6.place(x=350, y=80)
    e5 = Entry(rootS, text="Ipdst", bd=2, width=35)
    e5.place(x=420, y=83)
    l7 = Label(rootS, text='Mac src  :', font=('arial', 11))
    l7.place(x=10, y=110)
    e6 = Entry(rootS, text="Macsrc", bd=2, width=35)
    e6.place(x=80, y=113)
    l8 = Label(rootS, text='Mac dst  :', font=('arial', 11))
    l8.place(x=350, y=110)
    e7 = Entry(rootS, text="Macdst", bd=2, width=35)
    e7.place(x=420, y=113)

    butt1 = Button(rootS, text='    display All    ', font=("arial", 12), command=displayAll, bg="#67EB0C", bd=2)
    butt1.place(x=700, y=20)
    butt2 = Button(rootS, text='      Search       ', font=("arial", 12), command=search, bg="#63F094", bd=2)
    butt2.place(x=700, y=60)
    butt3 = Button(rootS, text='      Delete       ', font=("arial", 12), command=delete, bg="#F04744", bd=2)
    butt3.place(x=900, y=20)
    butt4 = Button(rootS, text='       close        ', font=("arial", 12), command=rootS.destroy, bg="#EF8C34", bd=2)
    butt4.place(x=900, y=60)
    butt5 = Button(rootS, text='  display detail ', font=("arial", 12), command=displayDetail, bg="#34D6EF", bd=2)
    butt5.place(x=700, y=100)
    butt6 = Button(rootS, text='       !!!!!!!!       ', font=("arial", 12), command=HelpS, bg="#E9EF34", bd=2)
    butt6.place(x=900, y=100)

    frame1 = Frame(rootS, width=900, height=250, highlightbackground="grey", highlightthicknes=1)
    frame1.grid(row=0, column=0, padx=10, pady=150)

    scroll1 = Scrollbar(frame1, orient="vertical")
    scroll1.pack(side=RIGHT, fill="y")

    xscroll1 = Scrollbar(frame1, orient="horizontal")
    xscroll1.pack(side=BOTTOM, fill="x")

    style = ttk.Style()
    style.configure("Treeview",
                    background="#9FECE4",
                    foreground="black",
                    fieldbackground="#9FECE4"
                    )
    style.map('Treeview', background=[('selected', 'blue')])

    tv1S = ttk.Treeview(frame1, columns=(
    "Date", "Time", "Version", "Ipsrc", "Ipdst", "protocole", "Macsrc", "Macdst", "Summary"),
                       xscrollcommand=xscroll1.set, yscrollcommand=scroll1.set, selectmode="extended")

    tv1S.column("#0", minwidth=10, width=10)
    tv1S.column("Date", minwidth=80, width=120)
    tv1S.column("Time", minwidth=80, width=120)
    tv1S.column("Version", minwidth=20, width=80)
    tv1S.column("Ipsrc", minwidth=100, width=160)
    tv1S.column("Ipdst", minwidth=100, width=160)
    tv1S.column("protocole", minwidth=30, width=90)
    tv1S.column("Macsrc", minwidth=100, width=160)
    tv1S.column("Macdst", minwidth=100, width=160)
    tv1S.column("Summary", minwidth=100)

    tv1S.heading("#0", text="")
    tv1S.heading("Date", text="Date")
    tv1S.heading("Time", text="Time")
    tv1S.heading("Version", text="Ip version")
    tv1S.heading("Ipsrc", text="Ip source")
    tv1S.heading("Ipdst", text="Ip destination")
    tv1S.heading("protocole", text="Protocole")
    tv1S.heading("Macsrc", text="Mac source")
    tv1S.heading("Macdst", text="Mac destination")
    tv1S.heading("Summary", text="Summary")

    tv1S.pack()
    scroll1.config(command=tv1S.yview)
    xscroll1.config(command=tv1S.xview)

    frame2 = Frame(rootS, width=900, height=250, highlightbackground="grey", highlightthicknes=1)
    frame2.place(x=10, y=400)

    scroll2 = Scrollbar(frame2, orient="vertical")
    scroll2.pack(side=RIGHT, fill="y")

    xscroll2 = Scrollbar(frame2, orient="horizontal")
    xscroll2.pack(side=BOTTOM, fill="x")

    tv2S = ttk.Treeview(frame2, columns=("details"), xscrollcommand=xscroll2.set, yscrollcommand=scroll2.set,
                       selectmode="extended")

    tv2S.column("#0", minwidth=10, width=10)
    tv2S.heading("#0", text="")
    tv2S.column("details", minwidth=800, width=1250)
    tv2S.heading("details", text="Détail du Trame")

    tv2S.pack()

    scroll2.config(command=tv2S.yview)
    xscroll2.config(command=tv2S.xview)

    rootS.mainloop()


def Help():
    img = cv2.imread("helpCapture.png")
    cv2.imshow("Image Aide1", img)
def Informations():
    root4 = Tk()
    root4.title("Informations :")
    root4.geometry("500x500")
    root4.minsize(500, 500)
    root4.maxsize(500, 500)
    l11 = Label(root4, text="<----- Projet du Fin d'Année ----->", font=('arial', 14), fg="#071FCD")
    l11.place(x=100, y=10)
    l12 = Label(root4, text="==> Réalisé par :", font=('arial', 14), fg="#179921")
    l12.place(x=10, y=50)
    l13 = Label(root4, text="- Mohamed Lahmiss ", font=('arial', 13))
    l13.place(x=30, y=80)
    l14 = Label(root4, text="- Smail Ait Izana ", font=('arial', 13))
    l14.place(x=30, y=110)
    l15 = Label(root4, text="- Abdesslam El Yahyaoui ", font=('arial', 13))
    l15.place(x=30, y=140)
    l16 = Label(root4, text=" Des élèves ingénieurs à l'INPT  ", font=('arial', 13))
    l16.place(x=50, y=190)
    l17 = Label(root4, text=" Filière : Cybersécurité & Confiance Numérique ", font=('arial', 13))
    l17.place(x=50, y=220)
    l18 = Label(root4, text="==> Encadré par :", font=('arial', 14), fg="#179921")
    l18.place(x=10, y=250)
    l19 = Label(root4, text="- Mr Kamal Idrissi Hamza ", font=('arial', 13))
    l19.place(x=30, y=280)
    l19 = Label(root4, text="- Mr Abdelhamid Belmekki ", font=('arial', 13))
    l19.place(x=30, y=310)
    l20 = Label(root4, text="==> Objectif de l'application :", font=('arial', 14), fg="#179921")
    l20.place(x=10, y=340)
    l21 = Label(root4, text=" Le capture et la géstion du trafic réseau à travers  ", font=('arial', 13))
    l21.place(x=30, y=370)
    l22 = Label(root4, text=" des bases de données et des interfaces graphiques  ", font=('arial', 13))
    l22.place(x=30, y=400)

    root4.mainloop()



def filtering():
    def Okkkk():
        list = []
        proto = str(Combo.get())
        host = "host " + str(entry1.get())
        port = "port " + str(Combo1.get())
        if proto:
            list.append(proto)
        if str(entry1.get()):
            list.append(host)
        if str(Combo1.get()):
            list.append(port)
        filter = " and ".join(list)
        entry2.delete(0, END)
        entry2.insert(0, filter)

    def confirm():
        filtre=entry2.get()
        listCombo.delete(0, END)
        listCombo.insert(0, filtre)



    root5 = Tk()
    root5.title("Interface de filtrage :")
    root5.geometry("500x400")
    root5.maxsize(500, 400)
    root5.minsize(500, 400)

    l1 = Label(root5, text='Protocole   :', font=('arial', 12))
    l1.place(x=20, y=50)
    l2 = Label(root5, text='Port             :', font=('arial', 12))
    l2.place(x=20, y=100)
    l3 = Label(root5, text='Host            :', font=('arial', 12))
    l3.place(x=20, y=150)
    protocoles = ["tcp", "udp", "icmp", 'arp']
    Combo = ttk.Combobox(root5, values=protocoles, width=50)
    Combo.place(x=130, y=53)
    ports = ['http', 'https', 'ftp']
    Combo1 = ttk.Combobox(root5, values=ports, width=50)
    Combo1.place(x=130, y=103)
    entry1 = Entry(root5, text="IP address", bd=2, width=53)
    entry1.place(x=130, y=153)
    ok = Button(root5, text='   Ok   ', font=("arial", 12), command=Okkkk, bg="#95F685", bd=2)
    ok.place(x=130, y=200)
    entry2 = Entry(root5, text="output", bd=2, width=70)
    entry2.place(x=20, y=280)
    Confirm = Button(root5, text='  confirmer  ', font=("arial", 12),command=confirm, bg="#ABDDF2", bd=2)
    Confirm.place(x=200, y=350)
    Cancel = Button(root5, text='   Annuler   ', font=("arial", 12), command=root5.destroy, bg="#EC9241", bd=2)
    Cancel.place(x=350, y=350)

    root5.mainloop()

def appliquer():
    Nbr = int(nbrCombo.get())
    filtre=listCombo.get()
    capture = sniff(filter=filtre,count=Nbr)
    listDates = []
    tupleDates = []
    listVersion = []
    listIPs = []
    listSummary = []
    listMacs = []
    listProt = []
    for packet in capture:
        dateT = str(datetime.datetime.now()).split(" ")
        DateTime = dateT[0] + "--" + dateT[1]
        listDates.append(DateTime)
        tupleDates.append((dateT[0],dateT[1]))
        data = to_dict(packet, strict=True)
        out = ""
        dataSummary = str(packet.summary())
        summar = ""
        for l in dataSummary:
            if l != " ":
                summar = summar + l
        listSummary.append(summar)
        for i in data:
            out += "###" + str(i) + "###"
            for j in data[i]:
                out += str(j) + "-->" + str(data[i][j]) + ","
        out1 = ""
        for k in out:
            if k != " ":
                out1 += k
        tv2.insert('', END, values=(DateTime + "---->" + out1[:len(out1) - 1]))
        tv2.insert('', END, values=("Summary" + "---->" + summar))
        layers = ""
        for i in packet.payload.layers():
            ALLlayer = str(i).split(".")
            Getlayer = ALLlayer[len(ALLlayer) - 1]
            layers = layers + Getlayer[:len(Getlayer) - 2] + '>'
        layerList = layers.split(">")
        if len(layerList) > 2:
            listProt.append(str(layerList[1]))
        else:
            listProt.append(str(layerList[0]))

        if 'IP' in data:
            src = "4" + "=>" + str(data['IP']['src'])  # +"||"+str(data[protocol]['sport'])
            dst = "4" + "=>" + str(data['IP']['dst'])  # + "||" + str(data[protocol]['dport'])
            macSrc = str(packet.src)
            macDst = str(packet.dst)
            listVersion.append(4)
            listIPs.append((str(data['IP']['src']), str(data['IP']['dst'])))
            # print(src,dst,macSrc,macDst)
            # print(data)

        if 'IPv6' in data:
            src = "6" + "=>" + str(data['IPv6']['src'])
            dst = "6" + "=>" + str(data['IPv6']['dst'])
            macSrc = str(packet.src)
            macDst = str(packet.dst)
            listVersion.append(6)
            listIPs.append((str(data['IPv6']['src']), str(data['IPv6']['dst'])))
            # print(src,dst,macSrc,macDst)
            # print(data)

        if 'ARP' in data:
            src = str(data['ARP']['plen']) + "=>" + str(data['ARP']['psrc'])
            dst = str(data['ARP']['plen']) + "=>" + str(data['ARP']['pdst'])
            macSrc = str(packet.src)
            macDst = str(packet.dst)
            listVersion.append(int(data['ARP']['plen']))
            listIPs.append((str(data['ARP']['psrc']), str(data['ARP']['pdst'])))
            # print(src,dst,macSrc,macDst)
        tv1.insert('', END, values=((DateTime, src, dst, layers, macSrc + "->" + macDst)))
        listMacs.append((macSrc,macDst))

    def saveFile():
        myfile = open("output.txt", "a+")
        for (packet,date) in zip(capture,listDates):
            res = str(packet.show)
            myfile.write("----------------> date : " + date + "\n")
            myfile.write(str(packet.summary())+"\n")
            myfile.write(res + "\n\n")
        myfile.close()
        messagebox.showinfo("confirmation :", "contenue ajouté !!")

    saveRoot = Tk()
    saveRoot.title("personnaliser la sauvegarde dans fichier :")
    saveRoot.geometry('300x100')
    saveRoot.maxsize(300, 120)
    saveRoot.minsize(300, 120)
    labelSave=Label(saveRoot, text='voulez vous sauvegarder les trames ?', font=('arial', 12))
    labelSave.place(x=30,y=20)
    butt1 = Button(saveRoot, text='    cancel    ', font=("arial", 12), command=saveRoot.destroy, bg="#EC9241", bd=2)
    butt1.place(x=30, y=50)
    butt2 = Button(saveRoot, text=' save in file ', font=("arial", 12), command=saveFile, bg="#75EB0C", bd=2)
    butt2.place(x=180, y=50)

    def saveDatabase():
        db = sqlite3.connect("SniffDataBase.db")
        cur = db.cursor()
        for (packet, item,version,Ip,prot,Admac,suma) in zip(capture, tupleDates,listVersion,listIPs,listProt,listMacs,listSummary):
            valeurs = (item[0],item[1],version,Ip[0],Ip[1],prot,Admac[0],Admac[1],suma)
            insert = r"insert into InfoTrame values(?,?,?,?,?,?,?,?,?)"
            cur.execute(insert, valeurs)
            db.commit()
        db.close()
        messagebox.showinfo("confirmation :", "contenue ajouté !!")


    saveDB = Tk()
    saveDB.title("personnaliser la sauvegarde dans la database :")
    saveDB.geometry('450x120')
    saveDB.maxsize(450, 150)
    saveDB.minsize(450, 120)
    labelSaveBD = Label(saveDB, text='voulez vous sauvegarder les trames dans la database ?', font=('arial', 12))
    labelSaveBD.place(x=30, y=20)
    butt4 = Button(saveDB, text='    cancel    ', font=("arial", 12), command=saveDB.destroy, bg="#EC9241",bd=2)
    butt4.place(x=30, y=50)
    butt5 = Button(saveDB, text=' save in database ', font=("arial", 12),command=saveDatabase,bg="#ABDDF2", bd=2)
    butt5.place(x=220, y=50)
    saveDB.mainloop()
    saveRoot.mainloop()

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

def saveSelction():
    myfile=open("SpetialOutput","a+")
    items=tv2.selection()
    for i in items:
        myfile.write(tv2.item(i)['values'][0]+"\n")
    myfile.close()
    messagebox.showinfo("confirmation :", "selection added !!")

def saveSelctionDB():
    db = sqlite3.connect("SniffDataBase.db")
    cur = db.cursor()
    items=tv2.selection()
    for i in items:
        valeurs = (str(tv2.item(i)['values'][0]),)
        insert =  r"insert into DetailTrame values(?)"
        cur.execute(insert, valeurs)
        db.commit()
    db.close()
    messagebox.showinfo("confirmation :", "selection added !!")


def remove_selection():
    for i in tv1.selection():
        tv1.delete(i)
    for j in tv2.selection():
        tv2.delete(j)
    messagebox.showinfo("confirmation :", "selection supprimée !!")

# ------------Créer et configurer l'interface principale-----------------

root=Tk()
root.title("Interface De Capture:")
root.geometry('1080x640')
root.maxsize(1080,640)
root.minsize(1080,640)
root.iconbitmap("2133050.ico")

# -----------Créer le menu d'utilisation de l'application----------------

menuBar=Menu(root)
menuFile=Menu(menuBar)
menuBar.add_cascade(label="Fichier",menu=menuFile)
menuFile.add_command(label="Quitter",command=root.destroy)
menuRech=Menu(menuBar)
menuBar.add_cascade(label="Recherche",menu=menuRech)
menuRech.add_command(label="Vers recherche",command=SearchInterface)
menuHelp=Menu(menuBar)
menuBar.add_cascade(label="Help",menu=menuHelp)
menuHelp.add_command(label="Vers Aide",command=Help)
menuInfo=Menu(menuBar)
menuBar.add_cascade(label="Info",menu=menuInfo)
menuInfo.add_command(label="Vers Informations",command=Informations)
root.config(menu=menuBar)

# ------------------Compléter les fonctionnalités de la fenetre principale--------------

Filter=Button(root,text=" Filtre ",font=("arial",12),command=filtering,bg="#95F685",bd=2)
Filter.place(x=10,y=10)
listFilters=["tcp","udp","icmp"]
listCombo=ttk.Combobox(root,values=listFilters,width=75)
listCombo.place(x=70,y=13)
b1=Button(root,text="    Apply    ",font=("arial",12),command=appliquer,bg="#2266EF",bd=2)
b1.place(x=755,y=8)
b2=Button(root,text="  Sniff all  ",font=("arial",12),command=sniffAll,bg="#ABDDF2",bd=2)
b2.place(x=855,y=8)
b3=Button(root,text="   Effacer   ",font=("arial",12),command=delete,bg="#78F5E0",bd=2)
b3.place(x=955,y=8)
b4=Button(root,text="      save in database      ",font=("arial",12),command=saveSelctionDB,bg="#8C5FE0",bd=2)
b4.place(x=200,y=585)
b5=Button(root,text="   save in file datagrame   ",font=("arial",12),command=saveSelction,bg="#ABDDF2",bd=2)
b5.place(x=450,y=585)
b6=Button(root,text="   Close   ",font=("arial",12),command=root.destroy,bg="#EC9241",bd=2)
b6.place(x=950,y=585)
NbrTrames=Label(root,text="Nombre:",font=("arial",12))
NbrTrames.place(x=550,y=10)
listNbr=[i for i in range(1,101)]
nbrCombo=ttk.Combobox(root,values=listNbr,width=15)
nbrCombo.current(9)
nbrCombo.place(x=620,y=13)

frame1=Frame(root,width=900,height=250,highlightbackground="grey",highlightthicknes=1)
frame1.grid(row=0,column=0,padx=20,pady=50)

scroll1=Scrollbar(frame1,orient="vertical")
scroll1.pack(side=RIGHT,fill="y")

xscroll1=Scrollbar(frame1,orient="horizontal")
xscroll1.pack(side=BOTTOM,fill="x")

style=ttk.Style()
style.configure("Treeview",
    background="silver",
    foreground="black",
    fieldbackground="silver"
)
style.map('Treeview',background=[('selected','blue')])

tv1=ttk.Treeview(frame1,columns=("datetime","Ipsrc","Ipdest","protocole","description"),xscrollcommand=xscroll1.set,yscrollcommand=scroll1.set,selectmode="extended")

tv1.column("#0",minwidth=10,width=10)
tv1.column("datetime",minwidth=100)
tv1.column("Ipsrc",minwidth=100)
tv1.column("Ipdest",minwidth=100)
tv1.column("protocole",minwidth=100)
tv1.column("description",minwidth=100)

tv1.heading("#0",text="")
tv1.heading("datetime",text="Date & Time")
tv1.heading("Ipsrc",text="version : Ip src : port")
tv1.heading("Ipdest",text="version : Ip dest : port")
tv1.heading("protocole",text="layers")
tv1.heading("description",text="Mac src -> Mac dst")

tv1.pack()
scroll1.config(command=tv1.yview)
xscroll1.config(command=tv1.xview)


frame2=Frame(root,width=900,height=250,highlightbackground="grey",highlightthicknes=1)
frame2.place(x=20,y=320)

scroll2=Scrollbar(frame2,orient="vertical")
scroll2.pack(side=RIGHT,fill="y")

xscroll2=Scrollbar(frame2,orient="horizontal")
xscroll2.pack(side=BOTTOM,fill="x")

tv2=ttk.Treeview(frame2,columns=("details"),xscrollcommand=xscroll2.set,yscrollcommand=scroll2.set,selectmode="extended")

tv2.column("#0",minwidth=10,width=10)
tv2.heading("#0",text="")
tv2.column("details",minwidth=300,width=1000)
tv2.heading("details",text="Détail du Trame")

tv2.pack()

scroll2.config(command=tv2.yview)
xscroll2.config(command=tv2.xview)


root.mainloop()