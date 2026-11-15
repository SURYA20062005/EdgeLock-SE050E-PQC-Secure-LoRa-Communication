"""Tkinter hardware GUI for the existing SCP03/ML-DSA/ML-KEM/LoRa implementation.
No mock crypto or radio operations. Run on the corresponding Raspberry Pi.
"""
import hashlib
import queue
import struct
import threading
import tkinter as tk
from tkinter import ttk, messagebox

BG='#0b1220'; PANEL='#152136'; PANEL2='#1c2b42'; TEXT='#eaf1fa'; MUTED='#9bafc7'; CYAN='#3fc9db'; BLUE='#4f8bff'; GREEN='#44d2a1'; AMBER='#f4bd65'

class Application:
    def __init__(self, root):
        self.root=root; root.title('EdgeLock | Quantum-Safe LoRa Console'); root.geometry('1120x760'); root.minsize(920,650); root.configure(bg=BG)
        self.role=None; self.events=queue.Queue(); self.actions=queue.Queue(); self.running=False; self.session_ready=False; self.turn=None; self.current_sid=None
        self.steps=[]; self.messages=[]; self.edge_items=[]; self.arrow_job=None; self.flow_active=False; self.flow_direction=None; self.flow_tick=0; self.flow_caption=""; self.stage='Idle'; self.worker=None; self.rekey_pending=False; self.rekey_requested=False; self.flow_progress='' 
        self.build_home(); root.after(70,self.pump)
    def clear(self):
        for c in self.root.winfo_children(): c.destroy()
    def label(self,parent,text,size=11,color=TEXT,bold=False,**kw):
        return tk.Label(parent,text=text,bg=kw.pop('bg',BG),fg=color,font=('DejaVu Sans',size,'bold' if bold else 'normal'),**kw)
    def btn(self,parent,text,command,primary=False):
        b=tk.Button(parent,text=text,command=command,font=('DejaVu Sans',11,'bold'),bg=BLUE if primary else PANEL2,fg='white',activebackground=CYAN,activeforeground=BG,relief='flat',bd=0,padx=18,pady=12,cursor='hand2')
        return b
    def build_home(self):
        self.clear()
        self.label(self.root,'EDGELOCK  /  SECURE COMMUNICATION',12,CYAN,True).pack(anchor='w',padx=55,pady=(56,16))
        self.label(self.root,'Quantum-safe LoRa messaging',28,TEXT,True).pack(anchor='w',padx=55)
        self.label(self.root,'NXP SE050E  •  SCP03  •  ML-DSA-65  •  ML-KEM-512  •  AES-256-GCM',12,MUTED).pack(anchor='w',padx=55,pady=(8,44))
        holder=tk.Frame(self.root,bg=BG); holder.pack(fill='x',padx=55)
        for role,subtitle in [('Alice','Initiator  ·  left-to-right LoRa transmission'),('Bob','Responder  ·  right-to-left LoRa transmission')]:
            card=tk.Frame(holder,bg=PANEL,padx=24,pady=26,highlightthickness=1,highlightbackground='#30435f'); card.pack(side='left',expand=True,fill='both',padx=(0,12) if role=='Alice' else (12,0))
            self.label(card,role,24,TEXT,True,bg=PANEL).pack(anchor='w')
            self.label(card,subtitle,10,MUTED,bg=PANEL).pack(anchor='w',pady=(8,24))
            self.btn(card,'Open '+role+' console',lambda r=role:self.open_console(r),True).pack(anchor='w')
        self.label(self.root,'Select the role matching this Raspberry Pi. Both devices must run the same protocol session.',10,MUTED).pack(anchor='w',padx=55,pady=32)
    def open_console(self,role):
        self.role=role; self.clear(); self.edge_items=[]; self.messages=[]; self.session_ready=False; self.turn=None
        header=tk.Frame(self.root,bg=BG); header.pack(fill='x',padx=22,pady=(15,8))
        self.label(header,'EDGELOCK  /  '+role.upper(),17,TEXT,True).pack(side='left')
        self.status=self.label(header,'●  Ready',10,MUTED); self.status.pack(side='right')
        bar=tk.Frame(self.root,bg=BG); bar.pack(fill='x',padx=22,pady=(2,12))
        self.start_btn=self.btn(bar,'Start new PQC session',self.start_session,True); self.start_btn.pack(side='left',padx=(0,9))
        self.next_btn=self.btn(bar,'Next step',self.next_step); self.next_btn.pack(side='left',padx=(0,9)); self.next_btn.config(state='disabled')
        
        self.canvas=tk.Canvas(self.root,bg=PANEL,highlightthickness=0,height=235); self.canvas.pack(fill='x',padx=22,pady=(0,10))
        self.canvas.bind('<Configure>',lambda e:self.draw_flow())
        lower=tk.Frame(self.root,bg=BG); lower.pack(fill='both',expand=True,padx=22,pady=(0,18))
        left=tk.Frame(lower,bg=PANEL,padx=15,pady=12); left.pack(side='left',fill='both',expand=False,padx=(0,9)); left.configure(width=315); left.pack_propagate(False)
        self.label(left,'PROTOCOL ACTIVITY',11,CYAN,True,bg=PANEL).pack(anchor='w')
        self.log=tk.Text(left,bg=PANEL,fg=TEXT,insertbackground=TEXT,relief='flat',font=('DejaVu Sans Mono',9),wrap='word',state='disabled',height=12); self.log.pack(fill='both',expand=True,pady=(10,0))
        right=tk.Frame(lower,bg=PANEL,padx=15,pady=12); right.pack(side='left',fill='both',expand=True,padx=(9,0))
        self.label(right,'SECURE MESSAGING',11,CYAN,True,bg=PANEL).pack(anchor='w')
        self.chat=tk.Text(right,bg=PANEL,fg=TEXT,relief='flat',font=('DejaVu Sans',10),wrap='word',state='disabled',height=11); self.chat.pack(fill='both',expand=True,pady=(9,5))
        compose=tk.Frame(right,bg=PANEL); compose.pack(fill='x')
        self.entry=tk.Entry(compose,bg=PANEL2,fg=TEXT,insertbackground=TEXT,relief='flat',font=('DejaVu Sans',11)); self.entry.pack(side='left',fill='x',expand=True,ipady=9)
        self.entry.bind('<Return>',lambda e:self.send_chat())
        self.send_btn=self.btn(compose,'Send',self.send_chat,True); self.send_btn.pack(side='left',padx=(8,0)); self.send_btn.config(state='disabled')
        self.draw_flow(); self.add_log('Ready. Start on Bob first, then Alice. Both consoles must be open.')
    def draw_flow(self):
        if not hasattr(self,'canvas') or not self.canvas.winfo_exists():return
        c=self.canvas; c.delete('all'); w=max(c.winfo_width(),850)
        c.create_text(20,18,anchor='w',text='LIVE PROTOCOL VISUALIZATION',fill=CYAN,font=('DejaVu Sans',10,'bold'))
        alice_x=w*.17; bob_x=w*.83; y=102; center=w*.5
        for x,title in [(alice_x,'ALICE · Pi 5'),(bob_x,'BOB · Pi 5')]:
            c.create_rectangle(x-104,y-32,x+104,y+35,fill=PANEL2,outline='#4b668b',width=2)
            c.create_text(x,y-5,text=title,fill=TEXT,font=('DejaVu Sans',13,'bold'))
            c.create_text(x,y+17,text='SX126X 915 MHz',fill=MUTED,font=('DejaVu Sans',9))
        c.create_line(alice_x+110,y,bob_x-110,y,fill='#415775',width=3)
        c.create_text(center,y-19,text='LoRa  •  915 MHz',fill=MUTED,font=('DejaVu Sans',10))
        self.marker=c.create_oval(center-8,y-8,center+8,y+8,fill=CYAN,outline='')
        c.create_rectangle(center-175,154,center+175,218,fill='#102c32',outline='#398c91',width=2)
        c.create_text(center,168,text='NXP EDGELOCK SE050E  /  SCP03',fill=GREEN,font=('DejaVu Sans',10,'bold'))
        keys = ('ML-DSA public + private  ·  Verified peer public\nAES-256 session key' if any('AES-256' in k for k in self.edge_items) else ('ML-DSA public + private  ·  Verified peer public' if len(self.edge_items)>1 else ('ML-DSA public + private' if self.edge_items else 'Waiting for secure key provisioning')))
        c.create_text(center,193,text=keys,fill=TEXT,font=('DejaVu Sans',8),justify='center',width=320)
        self.flow_text=c.create_text(center,136,text=self.stage,fill=AMBER,font=('DejaVu Sans',9,'bold'),width=max(260,int(w*.76)))
    def animate(self,direction,caption):
        """Persistent moving TX/RX indicator, driven by real radio operations."""
        if direction=='store':
            self.stage=caption; self.draw_flow()
            c=self.canvas; w=max(c.winfo_width(),850)
            c.create_line(w*.5,127,w*.5,150,fill=GREEN,arrow='last',width=4)
            self.root.after(1100,lambda:self.draw_flow() if c.winfo_exists() and not self.flow_active else None)
            return
        self.stage=caption
        self.flow_direction=direction
        self.flow_caption=caption
        self.flow_progress=''
        self.flow_active=True
        self.flow_tick=0
        self.draw_flow()
        self.tick_flow()

    def tick_flow(self):
        if not self.flow_active or not self.canvas.winfo_exists():return
        c=self.canvas; w=max(c.winfo_width(),850); y=102
        left=w*.17+114; right=w*.83-114
        start,end=(left,right) if self.flow_direction=='a2b' else (right,left)
        # Multiple packets travel continuously for the entire blocking radio operation.
        for item in c.find_withtag('moving-packet'):c.delete(item)
        for offset in (0,0.32,0.64):
            progress=(self.flow_tick/46+offset)%1.0
            x=start+(end-start)*progress
            c.create_oval(x-6,y-6,x+6,y+6,fill=CYAN,outline='',tags='moving-packet')
        c.itemconfig(self.flow_text,text=self.flow_progress or self.flow_caption)
        self.flow_tick+=1
        self.root.after(32,self.tick_flow)

    def stop_flow(self,caption):
        self.flow_active=False
        self.flow_progress=''
        self.stage=caption
        self.draw_flow()

    def add_log(self,msg):
        self.log.config(state='normal'); self.log.insert('end',msg+'\n'); self.log.see('end'); self.log.config(state='disabled')
    def add_chat(self,who,msg):
        self.chat.config(state='normal'); self.chat.insert('end',f'{who}   {msg}\n\n'); self.chat.see('end'); self.chat.config(state='disabled')
    def start_session(self):
        if self.running:
            if not self.session_ready:
                messagebox.showinfo('Protocol active','Finish the current handshake before starting another session.')
                return
            if self.rekey_requested:
                messagebox.showinfo('Already requested','New PQC session is already queued.')
                return
            if not messagebox.askyesno('New PQC session','Replace identity and session keys?'):
                return
            self.rekey_requested=True
            self.start_btn.config(state='disabled',text='New session requested')
            self.add_log('New PQC session requested. Sending authenticated rekey request.')
            if self.session_ready:
                self.actions.put(('rekey',None))
            return
        self.running=True; self.start_btn.config(text='Start new PQC session'); self.next_btn.config(state='normal'); self.send_btn.config(state='disabled')
        self.worker=threading.Thread(target=self.protocol,daemon=True); self.worker.start()
    def next_step(self):self.actions.put(('next',None))
    def show_chat(self):
        if self.session_ready:self.entry.focus_set()
    def send_chat(self):
        if not self.session_ready or self.rekey_requested:return
        text=self.entry.get().strip()
        if not text:return
        if len(text.encode())>2048:messagebox.showerror('Message too long','Maximum 2048 UTF-8 bytes');return
        self.entry.delete(0,'end'); self.actions.put(('message',text))
    def ask(self,kind,detail):
        self.events.put(('ask',kind,detail))
        while True:
            item=self.actions.get()
            if item[0]==kind:return item[1]
    def pump(self):
        try:
            for _ in range(30):
                e=self.events.get_nowait(); kind=e[0]
                if kind=='log':self.add_log(e[1])
                elif kind=='status':self.status.config(text='●  '+e[1],fg=GREEN if 'ready' in e[1].lower() else MUTED)
                elif kind=='flow':self.animate(e[1],e[2])
                elif kind=='flow_stop':self.stop_flow(e[1])
                elif kind=='progress':self.flow_progress=e[1];self.flow_caption=e[1]
                elif kind=='store':self.edge_items.append(e[1]);self.animate('store','SCP03 → EdgeLock: '+e[1])
                elif kind=='ask':
                    _,action,detail=e
                    if action=='next':self.next_btn.config(text=detail,state='normal')
                    elif action=='fingerprint':self.fingerprint_dialog(detail)
                    elif action=='confirm':self.confirm_dialog(detail)
                elif kind=='chat':self.add_chat(e[1],e[2])
                elif kind=='turn':
                    pass  # Chat no longer uses alternating Alice/Bob turns.
                elif kind=='ready':self.session_ready=True;self.rekey_requested=False;self.send_btn.config(state='normal');self.next_btn.config(state='disabled');self.start_btn.config(state='normal',text='Start new PQC session')
                elif kind=='reset':self.session_ready=False;self.rekey_requested=False;self.turn=None;self.send_btn.config(state='disabled');self.start_btn.config(state='normal',text='Start new PQC session');self.next_btn.config(state='disabled');self.edge_items=[];self.stop_flow('New PQC session');self.draw_flow()
                elif kind=='failed':
                    self.running=False;self.start_btn.config(state='normal',text='Start new PQC session');self.next_btn.config(state='disabled');self.send_btn.config(state='disabled');messagebox.showerror('Protocol stopped',e[1])
        except queue.Empty:pass
        self.root.after(70,self.pump)
    def confirm_dialog(self,detail):
        win=tk.Toplevel(self.root);win.title('Confirm identity replacement');win.configure(bg=PANEL);win.geometry('460x215');win.transient(self.root);win.grab_set()
        self.label(win,'Replace identity keys?',16,TEXT,True,bg=PANEL).pack(pady=(32,12))
        self.label(win,'Existing keys will be replaced.',11,AMBER,bg=PANEL).pack(pady=8)
        row=tk.Frame(win,bg=PANEL);row.pack(pady=18)
        def accept():
            win.destroy();self.actions.put(('confirm','REKEY'))
        def reject():
            win.destroy();self.actions.put(('confirm',None))
        self.btn(row,'Confirm & generate',accept,True).pack(side='left',padx=9)
        self.btn(row,'Cancel',reject).pack(side='left',padx=9)
        win.protocol('WM_DELETE_WINDOW',reject)

    def fingerprint_dialog(self,digest):
        win=tk.Toplevel(self.root);win.title('Verify peer identity');win.configure(bg=PANEL);win.geometry('790x290');win.transient(self.root);win.grab_set()
        self.label(win,'Verify peer identity?',17,TEXT,True,bg=PANEL).pack(pady=(20,12))
        self.label(win,'Received fingerprint — SHA-256',10,MUTED,bg=PANEL).pack()
        self.label(win,digest,10,CYAN,bg=PANEL).pack(pady=(5,15))
        self.label(win,'Compare with peer fingerprint.',10,AMBER,bg=PANEL).pack()
        verified=tk.BooleanVar(value=False)
        check=tk.Checkbutton(win,text='Fingerprints match (independently checked)',variable=verified,
            bg=PANEL,fg=TEXT,selectcolor=PANEL2,activebackground=PANEL,activeforeground=TEXT,
            font=('DejaVu Sans',10));check.pack(pady=(18,8))
        row=tk.Frame(win,bg=PANEL);row.pack()
        def accept():
            if not verified.get():
                messagebox.showwarning('Verification required','Check the OTHER Raspberry Pi’s OWN fingerprint first.',parent=win)
                return
            win.destroy();self.actions.put(('fingerprint',digest))
        def reject():
            win.destroy();self.actions.put(('fingerprint',None))
        self.btn(row,'Verify & trust peer',accept,True).pack(side='left',padx=8)
        self.btn(row,'Reject / cancel',reject).pack(side='left',padx=8)
        win.protocol('WM_DELETE_WINDOW',reject)

    def event(self,*args):self.events.put(args)
    def protocol(self):
        try:
            import identity,pairing,authentication,key_exchange,lora_transport,se050_bridge
            from se050_bridge import EXE
            if not EXE.exists():raise RuntimeError('SCP03 bridge missing. Build with: python3 se050_bridge.py')
            role=self.role
            def on_chunk(kind,index,total):
                direction='a2b' if (role=='Alice')==(kind=='tx') else 'b2a'
                if kind=='rx' and index==1:
                    self.event('flow','b2a' if role=='Alice' else 'a2b',f'{role} RX · LoRa chunks')
                self.event('progress',f'{role} {kind.upper()} · chunk {index}/{total}')
            lora_transport.PROGRESS_CALLBACK=on_chunk
            # Instrument the existing real functions (the actual cryptographic and LoRa code remains unchanged).
            def wrap_send(fn):
                def run(data,*args,**kwargs):
                    caption=f'{role} TX · {len(data)} bytes / {(len(data)+219)//220} LoRa chunks'
                    self.event('flow','a2b' if role=='Alice' else 'b2a',caption)
                    try:return fn(data,*args,**kwargs)
                    finally:self.event('flow_stop',f'{role} TX complete · {len(data)} bytes')
                return run
            def wrap_recv(fn):
                def run(*args,**kwargs):
                    try:
                        data=fn(*args,**kwargs)
                        return data
                    finally:
                        self.event('flow_stop',f'{role} RX complete / stopped')
                return run
            # All imported module-level aliases must be instrumented, not just transport's originals.
            for mod in (pairing,authentication,key_exchange):
                mod.send_complete=wrap_send(mod.send_complete)
                mod.receive_complete=wrap_recv(mod.receive_complete)
            for mod in (identity,pairing,key_exchange):
                for name,desc in [('replace_identity','Own ML-DSA public + private'),('replace_peer','Verified peer ML-DSA public'),('import_session_key','AES-256 session key')]:
                    if hasattr(mod,name):
                        original=getattr(mod,name)
                        def stored(*a,_f=original,_d=desc,**kw):
                            result=_f(*a,**kw);self.event('store',_d);return result
                        setattr(mod,name,stored)
            # Pairing's input prompt is replaced only inside pairing.exchange's global namespace.
            import builtins
            def verified_input(prompt):
                return self.ask('fingerprint',self.pending_digest)
            # Explicit controlled replacement, restored immediately afterward.
            while True:
                self.event('reset');self.event('status','Identity generation')
                if self.ask('confirm','REKEY')!='REKEY':raise RuntimeError('Key replacement not authorized')
                self.event('log','Generating fresh ML-DSA-65 identity and writing to EdgeLock via SCP03...')
                identity.provision_fresh()
                self.event('log','Own SHA-256: '+hashlib.sha256(se050_bridge.read_own_public()).hexdigest())
                self.event('log','Public key exchange: 1952-byte ML-DSA-65 public key')
                self.ask('next','Exchange public keys over LoRa')
                original_input=builtins.input
                def input_for_pair(prompt):
                    # digest is received peer key, obtained by intercepting its print in a wrapper below
                    return self.ask('fingerprint',self.pending_digest)
                # Replace only pairing.exchange globals via its own function code globals (input builtin lookup).
                old_print=pairing.__dict__.get('print',None)
                def capture_print(*a,**kw):
                    line=' '.join(map(str,a))
                    if line.startswith('RECEIVED peer SHA-256:'):
                        self.pending_digest=line.split(':',1)[1].strip()
                    self.event('log',line)
                pairing.print=capture_print;pairing.input=input_for_pair
                try:pairing.exchange(role)
                finally:
                    if old_print is None:pairing.__dict__.pop('print',None)
                    else:pairing.print=old_print
                    pairing.__dict__.pop('input',None)
                self.event('log','ML-DSA-65 mutual challenge-response authentication')
                self.ask('next','Run mutual authentication')
                transcript=authentication.authenticate(role)
                self.event('log','ML-KEM-512 signed public-key / ciphertext exchange')
                self.ask('next','Run ML-KEM + HKDF + EdgeLock save')
                sid=key_exchange.establish(role,transcript);self.current_sid=sid
                self.event('log','HKDF-SHA256 derived 32-byte AES key; stored in SE050E via SCP03')
                self.event('ready');self.event('status','Session ready')
                if self.chat_loop(role,sid):
                    self.event('reset')
                    self.event('log','Authenticated rekey request received; establishing new PQC session')
                    continue
                break
        except Exception as exc:
            self.event('log','ERROR: '+repr(exc));self.event('failed',f'{type(exc).__name__}: {exc}')
    def chat_loop(self,role,sid):
        """Bidirectional chat: each side may send consecutive messages.

        One worker owns the UART. Idle RX is polled briefly so queued local
        messages can transmit. Simultaneous transmissions can collide on LoRa;
        the existing stop-and-wait retries are retained, but this is not a
        collision-free multi-access protocol.
        """
        import lora_transport
        from se050_bridge import encrypt,decrypt
        aad=b'EDGELOCK-SCP03-GUI-V1|'+sid
        rx_direction='b2a' if role=='Alice' else 'a2b'
        tx_direction='a2b' if role=='Alice' else 'b2a'
        while True:
            try:
                kind,value=self.actions.get_nowait()
            except queue.Empty:
                kind=None
            if kind in ('message','rekey'):
                if self.rekey_requested:kind='rekey'
                if kind=='rekey':payload=b'R'
                else:
                    raw=value.encode('utf-8')
                    if len(raw)>2048:raise ValueError('Message exceeds 2048 bytes')
                    payload=b'M'+raw
                nonce,ct,tag=encrypt(payload,aad)
                framed=struct.pack('>H',len(payload))+nonce+ct+tag
                self.event('flow',tx_direction,f'{role} TX · AES-GCM / LoRa')
                try:lora_transport.send_framed_complete(framed)
                finally:self.event('flow_stop',f'{role} TX complete')
                if kind=='rekey':return True
                self.event('chat','You',value)
                continue
            # No animation during idle listening. The first RX chunk starts it.
            packet_raw=lora_transport.receive_complete(None,idle_timeout=0.16)
            if packet_raw is None:continue
            self.event('flow_stop',f'{role} RX complete')
            packet=lora_transport.unframe_complete(packet_raw)
            if len(packet)<31:raise RuntimeError('Invalid encrypted chat packet')
            n=struct.unpack('>H',packet[:2])[0]
            if n>2049 or len(packet)!=30+n:raise RuntimeError('Invalid chat packet length')
            plain=decrypt(packet[2:14],packet[14:14+n],packet[14+n:],aad)
            if plain==b'R':return True
            if not plain.startswith(b'M'):raise RuntimeError('Unknown chat command')
            self.event('chat','Bob' if role=='Alice' else 'Alice',plain[1:].decode('utf-8'))

def main():
    root=tk.Tk();Application(root);root.mainloop()

if __name__=='__main__':main()
