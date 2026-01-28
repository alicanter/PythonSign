import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers, PdfSigner

class SignerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Digital Signer")
        self.root.geometry("500x450")

        self.pdf_path = None
        self.p12_path = None
        self.empty_fields = []

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Step 1: Select PDF File", font=('Arial', 10, 'bold')).pack(pady=5)
        self.btn_pdf = tk.Button(self.root, text="Browse PDF", command=self.load_pdf)
        self.btn_pdf.pack()
        self.lbl_pdf = tk.Label(self.root, text="No file selected", fg="gray")
        self.lbl_pdf.pack(pady=2)

        self.btn_check = tk.Button(self.root, text="Find Empty Signature Fields", 
                                   command=self.check_fields, state=tk.DISABLED)
        self.btn_check.pack(pady=10)

        tk.Label(self.root, text="Select a signature field:").pack()
        self.listbox = tk.Listbox(self.root, height=5, width=50)
        self.listbox.pack(pady=5)
        self.listbox.bind('<<ListboxSelect>>', self.on_field_select)

        tk.Label(self.root, text="Step 2: Digital Identity", font=('Arial', 10, 'bold')).pack(pady=5)
        self.btn_p12 = tk.Button(self.root, text="Browse .p12 Certificate", 
                                 command=self.load_p12, state=tk.DISABLED)
        self.btn_p12.pack()
        self.lbl_p12 = tk.Label(self.root, text="No certificate selected", fg="gray")
        self.lbl_p12.pack(pady=2)

        self.btn_sign = tk.Button(self.root, text="Sign Document", bg="#4CAF50", fg="white",
                                  command=self.execute_signing, state=tk.DISABLED)
        self.btn_sign.pack(pady=20)

    def load_pdf(self):
        self.pdf_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if self.pdf_path:
            self.lbl_pdf.config(text=os.path.basename(self.pdf_path), fg="black")
            self.btn_check.config(state=tk.NORMAL)
            self.listbox.delete(0, tk.END)

    def check_fields(self):
        try:
            self.listbox.delete(0, tk.END)
            self.empty_fields = []
            with open(self.pdf_path, 'rb') as f:
                reader = PdfFileReader(f, strict=False)
                sig_fields = list(fields.enumerate_sig_fields(reader))
                
                for field_info in sig_fields:
                    name, value = field_info[0], field_info[1]
                    if value is None:
                        self.empty_fields.append(name)
                        self.listbox.insert(tk.END, name)

            if not self.empty_fields:
                messagebox.showinfo("Info", "No empty signature fields found in this document.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not read PDF: {e}")

    def on_field_select(self, event):
        if self.listbox.curselection():
            self.btn_p12.config(state=tk.NORMAL)

    def load_p12(self):
        self.p12_path = filedialog.askopenfilename(
            filetypes=[
                ("PKCS12 files", "*.p12 *.pfx"),
                ("All files", "*.*")
            ]
        )
        if self.p12_path:
            self.lbl_p12.config(text=os.path.basename(self.p12_path), fg="black")
            self.btn_sign.config(state=tk.NORMAL)

    def execute_signing(self):
        selection = self.listbox.curselection()
        if not selection:
            return
        
        target_field = self.listbox.get(selection[0])
        password = simpledialog.askstring("Password", "Enter certificate password:", show='*')
        
        if not password:
            return

        default_out = self.pdf_path.replace(".pdf", "_signed.pdf")
        output_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            initialfile=os.path.basename(default_out),
            filetypes=[("PDF files", "*.pdf")]
        )

        if not output_path:
            return

        try:
            signer = signers.SimpleSigner.load_pkcs12(
                pfx_file=self.p12_path,
                passphrase=password.encode("utf-8")
            )

            with open(self.pdf_path, 'rb+') as doc:
                writer = IncrementalPdfFileWriter(doc, strict=False)
                with open(output_path, 'wb') as out:
                    PdfSigner(
                        signature_meta=signers.PdfSignatureMetadata(field_name=target_field),
                        signer=signer,
                    ).sign_pdf(writer, output=out)
            
            messagebox.showinfo("Success", f"Document signed successfully!\nSaved to: {output_path}")
            
        except Exception as e:
            messagebox.showerror("Signing Error", f"An error occurred: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SignerApp(root)
    root.mainloop()
