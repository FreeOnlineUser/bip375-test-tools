#!/usr/bin/env python3
"""
BIP-375 Test Tool GUI

Simple GUI for generating Silent Payment addresses and BIP-375 PSBTs,
with QR codes for SeedSigner to scan.

Usage:
    python gui.py
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import io
import base64

try:
    import qrcode
    from PIL import Image, ImageTk
    HAS_QR = True
except ImportError:
    HAS_QR = False
    print("Warning: qrcode and/or Pillow not installed. QR codes will not be displayed.")
    print("Install with: pip install qrcode[pil]")

from generate_psbt import (
    generate_sp_address,
    create_bip375_psbt,
    parse_silent_payment_address,
    DEFAULT_MNEMONIC,
)


class BIP375TestToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BIP-375 Silent Payment Test Tool")
        self.root.geometry("1000x750")

        # Variables
        self.mnemonic_var = tk.StringVar(value=DEFAULT_MNEMONIC)
        self.network_var = tk.StringVar(value="mainnet")
        self.sp_address_var = tk.StringVar()
        self.amount_var = tk.StringVar(value="100000")
        self.psbt_var = tk.StringVar()

        # QR labels
        self.sp_qr_label = None
        self.psbt_qr_label = None

        self._create_widgets()

    def _create_widgets(self):
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)

        row = 0

        # === Mnemonic Section ===
        ttk.Label(main_frame, text="Mnemonic:", font=("", 10, "bold")).grid(
            row=row, column=0, sticky="w", pady=(0, 5)
        )
        row += 1

        mnemonic_frame = ttk.Frame(main_frame)
        mnemonic_frame.grid(row=row, column=0, sticky="ew", pady=(0, 5))
        mnemonic_frame.columnconfigure(0, weight=1)

        self.mnemonic_entry = ttk.Entry(mnemonic_frame, textvariable=self.mnemonic_var, width=100)
        self.mnemonic_entry.grid(row=0, column=0, sticky="ew")

        ttk.Button(mnemonic_frame, text="Default", command=self._reset_mnemonic, width=8).grid(
            row=0, column=1, padx=(5, 0)
        )

        row += 1

        # === Network Selection ===
        network_frame = ttk.Frame(main_frame)
        network_frame.grid(row=row, column=0, sticky="w", pady=5)

        ttk.Label(network_frame, text="Network:", font=("", 10, "bold")).grid(row=0, column=0, padx=(0, 10))
        ttk.Radiobutton(network_frame, text="Mainnet (sp1...)",
                       variable=self.network_var, value="mainnet").grid(row=0, column=1)
        ttk.Radiobutton(network_frame, text="Testnet (tsp1...)",
                       variable=self.network_var, value="testnet").grid(row=0, column=2, padx=(20, 0))

        row += 1

        # === Two-column layout for SP Address and PSBT ===
        ttk.Separator(main_frame, orient="horizontal").grid(
            row=row, column=0, sticky="ew", pady=10
        )
        row += 1

        columns_frame = ttk.Frame(main_frame)
        columns_frame.grid(row=row, column=0, sticky="nsew", pady=5)
        columns_frame.columnconfigure(0, weight=1)
        columns_frame.columnconfigure(1, weight=1)

        # === LEFT COLUMN: SP Address ===
        left_frame = ttk.LabelFrame(columns_frame, text="Step 1: SP Address", padding=10)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        left_frame.columnconfigure(0, weight=1)

        ttk.Button(left_frame, text="Generate SP Address",
                  command=self._generate_sp_address, width=25).grid(
            row=0, column=0, pady=(0, 10)
        )

        # SP Address entry
        sp_entry_frame = ttk.Frame(left_frame)
        sp_entry_frame.grid(row=1, column=0, sticky="ew", pady=(0, 5))
        sp_entry_frame.columnconfigure(0, weight=1)

        self.sp_entry = ttk.Entry(sp_entry_frame, textvariable=self.sp_address_var, width=50)
        self.sp_entry.grid(row=0, column=0, sticky="ew")

        ttk.Button(sp_entry_frame, text="Copy", command=self._copy_sp_address, width=6).grid(
            row=0, column=1, padx=(5, 0)
        )

        # SP Address QR code
        sp_qr_frame = ttk.Frame(left_frame, relief="sunken", borderwidth=2)
        sp_qr_frame.grid(row=2, column=0, sticky="n", pady=5)

        self.sp_qr_label = ttk.Label(sp_qr_frame, text="SP Address QR\nwill appear here",
                                     padding=20, anchor="center", justify="center",
                                     width=30)
        self.sp_qr_label.grid(row=0, column=0)

        # === RIGHT COLUMN: PSBT ===
        right_frame = ttk.LabelFrame(columns_frame, text="Step 2: BIP-375 PSBT", padding=10)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        right_frame.columnconfigure(0, weight=1)

        # Amount input
        amount_frame = ttk.Frame(right_frame)
        amount_frame.grid(row=0, column=0, sticky="w", pady=(0, 10))

        ttk.Label(amount_frame, text="Amount:").grid(row=0, column=0)
        ttk.Entry(amount_frame, textvariable=self.amount_var, width=12).grid(row=0, column=1, padx=(5, 0))
        ttk.Label(amount_frame, text="sats").grid(row=0, column=2, padx=(5, 0))

        ttk.Button(amount_frame, text="Generate PSBT",
                  command=self._generate_psbt, width=15).grid(row=0, column=3, padx=(15, 0))

        # PSBT text area
        psbt_text_frame = ttk.Frame(right_frame)
        psbt_text_frame.grid(row=1, column=0, sticky="ew", pady=(0, 5))
        psbt_text_frame.columnconfigure(0, weight=1)

        self.psbt_text = tk.Text(psbt_text_frame, height=3, width=50, wrap="char")
        self.psbt_text.grid(row=0, column=0, sticky="ew")

        psbt_btn_frame = ttk.Frame(psbt_text_frame)
        psbt_btn_frame.grid(row=0, column=1, sticky="n", padx=(5, 0))

        ttk.Button(psbt_btn_frame, text="Copy", command=self._copy_psbt, width=6).grid(row=0, column=0)
        ttk.Button(psbt_btn_frame, text="Save", command=self._save_psbt, width=6).grid(row=1, column=0, pady=(2, 0))

        # PSBT QR code
        psbt_qr_frame = ttk.Frame(right_frame, relief="sunken", borderwidth=2)
        psbt_qr_frame.grid(row=2, column=0, sticky="n", pady=5)

        self.psbt_qr_label = ttk.Label(psbt_qr_frame, text="PSBT QR\nwill appear here",
                                       padding=20, anchor="center", justify="center",
                                       width=30)
        self.psbt_qr_label.grid(row=0, column=0)

        row += 1

        # === Warning Label ===
        warning_frame = ttk.Frame(main_frame)
        warning_frame.grid(row=row, column=0, sticky="ew", pady=(5, 0))

        warning_text = "FOR TESTING ONLY: PSBTs reference non-existent inputs and cannot be broadcast to the network."
        warning_label = ttk.Label(warning_frame, text=warning_text, foreground="red", font=("", 9, "bold"))
        warning_label.grid(row=0, column=0, sticky="w")

        row += 1

        # === Info Labels ===
        info_text1 = "SP address is always the same (derived from mnemonic). PSBT changes each click (random txid + DLEQ nonce)."
        info_label1 = ttk.Label(main_frame, text=info_text1, foreground="gray", font=("", 8))
        info_label1.grid(row=row, column=0, sticky="w", pady=(2, 0))

        row += 1

        info_text2 = "This is the privacy feature: same SP address -> different on-chain output each time."
        info_label2 = ttk.Label(main_frame, text=info_text2, foreground="gray", font=("", 8))
        info_label2.grid(row=row, column=0, sticky="w", pady=(0, 0))

        row += 1

        # === Status Bar ===
        self.status_var = tk.StringVar(value="Ready. Generate an SP address to get started.")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief="sunken", anchor="w")
        status_bar.grid(row=row, column=0, sticky="ew", pady=(5, 0))

    def _reset_mnemonic(self):
        self.mnemonic_var.set(DEFAULT_MNEMONIC)
        self.status_var.set("Mnemonic reset to default test mnemonic")

    def _generate_sp_address(self):
        try:
            mnemonic = self.mnemonic_var.get().strip()
            network = self.network_var.get()

            sp_addr, B_scan, B_spend = generate_sp_address(mnemonic, network)
            self.sp_address_var.set(sp_addr)

            self.status_var.set(f"Generated {network} SP address successfully")
            self._show_sp_qr()  # Auto-show QR

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate SP address:\n{e}")
            self.status_var.set(f"Error: {e}")

    def _generate_psbt(self):
        try:
            sp_addr = self.sp_address_var.get().strip()
            if not sp_addr:
                messagebox.showwarning("Warning", "Please generate or enter an SP address first")
                return

            mnemonic = self.mnemonic_var.get().strip()
            amount = int(self.amount_var.get())

            psbt_base64, psbt, output_xonly = create_bip375_psbt(
                sp_address=sp_addr,
                amount_sats=amount,
                mnemonic=mnemonic
            )

            self.psbt_text.delete("1.0", tk.END)
            self.psbt_text.insert("1.0", psbt_base64)

            self.status_var.set(f"Generated BIP-375 PSBT: {len(psbt_base64)} chars")
            self._show_psbt_qr()  # Auto-show QR

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate PSBT:\n{e}")
            self.status_var.set(f"Error: {e}")

    def _generate_qr_image(self, data: str, size: int = 200):
        """Generate a QR code image."""
        if not HAS_QR:
            return None

        try:
            qr = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=4,
                border=2,
            )
            qr.add_data(data)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")

            # Convert to PhotoImage
            img_bytes = io.BytesIO()
            img.save(img_bytes, format="PNG")
            img_bytes.seek(0)

            pil_img = Image.open(img_bytes)

            # Resize if needed to fit better
            if pil_img.width > size or pil_img.height > size:
                pil_img.thumbnail((size, size), Image.Resampling.LANCZOS)

            return ImageTk.PhotoImage(pil_img)

        except Exception as e:
            print(f"QR generation error: {e}")
            return None

    def _show_sp_qr(self):
        if not HAS_QR:
            messagebox.showwarning("Missing Dependencies",
                "QR code display requires 'qrcode' and 'Pillow' packages.\n\n"
                "Install with: pip install qrcode[pil]")
            return

        sp_addr = self.sp_address_var.get().strip()
        if sp_addr:
            photo = self._generate_qr_image(sp_addr, size=250)
            if photo:
                self.sp_qr_label.configure(image=photo, text="")
                self.sp_qr_label.image = photo  # Keep reference
        else:
            self.sp_qr_label.configure(image="", text="SP Address QR\nwill appear here")

    def _show_psbt_qr(self):
        if not HAS_QR:
            messagebox.showwarning("Missing Dependencies",
                "QR code display requires 'qrcode' and 'Pillow' packages.\n\n"
                "Install with: pip install qrcode[pil]")
            return

        psbt = self.psbt_text.get("1.0", tk.END).strip()
        if psbt:
            photo = self._generate_qr_image(psbt, size=250)
            if photo:
                self.psbt_qr_label.configure(image=photo, text="")
                self.psbt_qr_label.image = photo  # Keep reference
        else:
            self.psbt_qr_label.configure(image="", text="PSBT QR\nwill appear here")

    def _copy_sp_address(self):
        sp_addr = self.sp_address_var.get()
        if sp_addr:
            self.root.clipboard_clear()
            self.root.clipboard_append(sp_addr)
            self.status_var.set("SP address copied to clipboard")

    def _copy_psbt(self):
        psbt = self.psbt_text.get("1.0", tk.END).strip()
        if psbt:
            self.root.clipboard_clear()
            self.root.clipboard_append(psbt)
            self.status_var.set("PSBT copied to clipboard")

    def _save_psbt(self):
        psbt = self.psbt_text.get("1.0", tk.END).strip()
        if not psbt:
            messagebox.showinfo("Info", "No PSBT to save")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".psbt",
            filetypes=[("PSBT files", "*.psbt"), ("Text files", "*.txt"), ("All files", "*.*")],
            title="Save PSBT"
        )

        if filename:
            with open(filename, "w") as f:
                f.write(psbt)
            self.status_var.set(f"PSBT saved to {filename}")


def main():
    root = tk.Tk()
    app = BIP375TestToolGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
