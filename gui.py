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
        self.root.geometry("900x700")

        # Variables
        self.mnemonic_var = tk.StringVar(value=DEFAULT_MNEMONIC)
        self.network_var = tk.StringVar(value="mainnet")
        self.sp_address_var = tk.StringVar()
        self.amount_var = tk.StringVar(value="100000")
        self.psbt_var = tk.StringVar()

        # Current QR data
        self.current_qr_data = None
        self.qr_label = None

        self._create_widgets()

    def _create_widgets(self):
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

        row = 0

        # === Mnemonic Section ===
        ttk.Label(main_frame, text="Mnemonic:", font=("", 10, "bold")).grid(
            row=row, column=0, sticky="nw", pady=(0, 5)
        )

        mnemonic_frame = ttk.Frame(main_frame)
        mnemonic_frame.grid(row=row, column=1, sticky="ew", pady=(0, 5))
        mnemonic_frame.columnconfigure(0, weight=1)

        self.mnemonic_entry = ttk.Entry(mnemonic_frame, textvariable=self.mnemonic_var, width=80)
        self.mnemonic_entry.grid(row=0, column=0, sticky="ew")

        ttk.Button(mnemonic_frame, text="Default", command=self._reset_mnemonic, width=8).grid(
            row=0, column=1, padx=(5, 0)
        )

        row += 1

        # === Network Selection ===
        ttk.Label(main_frame, text="Network:", font=("", 10, "bold")).grid(
            row=row, column=0, sticky="w", pady=5
        )

        network_frame = ttk.Frame(main_frame)
        network_frame.grid(row=row, column=1, sticky="w", pady=5)

        ttk.Radiobutton(network_frame, text="Mainnet (sp1...)",
                       variable=self.network_var, value="mainnet").grid(row=0, column=0)
        ttk.Radiobutton(network_frame, text="Testnet (tsp1...)",
                       variable=self.network_var, value="testnet").grid(row=0, column=1, padx=(20, 0))

        row += 1

        # === Generate SP Address Button ===
        ttk.Separator(main_frame, orient="horizontal").grid(
            row=row, column=0, columnspan=2, sticky="ew", pady=10
        )
        row += 1

        ttk.Button(main_frame, text="1. Generate SP Address",
                  command=self._generate_sp_address, width=25).grid(
            row=row, column=0, columnspan=2, pady=5
        )
        row += 1

        # === SP Address Display ===
        ttk.Label(main_frame, text="SP Address:", font=("", 10, "bold")).grid(
            row=row, column=0, sticky="nw", pady=5
        )

        sp_frame = ttk.Frame(main_frame)
        sp_frame.grid(row=row, column=1, sticky="ew", pady=5)
        sp_frame.columnconfigure(0, weight=1)

        self.sp_entry = ttk.Entry(sp_frame, textvariable=self.sp_address_var, width=80)
        self.sp_entry.grid(row=0, column=0, sticky="ew")

        ttk.Button(sp_frame, text="Show QR", command=self._show_sp_qr, width=10).grid(
            row=0, column=1, padx=(5, 0)
        )
        ttk.Button(sp_frame, text="Copy", command=self._copy_sp_address, width=6).grid(
            row=0, column=2, padx=(5, 0)
        )

        row += 1

        # === Amount ===
        ttk.Separator(main_frame, orient="horizontal").grid(
            row=row, column=0, columnspan=2, sticky="ew", pady=10
        )
        row += 1

        ttk.Label(main_frame, text="Amount (sats):", font=("", 10, "bold")).grid(
            row=row, column=0, sticky="w", pady=5
        )

        amount_frame = ttk.Frame(main_frame)
        amount_frame.grid(row=row, column=1, sticky="w", pady=5)

        ttk.Entry(amount_frame, textvariable=self.amount_var, width=15).grid(row=0, column=0)
        ttk.Label(amount_frame, text="satoshis").grid(row=0, column=1, padx=(5, 0))

        row += 1

        # === Generate PSBT Button ===
        ttk.Button(main_frame, text="2. Generate BIP-375 PSBT",
                  command=self._generate_psbt, width=25).grid(
            row=row, column=0, columnspan=2, pady=10
        )
        row += 1

        # === PSBT Display ===
        ttk.Label(main_frame, text="PSBT (base64):", font=("", 10, "bold")).grid(
            row=row, column=0, sticky="nw", pady=5
        )

        psbt_frame = ttk.Frame(main_frame)
        psbt_frame.grid(row=row, column=1, sticky="ew", pady=5)
        psbt_frame.columnconfigure(0, weight=1)

        self.psbt_text = tk.Text(psbt_frame, height=4, width=70, wrap="char")
        self.psbt_text.grid(row=0, column=0, sticky="ew")

        psbt_btn_frame = ttk.Frame(psbt_frame)
        psbt_btn_frame.grid(row=0, column=1, sticky="n", padx=(5, 0))

        ttk.Button(psbt_btn_frame, text="Show QR", command=self._show_psbt_qr, width=10).grid(row=0, column=0)
        ttk.Button(psbt_btn_frame, text="Copy", command=self._copy_psbt, width=10).grid(row=1, column=0, pady=(2, 0))
        ttk.Button(psbt_btn_frame, text="Save", command=self._save_psbt, width=10).grid(row=2, column=0, pady=(2, 0))

        row += 1

        # === QR Code Display Area ===
        ttk.Separator(main_frame, orient="horizontal").grid(
            row=row, column=0, columnspan=2, sticky="ew", pady=10
        )
        row += 1

        ttk.Label(main_frame, text="QR Code:", font=("", 10, "bold")).grid(
            row=row, column=0, sticky="nw", pady=5
        )

        qr_frame = ttk.Frame(main_frame, relief="sunken", borderwidth=2)
        qr_frame.grid(row=row, column=1, sticky="w", pady=5)

        self.qr_label = ttk.Label(qr_frame, text="Click 'Show QR' to display\na QR code for SeedSigner",
                                  padding=20, anchor="center", justify="center")
        self.qr_label.grid(row=0, column=0)

        row += 1

        # === Status Bar ===
        self.status_var = tk.StringVar(value="Ready. Generate an SP address to get started.")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief="sunken", anchor="w")
        status_bar.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(10, 0))

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

            self.status_var.set(f"Generated BIP-375 PSBT: {len(psbt_base64)} chars, output: {output_xonly.hex()[:16]}...")
            self._show_psbt_qr()  # Auto-show QR

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate PSBT:\n{e}")
            self.status_var.set(f"Error: {e}")

    def _show_qr(self, data: str, label: str):
        if not HAS_QR:
            messagebox.showwarning("Missing Dependencies",
                "QR code display requires 'qrcode' and 'Pillow' packages.\n\n"
                "Install with: pip install qrcode[pil]")
            return

        try:
            # Generate QR code
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
            photo = ImageTk.PhotoImage(pil_img)

            # Update label
            self.qr_label.configure(image=photo, text="")
            self.qr_label.image = photo  # Keep reference

            self.current_qr_data = data
            self.status_var.set(f"Showing QR for {label} ({len(data)} chars)")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate QR code:\n{e}")

    def _show_sp_qr(self):
        sp_addr = self.sp_address_var.get().strip()
        if sp_addr:
            self._show_qr(sp_addr, "SP Address")
        else:
            messagebox.showinfo("Info", "No SP address to display")

    def _show_psbt_qr(self):
        psbt = self.psbt_text.get("1.0", tk.END).strip()
        if psbt:
            self._show_qr(psbt, "PSBT")
        else:
            messagebox.showinfo("Info", "No PSBT to display")

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
