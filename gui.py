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

try:
    from urtypes.crypto import PSBT as UR_PSBT
    from ur2.ur_encoder import UREncoder
    from ur2.ur_decoder import URDecoder
    from ur2.ur import UR
    HAS_UR = True
except ImportError:
    HAS_UR = False
    print("Warning: urtypes not installed. Animated QR codes will not be available.")
    print("Install with: pip install urtypes")

# Camera scanning dependencies
try:
    import cv2
    from pyzbar import pyzbar
    from pyzbar.pyzbar import ZBarSymbol
    HAS_CAMERA = True
except ImportError:
    HAS_CAMERA = False
    print("Warning: opencv-python and/or pyzbar not installed. Camera scanning disabled.")
    print("Install with: pip install opencv-python pyzbar")

from generate_psbt import (
    generate_sp_address,
    create_bip375_psbt,
    parse_silent_payment_address,
    DEFAULT_MNEMONIC,
)

# Different test mnemonic for sender (visually distinct)
SENDER_MNEMONIC = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"


class BIP375TestToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BIP-375 Silent Payment Test Tool")
        self.root.geometry("1000x800")

        # Variables
        self.network_var = tk.StringVar(value="mainnet")
        self.sp_address_var = tk.StringVar()
        self.amount_var = tk.StringVar(value="100000")
        self.psbt_var = tk.StringVar()
        self.qr_mode_var = tk.StringVar(value="animated" if HAS_UR else "static")

        # QR labels
        self.sp_qr_label = None
        self.psbt_qr_label = None

        # Animation state
        self.ur_frames = []
        self.current_frame = 0
        self.animation_id = None

        # Camera scanner state
        self.camera_scanner = None

        self._create_widgets()

    def _create_widgets(self):
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)

        row = 0

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
        columns_frame = ttk.Frame(main_frame)
        columns_frame.grid(row=row, column=0, sticky="nsew", pady=5)
        columns_frame.columnconfigure(0, weight=1)
        columns_frame.columnconfigure(1, weight=1)

        # === LEFT COLUMN: SP Address (Recipient) ===
        left_frame = ttk.LabelFrame(columns_frame, text="Step 1: Recipient SP Address", padding=10)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        left_frame.columnconfigure(0, weight=1)

        # Recipient mnemonic (for SP address generation) - 2 lines
        ttk.Label(left_frame, text="Recipient mnemonic:", font=("", 9)).grid(
            row=0, column=0, sticky="w", pady=(0, 2)
        )

        recipient_frame = ttk.Frame(left_frame)
        recipient_frame.grid(row=1, column=0, sticky="ew", pady=(0, 5))
        recipient_frame.columnconfigure(0, weight=1)

        self.recipient_text = tk.Text(recipient_frame, height=2, width=40, wrap="word")
        self.recipient_text.grid(row=0, column=0, sticky="ew")
        self.recipient_text.insert("1.0", DEFAULT_MNEMONIC)

        recipient_btn_frame = ttk.Frame(recipient_frame)
        recipient_btn_frame.grid(row=0, column=1, sticky="n", padx=(5, 0))
        ttk.Button(recipient_btn_frame, text="Default", command=self._reset_recipient_mnemonic, width=8).grid(row=0, column=0)

        ttk.Button(left_frame, text="Generate SP Address",
                  command=self._generate_sp_address, width=25).grid(
            row=2, column=0, pady=(5, 10)
        )

        # SP Address entry
        sp_entry_frame = ttk.Frame(left_frame)
        sp_entry_frame.grid(row=3, column=0, sticky="ew", pady=(0, 5))
        sp_entry_frame.columnconfigure(0, weight=1)

        self.sp_entry = ttk.Entry(sp_entry_frame, textvariable=self.sp_address_var, width=50)
        self.sp_entry.grid(row=0, column=0, sticky="ew")

        ttk.Button(sp_entry_frame, text="Copy", command=self._copy_sp_address, width=6).grid(
            row=0, column=1, padx=(5, 0)
        )

        # Note about SP address
        ttk.Label(left_frame, text="(You can also paste any sp1.../tsp1... address here)",
                 foreground="gray", font=("", 8)).grid(row=4, column=0, sticky="w", pady=(0, 5))

        # SP Address QR code
        sp_qr_frame = ttk.Frame(left_frame, relief="sunken", borderwidth=2)
        sp_qr_frame.grid(row=5, column=0, sticky="n", pady=5)

        self.sp_qr_label = ttk.Label(sp_qr_frame, text="SP Address QR\nwill appear here",
                                     padding=20, anchor="center", justify="center",
                                     width=30)
        self.sp_qr_label.grid(row=0, column=0)

        # === RIGHT COLUMN: PSBT ===
        right_frame = ttk.LabelFrame(columns_frame, text="Step 2: BIP-375 PSBT", padding=10)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        right_frame.columnconfigure(0, weight=1)

        # Sender mnemonic (for signing) - 2 lines
        ttk.Label(right_frame, text="Sender seed (load into SeedSigner):", font=("", 9)).grid(
            row=0, column=0, sticky="w", pady=(0, 2)
        )

        sender_frame = ttk.Frame(right_frame)
        sender_frame.grid(row=1, column=0, sticky="ew", pady=(0, 5))
        sender_frame.columnconfigure(0, weight=1)

        self.sender_text = tk.Text(sender_frame, height=2, width=40, wrap="word")
        self.sender_text.grid(row=0, column=0, sticky="ew")
        self.sender_text.insert("1.0", SENDER_MNEMONIC)

        sender_btn_frame = ttk.Frame(sender_frame)
        sender_btn_frame.grid(row=0, column=1, sticky="n", padx=(5, 0))
        ttk.Button(sender_btn_frame, text="Default", command=self._reset_sender_mnemonic, width=8).grid(row=0, column=0)
        ttk.Button(sender_btn_frame, text="Seed QR", command=self._show_seed_qr, width=8).grid(row=1, column=0, pady=(2, 0))

        # Amount input and generate button
        amount_frame = ttk.Frame(right_frame)
        amount_frame.grid(row=2, column=0, sticky="w", pady=(5, 5))

        ttk.Label(amount_frame, text="Amount:").grid(row=0, column=0)
        ttk.Entry(amount_frame, textvariable=self.amount_var, width=12).grid(row=0, column=1, padx=(5, 0))
        ttk.Label(amount_frame, text="sats").grid(row=0, column=2, padx=(5, 0))

        ttk.Button(amount_frame, text="Generate PSBT",
                  command=self._generate_psbt, width=15).grid(row=0, column=3, padx=(15, 0))

        # QR Mode toggle
        qr_mode_frame = ttk.Frame(right_frame)
        qr_mode_frame.grid(row=3, column=0, sticky="w", pady=(0, 5))

        ttk.Label(qr_mode_frame, text="QR Mode:").grid(row=0, column=0, padx=(0, 5))
        anim_rb = ttk.Radiobutton(qr_mode_frame, text="Animated (UR)",
                       variable=self.qr_mode_var, value="animated",
                       command=self._on_qr_mode_change)
        anim_rb.grid(row=0, column=1)
        if not HAS_UR:
            anim_rb.configure(state="disabled")

        ttk.Radiobutton(qr_mode_frame, text="Static",
                       variable=self.qr_mode_var, value="static",
                       command=self._on_qr_mode_change).grid(row=0, column=2, padx=(10, 0))

        if not HAS_UR:
            ttk.Label(qr_mode_frame, text="(pip install urtypes)", foreground="gray").grid(row=0, column=3, padx=(5, 0))

        # Derived output address (bc1p...)
        output_addr_frame = ttk.Frame(right_frame)
        output_addr_frame.grid(row=4, column=0, sticky="ew", pady=(0, 5))
        output_addr_frame.columnconfigure(1, weight=1)

        ttk.Label(output_addr_frame, text="Output:", font=("", 9, "bold")).grid(row=0, column=0, padx=(0, 5))
        self.output_addr_var = tk.StringVar(value="(generate PSBT to see derived address)")
        self.output_addr_entry = ttk.Entry(output_addr_frame, textvariable=self.output_addr_var, width=45, state="readonly")
        self.output_addr_entry.grid(row=0, column=1, sticky="ew")
        ttk.Button(output_addr_frame, text="Copy", command=self._copy_output_addr, width=6).grid(row=0, column=2, padx=(5, 0))

        # PSBT text area
        psbt_text_frame = ttk.Frame(right_frame)
        psbt_text_frame.grid(row=5, column=0, sticky="ew", pady=(0, 5))
        psbt_text_frame.columnconfigure(0, weight=1)

        self.psbt_text = tk.Text(psbt_text_frame, height=3, width=50, wrap="char")
        self.psbt_text.grid(row=0, column=0, sticky="ew")

        psbt_btn_frame = ttk.Frame(psbt_text_frame)
        psbt_btn_frame.grid(row=0, column=1, sticky="n", padx=(5, 0))

        ttk.Button(psbt_btn_frame, text="Copy", command=self._copy_psbt, width=6).grid(row=0, column=0)
        ttk.Button(psbt_btn_frame, text="Save", command=self._save_psbt, width=6).grid(row=1, column=0, pady=(2, 0))

        # PSBT QR code
        psbt_qr_frame = ttk.Frame(right_frame, relief="sunken", borderwidth=2)
        psbt_qr_frame.grid(row=6, column=0, sticky="n", pady=5)

        self.psbt_qr_label = ttk.Label(psbt_qr_frame, text="PSBT QR\nwill appear here",
                                       padding=20, anchor="center", justify="center",
                                       width=30)
        self.psbt_qr_label.grid(row=0, column=0)

        # Camera scan button
        scan_btn = ttk.Button(right_frame, text="Use Camera to Verify Signed Transaction",
                             command=self._scan_signed_psbt)
        scan_btn.grid(row=7, column=0, pady=(5, 0))
        if not HAS_CAMERA:
            scan_btn.configure(state="disabled")
            ttk.Label(right_frame, text="(pip install opencv-python pyzbar)",
                     foreground="gray", font=("", 8)).grid(row=8, column=0)

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

    def _reset_sender_mnemonic(self):
        self.sender_text.delete("1.0", tk.END)
        self.sender_text.insert("1.0", SENDER_MNEMONIC)
        self.status_var.set("Sender mnemonic reset to default test mnemonic")

    def _reset_recipient_mnemonic(self):
        self.recipient_text.delete("1.0", tk.END)
        self.recipient_text.insert("1.0", DEFAULT_MNEMONIC)
        self.status_var.set("Recipient mnemonic reset to default test mnemonic")

    def _show_seed_qr(self):
        """Show a popup window with the sender mnemonic as a SeedQR (compact format)."""
        if not HAS_QR:
            messagebox.showwarning("Missing Dependencies",
                "QR code display requires 'qrcode' and 'Pillow' packages.\n\n"
                "Install with: pip install qrcode[pil]")
            return

        mnemonic = self.sender_text.get("1.0", tk.END).strip()
        if not mnemonic:
            messagebox.showwarning("Warning", "No mnemonic entered")
            return

        # Convert mnemonic to SeedQR format (compact numeric)
        # SeedQR encodes each word as its BIP-39 wordlist index (4 digits each)
        try:
            from embit import bip39
            wordlist = bip39.WORDLIST

            words = mnemonic.split()
            if len(words) not in (12, 24):
                messagebox.showerror("Error", "Mnemonic must be 12 or 24 words")
                return

            # Build numeric string: each word -> 4-digit index
            seed_qr_data = ""
            for word in words:
                if word not in wordlist:
                    messagebox.showerror("Error", f"Invalid BIP-39 word: {word}")
                    return
                index = wordlist.index(word)
                seed_qr_data += f"{index:04d}"

            # Create popup window
            popup = tk.Toplevel(self.root)
            popup.title("Seed QR - Scan with SeedSigner")
            popup.geometry("350x420")
            popup.resizable(False, False)

            # Warning label
            warn_label = ttk.Label(popup, text="FOR TESTING ONLY - Do not use with real funds!",
                                   foreground="red", font=("", 9, "bold"))
            warn_label.pack(pady=(10, 5))

            # Generate QR
            qr = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=6,
                border=2,
            )
            qr.add_data(seed_qr_data)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")

            img_bytes = io.BytesIO()
            img.save(img_bytes, format="PNG")
            img_bytes.seek(0)

            pil_img = Image.open(img_bytes)
            photo = ImageTk.PhotoImage(pil_img)

            # QR label
            qr_label = ttk.Label(popup, image=photo)
            qr_label.image = photo  # Keep reference
            qr_label.pack(pady=10)

            # Info label
            info_label = ttk.Label(popup, text=f"SeedQR format ({len(words)} words)\nScan with SeedSigner: Scan > Scan a SeedQR",
                                   justify="center", foreground="gray")
            info_label.pack(pady=(0, 10))

            # Close button
            ttk.Button(popup, text="Close", command=popup.destroy, width=10).pack(pady=(0, 10))

            self.status_var.set(f"Showing SeedQR for {len(words)}-word mnemonic")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate SeedQR:\n{e}")

    def _on_qr_mode_change(self):
        """Handle QR mode toggle - refresh PSBT QR if we have one."""
        psbt = self.psbt_text.get("1.0", tk.END).strip()
        if psbt:
            self._show_psbt_qr()

    def _generate_sp_address(self):
        try:
            mnemonic = self.recipient_text.get("1.0", tk.END).strip()
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
            # Stop any existing animation
            self._stop_animation()

            sp_addr = self.sp_address_var.get().strip()
            if not sp_addr:
                messagebox.showwarning("Warning", "Please generate or enter an SP address first")
                return

            sender_mnemonic = self.sender_text.get("1.0", tk.END).strip()
            amount = int(self.amount_var.get())

            psbt_base64, psbt, output_xonly = create_bip375_psbt(
                sp_address=sp_addr,
                amount_sats=amount,
                mnemonic=sender_mnemonic
            )

            self.psbt_text.delete("1.0", tk.END)
            self.psbt_text.insert("1.0", psbt_base64)

            # Convert x-only pubkey to bc1p... Taproot address
            # Determine network from SP address prefix
            if sp_addr.startswith("tsp1"):
                hrp = "tb"  # testnet
            else:
                hrp = "bc"  # mainnet

            output_addr = self._xonly_to_bech32m(output_xonly, hrp)
            self.output_addr_var.set(output_addr)

            self.status_var.set(f"Generated BIP-375 PSBT: {len(psbt_base64)} chars")
            self._show_psbt_qr()  # Auto-show QR

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate PSBT:\n{e}")
            self.status_var.set(f"Error: {e}")

    def _xonly_to_bech32m(self, xonly_pubkey: bytes, hrp: str = "bc") -> str:
        """Convert x-only pubkey to bech32m Taproot address."""
        from generate_psbt import bech32m_encode
        # Taproot witness version is 1, followed by 32-byte x-only pubkey
        data = bytes([1]) + xonly_pubkey
        return bech32m_encode(hrp, data)

    def _copy_output_addr(self):
        """Copy the derived output address to clipboard."""
        addr = self.output_addr_var.get()
        if addr and not addr.startswith("("):
            self.root.clipboard_clear()
            self.root.clipboard_append(addr)
            self.status_var.set("Output address copied to clipboard")

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

    def _generate_ur_frames(self, psbt_base64: str, max_fragment_len: int = 100) -> list:
        """Generate UR animated QR frames for a PSBT."""
        if not HAS_UR:
            return []

        try:
            # Decode base64 PSBT to bytes
            psbt_bytes = base64.b64decode(psbt_base64)

            # Create UR for crypto-psbt using urtypes
            ur_psbt = UR_PSBT(psbt_bytes)
            cbor_data = ur_psbt.to_cbor()

            # Create UR with type and CBOR data
            ur = UR(ur_psbt.registry_type().type, cbor_data)

            # Create encoder with fragment size
            encoder = UREncoder(ur, max_fragment_len=max_fragment_len)

            # Generate all frames
            frames = []
            # Get enough frames for smooth animation
            seq_len = encoder.fountain_encoder.seq_len()
            # Generate 2x the minimum frames for better scanning
            for _ in range(max(seq_len * 2, 10)):
                frame = encoder.next_part().upper()
                frames.append(frame)

            return frames

        except Exception as e:
            print(f"UR encoding error: {e}")
            import traceback
            traceback.print_exc()
            return []

    def _stop_animation(self):
        """Stop any running animation."""
        if self.animation_id:
            self.root.after_cancel(self.animation_id)
            self.animation_id = None
        self.ur_frames = []
        self.current_frame = 0

    def _animate_qr(self):
        """Display next frame in UR animation."""
        if not self.ur_frames:
            return

        frame_data = self.ur_frames[self.current_frame]
        photo = self._generate_qr_image(frame_data, size=280)

        if photo:
            self.psbt_qr_label.configure(image=photo, text="")
            self.psbt_qr_label.image = photo

        # Move to next frame
        self.current_frame = (self.current_frame + 1) % len(self.ur_frames)

        # Schedule next frame (200ms = 5 fps, good for scanning)
        self.animation_id = self.root.after(200, self._animate_qr)

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

        # Stop any existing animation
        self._stop_animation()

        psbt = self.psbt_text.get("1.0", tk.END).strip()
        if not psbt:
            self.psbt_qr_label.configure(image="", text="PSBT QR\nwill appear here")
            return

        qr_mode = self.qr_mode_var.get()

        if qr_mode == "animated" and HAS_UR:
            # Generate UR frames and start animation
            self.ur_frames = self._generate_ur_frames(psbt)
            if self.ur_frames:
                self.current_frame = 0
                self._animate_qr()
                self.status_var.set(f"Animated UR QR: {len(self.ur_frames)} frames @ 5fps")
            else:
                # Fallback to static if UR encoding fails
                self._show_static_psbt_qr(psbt)
        else:
            self._show_static_psbt_qr(psbt)

    def _show_static_psbt_qr(self, psbt: str):
        """Show static QR code for PSBT."""
        photo = self._generate_qr_image(psbt, size=280)
        if photo:
            self.psbt_qr_label.configure(image=photo, text="")
            self.psbt_qr_label.image = photo
            self.status_var.set(f"Static QR: {len(psbt)} chars (may be hard to scan)")
        else:
            self.psbt_qr_label.configure(image="", text="QR too large\nUse animated mode")
            self.status_var.set("Static QR failed - PSBT too large, try animated mode")

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

    def _scan_signed_psbt(self):
        """Open camera scanner to capture signed PSBT from SeedSigner."""
        if not HAS_CAMERA:
            messagebox.showwarning("Missing Dependencies",
                "Camera scanning requires 'opencv-python' and 'pyzbar' packages.\n\n"
                "Install with: pip install opencv-python pyzbar")
            return

        if not HAS_UR:
            messagebox.showwarning("Missing Dependencies",
                "UR decoding requires 'urtypes' package.\n\n"
                "Install with: pip install urtypes")
            return

        # Prevent multiple camera windows
        if self.camera_scanner is not None and self.camera_scanner.running:
            messagebox.showinfo("Camera Active",
                "A camera scanner is already open.")
            return

        # Cleanup callback when scanner closes (for any reason)
        def on_scanner_close():
            self.camera_scanner = None

        self.camera_scanner = CameraScannerPopup(
            self.root,
            self._on_psbt_scanned,
            on_close=on_scanner_close
        )
        self.camera_scanner.start()

    def _on_psbt_scanned(self, signed_psbt_base64: str):
        """Called when a signed PSBT is successfully scanned."""
        try:
            from embit import psbt as embit_psbt

            # Parse the signed PSBT
            psbt_bytes = base64.b64decode(signed_psbt_base64)
            signed_psbt = embit_psbt.PSBT.parse(psbt_bytes)

            # Check for signatures
            has_signature = False
            for inp in signed_psbt.inputs:
                if inp.final_scriptwitness:
                    has_signature = True
                    break
                # Check for Taproot signature
                if hasattr(inp, 'taproot_sigs') and inp.taproot_sigs:
                    has_signature = True
                    break

            if has_signature:
                messagebox.showinfo("Signature Verified",
                    "The signed PSBT contains a valid Taproot signature.\n\n"
                    "The signing flow completed successfully!")
                self.status_var.set("Signed PSBT verified - signature present")
            else:
                messagebox.showwarning("No Signature Found",
                    "The PSBT was scanned but no signature was found.\n\n"
                    "Make sure SeedSigner approved and signed the transaction.")
                self.status_var.set("Scanned PSBT has no signature")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to verify signed PSBT:\n{e}")
            self.status_var.set(f"Error verifying PSBT: {e}")


class CameraScannerPopup:
    """Popup window with webcam feed for scanning QR codes."""

    def __init__(self, parent, callback, on_close=None):
        self.parent = parent
        self.callback = callback
        self.on_close = on_close  # Called when scanner closes (for cleanup)
        self.popup = None
        self.video_label = None
        self.status_label = None
        self.progress_label = None
        self.cap = None
        self.running = False
        self.ur_decoder = None
        self.scan_after_id = None

    def start(self):
        """Open the scanner popup and start camera."""
        self.popup = tk.Toplevel(self.parent)
        self.popup.title("Scan Signed PSBT from SeedSigner")
        self.popup.geometry("500x480")
        self.popup.resizable(False, False)
        self.popup.protocol("WM_DELETE_WINDOW", self.stop)

        # Instructions
        ttk.Label(self.popup, text="Point camera at SeedSigner's animated QR code",
                 font=("", 10, "bold")).pack(pady=(10, 5))

        # Video frame
        video_frame = ttk.Frame(self.popup, relief="sunken", borderwidth=2)
        video_frame.pack(pady=5)

        self.video_label = ttk.Label(video_frame, text="Starting camera...",
                                     width=50, anchor="center")
        self.video_label.pack()

        # Progress
        self.progress_label = ttk.Label(self.popup, text="Waiting for QR code...",
                                        foreground="gray")
        self.progress_label.pack(pady=5)

        # Status
        self.status_label = ttk.Label(self.popup, text="", foreground="blue")
        self.status_label.pack(pady=5)

        # Cancel button
        ttk.Button(self.popup, text="Cancel", command=self.stop, width=10).pack(pady=10)

        # Initialize UR decoder
        self.ur_decoder = URDecoder()

        # Start camera
        self.cap = cv2.VideoCapture(0)
        if not self.cap.isOpened():
            messagebox.showerror("Camera Error", "Could not open webcam")
            self.popup.destroy()
            return

        self.running = True
        self._scan_frame()

    def _scan_frame(self):
        """Capture and process a single frame."""
        if not self.running or not self.cap or not self.popup:
            return

        ret, frame = self.cap.read()
        if ret:
            # Decode QR codes from frame
            decoded_objects = pyzbar.decode(frame, symbols=[ZBarSymbol.QRCODE])

            for obj in decoded_objects:
                qr_data = obj.data.decode('utf-8')

                # Draw rectangle around detected QR
                x, y, w, h = obj.rect
                cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 0), 2)

                # Process UR fragment
                if qr_data.upper().startswith("UR:"):
                    self._process_ur_fragment(qr_data)
                    # Check if we're done (popup closed)
                    if not self.running:
                        return

            # Only update UI if still running
            if self.running and self.popup:
                # Convert frame to display in tkinter
                frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                frame_resized = cv2.resize(frame_rgb, (400, 300))
                img = Image.fromarray(frame_resized)
                photo = ImageTk.PhotoImage(img)

                self.video_label.configure(image=photo, text="")
                self.video_label.image = photo

        # Schedule next frame
        if self.running and self.popup:
            self.scan_after_id = self.popup.after(30, self._scan_frame)

    def _process_ur_fragment(self, qr_data: str):
        """Process a UR fragment and check if complete."""
        try:
            added = self.ur_decoder.receive_part(qr_data)

            if added:
                # Update progress
                percent = int(self.ur_decoder.estimated_percent_complete() * 100)
                self.progress_label.configure(text=f"Scanning: {percent}% complete")

            if self.ur_decoder.is_success():
                # Complete! Extract PSBT
                self.status_label.configure(text="QR complete! Processing...", foreground="green")
                self.popup.update()

                # Get the CBOR data and extract PSBT bytes
                ur_result = self.ur_decoder.result
                psbt_bytes = UR_PSBT.from_cbor(ur_result.cbor).data

                # Convert to base64
                psbt_base64 = base64.b64encode(psbt_bytes).decode('utf-8')

                # Stop scanning and call callback
                self.stop()
                self.callback(psbt_base64)

            elif self.ur_decoder.is_failure():
                self.status_label.configure(text="UR decoding failed", foreground="red")
                # Reset decoder to try again
                self.ur_decoder = URDecoder()

        except Exception as e:
            self.status_label.configure(text=f"Error: {e}", foreground="red")

    def stop(self):
        """Stop scanning and close popup."""
        self.running = False

        if self.scan_after_id and self.popup:
            self.popup.after_cancel(self.scan_after_id)
            self.scan_after_id = None

        if self.cap:
            self.cap.release()
            self.cap = None

        if self.popup:
            self.popup.destroy()
            self.popup = None

        # Notify parent that scanner closed
        if self.on_close:
            self.on_close()


def main():
    root = tk.Tk()
    app = BIP375TestToolGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
