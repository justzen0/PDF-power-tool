import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import os
import threading
import time

# MODIFIED: pikepdf is no longer needed. We only use pypdf.
from pypdf import PdfReader, PdfWriter
from pypdf.errors import DependencyError

class PDFToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF PowerTool")
        self.root.geometry("650x600")

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", padding=6, relief="flat", font=('Helvetica', 10))
        style.configure("TLabel", padding=5, font=('Helvetica', 10))
        style.configure("TEntry", padding=5, font=('Helvetica', 10))
        style.configure("TFrame", padding=10)
        style.configure("Header.TLabel", font=('Helvetica', 14, 'bold'))

        self.notebook = ttk.Notebook(root)

        self.split_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.split_tab, text='Split PDF')
        self._create_split_widgets()

        self.merge_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.merge_tab, text='Merge PDFs')
        self._create_merge_widgets()

        self.unprotect_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.unprotect_tab, text='Unlock PDFs')
        self._create_unprotect_widgets() 

        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)

        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _update_status(self, message, clear_after_ms=None):
        self.status_var.set(message)
        self.root.update_idletasks()
        if clear_after_ms:
            self.root.after(clear_after_ms, lambda: self.status_var.set("Ready") if self.status_var.get() == message else None)

    # --- Split Tab Logic (Unchanged) ---
    def _create_split_widgets(self):
        # This function's code is correct and unchanged.
        ttk.Label(self.split_tab, text="Split PDF Document", style="Header.TLabel").grid(row=0, column=0, columnspan=3, pady=(0,15), sticky="w")
        ttk.Label(self.split_tab, text="Input PDF:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.split_input_pdf_var = tk.StringVar()
        self.split_input_pdf_entry = ttk.Entry(self.split_tab, textvariable=self.split_input_pdf_var, width=50, state='readonly')
        self.split_input_pdf_entry.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=5)
        ttk.Button(self.split_tab, text="Browse...", command=self._select_split_input_pdf).grid(row=1, column=2, sticky=tk.EW, padx=5, pady=5)
        ttk.Label(self.split_tab, text="Page Ranges:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.split_ranges_var = tk.StringVar()
        self.split_ranges_entry = ttk.Entry(self.split_tab, textvariable=self.split_ranges_var, width=50)
        self.split_ranges_entry.grid(row=2, column=1, sticky=tk.EW, padx=5, pady=5)
        ttk.Label(self.split_tab, text="e.g., 1-3, 5, 8-10").grid(row=2, column=2, sticky=tk.W, padx=5)
        ttk.Label(self.split_tab, text="Output Dir:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.split_output_dir_var = tk.StringVar()
        self.split_output_dir_entry = ttk.Entry(self.split_tab, textvariable=self.split_output_dir_var, width=50, state='readonly')
        self.split_output_dir_entry.grid(row=3, column=1, sticky=tk.EW, padx=5, pady=5)
        ttk.Button(self.split_tab, text="Browse...", command=self._select_split_output_dir).grid(row=3, column=2, sticky=tk.EW, padx=5, pady=5)
        self.split_button = ttk.Button(self.split_tab, text="Split PDF", command=self._start_split_pdf_thread)
        self.split_button.grid(row=4, column=1, pady=20, sticky=tk.EW)
        self.split_tab.columnconfigure(1, weight=1)

    def _select_split_input_pdf(self):
        filepath = filedialog.askopenfilename(title="Select Input PDF", filetypes=(("PDF files", "*.pdf"), ("All files", "*.*")))
        if filepath: self.split_input_pdf_var.set(filepath); self._update_status(f"Selected input: {os.path.basename(filepath)}")

    def _select_split_output_dir(self):
        dirpath = filedialog.askdirectory(title="Select Output Directory")
        if dirpath: self.split_output_dir_var.set(dirpath); self._update_status(f"Selected output directory: {dirpath}")

    def _parse_page_ranges(self, ranges_str, total_pages):
        parsed_ranges = []
        if not ranges_str.strip(): return None 
        parts = ranges_str.split(',')
        for part in parts:
            part = part.strip()
            if not part: continue
            if '-' in part:
                try:
                    start_str, end_str = part.split('-', 1); start, end = int(start_str), int(end_str)
                    if not (1 <= start <= end <= total_pages):
                        self.root.after(0, lambda s=start, e=end, t=total_pages: messagebox.showerror("Error", f"Page range {s}-{e} is invalid. Total pages: {t}."))
                        return None
                    parsed_ranges.append((start - 1, end - 1)) 
                except ValueError: self.root.after(0, lambda p=part: messagebox.showerror("Error", f"Invalid range format: '{p}'.")); return None
            else:
                try:
                    page = int(part)
                    if not (1 <= page <= total_pages):
                        self.root.after(0, lambda p=page, t=total_pages: messagebox.showerror("Error", f"Page number {p} is invalid. Total pages: {t}."))
                        return None
                    parsed_ranges.append((page - 1, page - 1))
                except ValueError: self.root.after(0, lambda p=part: messagebox.showerror("Error", f"Invalid page number: '{p}'.")); return None
        if not parsed_ranges: self.root.after(0, lambda: messagebox.showerror("Error", "No valid page ranges could be parsed.")); return None
        return parsed_ranges

    def _start_split_pdf_thread(self):
        input_pdf, ranges_str, output_dir = self.split_input_pdf_var.get(), self.split_ranges_var.get(), self.split_output_dir_var.get()
        if not all([input_pdf, ranges_str.strip(), output_dir]): messagebox.showerror("Error", "Please fill all fields for splitting."); return
        self.split_button.config(state=tk.DISABLED)
        self._update_status("Splitting PDF...")
        thread = threading.Thread(target=self._execute_split_pdf, args=(input_pdf, ranges_str, output_dir), daemon=True); thread.start()

    def _execute_split_pdf(self, input_pdf_path, ranges_str, output_dir):
        try:
            reader = PdfReader(input_pdf_path)
            if reader.is_encrypted:
                self.root.after(0, lambda: messagebox.showerror("Error", f"'{os.path.basename(input_pdf_path)}' is encrypted. Please unlock it first."))
                self.root.after(0, lambda: self.split_button.config(state=tk.NORMAL)); return
            total_pages = len(reader.pages)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to read PDF: {e}"))
            self.root.after(0, lambda: self.split_button.config(state=tk.NORMAL)); return
        page_ranges = self._parse_page_ranges(ranges_str, total_pages)
        if not page_ranges: self.root.after(0, lambda: self.split_button.config(state=tk.NORMAL)); return
        base_filename = os.path.splitext(os.path.basename(input_pdf_path))[0]
        output_files_count = 0
        for i, (start_page, end_page) in enumerate(page_ranges):
            writer = PdfWriter()
            suffix = f"p{start_page+1}" + (f"-{end_page+1}" if start_page != end_page else "")
            output_pdf_path = os.path.join(output_dir, f"{base_filename}_{suffix}.pdf")
            try:
                for page_num in range(start_page, end_page + 1): writer.add_page(reader.pages[page_num])
                with open(output_pdf_path, "wb") as f_out: writer.write(f_out)
                output_files_count += 1
                self.root.after(0, lambda p=output_pdf_path: self._update_status(f"Created: {os.path.basename(p)}")); time.sleep(0.1) 
            except Exception as e: self.root.after(0, lambda err=e, path=output_pdf_path: messagebox.showerror("Error", f"Failed to create {os.path.basename(path)}: {err}")); continue 
        if output_files_count > 0:
            success_msg = f"Successfully split into {output_files_count} PDF(s)."
            self.root.after(0, lambda: messagebox.showinfo("Success", success_msg))
            self.root.after(0, lambda: self._update_status(success_msg, 5000))
        self.root.after(0, lambda: self.split_button.config(state=tk.NORMAL))

    # --- Merge Tab Logic (Unchanged) ---
    def _create_merge_widgets(self):
        # This function's code is correct and unchanged.
        ttk.Label(self.merge_tab, text="Merge PDF Documents", style="Header.TLabel").grid(row=0, column=0, columnspan=3, pady=(0,15), sticky="w")
        ttk.Label(self.merge_tab, text="Files to Merge:").grid(row=1, column=0, sticky=tk.NW, pady=5)
        self.merge_listbox_frame = ttk.Frame(self.merge_tab)
        self.merge_listbox_frame.grid(row=1, column=1, rowspan=4, sticky=tk.NSEW, padx=5, pady=5)
        self.merge_listbox = tk.Listbox(self.merge_listbox_frame, selectmode=tk.EXTENDED, width=50, height=10, exportselection=False)
        self.merge_listbox_scrollbar = ttk.Scrollbar(self.merge_listbox_frame, orient=tk.VERTICAL, command=self.merge_listbox.yview)
        self.merge_listbox.config(yscrollcommand=self.merge_listbox_scrollbar.set)
        self.merge_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); self.merge_listbox_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        listbox_buttons_frame = ttk.Frame(self.merge_tab)
        listbox_buttons_frame.grid(row=1, column=2, rowspan=4, sticky=tk.NS, padx=5)
        ttk.Button(listbox_buttons_frame, text="Add PDF(s)", command=self._add_merge_files).pack(fill=tk.X, pady=2)
        ttk.Button(listbox_buttons_frame, text="Remove Selected", command=self._remove_selected_merge_file).pack(fill=tk.X, pady=2)
        ttk.Button(listbox_buttons_frame, text="Clear All", command=self._clear_merge_files).pack(fill=tk.X, pady=2)
        ttk.Button(listbox_buttons_frame, text="Move Up", command=lambda: self._move_merge_item(-1)).pack(fill=tk.X, pady=(10,2))
        ttk.Button(listbox_buttons_frame, text="Move Down", command=lambda: self._move_merge_item(1)).pack(fill=tk.X, pady=2)
        ttk.Label(self.merge_tab, text="Output File:").grid(row=5, column=0, sticky=tk.W, pady=(10,5))
        self.merge_output_file_var = tk.StringVar()
        self.merge_output_file_entry = ttk.Entry(self.merge_tab, textvariable=self.merge_output_file_var, width=50, state='readonly')
        self.merge_output_file_entry.grid(row=5, column=1, sticky=tk.EW, padx=5, pady=(10,5))
        ttk.Button(self.merge_tab, text="Save As...", command=self._select_merge_output_file).grid(row=5, column=2, sticky=tk.EW, padx=5, pady=(10,5))
        self.merge_button = ttk.Button(self.merge_tab, text="Merge PDFs", command=self._start_merge_pdfs_thread)
        self.merge_button.grid(row=6, column=1, pady=20, sticky=tk.EW)
        for i in range(1, 5): self.merge_tab.rowconfigure(i, weight=1)
        self.merge_tab.columnconfigure(1, weight=1)

    def _add_merge_files(self):
        filepaths = filedialog.askopenfilenames(title="Select PDFs to Merge", filetypes=(("PDF files", "*.pdf"), ("All files", "*.*")))
        if filepaths:
            current_files = self.merge_listbox.get(0, tk.END)
            for fp in filepaths:
                if fp not in current_files: self.merge_listbox.insert(tk.END, fp)
            self._update_status(f"Added {len(filepaths)} file(s).", 3000)

    def _remove_selected_merge_file(self):
        selected_indices = self.merge_listbox.curselection()
        if not selected_indices: messagebox.showwarning("Warning", "No file selected to remove."); return
        for i in sorted(selected_indices, reverse=True): self.merge_listbox.delete(i)
        self._update_status("Removed selected file(s).", 3000)

    def _clear_merge_files(self):
        self.merge_listbox.delete(0, tk.END); self._update_status("Cleared all files.", 3000)

    def _move_merge_item(self, direction):
        selected_indices = self.merge_listbox.curselection()
        if not selected_indices: messagebox.showwarning("Warning", "No file selected to move."); return
        idx = selected_indices[0]
        if (direction == -1 and idx == 0) or (direction == 1 and idx == self.merge_listbox.size() - 1): return
        text = self.merge_listbox.get(idx); self.merge_listbox.delete(idx)
        self.merge_listbox.insert(idx + direction, text); self.merge_listbox.selection_set(idx + direction)
        self.merge_listbox.activate(idx + direction); self._update_status("Moved item.", 2000)

    def _select_merge_output_file(self):
        filepath = filedialog.asksaveasfilename(title="Save Merged PDF As", defaultextension=".pdf", filetypes=(("PDF files", "*.pdf"), ("All files", "*.*")))
        if filepath: self.merge_output_file_var.set(filepath); self._update_status(f"Output file: {os.path.basename(filepath)}")

    def _start_merge_pdfs_thread(self):
        files_to_merge = list(self.merge_listbox.get(0, tk.END))
        output_file = self.merge_output_file_var.get()
        if len(files_to_merge) < 1: messagebox.showerror("Error", "Please add at least one PDF."); return
        if not output_file: messagebox.showerror("Error", "Please specify an output file."); return
        self.merge_button.config(state=tk.DISABLED); self._update_status("Merging PDFs...")
        thread = threading.Thread(target=self._execute_merge_pdfs, args=(files_to_merge, output_file), daemon=True); thread.start()

    def _execute_merge_pdfs(self, files_to_merge, output_file):
        writer = PdfWriter() 
        try:
            for i, pdf_path in enumerate(files_to_merge):
                self.root.after(0, lambda p=pdf_path, n=i+1, t=len(files_to_merge): self._update_status(f"Appending ({n}/{t}): {os.path.basename(p)}")); time.sleep(0.1) 
                try:
                    reader = PdfReader(pdf_path)
                    if reader.is_encrypted:
                        self.root.after(0, lambda path=pdf_path: messagebox.showwarning("Skipped", f"'{os.path.basename(path)}' is encrypted and will be skipped."))
                        continue
                    writer.append(pdf_path)
                except Exception as append_error:
                    self.root.after(0, lambda err=append_error, path=pdf_path: messagebox.showerror("Merge Error", f"Could not append '{os.path.basename(path)}': {err}"))
                    continue
            if len(writer.pages) > 0:
                with open(output_file, "wb") as f_out: writer.write(f_out)
                success_msg = f"Successfully merged files into {os.path.basename(output_file)}."
                self.root.after(0, lambda: messagebox.showinfo("Success", success_msg))
                self.root.after(0, lambda: self._update_status(success_msg, 5000))
            else:
                self.root.after(0, lambda: messagebox.showwarning("Merge Complete", "No files were merged."))

        except Exception as e: self.root.after(0, lambda err=e: messagebox.showerror("Error", f"Failed to merge PDFs: {err}"))
        finally: self.root.after(0, lambda: self.merge_button.config(state=tk.NORMAL))

    # --- Unlock Tab Widgets and Logic ---
    def _create_unprotect_widgets(self):
        # This function's code is correct and unchanged.
        ttk.Label(self.unprotect_tab, text="Unlock PDFs & Remove Restrictions", style="Header.TLabel").grid(row=0, column=0, columnspan=3, pady=(0,15), sticky="w")
        ttk.Label(self.unprotect_tab, text="Files to Unlock:").grid(row=1, column=0, sticky=tk.NW, pady=5)
        self.unprotect_listbox_frame = ttk.Frame(self.unprotect_tab)
        self.unprotect_listbox_frame.grid(row=1, column=1, rowspan=4, sticky=tk.NSEW, padx=5, pady=5)
        self.unprotect_listbox = tk.Listbox(self.unprotect_listbox_frame, selectmode=tk.EXTENDED, width=50, height=10, exportselection=False)
        self.unprotect_listbox_scrollbar = ttk.Scrollbar(self.unprotect_listbox_frame, orient=tk.VERTICAL, command=self.unprotect_listbox.yview)
        self.unprotect_listbox.config(yscrollcommand=self.unprotect_listbox_scrollbar.set)
        self.unprotect_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); self.unprotect_listbox_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        listbox_buttons_frame = ttk.Frame(self.unprotect_tab)
        listbox_buttons_frame.grid(row=1, column=2, rowspan=4, sticky=tk.NS, padx=5)
        ttk.Button(listbox_buttons_frame, text="Add PDF(s)", command=self._add_unprotect_files).pack(fill=tk.X, pady=2)
        ttk.Button(listbox_buttons_frame, text="Remove Selected", command=self._remove_selected_unprotect_file).pack(fill=tk.X, pady=2)
        ttk.Button(listbox_buttons_frame, text="Clear All", command=self._clear_unprotect_files).pack(fill=tk.X, pady=2)
        ttk.Label(self.unprotect_tab, text="Output Dir:").grid(row=5, column=0, sticky=tk.W, pady=(10,5))
        self.unprotect_output_dir_var = tk.StringVar()
        self.unprotect_output_dir_entry = ttk.Entry(self.unprotect_tab, textvariable=self.unprotect_output_dir_var, width=50, state='readonly')
        self.unprotect_output_dir_entry.grid(row=5, column=1, sticky=tk.EW, padx=5, pady=(10,5))
        ttk.Button(self.unprotect_tab, text="Browse...", command=self._select_unprotect_output_dir).grid(row=5, column=2, sticky=tk.EW, padx=5, pady=(10,5))
        self.unprotect_button = ttk.Button(self.unprotect_tab, text="Unlock Files", command=self._start_unprotect_pdf_thread)
        self.unprotect_button.grid(row=6, column=1, pady=20, sticky=tk.EW)
        for i in range(1, 5): self.unprotect_tab.rowconfigure(i, weight=1)
        self.unprotect_tab.columnconfigure(1, weight=1)

    def _add_unprotect_files(self):
        filepaths = filedialog.askopenfilenames(title="Select PDFs to Unlock", filetypes=(("PDF files", "*.pdf"), ("All files", "*.*")))
        if filepaths:
            current_files = self.unprotect_listbox.get(0, tk.END)
            for fp in filepaths:
                if fp not in current_files: self.unprotect_listbox.insert(tk.END, fp)
            self._update_status(f"Added {len(filepaths)} file(s) to unlock.", 3000)

    def _remove_selected_unprotect_file(self):
        selected_indices = self.unprotect_listbox.curselection()
        if not selected_indices: messagebox.showwarning("Warning", "No file selected to remove."); return
        for i in sorted(selected_indices, reverse=True): self.unprotect_listbox.delete(i)
        self._update_status("Removed selected file(s).", 3000)

    def _clear_unprotect_files(self):
        self.unprotect_listbox.delete(0, tk.END); self._update_status("Cleared all files.", 3000)
    
    def _select_unprotect_output_dir(self):
        dirpath = filedialog.askdirectory(title="Select Output Directory for Unlocked Files")
        if dirpath: self.unprotect_output_dir_var.set(dirpath); self._update_status(f"Selected output directory: {dirpath}")

    # --- REWRITTEN LOGIC USING pypdf ---
    def _start_unprotect_pdf_thread(self):
        """
        Gathers passwords in the main GUI thread before starting the background worker.
        """
        input_files = list(self.unprotect_listbox.get(0, tk.END))
        output_dir = self.unprotect_output_dir_var.get()

        if not input_files: messagebox.showerror("Error", "Please add at least one PDF."); return
        if not output_dir: messagebox.showerror("Error", "Please select an output directory."); return
        
        passwords_map = {}
        
        self._update_status("Checking files for passwords...")
        for file_path in input_files:
            try:
                reader = PdfReader(file_path)
                if reader.is_encrypted:
                    # Try unlocking with a blank password (for permissions-only lock)
                    if not reader.decrypt(''):
                        # If that fails, it needs a user password.
                        password = simpledialog.askstring(
                            "Password Required",
                            f"Enter password for:\n{os.path.basename(file_path)}",
                            show='*'
                        )
                        if password is None:
                            messagebox.showwarning("Cancelled", "Unlock process cancelled by user.")
                            self._update_status("Ready")
                            return
                        passwords_map[file_path] = password
            except DependencyError:
                messagebox.showerror("Dependency Error", "pypdf requires 'cryptography' to handle encrypted files.\nPlease install it by running: pip install cryptography")
                self._update_status("Ready")
                return
            except Exception as e:
                messagebox.showerror("Error", f"Could not read file '{os.path.basename(file_path)}':\n{e}")
                self._update_status("Ready")
                return

        self.unprotect_button.config(state=tk.DISABLED)
        self._update_status("Starting unlock process...")
        
        thread = threading.Thread(target=self._execute_batch_unprotect, args=(input_files, output_dir, passwords_map), daemon=True)
        thread.start()

    def _execute_batch_unprotect(self, input_files, output_dir, passwords_map):
        """
        Runs in the background, using pypdf to unlock and save files.
        """
        success_count, fail_count = 0, 0
        total_files = len(input_files)

        for i, input_path in enumerate(input_files):
            base_name = os.path.splitext(os.path.basename(input_path))[0]
            output_path = os.path.join(output_dir, f"{base_name}_unlocked.pdf")
            
            self.root.after(0, lambda p=input_path, n=i+1, t=total_files: self._update_status(f"Processing ({n}/{t}): {os.path.basename(p)}"))
            time.sleep(0.1)

            try:
                reader = PdfReader(input_path)
                
                # If it's encrypted, decrypt it with the stored password
                if reader.is_encrypted:
                    password = passwords_map.get(input_path, '') # Use blank password if not in map
                    if reader.decrypt(password):
                        pass # Successfully decrypted
                    else:
                        self.root.after(0, lambda p=input_path: messagebox.showwarning("Skipped", f"Incorrect password for '{os.path.basename(p)}'."))
                        fail_count += 1
                        continue # Move to the next file

                # Write the (now decrypted) file to a new PDF
                writer = PdfWriter()
                writer.clone_document_from_reader(reader)
                with open(output_path, "wb") as f_out:
                    writer.write(f_out)
                
                success_count += 1
            except Exception as e:
                fail_count += 1
                self.root.after(0, lambda err=e, p=input_path: messagebox.showerror("Error", f"An error occurred with '{os.path.basename(p)}':\n{err}"))

        final_msg = f"Unlock process complete.\n\nSuccessfully unlocked: {success_count}\nFailed or skipped: {fail_count}"
        self.root.after(0, lambda: messagebox.showinfo("Batch Complete", final_msg))
        self.root.after(0, lambda: self._update_status("Ready", 5000))
        self.root.after(0, lambda: self.unprotect_button.config(state=tk.NORMAL))


if __name__ == '__main__':
    root = tk.Tk()
    app = PDFToolApp(root)
    root.mainloop()