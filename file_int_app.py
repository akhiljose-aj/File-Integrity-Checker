import hashlib
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
from tkinter import *
class FileIntegrityCheckerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Checker")
        self.root.resizable(False, False)
        # Adding image icon
        photo = PhotoImage(file="file_int1.png")
        root.iconphoto(False, photo)

        self.file_path_var = tk.StringVar()
        self.stored_hash_var = tk.StringVar()
        self.result_var = tk.StringVar()

        # Darker theme
        root.configure(bg="#333333")

        # Entry for file path
        tk.Label(root, text="File Path:", bg="#333333", fg="white").pack(pady=5)
        self.file_path_entry = tk.Entry(root, textvariable=self.file_path_var, width=60, bg="#444444", fg="white")
        self.file_path_entry.pack(pady=10)

        # Browse button
        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file, bg="#555555", fg="white",cursor='hand2',height=1,width=15)
        self.browse_button.pack(pady=10)
        self.browse_button.bind("<Enter>", lambda event: self.on_enter(event, self.browse_button))
        self.browse_button.bind("<Leave>", lambda event: self.on_leave(event, self.browse_button))
        self.browse_button.bind("<Button-1>", lambda event: self.on_click(event, self.browse_button))

        # Calculate Hash button
        self.calculate_button = tk.Button(root, text="Calculate Hash", command=self.calculate_hash_action, bg="#555555", fg="white",cursor='hand2',height=1,width=15)
        self.calculate_button.pack(pady=10)
        self.calculate_button.bind("<Enter>", lambda event: self.on_enter(event, self.calculate_button))
        self.calculate_button.bind("<Leave>", lambda event: self.on_leave(event, self.calculate_button))
        self.calculate_button.bind("<Button-1>", lambda event: self.on_click(event, self.calculate_button))

        # Entry for stored hash
        tk.Label(root, text="Stored Hash:", bg="#333333", fg="white").pack(pady=5)
        self.stored_hash_entry = tk.Entry(root, textvariable=self.stored_hash_var, width=60, bg="#444444", fg="white")
        self.stored_hash_entry.pack(pady=5)

        # Check File Integrity button
        self.check_button = tk.Button(root, text="Check Integrity", command=self.check_file_integrity_action, bg="#555555", fg="white",cursor='hand2',height=1,width=15)
        self.check_button.pack(pady=10)
        self.check_button.bind("<Enter>", lambda event: self.on_enter(event, self.check_button))
        self.check_button.bind("<Leave>", lambda event: self.on_leave(event, self.check_button))
        self.check_button.bind("<Button-1>", lambda event: self.on_click(event, self.check_button))

        # Result display
        tk.Label(root, text="Result:", bg="#333333", fg="white").pack(pady=5)
        tk.Label(root, textvariable=self.result_var, fg="lightgreen", bg="#333333").pack(pady=5)

        # Exit button
        self.exit_button = tk.Button(root, text="Exit", command=root.destroy, bg="#555555", fg="white",cursor='hand2',height=1,width=15)
        self.exit_button.pack(pady=10)
        self.exit_button.bind("<Enter>", lambda event: self.on_enter(event, self.exit_button))
        self.exit_button.bind("<Leave>", lambda event: self.on_leave(event, self.exit_button))
        self.exit_button.bind("<Button-1>", lambda event: self.on_click(event, self.exit_button))

    def on_enter(self, event, button):
        button.config(bg="lightblue",fg='black')

    def on_leave(self, event, button):
        button.config(bg="#555555",fg="white")

    def on_click(self, event, button):
        button.config(bg="yellow",fg="black")

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_path_var.set(file_path)
        self.stored_hash_var.set("")  # Clear stored hash when browsing a new file

    def calculate_hash_action(self):
        file_path = self.file_path_var.get()
        if file_path:
            hash_value = self.calculate_hash(file_path)
            self.stored_hash_var.set(hash_value)
            self.result_var.set(f"Calculated Hash: {hash_value}")
            self.save_hash()  # Automatically save file path and calculated hash
        else:
            self.result_var.set("Please select a file.")

    def check_file_integrity_action(self):
        file_path = self.file_path_var.get()
        stored_hash = self.stored_hash_var.get()

        if file_path and stored_hash:
            if self.check_file_integrity(file_path, stored_hash):
                self.result_var.set("File integrity is still intact!")
            else:
                self.result_var.set("File integrity has been Lost!")
        else:
            self.result_var.set("Please provide both file path and stored hash.")

    def save_hash(self):
        file_path = self.file_path_var.get()
        stored_hash = self.stored_hash_var.get()

        if file_path and stored_hash:
            with open('stored_hashes.txt', 'a') as file:
                file.write(f"File Path: {file_path}\n")
                file.write(f"Stored Hash: {stored_hash}\n")
                file.write("----------------------------\n")
            self.result_var.set("Hash saved successfully.")
        else:
            self.result_var.set("Please provide both file path and stored hash.")

    def calculate_hash(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as file:
            for byte_block in iter(lambda: file.read(4096), b""):
                sha256.update(byte_block)
        return sha256.hexdigest()

    def check_file_integrity(self, file_path, stored_hash):
        current_hash = self.calculate_hash(file_path)
        return current_hash == stored_hash

if __name__ == "__main__":
    root = tk.Tk()
    app = FileIntegrityCheckerUI(root)
    root.geometry("500x380")
    root.mainloop()