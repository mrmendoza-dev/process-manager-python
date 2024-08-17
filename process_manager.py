import psutil
import tkinter as tk
from tkinter import ttk, messagebox


def get_processes():
    processes = {}
    for proc in psutil.process_iter(['pid', 'name']):
        processes[proc.info['pid']] = proc.info['name']
    return processes

def print_processes(processes):
	for pid, name in processes.items():
		print(f"PID: {pid}, Name: {name}")

def find_processes_by_name(processes, query):
    matching_processes = {pid: name for pid, name in processes.items() if query.lower() in name.lower()}
    return matching_processes


def terminate_process(pid):
    try:
        process = psutil.Process(pid)
        process.terminate()
        return True
    except psutil.NoSuchProcess:
        return False
    except psutil.AccessDenied:
        return False


class ProcessManagerApp:
	def __init__(self, master):
		self.master = master
		self.master.title("Process Manager")
		self.master.geometry("600x400")

		self.processes = get_processes()

		self.create_widgets()

	def create_widgets(self):
		# Search frame
		search_frame = ttk.Frame(self.master, padding="10")
		search_frame.pack(fill=tk.X)

		ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
		self.search_entry = ttk.Entry(search_frame, width=30)
		self.search_entry.pack(side=tk.LEFT, padx=(5, 10))
		self.search_entry.bind('<Return>', lambda event: self.search_processes())
		ttk.Button(search_frame, text="Search", command=self.search_processes).pack(side=tk.LEFT)
		ttk.Button(search_frame, text="Refresh", command=self.refresh_processes).pack(side=tk.LEFT, padx=(10, 0))

		# Process list
		self.tree = ttk.Treeview(self.master, columns=('PID', 'Name'), show='headings', selectmode='extended')
		self.tree.heading('PID', text='PID')
		self.tree.heading('Name', text='Name')
		self.tree.pack(fill=tk.BOTH, expand=True)

		# Terminate button
		ttk.Button(self.master, text="Terminate Selected Processes", command=self.terminate_selected).pack(pady=10)

		self.populate_tree()

	def populate_tree(self, processes=None):
		self.tree.delete(*self.tree.get_children())
		for pid, name in (processes or self.processes).items():
			self.tree.insert('', 'end', values=(pid, name))

	def search_processes(self):
		query = self.search_entry.get()
		if query:
			matching = find_processes_by_name(self.processes, query)
			self.populate_tree(matching)
		else:
			self.populate_tree()

	def refresh_processes(self):
		self.processes = get_processes()
		self.populate_tree()

	def terminate_selected(self):
		selected_items = self.tree.selection()
		if not selected_items:
			messagebox.showwarning("Warning", "No processes selected")
			return

		terminate_count = 0
		fail_count = 0
		for item in selected_items:
			pid = int(self.tree.item(item)['values'][0])
			if terminate_process(pid):
				terminate_count += 1
			else:
				fail_count += 1

		message = f"Successfully terminated {terminate_count} process(es)."
		if fail_count > 0:
			message += f"\nFailed to terminate {fail_count} process(es)."

		messagebox.showinfo("Termination Result", message)
		self.refresh_processes()

if __name__ == "__main__":
	root = tk.Tk()
	app = ProcessManagerApp(root)
	root.mainloop()

