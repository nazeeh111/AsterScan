#!/usr/bin/env python3
"""Local desktop workspace for the AsterScan command-line scanner."""

import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from lib.process_control import process_group_options, stop_process_tree


BG = '#111715'
SURFACE = '#19211e'
SURFACE_2 = '#223028'
LINE = '#334039'
TEXT = '#f2f5f1'
MUTED = '#aab7ae'
LIME = '#d8f47d'
ORANGE = '#ffad70'
RED = '#ff776d'
BLUE = '#85c9d3'


def application_path():
    return Path(sys.executable if getattr(sys, 'frozen', False) else __file__).resolve().parent


def command_for(name):
    root = application_path()
    executable = root / (name + '.exe')
    if os.name == 'nt' and executable.is_file():
        return [str(executable)]
    return [sys.executable, str(root / (name + '.py'))]


class Studio(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('AsterScan Studio')
        self.geometry('1180x760')
        self.minsize(900, 620)
        self.configure(bg=BG)
        self.queue = queue.Queue()
        self.process = None
        self.mode = None
        self.cancelled = False
        self.activity_lines = 0
        self.rows = {}
        self.report_path = None
        self.report_saved = False
        self.temp = tempfile.TemporaryDirectory(prefix='asterscan-studio-')
        self.target = tk.StringVar()
        self.depth = tk.StringVar(value='Fast')
        self.process_scan = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value='Ready')
        self.counts = {key: tk.IntVar(value=0) for key in ('ALERT', 'WARNING', 'NOTICE', 'ERROR')}
        self._style()
        self._layout()
        self.target.trace_add('write', lambda *_: self._refresh_actions())
        self.protocol('WM_DELETE_WINDOW', self._close)
        self.after(100, self._drain_queue)

    def _style(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('Aster.Treeview', background=SURFACE, fieldbackground=SURFACE,
                        foreground=TEXT, borderwidth=0, rowheight=36, font=('Helvetica', 11))
        style.map('Aster.Treeview', background=[('selected', SURFACE_2)],
                  foreground=[('selected', TEXT)])
        style.configure('Aster.Treeview.Heading', background=BG, foreground=MUTED,
                        borderwidth=0, relief='flat', font=('Helvetica', 10, 'bold'))
        style.map('Aster.Treeview.Heading', background=[('active', BG)])
        style.configure('Aster.Horizontal.TProgressbar', background=LIME, troughcolor=SURFACE_2,
                        bordercolor=SURFACE_2, lightcolor=LIME, darkcolor=LIME)
        style.configure('Aster.TCheckbutton', background=BG, foreground=TEXT,
                        font=('Helvetica', 11))
        style.map('Aster.TCheckbutton', background=[('active', BG)], foreground=[('disabled', MUTED)])

    def _button(self, parent, label, action, accent=False, compact=False):
        button = tk.Button(parent, text=label, command=action, cursor='hand2', relief='flat',
                           bd=0, highlightthickness=1, highlightbackground=LINE,
                           bg=LIME if accent else SURFACE_2, fg=BG if accent else TEXT,
                           activebackground='#ebffa5' if accent else '#34463a',
                           activeforeground=BG if accent else TEXT,
                           disabledforeground=MUTED, font=('Helvetica', 11, 'bold'),
                           padx=12 if compact else 18, pady=7 if compact else 11)
        return button

    def _label(self, parent, text, color=MUTED, size=10, weight='normal'):
        return tk.Label(parent, text=text, bg=parent.cget('bg'), fg=color,
                        font=('Helvetica', size, weight), anchor='w')

    def _layout(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        sidebar = tk.Frame(self, bg='#0d1411', width=202)
        sidebar.grid(row=0, column=0, sticky='ns')
        sidebar.grid_propagate(False)
        brand = tk.Frame(sidebar, bg='#0d1411')
        brand.pack(fill='x', padx=24, pady=(27, 40))
        logo_path = application_path() / '.github' / 'assets' / 'mark.png'
        try:
            self.logo = tk.PhotoImage(file=str(logo_path)).subsample(8, 8)
            tk.Label(brand, image=self.logo, bg='#0d1411').pack(side='left')
        except tk.TclError:
            self._label(brand, 'A', LIME, 22, 'bold').pack(side='left')
        names = tk.Frame(brand, bg='#0d1411')
        names.pack(side='left', padx=10)
        self._label(names, 'AsterScan', TEXT, 16, 'bold').pack(anchor='w')
        self._label(names, 'STUDIO', LIME, 8, 'bold').pack(anchor='w')
        self._label(sidebar, 'WORKSPACE', MUTED, 9, 'bold').pack(fill='x', padx=24, pady=(0, 12))
        self.side_status = self._label(sidebar, 'Ready', TEXT, 12, 'bold')
        self.side_status.pack(fill='x', padx=24)
        self._label(sidebar, 'LOCAL SCANNER', MUTED, 9, 'bold').pack(side='bottom', fill='x', padx=24, pady=25)

        main = tk.Frame(self, bg=BG)
        main.grid(row=0, column=1, sticky='nsew')
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(4, weight=1)
        heading = tk.Frame(main, bg=BG)
        heading.grid(row=0, column=0, sticky='ew', padx=34, pady=(28, 22))
        self._label(heading, 'Scanner', TEXT, 27, 'bold').pack(side='left')
        self.update_button = self._button(heading, 'Update rules', self._update_rules, compact=True)
        self.update_button.pack(side='right')

        controls = tk.Frame(main, bg=BG)
        controls.grid(row=1, column=0, sticky='ew', padx=34)
        controls.grid_columnconfigure(0, weight=1)
        self._label(controls, 'TARGET', MUTED, 9, 'bold').grid(row=0, column=0, sticky='w', pady=(0, 8))
        target_line = tk.Frame(controls, bg=BG)
        target_line.grid(row=1, column=0, columnspan=4, sticky='ew')
        target_line.grid_columnconfigure(0, weight=1)
        self.target_entry = tk.Entry(target_line, textvariable=self.target, bg=SURFACE, fg=TEXT,
                                     insertbackground=TEXT, relief='flat', highlightthickness=1,
                                     highlightbackground=LINE, highlightcolor=LIME,
                                     font=('Menlo', 11))
        self.target_entry.grid(row=0, column=0, sticky='ew', ipady=11)
        self._button(target_line, 'File', self._choose_file, compact=True).grid(row=0, column=1, padx=(8, 0))
        self._button(target_line, 'Folder', self._choose_folder, compact=True).grid(row=0, column=2, padx=(8, 0))

        options = tk.Frame(main, bg=BG)
        options.grid(row=2, column=0, sticky='ew', padx=34, pady=20)
        self._label(options, 'DEPTH', MUTED, 9, 'bold').pack(side='left', padx=(0, 13))
        self.fast_button = self._button(options, 'Fast', lambda: self._set_depth('Fast'), compact=True)
        self.fast_button.pack(side='left')
        self.deep_button = self._button(options, 'Deep', lambda: self._set_depth('Deep'), compact=True)
        self.deep_button.pack(side='left', padx=(3, 20))
        self._set_depth('Fast')
        self.process_check = ttk.Checkbutton(options, text='Processes', variable=self.process_scan,
                                             style='Aster.TCheckbutton')
        self.process_check.pack(side='left')
        if os.name != 'nt':
            self.process_check.state(['disabled'])
        self.cancel_button = self._button(options, 'Stop', self._stop, compact=True)
        self.cancel_button.pack(side='right', padx=(8, 0))
        self.start_button = self._button(options, 'Start scan', self._start_scan, accent=True)
        self.start_button.pack(side='right')

        metrics = tk.Frame(main, bg=BG, highlightbackground=LINE, highlightthickness=1, height=94)
        metrics.grid(row=3, column=0, sticky='ew', padx=34, pady=(0, 20))
        metrics.grid_propagate(False)
        for i, (level, title, color) in enumerate((('ALERT', 'Alerts', RED), ('WARNING', 'Warnings', ORANGE),
                                                   ('NOTICE', 'Notices', LIME), ('ERROR', 'Errors', RED))):
            metrics.grid_columnconfigure(i, weight=1)
            cell = tk.Frame(metrics, bg=BG)
            cell.grid(row=0, column=i, sticky='nsew', padx=18, pady=16)
            self._label(cell, title.upper(), MUTED, 9, 'bold').pack(anchor='w')
            tk.Label(cell, textvariable=self.counts[level], bg=BG, fg=color,
                     font=('Helvetica', 26, 'bold')).pack(anchor='w')
        metrics.grid_rowconfigure(0, weight=1)

        content = tk.Frame(main, bg=BG)
        content.grid(row=4, column=0, sticky='nsew', padx=34)
        content.grid_rowconfigure(1, weight=1)
        content.grid_columnconfigure(0, weight=1)
        tabs = tk.Frame(content, bg=BG)
        tabs.grid(row=0, column=0, sticky='ew')
        self.findings_tab = self._button(tabs, 'Findings', lambda: self._show_tab('findings'), compact=True)
        self.findings_tab.pack(side='left')
        self.activity_tab = self._button(tabs, 'Activity', lambda: self._show_tab('activity'), compact=True)
        self.activity_tab.pack(side='left', padx=4)
        self.open_button = self._button(tabs, 'Open report', self._open_report, compact=True)
        self.open_button.pack(side='right')
        self.save_button = self._button(tabs, 'Save report', self._save_report, compact=True)
        self.save_button.pack(side='right', padx=(0, 8))

        self.findings_view = tk.PanedWindow(content, orient='horizontal', bg=BG, sashwidth=5,
                                            bd=0, showhandle=False)
        self.findings_view.grid(row=1, column=0, sticky='nsew', pady=(12, 0))
        list_frame = tk.Frame(self.findings_view, bg=SURFACE)
        self.tree = ttk.Treeview(list_frame, columns=('severity', 'object', 'score'), show='headings',
                                 style='Aster.Treeview', selectmode='browse')
        for column, title, width, stretch in (('severity', 'Severity', 100, False),
                                             ('object', 'Object', 300, True), ('score', 'Score', 70, False)):
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, minwidth=width, stretch=stretch,
                             anchor='e' if column == 'score' else 'w')
        self.tree.tag_configure('ALERT', foreground=RED)
        self.tree.tag_configure('WARNING', foreground=ORANGE)
        self.tree.tag_configure('NOTICE', foreground=LIME)
        self.tree.pack(side='left', fill='both', expand=True)
        scroll = ttk.Scrollbar(list_frame, orient='vertical', command=self.tree.yview)
        scroll.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.bind('<<TreeviewSelect>>', self._select_finding)
        self.findings_view.add(list_frame, minsize=330)
        detail_frame = tk.Frame(self.findings_view, bg=BG)
        self.detail = tk.Text(detail_frame, bg=BG, fg=TEXT, insertbackground=TEXT, wrap='word',
                              relief='flat', bd=0, padx=17, pady=15, font=('Menlo', 10))
        self.detail.pack(fill='both', expand=True)
        self.detail.tag_configure('heading', foreground=LIME, font=('Helvetica', 16, 'bold'))
        self.detail.tag_configure('muted', foreground=MUTED)
        self.detail.configure(state='disabled')
        self.findings_view.add(detail_frame, minsize=290)
        self.activity_view = tk.Text(content, bg=SURFACE, fg=TEXT, insertbackground=TEXT,
                                     wrap='word', relief='flat', bd=0, padx=18, pady=14,
                                     font=('Menlo', 10), state='disabled')
        for level, color in (('ALERT', RED), ('WARNING', ORANGE), ('NOTICE', LIME), ('ERROR', RED)):
            self.activity_view.tag_configure(level, foreground=color)
        self._show_tab('findings')

        bottom = tk.Frame(main, bg=BG)
        bottom.grid(row=5, column=0, sticky='ew', padx=34, pady=(16, 25))
        self.progress = ttk.Progressbar(bottom, mode='indeterminate', style='Aster.Horizontal.TProgressbar')
        self.progress.pack(fill='x', pady=(0, 9))
        self._label(bottom, 'STATUS', MUTED, 9, 'bold').pack(side='left')
        tk.Label(bottom, textvariable=self.status, bg=BG, fg=TEXT,
                 font=('Helvetica', 10)).pack(side='left', padx=12)
        self._refresh_actions()

    def _set_depth(self, depth):
        self.depth.set(depth)
        for button, active in ((self.fast_button, depth == 'Fast'), (self.deep_button, depth == 'Deep')):
            button.configure(bg=LIME if active else SURFACE_2, fg=BG if active else TEXT)

    def _show_tab(self, name):
        if name == 'findings':
            self.activity_view.grid_forget()
            self.findings_view.grid(row=1, column=0, sticky='nsew', pady=(12, 0))
        else:
            self.findings_view.grid_forget()
            self.activity_view.grid(row=1, column=0, sticky='nsew', pady=(12, 0))
        self.findings_tab.configure(bg=LIME if name == 'findings' else SURFACE_2,
                                    fg=BG if name == 'findings' else TEXT)
        self.activity_tab.configure(bg=LIME if name == 'activity' else SURFACE_2,
                                    fg=BG if name == 'activity' else TEXT)

    def _refresh_actions(self):
        idle = self.process is None
        self.start_button.configure(state='normal' if idle and self.target.get().strip() else 'disabled')
        self.cancel_button.configure(state='normal' if not idle else 'disabled')
        self.update_button.configure(state='normal' if idle else 'disabled')
        available = self.report_path is not None and self.report_path.is_file()
        self.save_button.configure(state='normal' if available else 'disabled')
        self.open_button.configure(state='normal' if available else 'disabled')

    def _choose_file(self):
        path = filedialog.askopenfilename(parent=self, title='Choose file to scan')
        if path:
            self.target.set(path)

    def _choose_folder(self):
        path = filedialog.askdirectory(parent=self, title='Choose folder to scan')
        if path:
            self.target.set(path)

    def _set_status(self, value):
        self.status.set(value)
        self.side_status.configure(text=value)

    def _start_scan(self):
        target = self.target.get()
        if not target.strip() or self.process is not None:
            return
        if self.report_path and self.report_path.is_file() and not self.report_saved:
            if not messagebox.askyesno('Unsaved report',
                                       'The current report has not been saved. Start a new scan anyway?', parent=self):
                return
        self.activity_lines = 0
        self.rows.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        for count in self.counts.values():
            count.set(0)
        for widget in (self.detail, self.activity_view):
            widget.configure(state='normal')
            widget.delete('1.0', 'end')
            widget.configure(state='disabled')
        self.report_path = Path(self.temp.name) / ('scan-%s.html' % len(list(Path(self.temp.name).glob('scan-*.html'))))
        self.report_saved = False
        command = command_for('asterscan') + ['-p', target, '--jsonl', '--nolog', '--noindicator',
                                             '--report', str(self.report_path)]
        if self.depth.get() == 'Deep':
            command.append('--intense')
        if not (os.name == 'nt' and self.process_scan.get()):
            command.append('--noprocscan')
        self._launch(command, 'scan')

    def _update_rules(self):
        if self.process is None:
            self._launch(command_for('asterscan-updater') + ['--sigsonly', '--nolog'], 'update')

    def _launch(self, command, mode):
        self.cancelled = False
        try:
            environment = os.environ.copy()
            environment['PYTHONUNBUFFERED'] = '1'
            self.process = subprocess.Popen(command, cwd=application_path(), stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT, text=True, encoding='utf-8',
                                            errors='replace', bufsize=1, env=environment,
                                            **process_group_options())
        except OSError as exc:
            messagebox.showerror('AsterScan', 'Could not start %s: %s' % (mode, exc), parent=self)
            return
        self.mode = mode
        self._set_status('Scanning' if mode == 'scan' else 'Updating rules')
        self.progress.start(12)
        self._refresh_actions()
        threading.Thread(target=self._read_process, args=(self.process, mode), daemon=True).start()

    def _read_process(self, process, mode):
        try:
            for line in process.stdout:
                self.queue.put(('line', mode, line.rstrip('\r\n')))
        finally:
            self.queue.put(('done', mode, process.wait()))

    def _drain_queue(self):
        try:
            while True:
                kind, mode, value = self.queue.get_nowait()
                if kind == 'line':
                    self._handle_line(mode, value)
                else:
                    self._finish(mode, value)
        except queue.Empty:
            pass
        self.after(100, self._drain_queue)

    def _handle_line(self, mode, line):
        if not line:
            return
        event = None
        if mode == 'scan':
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                pass
        if event is None:
            event = {'level': 'INFO' if mode == 'update' else 'ERROR', 'module': mode, 'message': line}
        level = event.get('level', 'INFO')
        if level in self.counts:
            self.counts[level].set(self.counts[level].get() + 1)
        self.activity_view.configure(state='normal')
        self.activity_view.insert('end', '[%s] %s\n' % (level, event.get('message', '')), level)
        self.activity_lines += 1
        if self.activity_lines > 2500:
            self.activity_view.delete('1.0', '201.0')
            self.activity_lines -= 200
        self.activity_view.see('end')
        self.activity_view.configure(state='disabled')
        if mode == 'scan' and (level in ('ALERT', 'WARNING') or
                               (level == 'NOTICE' and event.get('data', {}).get('kind') == 'file')):
            data = event.get('data') or {}
            object_name = data.get('path') or event.get('module', 'Finding')
            item = self.tree.insert('', 'end', values=(level, object_name, data.get('score', '-')),
                                    tags=(level,))
            self.rows[item] = event
            if len(self.rows) == 1:
                self.tree.selection_set(item)
                self._select_finding()

    def _select_finding(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            return
        event = self.rows.get(selection[0])
        if not event:
            return
        data = event.get('data') or {}
        lines = [event.get('level', 'Finding'), '', data.get('path') or event.get('module', ''), '']
        for label, value in (('Score', data.get('score')), ('Type', data.get('file_type')),
                             ('Size', data.get('size'))):
            if value is not None:
                lines.append('%s  %s' % (label, value))
        for name, value in (data.get('hashes') or {}).items():
            lines.append('%s  %s' % (name.upper(), value))
        lines.append('')
        lines.append('REASONS')
        lines.extend(data.get('reasons') or [event.get('message', '')])
        self.detail.configure(state='normal')
        self.detail.delete('1.0', 'end')
        self.detail.insert('end', '\n'.join(str(line) for line in lines))
        self.detail.tag_add('heading', '1.0', '1.end')
        self.detail.tag_add('muted', '2.0', '2.end')
        self.detail.configure(state='disabled')

    def _finish(self, mode, code):
        self.process = None
        self.mode = None
        self.progress.stop()
        if self.cancelled:
            self._set_status('Stopped')
        elif code == 0:
            self._set_status('Scan complete' if mode == 'scan' else 'Rules updated')
        else:
            self._set_status('Scan incomplete' if mode == 'scan' else 'Update failed')
        self._refresh_actions()

    def _stop(self):
        if self.process is not None:
            self.cancelled = True
            self._set_status('Stopping')
            stop_process_tree(self.process)

    def _save_report(self):
        if not self.report_path or not self.report_path.is_file():
            return
        destination = filedialog.asksaveasfilename(parent=self, title='Save scan report',
                                                    defaultextension='.html',
                                                    filetypes=[('HTML report', '*.html')])
        if not destination:
            return
        if os.path.exists(destination) and not messagebox.askyesno('Replace report',
                                                                     'Replace the existing file?', parent=self):
            return
        try:
            shutil.copy2(self.report_path, destination)
            self.report_saved = True
            self._set_status('Report saved')
        except OSError as exc:
            messagebox.showerror('Save failed', str(exc), parent=self)

    def _open_report(self):
        if self.report_path and self.report_path.is_file():
            webbrowser.open(self.report_path.as_uri())

    def _close(self):
        if self.process is not None and not messagebox.askyesno('Stop scan',
                                                                 'Stop the current operation and close?', parent=self):
            return
        if self.report_path and self.report_path.is_file() and not self.report_saved:
            if not messagebox.askyesno('Unsaved report',
                                       'The current report has not been saved. Close anyway?', parent=self):
                return
        if self.process is not None:
            stop_process_tree(self.process)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                stop_process_tree(self.process, force=True)
        self.temp.cleanup()
        self.destroy()


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '--version':
        if sys.stdout is not None:
            print('AsterScan Studio 0.1')
        sys.exit(0)
    Studio().mainloop()
