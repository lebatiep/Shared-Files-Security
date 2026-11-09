from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import queue
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from ..application import create_application
from ..errors import ErrorCode, ShareError, safe_message
from ..models import OperationStatus, ReceiveRequest, SendRequest, TrustStatus, WarningCode


class App:
    def __init__(self, root, application):
        self.root = root
        self.app = application
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.results = queue.Queue()
        self.busy = False
        self.closed = False
        self.buttons = []
        self.profile = tk.StringVar()
        self.contact = tk.StringVar()
        self.status = tk.StringVar(value='Tạo hồ sơ, trao đổi khóa công khai và xác minh trước khi gửi tệp.')
        root.title('Shared Files Security')
        root.geometry('900x670')
        root.minsize(780, 570)
        root.protocol('WM_DELETE_WINDOW', self.close)
        outer = ttk.Frame(root, padding=20)
        outer.pack(fill='both', expand=True)
        ttk.Label(outer, text='Chia sẻ tệp an toàn', font=('Segoe UI', 21, 'bold')).pack(anchor='w')
        ttk.Label(outer, text='Tệp tối đa 10 MiB • Khóa riêng được bảo vệ bằng mật khẩu trên máy của bạn').pack(anchor='w', pady=(4, 18))
        line = ttk.Frame(outer)
        line.pack(fill='x')
        ttk.Label(line, text='Hồ sơ đang dùng').pack(side='left', padx=(0, 12))
        self.profiles = ttk.Combobox(line, textvariable=self.profile, state='readonly', width=30)
        self.profiles.pack(side='left')
        self.profiles.bind('<<ComboboxSelected>>', lambda event: self.refresh_contacts())
        self.button(line, 'Tạo hồ sơ', self.create_profile).pack(side='left', padx=8)
        tabs = ttk.Notebook(outer)
        tabs.pack(fill='both', expand=True, pady=18)
        profile_tab = ttk.Frame(tabs, padding=16)
        contacts_tab = ttk.Frame(tabs, padding=16)
        files_tab = ttk.Frame(tabs, padding=16)
        tabs.add(profile_tab, text='Khóa của tôi')
        tabs.add(contacts_tab, text='Người liên hệ')
        tabs.add(files_tab, text='Gửi / nhận tệp')
        self.identity = tk.Text(profile_tab, height=10, wrap='word', font=('Consolas', 11), state='disabled')
        self.identity.pack(fill='both', expand=True)
        self.button(profile_tab, 'Xuất khóa công khai', self.export_keys).pack(side='left', pady=12)
        self.button(profile_tab, 'Tạo cặp khóa mới', self.rotate_keys).pack(side='left', padx=8)
        self.button(profile_tab, 'Sao lưu hồ sơ', self.backup_profile).pack(side='left', padx=8)
        self.button(profile_tab, 'Khôi phục hồ sơ', self.restore_profile).pack(side='left', padx=8)
        ttk.Label(contacts_tab, text='Đối chiếu hai dấu vân tay qua gặp mặt hoặc cuộc gọi đã xác thực.', wraplength=740).pack(anchor='w')
        self.contacts = ttk.Treeview(contacts_tab, columns=('name', 'status'), show='headings', height=8)
        self.contacts.heading('name', text='Người liên hệ')
        self.contacts.heading('status', text='Trạng thái xác minh')
        self.contacts.pack(fill='both', expand=True, pady=12)
        contact_actions = ttk.Frame(contacts_tab)
        contact_actions.pack(fill='x')
        for label, action in [('Nhập khóa', self.import_contact), ('Xem dấu vân tay', self.show_contact), ('Xác minh', self.verify_contact), ('Vô hiệu hóa', self.disable_contact)]:
            self.button(contact_actions, label, action).pack(side='left', padx=(0, 8))
        ttk.Label(files_tab, text='Người nhận đã xác minh').pack(anchor='w')
        self.recipients = ttk.Combobox(files_tab, textvariable=self.contact, state='readonly', width=45)
        self.recipients.pack(anchor='w', pady=10)
        self.button(files_tab, 'Chọn tệp và mã hóa để gửi', self.send).pack(anchor='w', pady=12)
        ttk.Separator(files_tab).pack(fill='x', pady=16)
        self.button(files_tab, 'Mở gói .sfile đã nhận', self.receive).pack(anchor='w', pady=12)
        ttk.Label(files_tab, text='Người gửi cũng phải được xác minh trong danh bạ của bạn.\nMật khẩu chỉ dùng mở khóa riêng; không gửi mật khẩu cho người nhận.', wraplength=730).pack(anchor='w', pady=8)
        self.progress = ttk.Progressbar(outer, mode='indeterminate')
        self.progress.pack(fill='x')
        ttk.Label(outer, textvariable=self.status, wraplength=820).pack(anchor='w', pady=(8, 0))
        self.refresh()
        self.root.after(80, self.poll)

    def button(self, parent, text, command):
        def guarded():
            try:
                command()
            except ShareError as exc:
                messagebox.showerror('Không hoàn tất', exc.message, parent=self.root)
            except Exception:
                messagebox.showerror('Không hoàn tất', safe_message(ErrorCode.INTERNAL_ERROR), parent=self.root)
        button = ttk.Button(parent, text=text, command=guarded)
        self.buttons.append(button)
        return button

    def selected_profile(self):
        value = self.profile.get()
        if not value:
            raise ShareError(ErrorCode.PROFILE_INVALID)
        return value

    def selected_contact(self):
        selection = self.contacts.selection()
        if not selection:
            raise ShareError(ErrorCode.UNTRUSTED_RECIPIENT)
        return selection[0]

    def password(self, confirm=False):
        value = simpledialog.askstring('Mật khẩu khóa riêng', 'Nhập mật khẩu hồ sơ' + (' (ít nhất 12 ký tự)' if confirm else ''), show='*', parent=self.root)
        if value is None:
            return None
        if confirm:
            again = simpledialog.askstring('Xác nhận mật khẩu', 'Nhập lại mật khẩu', show='*', parent=self.root)
            if again is None:
                return None
            if value != again or len(value) < 12:
                raise ShareError(ErrorCode.INVALID_REQUEST)
        return value.encode('utf-8')

    def run(self, work, callback):
        if self.busy:
            return
        self.busy = True
        for button in self.buttons:
            button.state(['disabled'])
        self.profiles.configure(state='disabled')
        self.recipients.configure(state='disabled')
        self.progress.start(12)
        self.status.set('Đang xử lý…')

        def execute():
            try:
                result = work()
                self.results.put((callback, result, None))
            except ShareError as exc:
                self.results.put((callback, None, exc.code))
            except Exception:
                self.results.put((callback, None, ErrorCode.INTERNAL_ERROR))
        self.executor.submit(execute)

    def poll(self):
        try:
            callback, result, error = self.results.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            self.progress.stop()
            for button in self.buttons:
                button.state(['!disabled'])
            self.profiles.configure(state='readonly')
            self.recipients.configure(state='readonly')
            self.status.set('Sẵn sàng.')
            try:
                if error:
                    messagebox.showerror('Không hoàn tất', safe_message(error), parent=self.root)
                else:
                    callback(result)
            except ShareError as exc:
                messagebox.showerror('Không hoàn tất', exc.message, parent=self.root)
            except Exception:
                self.app.service.close()
                messagebox.showerror('Không hoàn tất', safe_message(ErrorCode.INTERNAL_ERROR), parent=self.root)
        if not self.closed:
            self.root.after(80, self.poll)

    def refresh(self):
        profiles = self.app.keys.list_profiles()
        values = [p.profile_id for p in profiles]
        self.profiles['values'] = values
        if self.profile.get() not in values:
            self.profile.set(values[0] if values else '')
        self.refresh_contacts()

    def refresh_contacts(self):
        self.contacts.delete(*self.contacts.get_children())
        entries = []
        text = 'Chưa có hồ sơ. Chọn “Tạo hồ sơ” để bắt đầu.'
        if self.profile.get():
            profile = self.app.keys.get_profile(self.profile.get())
            text = f'{profile.display_name} ({profile.profile_id})\n\nKhóa mã hóa:\n{profile.encryption_fingerprint}\n\nKhóa chữ ký:\n{profile.signing_fingerprint}\n\nChỉ chia sẻ khóa công khai. Giữ riêng mật khẩu và hồ sơ khóa.'
            entries = self.app.trust.list_contacts(profile.profile_id)
        self.identity.configure(state='normal')
        self.identity.delete('1.0', 'end')
        self.identity.insert('1.0', text)
        self.identity.configure(state='disabled')
        labels = {TrustStatus.VERIFIED: 'Đã xác minh', TrustStatus.UNVERIFIED: 'Chưa xác minh', TrustStatus.DISABLED: 'Đã vô hiệu hóa'}
        for entry in entries:
            self.contacts.insert('', 'end', iid=entry.contact_id, values=(f'{entry.display_name} ({entry.contact_id})', labels[entry.status]))
        recipients = [c.contact_id for c in entries if c.status is TrustStatus.VERIFIED]
        self.recipients['values'] = recipients
        if self.contact.get() not in recipients:
            self.contact.set(recipients[0] if recipients else '')

    def create_profile(self):
        profile_id = simpledialog.askstring('Tạo hồ sơ', 'Mã hồ sơ: chữ thường không dấu, số, _ hoặc -', parent=self.root)
        if not profile_id:
            return
        name = simpledialog.askstring('Tạo hồ sơ', 'Tên hiển thị', parent=self.root)
        if not name:
            return
        password = self.password(confirm=True)
        if password is None:
            return
        def done(profile):
            self.profile.set(profile.profile_id)
            self.refresh()
        self.run(lambda: self.app.keys.create_profile(profile_id, name, password), done)

    def export_keys(self):
        profile = self.selected_profile()
        path = filedialog.asksaveasfilename(parent=self.root, initialfile=f'{profile}-public.json', defaultextension='.json')
        if path:
            self.app.storage.save_atomic(self.app.keys.public_bundle(profile), Path(path), overwrite_confirmed=False,
                                         protected_paths=self.app.keys.protected_paths(profile))
            self.status.set('Đã xuất khóa công khai. Gửi tệp này cho người liên hệ.')

    def rotate_keys(self):
        profile = self.selected_profile()
        if not messagebox.askyesno('Đổi khóa', 'Tạo khóa mới? Sau đó cần xuất và xác minh lại với người liên hệ. Khóa cũ vẫn được giữ để mở tệp cũ.', parent=self.root):
            return
        password = self.password()
        if password is not None:
            self.run(lambda: self.app.keys.rotate_keys(profile, password), lambda result: self.refresh())

    def backup_profile(self):
        profile = self.selected_profile()
        path = filedialog.asksaveasfilename(parent=self.root, initialfile=f'{profile}.sbackup', defaultextension='.sbackup')
        if not path:
            return
        password = self.password()
        if password is None:
            return
        def work():
            data = self.app.keys.backup_profile(profile, password)
            self.app.storage.save_atomic(data, Path(path), protected_paths=self.app.keys.protected_paths(profile))
        def done(result):
            self.status.set('Đã sao lưu khóa riêng có mã hóa. Cất bản sao ở nơi riêng; không gửi cho người liên hệ.')
        self.run(work, done)

    def restore_profile(self):
        path = filedialog.askopenfilename(parent=self.root, filetypes=[('Hồ sơ sao lưu', '*.sbackup')])
        if not path:
            return
        password = self.password()
        if password is None:
            return
        def work():
            data = self.app.storage.read_limited(Path(path), 262144)
            return self.app.keys.restore_profile(data, password)
        def done(profile):
            self.profile.set(profile.profile_id)
            self.refresh()
            self.status.set('Đã khôi phục hồ sơ. Nhập và xác minh lại người liên hệ trên máy này.')
        self.run(work, done)

    def import_contact(self):
        profile = self.selected_profile()
        path = filedialog.askopenfilename(parent=self.root, filetypes=[('Khóa công khai', '*.json'), ('Tất cả', '*.*')])
        if not path:
            return
        contact = simpledialog.askstring('Người liên hệ', 'Mã người liên hệ (không dấu)', parent=self.root)
        if not contact:
            return
        data = self.app.storage.read_limited(Path(path), 8192)
        imported = self.app.trust.import_contact(profile, contact, data)
        if self.app.trust.find_name_conflicts(profile, contact):
            messagebox.showwarning(
                'Different keys for the same name',
                'Another contact has the same name but different keys. Keep the old pins and verify both new fingerprints independently.',
                parent=self.root)
        self.refresh_contacts()
        if imported.status is TrustStatus.UNVERIFIED:
            self.status.set('Public keys imported. Verify both fingerprints before use. Keep old keys under their existing contact ID.')
        else:
            self.status.set('These keys already exist. The contact name and trust status were preserved.')

    def show_contact(self):
        profile, contact_id = self.selected_profile(), self.selected_contact()
        contact = next(c for c in self.app.trust.list_contacts(profile) if c.contact_id == contact_id)
        messagebox.showinfo('Dấu vân tay', f'{contact.display_name}\n\nMã hóa:\n{contact.encryption_fingerprint}\n\nChữ ký:\n{contact.signing_fingerprint}', parent=self.root)

    def verify_contact(self):
        profile, contact = self.selected_profile(), self.selected_contact()
        encryption = simpledialog.askstring('Xác minh độc lập', 'Nhập đủ 64 ký tự dấu vân tay KHÓA MÃ HÓA do người liên hệ xác nhận trực tiếp hoặc qua cuộc gọi:', parent=self.root)
        if encryption is None:
            return
        signing = simpledialog.askstring('Xác minh độc lập', 'Nhập đủ 64 ký tự dấu vân tay KHÓA CHỮ KÝ từ cùng kênh đã xác thực:', parent=self.root)
        if signing is None:
            return
        self.app.trust.verify_contact(profile, contact, encryption.strip().lower(), signing.strip().lower())
        self.refresh_contacts()

    def disable_contact(self):
        profile, contact = self.selected_profile(), self.selected_contact()
        if messagebox.askyesno('Vô hiệu hóa', 'Ngừng gửi và nhận bằng khóa của liên hệ này?', parent=self.root):
            self.app.trust.disable_contact(profile, contact)
            self.refresh_contacts()

    def result(self, result):
        if result.error:
            messagebox.showerror('Không hoàn tất', f'{result.error.message}\nMã lỗi: {result.error.code}', parent=self.root)
        else:
            self.status.set('Đã lưu tệp thành công.')
        warnings = {WarningCode.DUPLICATE_TRANSFER: 'Gói này đã được mở trước đó.', WarningCode.HISTORY_UNAVAILABLE: 'Không đọc được lịch sử.', WarningCode.HISTORY_NOT_SAVED: 'Tệp đã lưu, nhưng chưa ghi được lịch sử.'}
        if result.warnings:
            messagebox.showwarning('Thông báo', '\n'.join(warnings[w] for w in result.warnings), parent=self.root)

    def send(self):
        profile, recipient = self.selected_profile(), self.contact.get()
        if not recipient:
            raise ShareError(ErrorCode.UNTRUSTED_RECIPIENT)
        source = filedialog.askopenfilename(parent=self.root)
        if not source:
            return
        destination = filedialog.asksaveasfilename(parent=self.root, initialfile=Path(source).name + '.sfile', defaultextension='.sfile')
        if not destination:
            return
        overwrite = Path(destination).exists()
        if overwrite and not messagebox.askyesno('Ghi đè', 'Thay thế tệp đích đang tồn tại?', parent=self.root):
            return
        password = self.password()
        if password is not None:
            request = SendRequest(profile, recipient, Path(source), Path(destination), password, overwrite)
            self.run(lambda: self.app.service.send_file(request), self.result)

    def receive(self):
        profile = self.selected_profile()
        package = filedialog.askopenfilename(parent=self.root, filetypes=[('Gói bảo mật', '*.sfile'), ('Tất cả', '*.*')])
        if not package:
            return
        password = self.password()
        if password is not None:
            request = ReceiveRequest(profile, Path(package), password)
            self.run(lambda: self.app.service.prepare_receive(request), self.prepared)

    def prepared(self, result):
        if result.status is not OperationStatus.PREPARED:
            self.result(result)
            return
        prepared = result.prepared
        notice = f'Người gửi: {prepared.sender_name}\nTên tệp: {prepared.filename}\nDung lượng: {prepared.byte_count:,} bytes'
        if prepared.duplicate:
            notice += '\nGói này đã được mở trước đó.'
        if WarningCode.HISTORY_UNAVAILABLE in result.warnings:
            notice += '\nKhông đọc được lịch sử mở tệp.'
        if not messagebox.askyesno('Đã xác thực nội dung', notice + '\n\nLưu tệp đã giải mã?', parent=self.root):
            self.app.service.discard_prepared(prepared.handle)
            return
        self.save_prepared(prepared)

    def save_prepared(self, prepared):
        destination = filedialog.asksaveasfilename(parent=self.root, initialfile=prepared.filename)
        if not destination:
            self.app.service.discard_prepared(prepared.handle)
            return
        overwrite = Path(destination).exists()
        if overwrite and not messagebox.askyesno('Ghi đè', 'Thay thế tệp đích đang tồn tại?', parent=self.root):
            self.app.service.discard_prepared(prepared.handle)
            return
        def done(result):
            self.result(result)
            if self.app.service.has_prepared:
                if messagebox.askyesno('Chọn lại nơi lưu', 'Tệp chưa được lưu. Chọn nơi lưu khác?', parent=self.root):
                    self.save_prepared(prepared)
                else:
                    self.app.service.discard_prepared(prepared.handle)
        self.run(lambda: self.app.service.save_received(prepared.handle, Path(destination), overwrite_confirmed=overwrite), done)

    def close(self):
        if self.busy:
            messagebox.showinfo('Đang xử lý', 'Chờ tác vụ hiện tại hoàn tất rồi đóng ứng dụng.', parent=self.root)
            return
        self.closed = True
        self.app.service.close()
        self.executor.shutdown(wait=False, cancel_futures=True)
        self.root.destroy()


def main():
    root = tk.Tk()
    try:
        App(root, create_application())
    except Exception:
        messagebox.showerror('Không khởi động được', 'Không đọc được dữ liệu ứng dụng. Hãy kiểm tra quyền truy cập và hồ sơ đã lưu.', parent=root)
        root.destroy()
        return 2
    root.mainloop()
    return 0
