from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import queue
import secrets
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from ..application import create_application
from ..errors import ErrorCode, ShareError, safe_message
from ..models import (
    ContributionRequest,
    OperationStatus,
    ReceiveRequest,
    SendRequest,
    ThresholdReceiveRequest,
    ThresholdSendRequest,
    TrustStatus,
    WarningCode,
)


class App:
    threshold_selectors: tuple[ttk.Combobox, ...] = ()

    def __init__(self, root, application):
        self.root = root
        self.app = application
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.results = queue.Queue()
        self.busy = False
        self.closed = False
        self.buttons = []
        self.recipient_profile = None
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
        self.profiles.bind('<<ComboboxSelected>>', lambda event: self.perform(self.refresh_contacts))
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
        ttk.Label(files_tab, text='Chọn người nhận đã xác minh').pack(anchor='w')
        self.recipients = ttk.Combobox(files_tab, textvariable=self.contact, state='readonly', width=45)
        self.recipients.pack(anchor='w', pady=10)
        self.button(files_tab, 'Chọn tệp và mã hóa để gửi', self.send).pack(anchor='w', pady=12)
        ttk.Separator(files_tab).pack(fill='x', pady=16)
        self.button(files_tab, 'Mở gói .sfile đã nhận', self.receive).pack(anchor='w', pady=12)
        ttk.Label(files_tab, text='Người gửi cũng phải được xác minh trong danh bạ của bạn.\nMật khẩu chỉ dùng mở khóa riêng; không gửi mật khẩu cho người nhận.', wraplength=730).pack(anchor='w', pady=8)
        threshold_tab = ttk.Frame(tabs, padding=16)
        tabs.add(threshold_tab, text='Chia sẻ 2-trên-3')
        self.build_threshold_tab(threshold_tab)
        self.progress = ttk.Progressbar(outer, mode='indeterminate')
        self.progress.pack(fill='x')
        ttk.Label(outer, textvariable=self.status, wraplength=820).pack(anchor='w', pady=(8, 0))
        self.refresh()
        self.root.after(80, self.poll)

    def build_threshold_tab(self, tab):
        ttk.Label(
            tab,
            text='Gửi cùng gói .sfile2 cho cả ba người giữ. Một người giữ mở tệp bằng khóa riêng '
                 'của mình và tệp .sapproval do một người giữ khác gửi cho họ.\n'
                 'Người giữ cần xác minh người gửi gói. Người góp cần xác minh thêm người sẽ mở.',
            wraplength=680,
        ).pack(anchor='w', pady=(0, 8))
        send = ttk.LabelFrame(tab, text='1. Tạo gói .sfile2', padding=8)
        send.pack(fill='x', pady=(0, 6))
        holders = ttk.Frame(send)
        holders.pack(anchor='w')
        selectors = []
        for column in range(3):
            ttk.Label(holders, text=f'Người giữ {column + 1}').grid(row=0, column=column, sticky='w')
            selector = ttk.Combobox(holders, state='readonly', width=20)
            selector.grid(row=1, column=column, padx=(0, 10), pady=(2, 0), sticky='w')
            selectors.append(selector)
        self.threshold_holders = tuple(selectors)
        self.button(send, 'Chọn tệp và tạo gói', self.send_threshold).pack(anchor='w', pady=(6, 0))

        contribute = ttk.LabelFrame(tab, text='2. Góp một phần khóa', padding=8)
        contribute.pack(fill='x', pady=(0, 6))
        ttk.Label(contribute, text='Người giữ sẽ mở gói').pack(side='left', padx=(0, 8))
        self.contribution_recipient = ttk.Combobox(contribute, state='readonly', width=20)
        self.contribution_recipient.pack(side='left', padx=(0, 8))
        self.button(contribute, 'Chọn gói và xuất .sapproval', self.export_contribution).pack(side='left')
        self.threshold_selectors = (*self.threshold_holders, self.contribution_recipient)

        receive = ttk.LabelFrame(tab, text='3. Mở tệp', padding=8)
        receive.pack(fill='x')
        self.button(receive, 'Chọn .sfile2 và .sapproval', self.receive_threshold).pack(anchor='w')

    def button(self, parent, text, command):
        button = ttk.Button(parent, text=text, command=lambda: self.perform(command))
        self.buttons.append(button)
        return button

    def perform(self, command):
        if self.busy or self.closed:
            return
        try:
            command()
        except ShareError as exc:
            self.show_error(exc.code)
        except Exception:
            self.show_error(ErrorCode.INTERNAL_ERROR)

    def show_error(self, code):
        self.status.set('Không hoàn tất thao tác.')
        messagebox.showerror(
            'Không hoàn tất', f'{safe_message(code)}\nMã lỗi: {code.value}', parent=self.root)

    def cancel(self):
        self.status.set('Đã hủy thao tác.')

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

    def set_busy(self, busy):
        self.busy = busy
        for button in self.buttons:
            button.state(['disabled' if busy else '!disabled'])
        state = 'disabled' if busy else 'readonly'
        self.profiles.configure(state=state)
        self.recipients.configure(state=state)
        for selector in self.threshold_selectors:
            selector.configure(state=state)
        if busy:
            self.progress.start(12)
            self.status.set('Đang xử lý…')
        else:
            self.progress.stop()
            self.status.set('Sẵn sàng.')

    def run(self, work, callback):
        if self.busy or self.closed:
            return

        def execute():
            try:
                result = work()
                self.results.put((callback, result, None))
            except ShareError as exc:
                self.results.put((callback, None, exc.code))
            except Exception:
                self.results.put((callback, None, ErrorCode.INTERNAL_ERROR))
        self.executor.submit(execute)
        self.set_busy(True)

    def poll(self):
        try:
            callback, result, error = self.results.get_nowait()
        except queue.Empty:
            pass
        else:
            self.set_busy(False)
            try:
                if error:
                    self.app.service.close()
                    self.show_error(error)
                else:
                    callback(result)
            except ShareError as exc:
                self.app.service.close()
                self.show_error(exc.code)
            except Exception:
                self.app.service.close()
                self.show_error(ErrorCode.INTERNAL_ERROR)
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
        profile_id = self.profile.get()
        contact_id = self.contact.get() if self.recipient_profile == profile_id else ''
        self.recipients['values'] = ()
        self.contact.set('')
        text = 'Chưa có hồ sơ. Chọn “Tạo hồ sơ” để bắt đầu.'
        if profile_id:
            profile = self.app.keys.get_profile(profile_id)
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
        if contact_id in recipients:
            self.contact.set(contact_id)
        for selector in self.threshold_selectors:
            selected = selector.get() if self.recipient_profile == profile_id else ''
            selector['values'] = recipients
            selector.set(selected if selected in recipients else '')
        self.recipient_profile = profile_id

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
            self.show_error(result.error.code)
        elif result.status is OperationStatus.CANCELLED:
            self.cancel()
        elif result.status is OperationStatus.SUCCESS and result.receipt is not None:
            self.status.set(f'Đã lưu tệp tại {result.receipt.destination}')
        else:
            self.show_error(ErrorCode.INTERNAL_ERROR)
        warnings = {
            WarningCode.DUPLICATE_TRANSFER: 'Gói này đã được mở trước đó.',
            WarningCode.HISTORY_UNAVAILABLE: 'Không đọc được lịch sử.',
            WarningCode.HISTORY_NOT_SAVED: 'Tệp đã lưu, nhưng chưa ghi được lịch sử.',
        }
        if result.warnings:
            notices = [warnings[warning] for warning in result.warnings]
            if WarningCode.HISTORY_NOT_SAVED in result.warnings and result.receipt is not None:
                notices.append(f'Vị trí tệp đã lưu: {result.receipt.destination}')
            messagebox.showwarning('Thông báo', '\n'.join(notices), parent=self.root)

    def choose_destination(self, filename, *, extension=''):
        while True:
            selected = filedialog.asksaveasfilename(
                parent=self.root, initialfile=filename, defaultextension=extension)
            if not selected:
                return None
            destination = Path(selected)
            overwrite = destination.exists()
            if not overwrite or messagebox.askyesno(
                'Ghi đè', f'Thay thế tệp đang tồn tại?\n{destination}',
                default=messagebox.NO, parent=self.root,
            ):
                return destination, overwrite

    def send(self):
        profile, contact_id = self.selected_profile(), self.contact.get()
        if not contact_id:
            self.status.set('Chọn người nhận đã xác minh trước khi gửi.')
            return
        recipient = self.app.trust.resolve_recipient(profile, contact_id)
        source = filedialog.askopenfilename(parent=self.root)
        if not source:
            self.cancel()
            return
        selected = self.choose_destination(f'{secrets.token_hex(16)}.sfile', extension='.sfile')
        if selected is None:
            self.cancel()
            return
        destination, overwrite = selected
        if not messagebox.askyesno(
            'Xác nhận người nhận',
            f'Mã người nhận: {recipient.contact_id}\nTên hiển thị: {recipient.display_name}\n'
            f'Dấu vân tay khóa mã hóa:\n{recipient.encryption_fingerprint}\n'
            f'Dấu vân tay khóa ký:\n{recipient.signing_fingerprint}\n\n'
            f'Tệp nguồn: {source}\nGói sẽ lưu tại: {destination}\n\nMã hóa tệp cho người này?',
            default=messagebox.NO, parent=self.root,
        ):
            self.cancel()
            return
        password = self.password()
        if password is None:
            self.cancel()
            return
        request = SendRequest(
            profile, contact_id, Path(source), destination, password,
            overwrite_confirmed=overwrite,
            expected_recipient_fingerprints=(recipient.encryption_fingerprint, recipient.signing_fingerprint),
        )
        self.run(lambda: self.app.service.send_file(request), self.result)

    def receive(self):
        profile = self.selected_profile()
        package = filedialog.askopenfilename(parent=self.root, filetypes=[('Gói bảo mật', '*.sfile'), ('Tất cả', '*.*')])
        if not package:
            self.cancel()
            return
        password = self.password()
        if password is None:
            self.cancel()
            return
        request = ReceiveRequest(profile, Path(package), password)
        self.run(lambda: self.app.service.prepare_receive(request), self.prepared)

    def send_threshold(self):
        profile = self.selected_profile()
        holder_ids = tuple(selector.get() for selector in self.threshold_holders)
        if not all(holder_ids) or len(set(holder_ids)) != 3:
            raise ShareError(ErrorCode.INVALID_THRESHOLD_RECIPIENTS)
        holders = tuple(self.app.trust.resolve_recipient(profile, contact_id) for contact_id in holder_ids)
        fingerprints = tuple((holder.encryption_fingerprint, holder.signing_fingerprint) for holder in holders)
        if len({fingerprint for pair in fingerprints for fingerprint in pair}) != 6:
            raise ShareError(ErrorCode.INVALID_THRESHOLD_RECIPIENTS)
        source = filedialog.askopenfilename(title='Chọn tệp nguồn', parent=self.root)
        if not source:
            self.cancel()
            return
        selected = self.choose_destination(f'{secrets.token_hex(16)}.sfile2', extension='.sfile2')
        if selected is None:
            self.cancel()
            return
        destination, overwrite = selected
        identities = '\n\n'.join(
            f'{holder.display_name} ({holder.contact_id})\n'
            f'Mã hóa: {holder.encryption_fingerprint}\nChữ ký: {holder.signing_fingerprint}'
            for holder in holders
        )
        if not messagebox.askyesno(
            'Xác nhận ba người giữ',
            f'{identities}\n\nTệp nguồn: {source}\nGói sẽ lưu tại: {destination}\n\nTạo gói cho ba người này?',
            default=messagebox.NO, parent=self.root,
        ):
            self.cancel()
            return
        password = self.password()
        if password is None:
            self.cancel()
            return
        request = ThresholdSendRequest(
            profile, holder_ids, Path(source), destination, password,
            overwrite_confirmed=overwrite, expected_recipient_fingerprints=fingerprints,
        )
        self.run(lambda: self.app.service.send_threshold(request), self.result)

    def select_threshold_package(self):
        return filedialog.askopenfilename(
            title='Chọn gói .sfile2', parent=self.root,
            filetypes=[('Gói 2-trên-3', '*.sfile2'), ('Tất cả', '*.*')],
        )

    def export_contribution(self):
        profile, contact_id = self.selected_profile(), self.contribution_recipient.get()
        if not contact_id:
            self.status.set('Chọn người giữ sẽ mở gói trong danh sách liên hệ đã xác minh.')
            return
        recipient = self.app.trust.resolve_recipient(profile, contact_id)
        package = self.select_threshold_package()
        if not package:
            self.cancel()
            return
        selected = self.choose_destination(f'{secrets.token_hex(16)}.sapproval', extension='.sapproval')
        if selected is None:
            self.cancel()
            return
        destination, overwrite = selected
        if not messagebox.askyesno(
            'Xác nhận người nhận phần đóng góp',
            f'{recipient.display_name} ({recipient.contact_id})\n'
            f'Dấu vân tay khóa mã hóa:\n{recipient.encryption_fingerprint}\n\n'
            f'Gói: {package}\nPhần đóng góp sẽ lưu tại: {destination}\n\nXuất phần đóng góp cho người này?',
            default=messagebox.NO, parent=self.root,
        ):
            self.cancel()
            return
        password = self.password()
        if password is None:
            self.cancel()
            return
        request = ContributionRequest(
            profile, contact_id, Path(package), destination, password,
            overwrite_confirmed=overwrite, expected_recipient_fingerprint=recipient.encryption_fingerprint,
        )
        self.run(lambda: self.app.service.export_contribution(request), self.result)

    def receive_threshold(self):
        profile = self.selected_profile()
        package = self.select_threshold_package()
        if not package:
            self.cancel()
            return
        contribution = filedialog.askopenfilename(
            title='Chọn phần đóng góp gửi cho bạn', parent=self.root,
            filetypes=[('Phần đóng góp', '*.sapproval'), ('Tất cả', '*.*')],
        )
        if not contribution:
            self.cancel()
            return
        password = self.password()
        if password is None:
            self.cancel()
            return
        request = ThresholdReceiveRequest(profile, Path(package), Path(contribution), password)
        self.run(lambda: self.app.service.prepare_threshold_receive(request), self.prepared)

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
        if not messagebox.askyesno(
            'Đã xác thực nội dung', notice + '\n\nLưu tệp đã giải mã?',
            default=messagebox.NO, parent=self.root,
        ):
            self.result(self.app.service.discard_prepared(prepared.handle))
            return
        self.save_prepared(prepared)

    def save_prepared(self, prepared):
        selected = self.choose_destination(prepared.filename)
        if selected is None:
            self.result(self.app.service.discard_prepared(prepared.handle))
            return
        destination, overwrite = selected

        def done(result):
            self.result(result)
            if self.app.service.has_prepared:
                if messagebox.askyesno('Chọn lại nơi lưu', 'Tệp chưa được lưu. Chọn nơi lưu khác?', parent=self.root):
                    self.save_prepared(prepared)
                else:
                    self.result(self.app.service.discard_prepared(prepared.handle))
        self.run(
            lambda: self.app.service.save_received(prepared.handle, destination, overwrite_confirmed=overwrite),
            done,
        )

    def close(self):
        if self.busy:
            messagebox.showinfo('Đang xử lý', 'Chờ tác vụ hiện tại hoàn tất rồi đóng ứng dụng.', parent=self.root)
            return
        self.closed = True
        self.app.service.close()
        self.executor.shutdown(wait=False, cancel_futures=True)
        self.root.destroy()


def main():
    try:
        root = tk.Tk()
    except tk.TclError:
        print('Không khởi động được giao diện Tkinter. Hãy kiểm tra cài đặt Python và Tcl/Tk.', file=sys.stderr)
        return 2
    try:
        App(root, create_application())
    except Exception:
        messagebox.showerror('Không khởi động được', 'Không đọc được dữ liệu ứng dụng. Hãy kiểm tra quyền truy cập và hồ sơ đã lưu.', parent=root)
        root.destroy()
        return 2
    root.mainloop()
    return 0
