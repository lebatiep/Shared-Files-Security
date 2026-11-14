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
    ThresholdReceiveRequest,
    ThresholdSendRequest,
    TrustStatus,
    WarningCode,
)


class App:
    def __init__(self, root, application):
        self.root = root
        self.app = application
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.results = queue.Queue()
        self.busy = False
        self.closed = False
        self.buttons = []
        self.contacts_profile = None
        self.profile = tk.StringVar()
        self.status = tk.StringVar(value='Create a profile and verify contacts to share files with two of three holders.')
        root.title('Shared-Files-Security')
        root.geometry('900x670')
        root.minsize(780, 570)
        root.protocol('WM_DELETE_WINDOW', self.close)
        outer = ttk.Frame(root, padding=20)
        outer.pack(fill='both', expand=True)
        ttk.Label(outer, text='Two-of-Three File Sharing', font=('Segoe UI', 21, 'bold')).pack(anchor='w')
        ttk.Label(outer, text='Files up to 10 MiB | Private keys are password-protected on your device').pack(anchor='w', pady=(4, 18))
        line = ttk.Frame(outer)
        line.pack(fill='x')
        ttk.Label(line, text='Active profile').pack(side='left', padx=(0, 12))
        self.profiles = ttk.Combobox(line, textvariable=self.profile, state='readonly', width=30)
        self.profiles.pack(side='left')
        self.profiles.bind('<<ComboboxSelected>>', lambda event: self.perform(self.refresh_contacts))
        self.button(line, 'Create profile', self.create_profile).pack(side='left', padx=8)
        tabs = ttk.Notebook(outer)
        tabs.pack(fill='both', expand=True, pady=18)
        threshold_tab = ttk.Frame(tabs, padding=16)
        profile_tab = ttk.Frame(tabs, padding=16)
        contacts_tab = ttk.Frame(tabs, padding=16)
        tabs.add(profile_tab, text='My keys')
        tabs.add(contacts_tab, text='Contacts')
        tabs.add(threshold_tab, text='Two-of-three sharing')
        tabs.select(threshold_tab)
        self.build_threshold_tab(threshold_tab)
        self.identity = tk.Text(profile_tab, height=10, wrap='word', font=('Consolas', 11), state='disabled')
        self.identity.pack(fill='both', expand=True)
        self.button(profile_tab, 'Export public keys', self.export_keys).pack(side='left', pady=12)
        self.button(profile_tab, 'Rotate keys', self.rotate_keys).pack(side='left', padx=8)
        self.button(profile_tab, 'Back up profile', self.backup_profile).pack(side='left', padx=8)
        self.button(profile_tab, 'Restore profile', self.restore_profile).pack(side='left', padx=8)
        ttk.Label(contacts_tab, text='Compare both fingerprints in person or over an authenticated call.', wraplength=740).pack(anchor='w')
        self.contacts = ttk.Treeview(contacts_tab, columns=('name', 'status'), show='headings', height=8)
        self.contacts.heading('name', text='Contacts')
        self.contacts.heading('status', text='Verification status')
        self.contacts.pack(fill='both', expand=True, pady=12)
        contact_actions = ttk.Frame(contacts_tab)
        contact_actions.pack(fill='x')
        for label, action in [('Import keys', self.import_contact), ('View fingerprints', self.show_contact), ('Verify', self.verify_contact), ('Disable', self.disable_contact)]:
            self.button(contact_actions, label, action).pack(side='left', padx=(0, 8))
        self.progress = ttk.Progressbar(outer, mode='indeterminate')
        self.progress.pack(fill='x')
        ttk.Label(outer, textvariable=self.status, wraplength=820).pack(anchor='w', pady=(8, 0))
        self.refresh()
        self.root.after(80, self.poll)

    def build_threshold_tab(self, tab):
        ttk.Label(
            tab,
            text='Send the same .sfile2 package to all three holders. A holder opens it using their private key '
                 'and an .sapproval contribution sent to them by another holder.\n'
                 'Holders must verify the sender. Contributors must also verify the holder who will open the file.',
            wraplength=680,
        ).pack(anchor='w', pady=(0, 8))
        send = ttk.LabelFrame(tab, text='1. Create a .sfile2 package', padding=8)
        send.pack(fill='x', pady=(0, 6))
        holders = ttk.Frame(send)
        holders.pack(anchor='w')
        selectors = []
        for column in range(3):
            ttk.Label(holders, text=f'Holder {column + 1}').grid(row=0, column=column, sticky='w')
            selector = ttk.Combobox(holders, state='readonly', width=20)
            selector.grid(row=1, column=column, padx=(0, 10), pady=(2, 0), sticky='w')
            selectors.append(selector)
        self.threshold_holders = tuple(selectors)
        self.button(send, 'Choose file and create package', self.send_threshold).pack(anchor='w', pady=(6, 0))

        contribute = ttk.LabelFrame(tab, text='2. Contribute a key share', padding=8)
        contribute.pack(fill='x', pady=(0, 6))
        ttk.Label(contribute, text='Holder who will open the file').pack(side='left', padx=(0, 8))
        self.contribution_recipient = ttk.Combobox(contribute, state='readonly', width=20)
        self.contribution_recipient.pack(side='left', padx=(0, 8))
        self.button(contribute, 'Choose package and export .sapproval', self.export_contribution).pack(side='left')
        self.threshold_selectors = (*self.threshold_holders, self.contribution_recipient)

        receive = ttk.LabelFrame(tab, text='3. Open a file', padding=8)
        receive.pack(fill='x')
        self.button(receive, 'Choose .sfile2 and .sapproval', self.receive_threshold).pack(anchor='w')

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
        self.status.set('Operation could not be completed.')
        messagebox.showerror(
            'Operation failed', f'{safe_message(code)}\nError code: {code.value}', parent=self.root)

    def cancel(self):
        self.status.set('Operation cancelled.')

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
        value = simpledialog.askstring('Private key passphrase', 'Enter the profile passphrase' + (' (at least 12 characters)' if confirm else ''), show='*', parent=self.root)
        if value is None:
            return None
        if confirm:
            again = simpledialog.askstring('Confirm passphrase', 'Enter the passphrase again', show='*', parent=self.root)
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
        for selector in self.threshold_selectors:
            selector.configure(state=state)
        if busy:
            self.progress.start(12)
            self.status.set('Processing...')
        else:
            self.progress.stop()
            self.status.set('Ready.')

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
        text = 'No profiles yet. Select Create profile to get started.'
        if profile_id:
            profile = self.app.keys.get_profile(profile_id)
            text = f'{profile.display_name} ({profile.profile_id})\n\nEncryption key fingerprint:\n{profile.encryption_fingerprint}\n\nSigning key fingerprint:\n{profile.signing_fingerprint}\n\nShare only public keys. Keep your passphrase and private key profile secret.'
            entries = self.app.trust.list_contacts(profile.profile_id)
        self.identity.configure(state='normal')
        self.identity.delete('1.0', 'end')
        self.identity.insert('1.0', text)
        self.identity.configure(state='disabled')
        labels = {TrustStatus.VERIFIED: 'Verified', TrustStatus.UNVERIFIED: 'Unverified', TrustStatus.DISABLED: 'Disabled'}
        for entry in entries:
            self.contacts.insert('', 'end', iid=entry.contact_id, values=(f'{entry.display_name} ({entry.contact_id})', labels[entry.status]))
        verified_ids = [entry.contact_id for entry in entries if entry.status is TrustStatus.VERIFIED]
        for selector in self.threshold_selectors:
            selected = selector.get() if self.contacts_profile == profile_id else ''
            selector['values'] = verified_ids
            selector.set(selected if selected in verified_ids else '')
        self.contacts_profile = profile_id

    def create_profile(self):
        profile_id = simpledialog.askstring('Create profile', 'Profile ID: lowercase ASCII letters, digits, _ or -', parent=self.root)
        if not profile_id:
            return
        name = simpledialog.askstring('Create profile', 'Display name', parent=self.root)
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
            self.status.set('Public keys exported. Send this file to your contact.')

    def rotate_keys(self):
        profile = self.selected_profile()
        if not messagebox.askyesno('Rotate keys', 'Generate new keys? Export and verify them with your contacts afterwards. Old keys are retained to open existing files.', parent=self.root):
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
            self.status.set('Encrypted private keys backed up. Store the backup privately; do not send it to contacts.')
        self.run(work, done)

    def restore_profile(self):
        path = filedialog.askopenfilename(parent=self.root, filetypes=[('Profile backup', '*.sbackup')])
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
            self.status.set('Profile restored. Import and verify contacts again on this device.')
        self.run(work, done)

    def import_contact(self):
        profile = self.selected_profile()
        path = filedialog.askopenfilename(parent=self.root, filetypes=[('Public keys', '*.json'), ('All files', '*.*')])
        if not path:
            return
        contact = simpledialog.askstring('Contacts', 'Contact ID (ASCII letters, digits, _ or -)', parent=self.root)
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
        messagebox.showinfo('Fingerprints', f'{contact.display_name}\n\nEncryption key fingerprint:\n{contact.encryption_fingerprint}\n\nSigning key fingerprint:\n{contact.signing_fingerprint}', parent=self.root)

    def verify_contact(self):
        profile, contact = self.selected_profile(), self.selected_contact()
        encryption = simpledialog.askstring('Independent verification', 'Enter all 64 characters of the ENCRYPTION KEY fingerprint confirmed by the contact in person or over an authenticated call:', parent=self.root)
        if encryption is None:
            return
        signing = simpledialog.askstring('Independent verification', 'Enter all 64 characters of the SIGNING KEY fingerprint from the same authenticated channel:', parent=self.root)
        if signing is None:
            return
        self.app.trust.verify_contact(profile, contact, encryption.strip().lower(), signing.strip().lower())
        self.refresh_contacts()

    def disable_contact(self):
        profile, contact = self.selected_profile(), self.selected_contact()
        if messagebox.askyesno('Disable', 'Stop sending and receiving with this contact and their keys?', parent=self.root):
            self.app.trust.disable_contact(profile, contact)
            self.refresh_contacts()

    def result(self, result):
        if result.error:
            self.show_error(result.error.code)
        elif result.status is OperationStatus.CANCELLED:
            self.cancel()
        elif result.status is OperationStatus.SUCCESS and result.receipt is not None:
            self.status.set(f'File saved to {result.receipt.destination}')
        else:
            self.show_error(ErrorCode.INTERNAL_ERROR)
        warnings = {
            WarningCode.DUPLICATE_TRANSFER: 'This package has been opened before.',
            WarningCode.HISTORY_UNAVAILABLE: 'Could not read the history.',
            WarningCode.HISTORY_NOT_SAVED: 'The file was saved, but its history could not be recorded.',
        }
        if result.warnings:
            notices = [warnings[warning] for warning in result.warnings]
            if WarningCode.HISTORY_NOT_SAVED in result.warnings and result.receipt is not None:
                notices.append(f'Saved file location: {result.receipt.destination}')
            messagebox.showwarning('Notice', '\n'.join(notices), parent=self.root)

    def choose_destination(self, filename, *, extension=''):
        while True:
            selected = filedialog.asksaveasfilename(
                parent=self.root, initialfile=filename, defaultextension=extension)
            if not selected:
                return None
            destination = Path(selected)
            overwrite = destination.exists()
            if not overwrite or messagebox.askyesno(
                'Overwrite', f'Replace the existing file?\n{destination}',
                default=messagebox.NO, parent=self.root,
            ):
                return destination, overwrite

    def send_threshold(self):
        profile = self.selected_profile()
        holder_ids = tuple(selector.get() for selector in self.threshold_holders)
        if not all(holder_ids) or len(set(holder_ids)) != 3:
            raise ShareError(ErrorCode.INVALID_THRESHOLD_RECIPIENTS)
        holders = tuple(self.app.trust.resolve_recipient(profile, contact_id) for contact_id in holder_ids)
        fingerprints = tuple((holder.encryption_fingerprint, holder.signing_fingerprint) for holder in holders)
        if len({fingerprint for pair in fingerprints for fingerprint in pair}) != 6:
            raise ShareError(ErrorCode.INVALID_THRESHOLD_RECIPIENTS)
        source = filedialog.askopenfilename(title='Choose source file', parent=self.root)
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
            f'Encryption key fingerprint: {holder.encryption_fingerprint}\nSigning key fingerprint: {holder.signing_fingerprint}'
            for holder in holders
        )
        if not messagebox.askyesno(
            'Confirm three holders',
            f'{identities}\n\nSource file: {source}\nSave package to: {destination}\n\nCreate a package for these three holders?',
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
            title='Choose a .sfile2 package', parent=self.root,
            filetypes=[('Two-of-three package', '*.sfile2'), ('All files', '*.*')],
        )

    def export_contribution(self):
        profile, contact_id = self.selected_profile(), self.contribution_recipient.get()
        if not contact_id:
            self.status.set('Select the holder who will open the file from your verified contacts.')
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
            'Confirm contribution recipient',
            f'{recipient.display_name} ({recipient.contact_id})\n'
            f'Encryption key fingerprint:\n{recipient.encryption_fingerprint}\n\n'
            f'Package: {package}\nSave contribution to: {destination}\n\nExport a contribution for this holder?',
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
            title='Choose the contribution sent to you', parent=self.root,
            filetypes=[('Contribution', '*.sapproval'), ('All files', '*.*')],
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
        notice = f'Sender: {prepared.sender_name}\nFilename: {prepared.filename}\nSize: {prepared.byte_count:,} bytes'
        if prepared.duplicate:
            notice += '\nThis package has been opened before.'
        if WarningCode.HISTORY_UNAVAILABLE in result.warnings:
            notice += '\nCould not read the file opening history.'
        if not messagebox.askyesno(
            'Content verified', notice + '\n\nSave the decrypted file?',
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
                if messagebox.askyesno('Choose another location', 'The file has not been saved. Choose another location?', parent=self.root):
                    self.save_prepared(prepared)
                else:
                    self.result(self.app.service.discard_prepared(prepared.handle))
        self.run(
            lambda: self.app.service.save_received(prepared.handle, destination, overwrite_confirmed=overwrite),
            done,
        )

    def close(self):
        if self.busy:
            messagebox.showinfo('Processing', 'Wait for the current operation to finish before closing the app.', parent=self.root)
            return
        self.closed = True
        self.app.service.close()
        self.executor.shutdown(wait=False, cancel_futures=True)
        self.root.destroy()


def main():
    try:
        root = tk.Tk()
    except tk.TclError:
        print('Could not start Tkinter. Check your Python and Tcl/Tk installation.', file=sys.stderr)
        return 2
    try:
        App(root, create_application())
    except Exception:
        messagebox.showerror('Startup failed', 'Could not read application data. Check access permissions and saved profiles.', parent=root)
        root.destroy()
        return 2
    root.mainloop()
    return 0
