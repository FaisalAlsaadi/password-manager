from PyInstaller.utils.hooks import copy_metadata, collect_data_files

datas = collect_data_files('ttkbootstrap.localization')
datas += copy_metadata('ttkbootstrap')

# Patch the module at import time
def exec_statement(statement):
    return statement

exec_statement('''
import sys
class DummyMsgcat:
    @staticmethod
    def set_many(*args, **kwargs):
        return 0
sys.modules['ttkbootstrap.localization.msgcat'] = type('module', (), {'MessageCatalog': DummyMsgcat})()
''')
