import os

class FilePathCheck:
    def __init__(self, file_path):
        self.file_path = file_path
        self.tmp_lst = file_path.split(os.sep)
        self.origin_package_name = self.tmp_lst[1]

    def check_shared_and_pref(self):
        return 'shared' in self.file_path and 'pref' in self.file_path

    def check_path(self):
        package_parts = self.origin_package_name.split('.')
        thd = len(package_parts) - 1
        chk_num = 0

        for i in self.tmp_lst[3:]:
            # print(i)
            if i in package_parts:
                chk_num += 1

        return chk_num >= thd

    def validate(self):
        if self.check_shared_and_pref() or self.check_path():
            return self.file_path
        return None