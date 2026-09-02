import re
from datetime import datetime

class Item:

    def __init__(self, date, time, level, user, ip, action, status=None, reason=None, file=None, size=None):
        self.date = date
        self.time = time
        self.level = level
        self.user = user
        self.ip = ip
        self.action = action
        self.status = status
        self.reason = reason
        self.file = file
        self.size = size


class LoadData:

    def __init__(self):
        self.valid_log = []
        self.invalid_log = []

    def generate_data(self): # For extracting data from text file and load it to list as object and item
        with open('data.txt', 'r') as f:

            for line in f:
                data = re.search(r'^(?P<date>2026-(?:1[0-2]|0[1-9])-(?:3[0-1]|[1-2][0-9]|0[1-9]))(\s)(?P<time>(?:2[0-3]|[0-1][0-9]):[0-5][0-9]:[0-5][0-9])(\s\[)(?P<level>\w+)(\]\suser=)(?P<user>\w+)(\sip=)(?P<ip>\d+\.\d+\.\d+\.\d+)(\saction=)(?P<action>\w+)((\sstatus=)(?P<status>\w+))?((\sreason=\")(?P<reason>\w+\s\w+)(\"))?((\sfile=\")(?P<file>\w+\.\w+)(\"))?((\ssize=)(?P<size>\d+))?$', line)

                if data:
                    date = data.group('date')
                    
                    try:
                        datetime.strptime(date, "%Y-%m-%d")
                    except ValueError:
                        line = line.strip()
                        self.invalid_log.append(line)
                        continue

                    time = data.group('time')
                    level = data.group('level')
                    user = data.group('user')
                    ip = data.group('ip')
                    action = data.group('action')
                    status = data.group('status')
                    reason = data.group('reason')
                    file = data.group('file')
                    size = data.group('size')

                    item = Item(date, time, level, user, ip, action, status, reason, file, size)
                    self.valid_log.append(item)

                else:
                    line = line.strip()
                    self.invalid_log.append(line)

    def remove_none(self, obj): # Remove none keys from object for data presentation
        return {
            key: value
            for key, value in obj.__dict__.items()
            if value != None
        }

class Report:

    def __init__(self):
        self.suspicious_ip = {}
        self.suspicious_user = []
        self.valid_ip = []
        self.invalid_ip = []
        self.levels = {}
        self.unique = {}

    def failed_logs(self, valid_log_list):
        failed_log_count = {}
        for logs in valid_log_list:
            if logs.status == 'failed':
                if logs.ip in failed_log_count:
                    failed_log_count[logs.ip] += 1
                else:
                    failed_log_count[logs.ip] = 1

        return failed_log_count

    def sus_ip_generate(self, failed_log_count):
        sus_return = True
        for key, value in failed_log_count.items():
            if value > 5:
                self.suspicious_ip[key] = value
                sus_return = False

        if sus_return:
            return False
        else:
            return True

    def sus_user_generate(self, valid_log_list):
        sus_user = ['admin', 'root', 'administrator', 'test', 'guest']
        for item in valid_log_list:
            if item.user in sus_user and item.status == 'failed':
                self.suspicious_user.append(item)

    def valid_invalid_ip_generate(self, valid_log_list):
        for item in valid_log_list:
            valid_ip = re.search(r'(?P<a>\d+)\.(?P<b>\d+)\.(?P<c>\d+)\.(?P<d>\d+)', item.ip)
            if valid_ip:
                a = int(valid_ip.group('a'))
                b = int(valid_ip.group('b'))
                c = int(valid_ip.group('c'))
                d = int(valid_ip.group('d'))
                if 0 <= a <= 255 and 0 <= b <= 255 and 0 <= c <= 255 and 0 <= d <= 255 :
                    self.valid_ip.append(item)
                else:
                    self.invalid_ip.append(item)
            else:
                 self.invalid_ip.append(item)


    def level_extract(self, valid_log_list):
        for item in valid_log_list:
            if item.level in self.levels:
                self.levels[item.level] += 1
            else:
                self.levels[item.level] = 1
        return self.levels

    def failed_log_count(self, valid_log_list):
        failed = 0
        for item in valid_log_list:
            if item.status == 'failed':
                failed += 1
        return failed
    
    def success_log_count(self, valid_log_list):
        success = 0
        for item in valid_log_list:
            if item.status == 'success':
                success += 1
        return success

    def unique_find(self, valid_log_list):
        for item in valid_log_list:
            if item.ip not in self.unique:
                self.unique[item.ip] = [item.user]
            else:
                if item.user not in self.unique[item.ip]:
                    self.unique[item.ip].append(item.user)

        return self.unique

            


if __name__ == '__main__':

    load_data = LoadData() # create an object 
    report = Report() # Create an object

    load_data.generate_data() # extract data from text file in valid_log & invalid_log list

    print(f'\n***All Valid logs***, Total: {len(load_data.valid_log)} [1. Log parser, 2. Multiple log formats handle]')

    for item in load_data.valid_log:
        cleaned_data = load_data.remove_none(item)
        print(cleaned_data)

    print(f'\n***All Invalid logs***, Total: {len(load_data.invalid_log)} [3. Invalid log detect]')

    for item in load_data.invalid_log:
        print(item)


    print(f'\n***All Suspicious Ip\'s and count*** [4. Security analysis - Suspicious IP]')

    failed_log_count = report.failed_logs(load_data.valid_log) # Extract failed logins as {ip:count}

    if report.sus_ip_generate(failed_log_count):
        for key, value in report.suspicious_ip.items():
            print(f'Suspicious ip: {key}, Failed attempts: {value}')
    else:
        print('No suspicious ip found')


    print(f'\n***All Special Users failed attempts and Reason*** [5. Suspicious usernames]')

    report.sus_user_generate(load_data.valid_log)

    for item in report.suspicious_user:
        print(f'special user: {item.user}, login: Failed, Reason: {item.reason}')

    print(f'\n***All IP\'s check*** [6. IP validation]')

    report.valid_invalid_ip_generate(load_data.valid_log)
    print('Valid IP list:')
    for item in report.valid_ip:
        print(item.ip)
    print('Invalid IP list:')
    for item in report.invalid_ip:
        print(item.ip)

    levels = report.level_extract(load_data.valid_log)

    failed = report.failed_log_count(load_data.valid_log)
    success = report.success_log_count(load_data.valid_log)


    with open('report.txt', 'w') as f:
        f.write(f'\n{'':<4}{'='*15} LOG ANALYSIS {'='*15}')
        f.write(f'\n\n')
        f.write(f"{'Total logs':<22}{':':<4}{len(load_data.valid_log)+len(load_data.invalid_log)}\n{'Valid logs':<22}{':':<4}{len(load_data.valid_log)}\n{'Invalid logs':<22}{':':<4}{len(load_data.invalid_log)}")
        f.write(f'\n\n')
        for key, value in levels.items():
            f.write(f'{key:<22}{':':<4}{value}\n')

        f.write(f'\n\n')
        f.write(f'{'Successful login':<22}{':':<4}{success}\n')
        f.write(f'{'Failed login':<22}{':':<4}{failed}')

        f.write(f'\n\n')
        unique = report.unique_find(load_data.valid_log)
        unique_ip = 0
        unique_user = []
        for key, value in unique.items():
            unique_ip += 1
            for users in value:
                if users not in unique_user:
                    unique_user.append(users)
        f.write(f'{'Unique users':<22}{':':<4}{len(unique_user)}\n{'Unique IPs':<22}{':':<4}{unique_ip}')

        f.write(f'\n\n')
        sus_ip_count = 0
        for key, value in report.suspicious_ip.items():
            sus_ip_count += 1
        f.write(f'{'Suspicious IPs':<22}{':':<4}{sus_ip_count}')

        f.write(f'\n\n')
        f.write(f'{'':<4}{'='*40}')
        

    
    






    




