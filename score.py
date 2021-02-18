#!/usr/bin/python3.6

import crypt
import subprocess
import shlex
import shutil
import datetime
import os
import pwd
import math
import re 
import glob
from multiprocessing import cpu_count
import psutil
from socket import gethostname


try:
    import rich
    from rich import print

    def bold(text):
        return f"[bold yellow]{text}[/bold yellow]"

except ImportError:
    def bold(text):
        return text


def run(command, is_shell=False):
    """Runs a shell command and returns the stdout response"""
    result = subprocess.run(shlex.split(command),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=is_shell,
                            )
    result.stdout = result.stdout.decode('utf-8')
    result.stderr = result.stderr.decode('utf-8')
    return result.stdout.strip()


def check_password(user, pw):
    userline = run(f"grep '^{user}' /etc/shadow")
    userfields = userline.split(':')
    users=dict((i.split(':')[0], i.split(':')[1]) for i in open('/etc/shadow').readlines())
    _, alg, salt, hash = users[user].split('$')
    calculated_shadow_line = crypt.crypt(pw, f"${alg}${salt}$")
    return calculated_shadow_line == users[user]


def main_user(uid):
    return pwd.getpwuid(uid).pw_name


def main_user_name_ish(user, uid):
    username = main_user(uid)
    return user in username


def get_user_sudo_perms(user):
    sudo_line = run(f"sudo -l -U {user}").splitlines()[-1]
    commands = re.search(r'\(.*?\) (?:NOPASSWD: )?(.*)', sudo_line)
    if not commands:
        return set()
    commands = commands.group(1)
    return set(map(lambda x: x.strip(), commands.split(',')))


def is_user_in_passwd(user):
    pass_line = run(f"grep {user} /etc/passwd")
    return pass_line.strip != ''


def is_user_home_removed(user):
    try:
        return not os.path.isdir(f"/home/{user}")
    except:
        return True


def is_user_removed(user):
    return is_user_home_removed(user) and not is_user_in_passwd(user)


def is_root_login_disabled():
    root_line = run("grep ^root /etc/shadow")
    pass_hash = root_line.split(':')[1]
    return '!' in pass_hash


def is_root_ssh_login_disabled():
    permit_root_login = run("grep ^PermitRootLogin /etc/ssh/sshd_config")
    is_yes = "yes" in permit_root_login
    return not is_yes


def is_user_in_admin(user):
    return 'sudo' in run(f"groups {user}")


def get_partition_size_bytes(partition):
    if "/dev/sd" in partition:
        partitions = psutil.disk_partitions(all=True)
        part_info = next((x for x in partitions if x.device == partition), None)
        if part_info is None:
            raise KeyError(f"Partition {partition} is not mounted.")
        mountpoint = part_info.mountpoint
    else:
        mountpoint = partition
    return psutil.disk_usage(mountpoint).total


def pg_run(sql):
    return run(f'sudo -u postgres psql -t -c "{sql}"')


def pg_user_exists(user):
    sql = f"select usename from pg_user where usename='{user}';"
    result = pg_run(sql)
    return result.strip() != ""


def pg_database_exists(db):
    sql = f"select datname from pg_database where datname='{db}';"
    result = pg_run(sql)
    return result.strip() != ""


def pg_database_owner(db, owner):
    sql = f"select pg_get_userbyid(datdba) from pg_database where datname='{db}';"
    result = pg_run(sql)
    return result.strip() == owner


def pg_user_pwhash(user):
    sql = f"select passwd from pg_shadow where usename='{user}';"
    return pg_run(sql).strip()


def is_program_installed(program):
    return shutil.which(program) != ''


def is_one_of_program_installed(*programs):
    return any(map(is_program_installed, programs))


def is_program_uptodate(program):
    if is_program_installed("apt"):
        result = run(f"apt list {program}")
        return not "upgradable" in result
    elif is_program_installed("pacman"):
        result = run(f"pacman -Qu {program}")
        return result == ""
    else:
        raise NotImplementedError("Scoring can only run on systems with apt or pacman")


def is_software_uptodate():
    if is_program_installed("apt"):
        result = run("apt list --upgradable")
    elif is_program_installed("pacman"):
        result = run("pacman -Qu")
    else:
        raise NotImplementedError("Scoring can only run on systems with apt or pacman")
    return result.strip() != ""


def is_service_running(service):
    active_line = run(f"systemctl is-active {service}")
    is_active = "inactive" not in active_line
    return is_active


def is_service_enabled(service):
    enabled_line = run(f"systemctl is-enabled {service}")
    is_enabled = "disabled" not in enabled_line
    return is_enabled


def is_service_removed(service):
    return not is_service_running(service) and not is_service_enabled(service)


def is_ufw_enabled():
    enabled_line = run("ufw status")
    is_enabled = "inactive" not in enabled_line
    return is_enabled


def is_cron_job_set(search_text, frequency = "daily"):
    grep = run(f"grep -Rl '{search_text}' /etc/cron.{frequency}").strip()
    executable = os.access(grep, os.X_OK)
    return grep != "" and executable


def is_daily_update_checked():
    update_package_list = run("grep 'APT::Periodic::Update-Package_Lists' /etc/apt/apt.conf.d/*")
    return '1' in update_package_list


def is_auto_upgrade_enabled():
    unattended_upgrade = run("grep 'APT::Periodic::Unattended-Upgrade' /etc/apt/apt.conf.d/*")
    return '1' in unattended_upgrade


def GiB(bytes):
    return bytes/1024.0**3


def part_info(mountpoint):
    partitions = psutil.disk_partitions()
    return next((x for x in partitions if x.mountpoint == mountpoint), None)


def part_fs(mountpoint):
    info = part_info(mountpoint)
    if info is None:
        return info
    return info.fstype


def part_exists(mountpoint):
    return part_info(mountpoint) is not None


def check_partition_size(mountpoint, size):
    total_size = GiB(psutil.disk_usage(mountpoint).total)
    return math.isclose(size, total_size, rel_tol = 0.1) or (math.isclose(size, total_size, rel_tol = 0.2) and total_size > size)


def test_3G_of_memory():
    memory = GiB(psutil.virtual_memory().total)
    return math.isclose(memory, MEMORY_GB, abs_tol=0.1)


def test_2_processors():
    procs = psutil.cpu_count(logical=False)
    return procs == PROCESSORS


class Task:
    def __init__(self, name, function, arguments=None, expected=True, failmsg=None):
        self.name = name
        self.function = function
        if isinstance(arguments, list) or isinstance(arguments, tuple):
            self.args = list(arguments)
        else:
            self.args = [arguments]
        self.expected = expected
        if failmsg is None:
            self.failmsg = f"Function {self.function.__name__} with arguments {self.args} was not {expected} as expected."
        else:
            self.failmsg = failmsg
        self.print_if_failed = True


    def check(self):
        if len(self.args)==1 and self.args[0] is None:
            value = (self.function() == self.expected)
        else:
            value = (self.function(*self.args) == self.expected)
        return value


    def report(self):
        result = self.check()
        icon = "\N{heavy check mark}" if result else "\N{heavy ballot x}"
        msg = "" if result else self.failmsg
        line = f"[{icon}]  {self.name: <35}   {msg}"
        return result, line


class TestSuite:
    def __init__(self, tasks=None):
        self.tasks = tasks if tasks is not None else []
        self.results = []

    
    def _is_secret(self):
        tasks_hidden = [not x.print_if_failed for x in self.tasks]
        return all(tasks_hidden)


    def report(self):
        results = []
        for task in self.tasks:
            result, report = task.report()
            results.append( (task.print_if_failed, result, report) )
        
        if not self._is_secret() or any([x[1] for x in results]):
            print(self.__doc__)
            for pif, result, report in results:
                if not result and not pif:
                    continue
                print(report)
            successes = [x[1] for x in results].count(True)
            summary_line = f"{successes} Successful out of {len(results)}"
            print(summary_line)
        return [x[1] for x in results]


class TestSystemSpecifications(TestSuite):
    """
    ================================================
    =               VM SPECIFICATION               =
    ================================================
    """
    def __init__(self):

        self.tasks = [
            Task("Memory Size", test_3G_of_memory, failmsg="Not 3G of memory"),
            Task("Processors", test_2_processors, failmsg="Should have 2 processors"),
            Task("Home Partition Exists", part_exists, "/home", failmsg="There is no separate home partition"),
            Task("Root Partition Size", check_partition_size, ["/", ROOT_SIZE_GB], failmsg="Root partition is wrong size"),
            Task("Home Partition Size", check_partition_size, ["/home", HOME_SIZE_GB], failmsg="Home partition is wrong size"),
            Task("Root Partition Filesystem", part_fs, "/", expected="ext4", failmsg="Root partition should be ext4 filesystem"),
            Task("Home Partition Filesystem", part_fs, "/home", expected="ext4", failmsg="Home partition should be ext4 filesystem"),
            Task("Hostname set", gethostname, expected="newguyscomp", failmsg="Hostname should be 'newguyscomp'"),
        ]


class TestUserSetup(TestSuite):
    """
    ================================================
    =              USER CONFIGURATION              =
    ================================================
    """
    def __init__(self):
        self.tasks = [
            Task("Main user has 'admin' in username", main_user_name_ish, ["admin", 1000], failmsg="Main user should be 'admin'-ish"),
            Task("Admin password", check_password, [main_user(1000), "slotHMammoth7!"], failmsg="Admin password should be 'slotHMammoth7!"),
            Task("Newguy User Exists", is_user_in_passwd, "newguy", failmsg="User 'newguy' doesn't exist"),
            Task("Newguy password", check_password, ["newguy", "newguy#5%"], failmsg="Newguy's password should be 'newguy#5%"),
            Task("Newguy's sudo commands", get_user_sudo_perms, "newguy", SUDO_COMMANDS, failmsg="Newguy's sudo commands incorrect"),
        ]


class TestSoftwareInstallations(TestSuite):
    """
    =================================================
    =             SOFTWARE INSTALLATION             = 
    =================================================
    """
    def __init__(self):
        self.tasks = [
            Task("Software is updated", is_software_uptodate,  failmsg="Software is not all upgraded"),
            Task("Yakuake or Guake installed", is_one_of_program_installed, ['yakuake', 'guake'], failmsg=f"Yakuake or Guake should be installed, depending on your desktop"),
        ]
        for prog in ['git', 'vim', 'bpython', 'nodejs', 'code']:
            self.tasks.append(
                Task(f"Program {prog} installed", is_program_installed, prog, failmsg=f"Program {prog} should be installed")
            )
        self.tasks.append(
            Task("Cron job set to scan home", is_cron_job_set, "clamscan", failmsg="Cron job should be set to scan home directory every day")
        )


class TestPostgresSetup(TestSuite):
    """
    =================================================
    =            DATABASE CONFIGURATION             = 
    =================================================
    """
    def __init__(self):
        self.tasks = [
            Task("Postgres service should be running", is_service_running, "postgresql", failmsg="Postgres server not running"),
            Task("Database user newguydb exists", pg_user_exists, "newguydb", failmsg="Postgres should have a user named newguydb"),
            Task("Database user has correct password", pg_user_pwhash, "newguydb", PG_PASSWD_HASH, failmsg="Postgres user newguydb should have password 'postgresRulez!"),
            Task("Database widget_test exists", pg_database_exists, "widget_test", failmsg="Postgres database 'widget_test' should be created"),
            Task("Database owner correct", pg_database_owner, ["widget_test", "newguydb"], failmsg="Postgres database 'widget_test' should be owned by 'newguydb'"),
        ]


class TestBonusPoints(TestSuite):
    """
    =================================================
    =                 BONUS POINTS                  = 
    =================================================
    """
    def __init__(self):
        self.tasks = [
            Task("Firewall Enabled", is_ufw_enabled, failmsg="Firewall not enabled"),
            Task("Check for updates daily", is_daily_update_checked, failmsg="Should automatically check for updates every day"),
            Task("Auto-upgrade", is_auto_upgrade_enabled, failmsg="Should automatically upgrade")
        ]







if __name__ == "__main__":
    if pwd.getpwuid( os.getuid() ).pw_name != 'root':
        print("""Since the scoring software needs to access system configurations,
                it must be run with elevated privileges. Try again with 'sudo'.
            """)
        exit()
    
    #Requirements
    MEMORY_GB = 3
    PROCESSORS = 2
    HOME_SIZE_GB = 5
    ROOT_SIZE_GB = 20
    PG_PASSWD_HASH = 'md51efb824c86d1810d4dc8cec3d54148a2'
    SUDO_COMMANDS = set(['/usr/bin/apt update', '/usr/bin/apt upgrade', '/usr/bin/systemctl start openvpn'])
    NODE_VERSION = 14

    tests = [
        TestSystemSpecifications(),
        TestUserSetup(),
        TestSoftwareInstallations(),
        TestPostgresSetup(),
        TestBonusPoints(),
    ]

    for test in tests:
        test.report()
