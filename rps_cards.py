import os
import sys
import time
import getpass
import msvcrt
import datetime
import subprocess

from smartcard.System import readers
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


PROGRAM_VERSION = "1.0"

PLINK_PATH = r"C:\Program Files\PuTTY\plink.exe"
DATABASE_NAME = "rpsMDBG"
BACKUP_FOLDER = r"C:\rps_backup"

FACTORY_KEY = "FFFFFFFFFFFF"
ACCESS_BITS = "FF078069"
KEY_B = "FFFFFFFFFFFF"

AES_KEY = bytes.fromhex("87032F64D483EE7D5B992F6B73784ADE0ADDAF74D0BDDCCF7B232A8239D53FC3")
AES_IV = bytes.fromhex("080FA8FC18D842A0F7E27745974992E3")

FACTORY_KEY_SLOT = 0
OBJECT_KEY_SLOT = 1
HIDE_WINDOW = 0x08000000


settings = {
    "host": "127.0.0.1",
    "port": 2325,
    "user": "Server",
    "password": "",
    "host_key": "",
    "object_key": "",
    "sector": 1,
    "byte_order": "big",
    "card_fields": {
        "Blocked": 0,
        "ZoneidFC": 1,
        "ClientGroupidFC": 1,
        "TSidFC": 1,
        "TPidFC": 1,
        "ClientTypidFC": 0,
        "SumOnCard": 0,
        "_IsDeleted": 0,
    },
}


def setup_console():
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:
        pass
    for stream in (sys.stdout, sys.stderr, sys.stdin):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def program_folder():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def find_plink():
    if getattr(sys, "frozen", False):
        inside = os.path.join(sys._MEIPASS, "plink.exe")
        if os.path.exists(inside):
            return inside
    if os.path.exists(PLINK_PATH):
        return PLINK_PATH
    return "plink.exe"


def bytes_to_hex(data):
    result = ""
    for one_byte in data:
        result = result + "%02X" % one_byte
    return result.lower()


def hex_to_bytes(text):
    result = []
    for position in range(0, len(text), 2):
        result.append(int(text[position:position + 2], 16))
    return result


def key_is_valid(key):
    if len(key) != 12:
        return False
    for letter in key:
        if letter not in "0123456789abcdef":
            return False
    return True


def run_ssh(remote_command, input_text=None, timeout=120):
    full_command = [
        find_plink(), "-batch",
        "-hostkey", settings["host_key"],
        "-P", str(settings["port"]),
        "-pw", settings["password"],
        settings["user"] + "@" + settings["host"],
        remote_command,
    ]
    return subprocess.run(full_command, input=input_text, capture_output=True,
                          text=True, timeout=timeout, creationflags=HIDE_WINDOW,
                          errors="replace")


def find_host_key():
    probe_command = [
        find_plink(), "-v", "-batch",
        "-P", str(settings["port"]),
        "-pw", settings["password"],
        settings["user"] + "@" + settings["host"],
        "exit",
    ]
    try:
        result = subprocess.run(probe_command, capture_output=True,
                                text=True, timeout=15, creationflags=HIDE_WINDOW,
                                errors="replace")
        output = (result.stdout or "") + (result.stderr or "")
    except subprocess.TimeoutExpired as e:
        output = (e.stdout or "") + (e.stderr or "")
        place = output.find("SHA256:")
        if place >= 0:
            return output[place:].split()[0], ""
        return "", "сервер не отвечает (тайм-аут 15с)\n--- Подробности ---\n" + output.strip() + "\n-------------------------------"
    
    place = output.find("SHA256:")
    if place >= 0:
        return output[place:].split()[0], ""
    
    details = "\n--- Подробности подключения ---\n" + output.strip() + "\n-------------------------------"
    lowered = output.lower()
    if "closed" in lowered:
        return "", "сервер закрыл соединение" + details
    if "refused" in lowered:
        return "", "порт закрыт, проброс не поднят" + details
    if "denied" in lowered or "password" in lowered:
        return "", "логин или пароль не подошли" + details
    return "", "нет связи" + details


def run_sql(query, timeout=180):
    remote_command = ('sqlcmd -S localhost -d ' + DATABASE_NAME +
                      ' -E -b -h-1 -W -s"|" -Q "' + query + '"')
    try:
        result = run_ssh(remote_command, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, []
    output = (result.stdout or "") + (result.stderr or "")
    lines = []
    for line in output.splitlines():
        line = line.strip()
        if line != "":
            lines.append(line)
    return result.returncode == 0, lines


def database_is_available():
    ok, lines = run_sql("SELECT 1")
    if not ok:
        return False
    for line in lines:
        if line == "1":
            return True
    return False


def read_setting(name):
    ok, lines = run_sql("SET NOCOUNT ON; SELECT Value FROM Setting WHERE Name='" + name + "'")
    if ok and len(lines) > 0:
        return lines[0]
    return ""


def read_object_key_from_database():
    encrypted = read_setting("CardKey")
    if encrypted == "":
        return ""
    try:
        raw = bytes.fromhex(encrypted)
        decrypted = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(raw)
        return unpad(decrypted, 16).decode("ascii")
    except Exception:
        return ""


def count_cards():
    ok, lines = run_sql("SET NOCOUNT ON; SELECT COUNT(*) FROM Cards")
    if ok and len(lines) > 0 and lines[0].isdigit():
        return int(lines[0])
    return 0


def detect_settings_from_database():
    ok, lines = run_sql(
        "SET NOCOUNT ON; "
        "SELECT Value FROM DeviceRackSettings WHERE Name='SectorNumber' AND Value IS NOT NULL "
        "UNION ALL SELECT Value FROM DeviceCMSettings WHERE Name='SectorNumber' AND Value IS NOT NULL")
    if ok:
        for line in lines:
            if line.isdigit():
                settings["sector"] = int(line)
                break

    if read_setting("CardidReverseDec").strip() == "1":
        settings["byte_order"] = "little"
    else:
        settings["byte_order"] = "big"

    ok, lines = run_sql(
        "SET NOCOUNT ON; SELECT TOP 1 "
        "ISNULL(CAST(ZoneidFC AS varchar),'x')+'|'+"
        "ISNULL(CAST(ClientGroupidFC AS varchar),'x')+'|'+"
        "ISNULL(CAST(TSidFC AS varchar),'x')+'|'+"
        "ISNULL(CAST(TPidFC AS varchar),'x')+'|'+"
        "ISNULL(CAST(ClientTypidFC AS varchar),'x') "
        "FROM Cards WHERE Blocked=0 AND ISNULL(_IsDeleted,0)=0 "
        "GROUP BY ZoneidFC,ClientGroupidFC,TSidFC,TPidFC,ClientTypidFC "
        "ORDER BY COUNT(*) DESC")
    if ok and len(lines) > 0:
        parts = lines[0].split("|")
        names = ["ZoneidFC", "ClientGroupidFC", "TSidFC", "TPidFC", "ClientTypidFC"]
        new_fields = {"Blocked": 0, "_IsDeleted": 0, "SumOnCard": 0}
        for position in range(len(names)):
            value = parts[position]
            if value.lstrip("-").isdigit():
                new_fields[names[position]] = int(value)
        settings["card_fields"] = new_fields


def backup_database():
    run_sql("EXEC master.dbo.xp_create_subdir N'" + BACKUP_FOLDER + "'")
    query = ("SET NOCOUNT ON; DECLARE @path nvarchar(400)=N'" + BACKUP_FOLDER + "\\" +
             DATABASE_NAME + "_'+FORMAT(GETDATE(),'yyyyMMdd_HHmmss')+N'.bak'; "
             "BACKUP DATABASE " + DATABASE_NAME + " TO DISK=@path WITH INIT; SELECT @path")
    ok, lines = run_sql(query, timeout=180)
    return ok


def insert_one_batch(numbers):
    fields = settings["card_fields"]
    column_names = "CardId"
    field_values = ""
    for name in fields:
        column_names = column_names + "," + name
        if field_values != "":
            field_values = field_values + ","
        field_values = field_values + str(fields[name])
    column_names = column_names + ",DateSaveCard"

    rows_text = ""
    for number in numbers:
        if rows_text != "":
            rows_text = rows_text + ","
        rows_text = rows_text + "(" + str(number) + ")"

    query = ("SET NOCOUNT ON; SET XACT_ABORT ON; "
             "CREATE TABLE #new(CardId bigint PRIMARY KEY); "
             "INSERT INTO #new(CardId) VALUES " + rows_text + "; "
             "DECLARE @total int=(SELECT COUNT(*) FROM #new); "
             "DECLARE @existing int=(SELECT COUNT(*) FROM #new t JOIN Cards c ON c.CardId=t.CardId); "
             "BEGIN TRAN; "
             "INSERT INTO Cards (" + column_names + ") "
             "SELECT t.CardId," + field_values + ",GETDATE() FROM #new t "
             "WHERE NOT EXISTS(SELECT 1 FROM Cards c WHERE c.CardId=t.CardId); "
             "DECLARE @added int=@@ROWCOUNT; "
             "IF @added=@total-@existing BEGIN COMMIT END ELSE BEGIN ROLLBACK END; "
             "SELECT @total,@existing,@added,CASE WHEN @added=@total-@existing THEN 1 ELSE 0 END; "
             "DROP TABLE #new;")

    ok, lines = run_sql(query, timeout=300)
    for line in lines:
        parts = line.split("|")
        if len(parts) == 4 and parts[0].strip().lstrip("-").isdigit():
            added = int(parts[2].strip())
            existing = int(parts[1].strip())
            committed = parts[3].strip()
            if ok and committed == "1":
                return True, added, existing
    return False, 0, 0


def add_cards_to_database(numbers):
    unique_numbers = sorted(set(int(x) for x in numbers))
    if len(unique_numbers) == 0:
        return True, 0, 0
    total_added = 0
    total_existing = 0
    position = 0
    while position < len(unique_numbers):
        part = unique_numbers[position:position + 300]
        position = position + 300
        success = False
        added = 0
        existing = 0
        attempt = 0
        while attempt < 5:
            success, added, existing = insert_one_batch(part)
            if success:
                break
            attempt = attempt + 1
            time.sleep(3)
        if not success:
            return False, total_added, total_existing
        total_added = total_added + added
        total_existing = total_existing + existing
    return True, total_added, total_existing


class CardReader:
    def __init__(self):
        found = []
        for reader in readers():
            name = str(reader).upper()
            if "CL" in name or "CONTACTLESS" in name:
                found.append(reader)
        if len(found) == 0:
            raise Exception("не вижу бесконтактный считыватель (нужен драйвер omnikey)")
        self.reader = found[0]
        self.connection = None
        self.keys_loaded = False

    def connect(self):
        self.connection = self.reader.createConnection()
        self.connection.connect()

    def reconnect(self):
        try:
            self.connection.reconnect()
        except Exception:
            self.connect()

    def load_key(self, key, slot):
        command = [0xFF, 0x82, 0x20, slot, 0x06] + key
        data, status1, status2 = self.connection.transmit(command)
        if status1 != 0x90 or status2 != 0x00:
            raise Exception("считыватель не принял ключ")

    def load_keys(self):
        if self.keys_loaded:
            return
        self.load_key(hex_to_bytes(FACTORY_KEY), FACTORY_KEY_SLOT)
        self.load_key(hex_to_bytes(settings["object_key"]), OBJECT_KEY_SLOT)
        self.keys_loaded = True

    def authenticate(self, block, slot):
        command = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, 0x60, slot]
        data, status1, status2 = self.connection.transmit(command)
        return status1 == 0x90 and status2 == 0x00

    def write_block(self, block, data):
        command = [0xFF, 0xD6, 0x00, block, 0x10] + list(data)
        result, status1, status2 = self.connection.transmit(command)
        if status1 != 0x90 or status2 != 0x00:
            raise Exception("не пишется")

    def read_uid(self):
        try:
            self.connect()
            data, status1, status2 = self.connection.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
            if status1 == 0x90 and status2 == 0x00:
                return data
        except Exception:
            return None
        return None

    def card_number_from_uid(self, uid):
        return int.from_bytes(bytes(uid), settings["byte_order"])

    def card_has_object_key(self):
        self.load_keys()
        self.reconnect()
        return self.authenticate(settings["sector"] * 4, OBJECT_KEY_SLOT)

    def card_is_blank(self):
        self.load_keys()
        self.reconnect()
        return self.authenticate(settings["sector"] * 4, FACTORY_KEY_SLOT)

    def write_object_key(self):
        first_block = settings["sector"] * 4
        trailer_block = first_block + 3
        self.load_keys()
        self.reconnect()
        if not self.authenticate(trailer_block, FACTORY_KEY_SLOT):
            raise Exception("не болванка")
        trailer = hex_to_bytes(settings["object_key"]) + hex_to_bytes(ACCESS_BITS) + hex_to_bytes(KEY_B)
        self.write_block(trailer_block, trailer)
        self.reconnect()
        if not self.authenticate(first_block, OBJECT_KEY_SLOT):
            raise Exception("записал, но ключ не читается")


def write_to_log(card_number, card_uid):
    today = datetime.date.today().isoformat()
    path = os.path.join(program_folder(), "issued_" + today + ".csv")
    is_new = not os.path.exists(path)
    try:
        with open(path, "a", encoding="utf-8") as log_file:
            if is_new:
                log_file.write("время,номер,uid,ключ\n")
            now = datetime.datetime.now().strftime("%H:%M:%S")
            log_file.write(now + "," + str(card_number) + "," + card_uid + "," +
                           settings["object_key"] + "\n")
    except Exception:
        pass


def load_saved_settings():
    path = os.path.join(program_folder(), "settings.txt")
    host = "127.0.0.1"
    port = "2325"
    user = "Server"
    try:
        with open(path, encoding="utf-8") as settings_file:
            for line in settings_file:
                line = line.strip()
                if line.startswith("host="):
                    host = line[5:]
                if line.startswith("port="):
                    port = line[5:]
                if line.startswith("user="):
                    user = line[5:]
    except Exception:
        pass
    return host, port, user


def save_settings():
    path = os.path.join(program_folder(), "settings.txt")
    try:
        with open(path, "w", encoding="utf-8") as settings_file:
            settings_file.write("host=" + settings["host"] + "\n")
            settings_file.write("port=" + str(settings["port"]) + "\n")
            settings_file.write("user=" + settings["user"] + "\n")
    except Exception:
        pass


def ask_connection_settings():
    saved_host, saved_port, saved_user = load_saved_settings()

    host = input("адрес сервера [" + saved_host + "]: ").strip()
    if host == "":
        host = saved_host
    settings["host"] = host

    port = input("порт [" + saved_port + "]: ").strip()
    if port == "":
        port = saved_port
    while not port.isdigit():
        port = input("порт цифрами: ").strip()
        if port == "":
            port = saved_port
    settings["port"] = int(port)

    user = input("логин [" + saved_user + "]: ").strip()
    if user == "":
        user = saved_user
    settings["user"] = user

    password = os.environ.get("RPS_PASS", "")
    if password != "":
        print("пароль: (из переменной RPS_PASS)")
    else:
        password = getpass.getpass("пароль: ")
    settings["password"] = password


def connect_to_server():
    print("")
    print("связь...", end=" ", flush=True)

    host_key, error_text = find_host_key()
    if host_key == "":
        print(error_text)
        return False
    settings["host_key"] = host_key

    if not database_is_available():
        print("сервер есть, база не отвечает")
        return False
    print("ок")

    key_from_database = read_object_key_from_database()
    
    if key_is_valid(key_from_database):
        print("ключ в базе: " + key_from_database)
        answer = input("нажмите enter чтобы использовать его, или введите другой вручную (12 знаков): ").strip().lower()
    else:
        print("не смог достать ключ объекта из базы")
        answer = input("введите ключ вручную (12 знаков): ").strip().lower()
    
    if answer != "":
        if not key_is_valid(answer):
            print("ключ должен быть 12 знаков (0-9, a-f)")
            return False
        settings["object_key"] = answer
    else:
        if not key_is_valid(key_from_database):
            print("ключ не задан")
            return False
        settings["object_key"] = key_from_database

    detect_settings_from_database()
    print("ключ объекта: " + settings["object_key"])
    print("сектор " + str(settings["sector"]) + ", карт в базе " + str(count_cards()))
    return True


def save_cards_to_database(cards_in_list, backup_done):
    if len(cards_in_list) == 0:
        print("нечего писать")
        return backup_done

    if not backup_done:
        print("бэкап...", end=" ", flush=True)
        if backup_database():
            print("ок")
        else:
            print("не вышло - пишу без бэкапа")
        backup_done = True

    print("пишу " + str(len(cards_in_list)) + "...", end=" ", flush=True)
    try:
        success, added, existing = add_cards_to_database(cards_in_list.keys())
    except Exception as error_text:
        print("ошибка:", error_text)
        return backup_done

    if success:
        message = "добавлено " + str(added)
        if existing > 0:
            message = message + ", уже были " + str(existing)
        print(message)
        cards_in_list.clear()
    else:
        print("не записалось, добавлено " + str(added) + ". карты остались в списке")
    return backup_done


def code_cards(reader):
    cards_in_list = {}
    backup_done = False
    print("")
    print("клади карты. c - записать в базу, q - выход")
    print("")

    last_card = None
    while True:
        if msvcrt.kbhit():
            pressed = msvcrt.getch().decode(errors="ignore").lower()
            if pressed == "q":
                if len(cards_in_list) > 0:
                    print("")
                    print("в списке " + str(len(cards_in_list)) + " карт. записать? (y/n) ", end="", flush=True)
                    answer = msvcrt.getch().decode(errors="ignore").lower()
                    print("")
                    if answer == "y":
                        save_cards_to_database(cards_in_list, backup_done)
                    else:
                        print("не записал")
                return
            if pressed == "c":
                print("")
                backup_done = save_cards_to_database(cards_in_list, backup_done)
                print("")
            continue

        uid = reader.read_uid()
        if uid is None:
            last_card = None
            time.sleep(0.15)
            continue

        card_uid = bytes_to_hex(uid)
        if card_uid == last_card:
            continue
        last_card = card_uid

        card_number = reader.card_number_from_uid(uid)
        if card_number in cards_in_list:
            print("  " + card_uid + "  " + str(card_number) + "  уже в списке")
            continue

        try:
            if reader.card_has_object_key():
                status = "была готова"
            elif reader.card_is_blank():
                reader.write_object_key()
                status = "ok"
            else:
                print("  " + card_uid + "  " + str(card_number) + "  чужой ключ, пропуск")
                continue
        except Exception as error_text:
            print("  " + card_uid + "  " + str(card_number) + "  " + str(error_text))
            continue

        cards_in_list[card_number] = card_uid
        write_to_log(card_number, card_uid)
        print("  " + card_uid + "  " + str(card_number) + "  " + status + "  [" + str(len(cards_in_list)) + "]")


def read_numbers_from_file(path):
    numbers = []
    try:
        with open(path, encoding="utf-8", errors="replace") as data_file:
            for line in data_file:
                line = line.strip()
                if line == "":
                    continue
                if "," in line:
                    candidate = line.split(",")[1].strip()
                else:
                    candidate = line
                if candidate.isdigit():
                    numbers.append(int(candidate))
    except Exception as error_text:
        print("не читается файл:", error_text)
    return sorted(set(numbers))


def load_file_into_database(path):
    numbers = read_numbers_from_file(path)
    if len(numbers) == 0:
        print("в файле нет номеров карт")
        return
    print("из файла: " + str(len(numbers)) + " карт")

    print("")
    print("связь...", end=" ", flush=True)
    host_key, error_text = find_host_key()
    if host_key == "":
        print(error_text)
        return
    settings["host_key"] = host_key
    if not database_is_available():
        print("сервер есть, база не отвечает")
        return
    print("ок")

    detect_settings_from_database()
    save_settings()

    print("бэкап...", end=" ", flush=True)
    if backup_database():
        print("ок")
    else:
        print("не вышло - пишу без бэкапа")

    print("пишу " + str(len(numbers)) + "...")
    try:
        success, added, existing = add_cards_to_database(numbers)
    except Exception as error_text:
        print("ошибка:", error_text)
        return

    if success:
        message = "готово: добавлено " + str(added)
        if existing > 0:
            message = message + ", уже были " + str(existing)
        print(message)
    else:
        print("не всё записалось, добавлено " + str(added) + " - можно запустить файл ещё раз")


def main():
    setup_console()
    print("rps карты " + PROGRAM_VERSION)
    print("")

    dropped_files = []
    for argument in sys.argv[1:]:
        if os.path.exists(argument):
            dropped_files.append(argument)

    try:
        ask_connection_settings()
    except (EOFError, KeyboardInterrupt):
        return

    if len(dropped_files) > 0:
        load_file_into_database(dropped_files[0])
        print("")
        print("пока")
        return

    if not connect_to_server():
        return
    save_settings()

    try:
        reader = CardReader()
    except Exception as error_text:
        print(error_text)
        return

    try:
        code_cards(reader)
    except KeyboardInterrupt:
        pass
    print("")
    print("пока")


if __name__ == "__main__":
    try:
        main()
    except Exception as error_text:
        print("")
        print("ошибка:", error_text)
    if sys.stdin is not None and sys.stdin.isatty():
        input("нажмите enter чтобы закрыть")
