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

try:
    from dispenser import CardDispenser
except ImportError:
    CardDispenser = None

try:
    from mt625 import MT625Reader
except ImportError:
    MT625Reader = None

PROGRAM_VERSION = "2.0"

PLINK_PATH = r"C:\Program Files\PuTTY\plink.exe"
DATABASE_NAME = "rpsMDBG"
BACKUP_FOLDER = r"C:\rps_backup"

FACTORY_KEY = "ffffffffffff"
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
        self.sector = settings.get("sector", 1)
        self.byte_order = settings.get("byte_order", "big")
        self.factory_key = FACTORY_KEY
        self.object_key = settings.get("object_key", "")

    def connect(self):
        self.connection = self.reader.createConnection()
        self.connection.connect()

    def close(self):
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            self.connection = None

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
        fk = self.factory_key or FACTORY_KEY
        ok = self.object_key or settings["object_key"]
        self.load_key(hex_to_bytes(fk), FACTORY_KEY_SLOT)
        self.load_key(hex_to_bytes(ok), OBJECT_KEY_SLOT)
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
        return int.from_bytes(bytes(uid), self.byte_order)

    def card_has_object_key(self):
        self.load_keys()
        self.reconnect()
        return self.authenticate(self.sector * 4, OBJECT_KEY_SLOT)

    def card_is_blank(self):
        self.load_keys()
        self.reconnect()
        return self.authenticate(self.sector * 4, FACTORY_KEY_SLOT)

    def write_object_key(self):
        first_block = self.sector * 4
        trailer_block = first_block + 3
        self.load_keys()
        self.reconnect()
        if not self.authenticate(trailer_block, FACTORY_KEY_SLOT):
            raise Exception("не болванка")
        ok = self.object_key or settings["object_key"]
        trailer = hex_to_bytes(ok) + hex_to_bytes(ACCESS_BITS) + hex_to_bytes(KEY_B)
        self.write_block(trailer_block, trailer)
        self.reconnect()
        if not self.authenticate(first_block, OBJECT_KEY_SLOT):
            raise Exception("записал, но ключ не читается")


OmnikeyReader = CardReader


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


def normalize_port_name(port_input):
    if port_input is None:
        return ""
    p = str(port_input).strip()
    if not p:
        return ""
    if p.isdigit():
        return f"COM{p}"
    if p.upper().startswith("COM"):
        return p.upper()
    return p


def get_available_com_ports():
    try:
        import serial.tools.list_ports
        return [p.device for p in serial.tools.list_ports.comports()]
    except Exception:
        return []


def load_saved_settings():
    path = os.path.join(program_folder(), "settings.txt")
    cfg = {
        "host": "127.0.0.1",
        "port": "2325",
        "user": "Server",
        "dispenser_port": "",
        "mt625_port": "",
        "factory_key": "ffffffffffff",
        "mode": "1",
        "reader_type": "1",
        "batch_size": "10",
    }
    try:
        with open(path, encoding="utf-8") as settings_file:
            for line in settings_file:
                line = line.strip()
                if line.startswith("host="): cfg["host"] = line[5:]
                elif line.startswith("port="): cfg["port"] = line[5:]
                elif line.startswith("user="): cfg["user"] = line[5:]
                elif line.startswith("dispenser_port="): cfg["dispenser_port"] = normalize_port_name(line[15:])
                elif line.startswith("mt625_port="): cfg["mt625_port"] = normalize_port_name(line[11:])
                elif line.startswith("factory_key="): cfg["factory_key"] = line[12:]
                elif line.startswith("mode="): cfg["mode"] = line[5:]
                elif line.startswith("reader_type="): cfg["reader_type"] = line[12:]
                elif line.startswith("batch_size="): cfg["batch_size"] = line[11:]
    except Exception:
        pass
    return cfg


def save_settings():
    path = os.path.join(program_folder(), "settings.txt")
    try:
        with open(path, "w", encoding="utf-8") as settings_file:
            settings_file.write("host=" + str(settings.get("host", "127.0.0.1")) + "\n")
            settings_file.write("port=" + str(settings.get("port", 2325)) + "\n")
            settings_file.write("user=" + str(settings.get("user", "Server")) + "\n")
            settings_file.write("factory_key=" + FACTORY_KEY + "\n")
            settings_file.write("mode=" + str(settings.get("mode", "1")) + "\n")
            settings_file.write("reader_type=" + str(settings.get("reader_type", "1")) + "\n")
            settings_file.write("dispenser_port=" + normalize_port_name(settings.get("dispenser_port", "")) + "\n")
            settings_file.write("mt625_port=" + normalize_port_name(settings.get("mt625_port", "")) + "\n")
            settings_file.write("batch_size=" + str(settings.get("batch_size", 10)) + "\n")
    except Exception:
        pass


def ask_connection_settings():
    global FACTORY_KEY
    saved = load_saved_settings()
    settings["saved_config"] = saved

    FACTORY_KEY = saved["factory_key"]
    fk_input = input("ключ чистых карт [" + FACTORY_KEY + "]: ").strip().lower()
    if fk_input != "":
        if key_is_valid(fk_input):
            FACTORY_KEY = fk_input
        else:
            print("ключ должен быть 12 знаков (0-9, a-f). использую " + FACTORY_KEY)

    host = input("адрес сервера [" + saved["host"] + "]: ").strip()
    if host == "":
        host = saved["host"]
    settings["host"] = host

    port = input("порт [" + str(saved["port"]) + "]: ").strip()
    if port == "":
        port = str(saved["port"])
    while not port.isdigit():
        port = input("порт цифрами: ").strip()
        if port == "":
            port = str(saved["port"])
    settings["port"] = int(port)

    user = input("логин [" + saved["user"] + "]: ").strip()
    if user == "":
        user = saved["user"]
    settings["user"] = user

    password = os.environ.get("RPS_PASS", "")
    if password != "":
        print("пароль: (из переменной RPS_PASS)")
    else:
        password = getpass.getpass("пароль: ")
    settings["password"] = password

    batch_s = str(saved.get("batch_size", "10"))
    settings["batch_size"] = int(batch_s) if batch_s.isdigit() else 10


def ask_hardware_mode():
    saved = settings.get("saved_config", {})
    saved_mode = saved.get("mode", "1")
    if saved_mode not in ("1", "2"):
        saved_mode = "1"

    print("")
    print("Режим работы:")
    print("  1 - Ручной режим")
    print("  2 - Автоматический режим (диспенсер + MT625)")
    mode = input("выберите режим [" + saved_mode + "]: ").strip()
    if mode not in ("1", "2"):
        mode = saved_mode
    settings["mode"] = mode

    ports = get_available_com_ports()
    ports_info = (" (в системе есть: " + ", ".join(ports) + ")") if ports else ""

    if mode == "1":
        saved_reader = saved.get("reader_type", "1")
        if saved_reader not in ("1", "2"):
            saved_reader = "1"

        print("")
        print("Считыватель:")
        print("  1 - Omnikey (USB PC/SC)")
        print("  2 - MT625 (COM-порт)")
        reader_type = input("выберите считыватель [" + saved_reader + "]: ").strip()
        if reader_type not in ("1", "2"):
            reader_type = saved_reader
        settings["reader_type"] = reader_type

        if reader_type == "2":
            saved_mt625 = normalize_port_name(saved.get("mt625_port", "COM4")) or "COM4"
            print("COM-порт MT625" + ports_info)
            mt625_port = input("порт (например 4 или COM4) [" + saved_mt625 + "]: ").strip()
            if mt625_port == "":
                mt625_port = saved_mt625
            settings["mt625_port"] = normalize_port_name(mt625_port)
    else:
        saved_disp = normalize_port_name(saved.get("dispenser_port", "COM3")) or "COM3"
        saved_mt625 = normalize_port_name(saved.get("mt625_port", "COM4")) or "COM4"

        print("")
        print("Настройка COM-портов" + ports_info + ":")
        disp_port = input("COM порт диспенсера (например 3 или COM3) [" + saved_disp + "]: ").strip()
        if disp_port == "":
            disp_port = saved_disp
        settings["dispenser_port"] = normalize_port_name(disp_port)

        mt625_port = input("COM порт MT625 (например 4 или COM4) [" + saved_mt625 + "]: ").strip()
        if mt625_port == "":
            mt625_port = saved_mt625
        settings["mt625_port"] = normalize_port_name(mt625_port)

    save_settings()



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


def code_cards(reader, dispenser, batch_size=10):
    cards_in_list = {}
    backup_done = False

    print("")
    if dispenser:
        print(f"Автоматический режим: диспенсер + MT625 (запись в БД пачками по {batch_size}). q - выход")
    else:
        reader_name = "MT625" if (MT625Reader and isinstance(reader, MT625Reader)) else "Omnikey"
        print(f"Ручной режим [{reader_name}]: клади карты (запись в БД пачками по {batch_size}). q - выход")
    print("")

    last_card = None
    last_dispense_time = 0
    card_first_seen_time = 0
    status_fail_count = 0

    try:
        while True:
            if msvcrt.kbhit():
                pressed = msvcrt.getch().decode(errors="ignore").lower()
                if pressed == "q":
                    break
                continue

            if dispenser:
                status = dispenser.check_status()
                if status is None:
                    status_fail_count += 1
                    if status_fail_count % 8 == 1:
                        print(f"\r[диспенсер на {dispenser.port} не отвечает, проверяю связь...] ", end="", flush=True)
                    time.sleep(0.5)
                    continue
                else:
                    if status_fail_count > 0:
                        print("\r" + " " * 65 + "\r", end="", flush=True)
                        status_fail_count = 0

                # 1. Авария замятия в тракте (Bit 1 / 0x02 CardError)
                if dispenser.is_device_error(status):
                    print("\n[!] Диспенсер сообщает о замятии карты (код 0x02)! Проверьте карты и тракт. (q - выход)")
                    for _ in range(30):
                        if msvcrt.kbhit(): break
                        time.sleep(0.1)
                    continue

                # 2. Магазин карт пуст (Bit 7 / 0x80 CardEmpty)
                if dispenser.is_stack_empty(status):
                    if len(cards_in_list) > 0:
                        print(f"\nМагазин пуст. Сохраняю оставшиеся карты ({len(cards_in_list)})...", end=" ", flush=True)
                        backup_done = save_cards_to_database(cards_in_list, backup_done)
                    print("\r[Магазин карт пуст. Доложите карты в лоток. q - выход] ", end="", flush=True)
                    time.sleep(1.0)
                    continue

                # 3. Если предыдущая карта еще в выходной щели (bezel) — ждем, пока освободится
                if dispenser.is_card_in_bezel(status):
                    time.sleep(0.1)
                    continue

                # 4. Проверяем наличие карты точно под ридером MT625 (Bit 5 / 0x20 CardPreSendPos)
                card_at_read_pos = dispenser.is_card_at_reader(status)

                if not card_at_read_pos:
                    # Подаем ровно одну карту из магазина под ридер (0x31 0x30 SendFromBoxToReadPosition)
                    print("  подача карты под ридер...", end=" ", flush=True)
                    dispense_ok = dispenser.dispense_to_read_pos()
                    if not dispense_ok:
                        print("не удалось подать (проверьте карты / грузик)")
                        time.sleep(1.5)
                        continue
                    print("ок")
                    time.sleep(0.2)

                # 5. Карта под ридером: опрашиваем чип считывателем MT625 (до 3 секунд)
                uid = None
                t_poll_start = time.time()
                while time.time() - t_poll_start < 3.0:
                    uid = reader.read_uid()
                    if uid is not None:
                        break
                    time.sleep(0.08)

                if uid is None:
                    print("  [!] Карта под ридером, но чип не отвечает (брак) -> сброс в отказник")
                    dispenser.retain_card()
                    time.sleep(0.5)
                    last_card = None
                    continue

            else:
                uid = reader.read_uid()
                if uid is None:
                    last_card = None
                    time.sleep(0.15)
                    continue

            card_uid = bytes_to_hex(uid)
            if card_uid == last_card:
                time.sleep(0.15)
                continue
            last_card = card_uid

            card_number = reader.card_number_from_uid(uid)
            if card_number in cards_in_list:
                print(f"  {card_uid}  {card_number}  уже в текущей пачке")
                if dispenser:
                    dispenser.eject_card()
                    last_card = None
                continue

            write_success = False
            try:
                if reader.card_has_object_key():
                    status_msg = "была готова"
                    write_success = True
                elif reader.card_is_blank():
                    reader.write_object_key()
                    status_msg = "ok"
                    write_success = True
                else:
                    status_msg = "чужой ключ, брак"
            except Exception as error_text:
                status_msg = f"ошибка: {error_text}"

            print(f"  {card_uid}  {card_number}  {status_msg}")

            if write_success:
                cards_in_list[card_number] = card_uid
                write_to_log(card_number, card_uid)

                if dispenser:
                    dispenser.eject_card()
                    last_card = None

                if len(cards_in_list) >= batch_size:
                    print(f"  --> сохранение пачки ({len(cards_in_list)} карт)...", end=" ", flush=True)
                    backup_done = save_cards_to_database(cards_in_list, backup_done)
            else:
                if dispenser:
                    dispenser.retain_card()
                    last_card = None

    finally:
        if len(cards_in_list) > 0:
            print(f"\nсохранение оставшихся карт ({len(cards_in_list)})...", end=" ", flush=True)
            backup_done = save_cards_to_database(cards_in_list, backup_done)
        if dispenser:
            dispenser.close()
        if reader:
            reader.close()


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

    try:
        ask_hardware_mode()
    except (EOFError, KeyboardInterrupt):
        return

    mode = settings.get("mode", "1")
    dispenser = None
    reader = None

    if mode == "1":
        # Ручной режим
        reader_type = settings.get("reader_type", "1")
        if reader_type == "2":
            # MT625
            if MT625Reader is None:
                print("mt625.py не найден")
                return
            port = normalize_port_name(settings.get("mt625_port", "COM4"))
            print("подключение к MT625 (" + port + ")...", end=" ", flush=True)
            reader = MT625Reader(port)
            if not reader.connect():
                return
            print("ок")
        else:
            # Omnikey
            try:
                reader = CardReader()
            except Exception as error_text:
                print(error_text)
                return
    else:
        # Автоматический режим: диспенсер + MT625
        if CardDispenser is None:
            print("dispenser.py не найден")
            return
        disp_port = normalize_port_name(settings.get("dispenser_port", "COM3"))
        print("подключение к диспенсеру (" + disp_port + ")...", end=" ", flush=True)
        dispenser = CardDispenser(disp_port)
        if not dispenser.connect():
            return
        status = dispenser.check_status()
        if status is not None:
            details = []
            if dispenser.is_stack_empty(status): details.append("стек пуст")
            elif dispenser.is_card_shortage(status): details.append("мало карт")
            if dispenser.is_card_at_reader(status): details.append("карта под ридером")
            if dispenser.is_card_in_bezel(status): details.append("карта в щели")
            if dispenser.is_device_error(status): details.append("замятие")
            info = (", ".join(details)) if details else "норма"
            print("ок (скорость %d бод, статус: 0x%02X [%s])" % (dispenser.baudrate, status, info))
        else:
            print("ВНИМАНИЕ: диспенсер не ответил на опрос статуса на порту " + disp_port)

        if MT625Reader is None:
            print("mt625.py не найден")
            dispenser.close()
            return
        mt625_port = normalize_port_name(settings.get("mt625_port", "COM4"))
        print("подключение к MT625 (" + mt625_port + ")...", end=" ", flush=True)
        reader = MT625Reader(mt625_port)
        if not reader.connect():
            dispenser.close()
            return
        print("ок")

    reader.sector = settings["sector"]
    reader.byte_order = settings["byte_order"]
    reader.factory_key = FACTORY_KEY
    reader.object_key = settings["object_key"]

    try:
        batch_size = settings.get("batch_size", 10)
        code_cards(reader, dispenser, batch_size=batch_size)
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
