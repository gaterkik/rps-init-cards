import time
import serial


def hex_to_bytes(text):
    text = text.strip().lower()
    return [int(text[i:i + 2], 16) for i in range(0, len(text), 2)]


def bytes_to_hex(data):
    return "".join(f"{b:02x}" for b in data)


def normalize_port(port):
    if port is None:
        return ""
    p = str(port).strip()
    if not p:
        return ""
    if p.isdigit():
        return f"COM{p}"
    if p.upper().startswith("COM"):
        return p.upper()
    return p


class MT625Reader:
    """
    Драйвер считывателя бесконтактных карт MT625 (Mifare Classic 1K / 4K).
    Протокол RS-232 / UART: 115200 8N1.
    """

    def __init__(self, port, baudrate=115200, timeout=0.3):
        self.port = normalize_port(port)
        self.baudrate = baudrate
        self.timeout = timeout
        self.ser = None

        # Конфигурационные параметры (задаются из настроек системы)
        self.sector = 1
        self.byte_order = "big"
        self.factory_key = "ffffffffffff"
        self.object_key = ""

    def connect(self):
        try:
            if self.ser and self.ser.is_open:
                self.ser.close()
            self.ser = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=self.timeout,
                write_timeout=self.timeout,
            )
            self.ser.reset_input_buffer()
            self.ser.reset_output_buffer()
            return True
        except Exception as e:
            print(f"Ошибка подключения к MT625 ({self.port}): {e}")
            return False

    def close(self):
        if self.ser and self.ser.is_open:
            try:
                self.ser.close()
            except Exception:
                pass

    def reopen(self):
        self.close()
        time.sleep(0.1)
        return self.connect()

    @staticmethod
    def _calc_bcc(data):
        bcc = 0
        for b in data:
            bcc ^= b
        return bcc

    def _make_frame(self, cmd_group, opcode, payload=b""):
        length = 2 + len(payload)
        len_h = (length >> 8) & 0xFF
        len_l = length & 0xFF
        frame = bytearray([0x02, len_h, len_l, cmd_group, opcode])
        frame.extend(payload)
        frame.append(0x03)
        frame.append(self._calc_bcc(frame))
        return bytes(frame)

    def _send_command(self, cmd_group, opcode, payload=b"", timeout=None):
        if not self.ser or not self.ser.is_open:
            return None
        frame = self._make_frame(cmd_group, opcode, payload)
        tout = timeout if timeout is not None else self.timeout

        try:
            self.ser.reset_input_buffer()
            self.ser.reset_output_buffer()
            self.ser.write(frame)
        except Exception:
            return None

        start_time = time.time()
        stx = b""
        while time.time() - start_time < tout:
            b = self.ser.read(1)
            if not b:
                continue
            if b[0] == 0x02:
                stx = b
                break
            if b[0] == 0x03:
                # Специальный NAK [0x03, 0x03]
                b2 = self.ser.read(1)
                if b2 and b2[0] == 0x03:
                    return [0x03, 0x03]

        if not stx:
            return None

        len_bytes = self.ser.read(2)
        if len(len_bytes) < 2:
            return None
        length = (len_bytes[0] << 8) | len_bytes[1]

        # Оставшаяся часть пакета: полезная нагрузка (length байт) + ETX (0x03) + BCC (1 байт)
        rest = self.ser.read(length + 2)
        if len(rest) < length + 2:
            return None

        full_resp = bytearray(stx + len_bytes + rest)
        if full_resp[-2] != 0x03:
            return None

        calc_bcc = self._calc_bcc(full_resp[:-1])
        if calc_bcc != full_resp[-1]:
            return None

        return list(full_resp)

    def get_version(self):
        """Запрос версии прошивки считывателя (0x31 0x40)."""
        res = self._send_command(0x31, 0x40)
        if res and len(res) >= 6 and res[4] == 0x40:
            return res[5:-2]
        return None

    def get_card(self):
        """Проверка наличия карты в поле (0x34 0x30)."""
        res = self._send_command(0x34, 0x30)
        return bool(res and len(res) >= 6 and res[4] == 0x30 and res[5] == 0x59)

    def get_id_card(self):
        """Чтение идентификатора UID карты (0x34 0x31)."""
        res = self._send_command(0x34, 0x31)
        if res and len(res) >= 7 and res[4] == 0x31 and res[5] == 0x59:
            uid_len = res[2] - 3
            if uid_len > 0 and len(res) >= 6 + uid_len:
                return list(res[6:6 + uid_len])
        return None

    def check_key_a(self, sector, key_bytes):
        """Авторизация сектора ключом KeyA (0x34 0x32)."""
        payload = bytes([sector]) + bytes(key_bytes)
        res = self._send_command(0x34, 0x32, payload)
        return bool(res and len(res) >= 7 and res[4] == 0x32 and res[6] == 0x59)

    def check_key_b(self, sector, key_bytes):
        """Авторизация сектора ключом KeyB (0x34 0x39)."""
        payload = bytes([sector]) + bytes(key_bytes)
        res = self._send_command(0x34, 0x39, payload)
        return bool(res and len(res) >= 7 and res[4] == 0x39 and res[6] == 0x59)

    def write_key(self, sector, new_key_bytes):
        """Запись нового ключа KeyA в сектор (0x34 0x35)."""
        payload = bytes([sector]) + bytes(new_key_bytes)
        res = self._send_command(0x34, 0x35, payload)
        return bool(res and len(res) >= 7 and res[4] == 0x35 and res[6] == 0x59)

    # --- Унифицированный интерфейс считывателя (совместимый с OmnikeyReader) ---

    def read_uid(self):
        """
        Возвращает UID карты в виде списка байт [0x.., 0x..], либо None если карты нет в поле.
        """
        if not self.get_card():
            return None
        # Если карта обнаружена, считываем UID с возможным повтором при помехе
        for _ in range(2):
            uid = self.get_id_card()
            if uid is not None:
                return uid
            time.sleep(0.02)
        return None

    def card_number_from_uid(self, uid):
        """Преобразование байт UID в десятичный номер с учетом byte_order."""
        return int.from_bytes(bytes(uid), self.byte_order)

    def card_has_object_key(self):
        """Проверяет, прошита ли уже карта рабочим ключом объекта."""
        if not self.object_key:
            return False
        key = hex_to_bytes(self.object_key)
        return self.check_key_a(self.sector, key)

    def card_is_blank(self):
        """Проверяет, является ли карта чистой («болванкой») с заводским ключом."""
        key = hex_to_bytes(self.factory_key)
        return self.check_key_a(self.sector, key)

    def write_object_key(self):
        """
        Прошивает рабочий ключ объекта в карту.
        1. Авторизация заводским ключом (проверка на чистоту).
        2. Запись ключа объекта (WriteKey).
        3. Верификация: проверка авторизации новым ключом объекта.
        """
        factory_bytes = hex_to_bytes(self.factory_key)
        object_bytes = hex_to_bytes(self.object_key)

        # 1. Проверяем, что карта чистая (заводской ключ FF FF FF FF FF FF)
        if not self.check_key_a(self.sector, factory_bytes):
            raise Exception("не болванка")

        time.sleep(0.05)  # Небольшая пауза перед записью EEPROM

        # 2. Прошиваем новый ключ объекта
        if not self.write_key(self.sector, object_bytes):
            raise Exception("ошибка записи ключа")

        time.sleep(0.08)  # Пауза на фиксацию записи в EEPROM чипа

        # 3. ОБЯЗАТЕЛЬНАЯ ВЕРИФИКАЦИЯ: проверяем, что сектор открывается новым ключом
        if not self.check_key_a(self.sector, object_bytes):
            raise Exception("записал, но ключ не читается (проверка не прошла)")
