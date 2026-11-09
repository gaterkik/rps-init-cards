import time
import serial


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


class CardDispenser:
    def __init__(self, port, baudrate=9600):
        self.port = normalize_port(port)
        self.baudrate = baudrate
        self.ser = None

    def connect(self):
        """
        Подключение к диспенсеру с автоматическим определением скорости (9600 / 38400).
        """
        baudrates_to_try = [self.baudrate]
        for b in [9600, 38400, 19200, 115200]:
            if b not in baudrates_to_try:
                baudrates_to_try.append(b)

        for baud in baudrates_to_try:
            try:
                if self.ser and self.ser.is_open:
                    self.ser.close()
                self.ser = serial.Serial(
                    self.port,
                    baud,
                    bytesize=serial.EIGHTBITS,
                    parity=serial.PARITY_NONE,
                    stopbits=serial.STOPBITS_ONE,
                    timeout=0.6,
                    write_timeout=0.6,
                )
                time.sleep(0.15)
                self.ser.reset_input_buffer()
                self.ser.reset_output_buffer()

                st = self.check_status()
                if st is not None:
                    self.baudrate = baud
                    # Устанавливаем рабочие таймауты
                    self.ser.timeout = 1.0
                    self.ser.write_timeout = 1.0
                    return True
            except Exception:
                pass

        # Если ни на одной скорости не получен ответ, открываем порт на 9600 по умолчанию
        try:
            if self.ser and self.ser.is_open:
                self.ser.close()
            self.baudrate = 9600
            self.ser = serial.Serial(
                self.port,
                9600,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=1.0,
                write_timeout=1.0,
            )
            time.sleep(0.15)
            self.ser.reset_input_buffer()
            self.ser.reset_output_buffer()
            return True
        except Exception as e:
            print(f"Ошибка открытия порта {self.port}: {e}")
            return False

    def close(self):
        if self.ser and self.ser.is_open:
            try:
                self.ser.close()
            except Exception:
                pass

    def _calc_bcc(self, data):
        bcc = 0
        for b in data:
            bcc ^= b
        return bcc

    def _send_command(self, cmd_bytes, timeout=1.0):
        if not self.ser or not self.ser.is_open:
            return None

        stx = 0x02
        etx = 0x03
        len_h = (len(cmd_bytes) >> 8) & 0xFF
        len_l = len(cmd_bytes) & 0xFF

        bcc = stx ^ len_h ^ len_l
        for b in cmd_bytes:
            bcc ^= b
        bcc ^= etx

        frame = [stx, len_h, len_l] + list(cmd_bytes) + [etx, bcc]

        try:
            self.ser.reset_input_buffer()
            self.ser.reset_output_buffer()
            self.ser.write(bytes(frame))
        except Exception:
            return None

        # Чтение ответа с поиском байта STX (0x02)
        start_time = time.time()
        resp_stx = b""
        while time.time() - start_time < timeout:
            b = self.ser.read(1)
            if not b:
                continue
            if b[0] == 0x02:
                resp_stx = b
                break

        if not resp_stx:
            return None

        len_b = self.ser.read(2)
        if len(len_b) < 2:
            return None
        payload_len = (len_b[0] << 8) | len_b[1]

        # Полезная нагрузка + ETX (1 байт) + BCC (1 байт)
        rest = self.ser.read(payload_len + 2)
        if len(rest) < payload_len + 2:
            return None

        data = rest[:payload_len]
        resp_etx = rest[payload_len]
        resp_bcc = rest[payload_len + 1]

        if resp_etx != 0x03:
            return None

        # Проверка BCC
        calc_bcc = 0x02 ^ len_b[0] ^ len_b[1]
        for b in data:
            calc_bcc ^= b
        calc_bcc ^= 0x03

        if calc_bcc != resp_bcc:
            return None

        return list(data)

    def check_status(self):
        """
        GetStatus: CW='2', CP='0' (0x32 0x30).
        Возвращает байт маски датчиков либо None.
        """
        res = self._send_command([0x32, 0x30], timeout=0.8)
        if res and len(res) >= 3 and res[0] == 0x32 and res[1] == 0x30:
            return res[2]
        return None

    def is_card_at_reader(self, status):
        """Bit 5 (0x20) CardPreSendPos: карта находится точно под ридером MT625."""
        return bool(status is not None and (status & 0x20) != 0)

    def is_card_at_read_pos(self, status):
        """Совместимый метод: карта под ридером (Bit 5, 0x20)."""
        return self.is_card_at_reader(status)

    def is_card_in_bezel(self, status):
        """Bit 6 (0x40) CardDespensePos: карта находится в выходной щели (в губах)."""
        return bool(status is not None and (status & 0x40) != 0)

    def is_device_error(self, status):
        """Bit 1 (0x02) CardError: замятие карты в тракте."""
        return bool(status is not None and (status & 0x02) != 0)

    def is_card_shortage(self, status):
        """Bit 4 (0x10) CardShortage: мало карт в магазине (Pre-empty)."""
        return bool(status is not None and (status & 0x10) != 0)

    def is_stack_empty(self, status):
        """Bit 7 (0x80) CardEmpty: магазин карт полностью пуст."""
        return bool(status is not None and (status & 0x80) != 0)

    def dispense_to_read_pos(self):
        """
        SendFromBoxToReadPosition: CW='1', CP='0' (0x31 0x30).
        Подача 1 карты из магазина точно в позицию RF-кодирования (под ридер MT625).
        """
        res = self._send_command([0x31, 0x30], timeout=6.0)
        return bool(res and len(res) >= 3 and res[2] == 0x59)  # 'Y' (0x59)

    def dispense_card(self):
        """Алиас для подачи карты под ридер (0x31 0x30)."""
        return self.dispense_to_read_pos()

    def eject_card(self, hold=False):
        """
        Выдача карты наружу.
        hold=True:  CW='1', CP='1' (0x31 0x31) - выдать в щель с удержанием роликами.
        hold=False: CW='1', CP='2' (0x31 0x32) - вытолкнуть наружу без удержания.
        """
        cmd = [0x31, 0x31] if hold else [0x31, 0x32]
        res = self._send_command(cmd, timeout=4.0)
        return bool(res and len(res) >= 3 and res[2] == 0x59)

    def retain_card(self):
        """
        SendCardToRecycleBox: CW='3', CP='0' (0x33 0x30).
        Сброс неисправной/бракованной карты в нижний внутренний ящик сбора (отказник).
        """
        res = self._send_command([0x33, 0x30], timeout=4.0)
        return bool(res and len(res) >= 3 and res[2] == 0x59)

    def pull_from_bezel_to_reader(self):
        """
        SendFromBezelToReadPosition: CW='3', CP='2' (0x33 0x32).
        Втягивание карты из щели обратно под ридер.
        """
        res = self._send_command([0x33, 0x32], timeout=4.0)
        return bool(res and len(res) >= 3 and res[2] == 0x59)
