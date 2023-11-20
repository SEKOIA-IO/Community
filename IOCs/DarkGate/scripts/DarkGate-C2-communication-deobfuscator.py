import base64
import binascii
import urllib


def unhex(hex_string):
    """oalabs fonction copy from:
    https://github.com/OALabs/research/blob/master/_notebooks/2021-06-27-python3_examples.ipynb
    """

    if type(hex_string) == str:
        return binascii.unhexlify(hex_string.encode())
    else:
        return binascii.unhexlify(hex_string)


class DarkgateDecoder:
    """utility to decode darkgate message"""

    def __init__(self, botId: str, darkgate_base6_alphabet: str):
        self.botId = botId
        self.darkgate_base6_alphabet = darkgate_base6_alphabet
        self.xorKey = self.__xorKey_setup()

    def __xorKey_setup(self) -> int:
        """setup XOR key same maner as DarkGate"""

        xorKey = len(self.botId)

        for char in self.botId:
            xorKey ^= ord(char)

        return xorKey

    def custom_base64_decode(self, data: str) -> bytes:
        """base64 decode using DarkGate mixed alphabet"""

        __standard_alphabet = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        )
        __decode_trans = str.maketrans(
            self.darkgate_base6_alphabet, __standard_alphabet
        )

        return base64.b64decode(data.translate(__decode_trans))

    def deobfuscated(self, data: str) -> str:
        """deobfuscated Darkgate message:
        1. base64 decode with the custom alphabet
        2. XOR decode message
        3. (Optional) convert wide string in hex format to standard string"""

        cleartext = ""
        pad = lambda x: x + (4 - (len(x) % 4)) * "+"

        data = pad(data)

        decoded_string = self.custom_base64_decode(data)

        for x in decoded_string:
            cleartext += chr(~(x ^ self.xorKey) & 0xFF)

        if "|" in cleartext:
            cleartext = cleartext.split("|")
            for position, item in enumerate(cleartext.copy()):
                if "00" in item:
                    item = unhex(item).replace(b"\x00", b"").decode()
                    cleartext[position] = item

            cleartext = "|".join(cleartext)

        return cleartext


def deobfuscate_pcap(filepath: str, decoder: DarkgateDecoder) -> None:
    """read pcap and deobfuscate messages"""

    import pyshark

    pcap = pyshark.FileCapture(filepath, display_filter="http")

    for packet in pcap:
        try:
            forms = urllib.parse.unquote(packet.http.file_data).split("&")
            for form, value in map(lambda x: x.split("=", 1), forms):
                if form == "data":
                    cleartext = decoder.deobfuscated(value)
                    print(f"{cleartext}")
        except Exception:
            pass


if __name__ == "__main__":
    import argparse

    # example of obfuscated message
    # boMBbwxZboMjwDhjbEngbEMncoMjwH8jbfA7rHAY4H+iXwACwwAijnrcj7tYjwwc=QtDjb+cvw+MvBMd8nwMBSrvDSANTYtp=EOq8bEDDG+Cwo=jbEBZbEMnboMjwH8jbEvZbEMnboMjw+bjbEvZbEMDbEMjwovjbEhvbEMZboMjbDMjbEhvbEMvbDMjwD5jbEBjbEMncEMjwDyjbEvBbEMvb+

    # BotId: dEGDGKCcDdGdfbBhBaGGhhbBcEEFEcHh
    # B64 alphabet: zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+=

    parser = argparse.ArgumentParser(
        "DarkGate C2 communications deobfuscation" "external requirement: pyshark"
    )
    parser.add_argument(
        "-a",
        "--alphabet",
        help="alphabet configured to decode the" "custom base64 encoding of DarkGate",
    )
    parser.add_argument(
        "-b",
        "--bot-id",
        help="botId can be found in the PCAP,"
        "it is send in every POST request of the bot",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="filepath to the PCAP")
    group.add_argument("-d", "--data", help="raw data extracted from a PCAP")

    args = parser.parse_args()

    decoder = DarkgateDecoder(
        botId=args.bot_id,
        darkgate_base6_alphabet=args.alphabet,
    )

    if args.data:
        cleartext = decoder.deobfuscated(args.data)
        print(f"Cleartext: {cleartext}")
    else:
        deobfuscate_pcap(args.file, decoder)
