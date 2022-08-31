from libs.transform import MaltegoTransform
from libs.config import config
import subprocess as sp
import argparse
import tempfile
import sys
import re
import os

class Transform():

    def __init__(self):
        self.transform     = MaltegoTransform()
        self.value         = None
        self.parent_fields = self._additional_fields_to_dict()

    def _additional_fields_to_dict(self):
        """
            Method: _additional_fields_to_dict
            Description: Translate additional fields to dict.
            Arguments: No.
        """
        rtn = {"parent.entity.value" : "", "entity.value" : ""}
        try:
            for i, field in enumerate(sys.argv[3].split("#")):
                field = field.split("=")
                if i == 0:
                    rtn["entity.value"] = field[1]
                else:
                    rtn[field[0]] = field[1]
        except:
            pass

        return rtn

    def hexeditor(self):
        """ Open an hex editor """
        
        if re.match("[a-f0-9]{64}", self.value):
            bin_path = os.path.join(tempfile.gettempdir(), f"{self.value}.bin")
        else:
            bin_path = self.value

        if os.path.isfile(bin_path):
            if os.path.isfile(config["tools"]["hexeditor"]):
                sp.Popen([config["tools"]["hexeditor"], bin_path], stdout=sp.PIPE,  stderr=sp.PIPE, start_new_session=True).wait()
            else:
                self.transform.addUIMessage("Please define your Hexadecimal editor in config.yaml")
        else:
            self.transform.addUIMessage(f"Your file doesn't exist in {bin_path} !")

        self.transform.returnOutput()

    def texteditor(self):
        """ Open a text editor """
        
        if re.match("[a-f0-9]{64}", self.value):
            bin_path = os.path.join(tempfile.gettempdir(), f"{self.value}.bin")
        else:
            bin_path = self.value

        if os.path.isfile(bin_path):
            if os.path.isfile(config["tools"]["texteditor"]):
                sp.Popen([config["tools"]["texteditor"], bin_path], stdout=sp.PIPE,  stderr=sp.PIPE, start_new_session=True).wait()
            else:
                self.transform.addUIMessage("Please define your texteditor in config.yaml")
        else:
            self.transform.addUIMessage(f"Your file doesn't exist in {bin_path} !")

        self.transform.returnOutput()

    def disassembler(self):
        """ Open a dissassembler """
        
        if re.match("[a-f0-9]{64}", self.value):
            bin_path = os.path.join(tempfile.gettempdir(), f"{self.value}.bin")
        else:
            bin_path = self.value

        if os.path.isfile(bin_path):
            if os.path.isfile(config["tools"]["disassembler"]):
                self.transform.addUIMessage("Exception Occurred")
                sp.Popen([config["tools"]["disassembler"], bin_path], stdout=sp.PIPE,  stderr=sp.PIPE, start_new_session=True).wait()
            else:
                self.transform.addUIMessage("Please define your dissasembler editor in config.yaml")
        else:
            self.transform.addUIMessage(f"Your file doesn't exist in {bin_path} !")

        self.transform.returnOutput()

parser = argparse.ArgumentParser()
parser.add_argument('--method', type=str, help='The method to ask')
args = parser.parse_known_args()

method = args[0].method

t = Transform()
t.value = args[1][0].strip()

if re.match("[a-zA-Z\_]+", method):
    eval("t.%s()" % (method))
