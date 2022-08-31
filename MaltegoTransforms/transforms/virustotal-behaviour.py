from libs.transform import MaltegoTransform, MaltegoEntity
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from libs.config import config
import tempfile
import argparse
import requests
import json
import sys
import re
import os

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Transform():

    def __init__(self):
        self.transform     = MaltegoTransform()
        self.value         = None
        self.parent_fields = self._additional_fields_to_dict()
        self.API_URL       = config["apis"]["virustotal"]["url"]
        self.API_KEY       = config["apis"]["virustotal"]["api_key"]
        self.limit         = 100

    def _additional_fields_to_dict(self):
        """Translate additional fields to dict.

        Returns:
            dic: Dict containing parents fields.
        """
        rtn = {"parent.entity.value" : "", "entity.value" : ""}
        for i, field in enumerate(sys.argv[3].split("#")):
            field = field.split("=")
            if i == 0:
                rtn["entity.value"] = field[1]
            else:
                try:
                    rtn[field[0]] = field[1]
                except:
                    continue
        return rtn

    def _do_get_request(self, url):
        """Do a get request to the url and return the JSON.

        Args:
            url (str): the URL to query

        Returns:
            dict: Answer JSON as dict
        """
        try:
            print(f"<!-- { url }-->")
            return requests.get(url, verify=False, headers={"x-apikey" : self.API_KEY}).json()
        except:
            print("<!-- Issue during the HTTP Request -->")
            print(f"<!-- { url }-->")
            self.transform.returnOutput()
            exit()

    def _reputation_to_color(self, i):
        """Some reputation (int) to color code.

        Args:
            i (int): reputation code

        Returns:
            str: color hex notation.
        """
        if i == 0:
            return "#7CFC00"
        elif i < 4:
            return "#ff7f00"
        elif i > 3:
            return "#ff0000"
        
    def search(self):
        """ Search a behaviour in VT """
        
        search_value = f'behaviour:"{self.value}"'
        url = f"{self.API_URL}intelligence/search?query={search_value}&limit=300"
        res = self._do_get_request(url)

        if "data" in res:
            for obj in res["data"]:
                if obj["id"] != self.parent_fields["parent.entity.value"]:
                    if obj["type"] == "file":
                        e = MaltegoEntity()
                        e.setType("maltego.custom.file")
                        e.addAdditionalFields(fieldName="parent.entity.value",
                                            displayName="Parent Entity", 
                                            value=self.parent_fields["entity.value"])
                        try:
                            e.addAdditionalFields(fieldName="file.name",
                                            displayName="File Name", 
                                            value=obj["attributes"]["names"][0] if len(obj["attributes"]["names"]) else "")
                        except:
                            pass
                        try:
                            e.addAdditionalFields(fieldName="file.type",
                                            displayName="File Type", 
                                            value=obj["attributes"]["exiftool"]["MIMEType"])
                        except:
                            pass
                        try:
                            e.addAdditionalFields(fieldName="file.ssdeep",
                                            displayName="SSDeep", 
                                            value=obj["attributes"]["ssdeep"])
                        except:
                            pass
                        try:
                            e.addAdditionalFields(fieldName="file.md5",
                                            displayName="MD5", 
                                            value=obj["attributes"]["md5"])
                        except:
                            pass
                        try:
                            e.addAdditionalFields(fieldName="file.sha1",
                                            displayName="SHA1", 
                                            value=obj["attributes"]["sha1"])
                        except:
                            pass
                        try:
                            e.addAdditionalFields(fieldName="file.sha256",
                                            displayName="SHA256", 
                                            value=obj["attributes"]["sha256"])
                        except:
                            pass
                        try:
                            e.addAdditionalFields(fieldName="file.size",
                                            displayName="File size", 
                                            value=str(obj["attributes"]["size"]))
                        except:
                            pass
                        try:
                            e.addAdditionalFields(fieldName="file.magic",
                                            displayName="File magic", 
                                            value=obj["attributes"]["magic"])
                        except:
                            pass
                        try:
                            e.addAdditionalFields(fieldName="file.reputation",
                                            displayName="File reputation", 
                                            value=self._reputation_to_color(obj["attributes"]["last_analysis_stats"]["malicious"]))
                        except:
                            pass
                        e.setValue(obj["id"])
                        self.transform.addEntityToMessage(e)

        self.transform.returnOutput()

        self.transform.returnOutput()
    
    def to_registry_keys_set(self):
        """ Get the registry keys set during the execution """
        
        try:

            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for kv in res["data"]["registry_keys_set"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(kv["key"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="Registry")
                e.addAdditionalFields(fieldName="behaviour.details",
                                    displayName="Behaviour details", 
                                    value="Value: " + kv["value"])
                e.setLinkLabel("Set this registry key")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_registry_keys_deleted(self):
        """ Get the registry keys deleted during the execution """
        
        try:

            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for k in res["data"]["registry_keys_deleted"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(k)
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="Registry")
                e.setLinkLabel("Delete this registry key")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_mutexes_created(self):
        """ Get the mutex created during the execution """
        
        try:

            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for m in res["data"]["mutexes_created"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(m)
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="Mutex")
                e.setLinkLabel("Mutex created")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_files_written(self):
        """ Get the files written during the execution """
        
        try:

            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for file in res["data"]["files_written"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(file)
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="File written")
                e.setLinkLabel("File written")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_files_opened(self):
        """ Get the files opened during the execution """
        
        try:

            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for file in res["data"]["files_opened"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(file)
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="File opened")
                e.setLinkLabel("File opened")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_files_deleted(self):
        """ Get the files deleted during the execution """
        
        try:

            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for file in res["data"]["files_deleted"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(file)
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="File deleted")
                e.setLinkLabel("File deleted")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_tags(self):
        """ Get the behaviour tags during the execution """
        
        try:

            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for tag in res["data"]["tags"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(tag)
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="VT Tag")
                e.setLinkLabel("Tags")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_attack_techniques(self):
        """ Get the attack techniques seen during the execution """
        
        try:
            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for attack, desc in res["data"]["attack_techniques"].items():
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(attack)
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="Att&ck")
                e.addAdditionalFields(fieldName="behaviour.details",
                                    displayName="Behaviour details", 
                                    value="\n".join(["{} ({})".format(d["description"], d["severity"]) for d in desc]))
                e.setLinkLabel("Technique")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_processes_created(self):
        """ Get the process created during the execution """
        
        try:

            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for p in res["data"]["processes_created"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(p)
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="Process created")
                e.setLinkLabel("Created process")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_processes_terminated(self):
        """ Get the process terminated during the execution """
        
        try:

            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for p in res["data"]["processes_terminated"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(p)
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="Process terminated")
                e.setLinkLabel("Process terminated")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_processes_killed(self):
        """ Get the process killed during the execution """
        
        try:

            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for p in res["data"]["processes_killed"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(p)
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="Process killed")
                e.setLinkLabel("Process killed")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_processes_injected(self):
        """ Get the process injected during the execution """
        
        try:

            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for p in res["data"]["processes_injected"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(p)
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="Process injected")
                e.setLinkLabel("Process injected")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_dns_lookups(self):
        """ Get the DNS Lookups during the execution """
        
        try:

            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for l in res["data"]["dns_lookups"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(l["hostname"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="DNS Lookup")
                e.addAdditionalFields(fieldName="behaviour.details",
                                    displayName="Behaviour details", 
                                    value="\n".join(l["resolved_ips"]))
                e.setLinkLabel("DNS Lookup")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()


    def to_ip_traffic(self):
        """ Get the IP traffic seen during the execution """

        try:
            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for r in res["data"]["ip_traffic"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(r["destination_ip"] + ":" + str(r["destination_port"]))
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="IP Traffic")
                e.setLinkLabel("Network request")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()


    def to_processes_tree(self):
        """ Get the IP traffic seen during the execution """

        try:

            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for r in res["data"]["processes_tree"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(r["name"])
                if "children" in r: e.setNote(json.dumps(r["children"], indent=1))
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="Process tree")
                e.setLinkLabel("Process tree")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_services_created(self):
        """ Get the services created during the execution """

        try:
            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for s in res["data"]["services_created"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(s)
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="Service created")
                e.setLinkLabel("Service created")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_services_deleted(self):
        """ Get the services deleted during the execution """

        try:
            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for s in res["data"]["services_deleted"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(s)
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="Service deleted")
                e.setLinkLabel("Service deleted")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_text_decoded(self):
        """ Get the text decoded during the execution """

        try:
            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            for s in res["data"]["text_decoded"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(s)
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="Text decoded")
                e.setLinkLabel("Text decoded")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_ja3s(self):
        """ Get the ja3s during the execution """

        try:
            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            e = MaltegoEntity()
            e.setType("maltego.custom.FileBehaviour")
            e.setValue(res["data"]["tls"]["ja3s"])
            e.addAdditionalFields(fieldName="parent.entity.value",
                                displayName="Parent Entity", 
                                value=self.parent_fields["entity.value"])
            e.addAdditionalFields(fieldName="behaviour.type",
                                displayName="Behaviour type", 
                                value="JA3S")
            e.setLinkLabel("JA3S")
            self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def to_ja3(self):
        """ Get the ja3s during the execution """

        try:
            url = f"{self.API_URL}files/{self.value}/behaviour_summary"
            res = self._do_get_request(url)

            e = MaltegoEntity()
            e.setType("maltego.custom.FileBehaviour")
            e.setValue(res["data"]["tls"]["ja3"])
            e.addAdditionalFields(fieldName="parent.entity.value",
                                displayName="Parent Entity", 
                                value=self.parent_fields["entity.value"])
            e.addAdditionalFields(fieldName="behaviour.type",
                                displayName="Behaviour type", 
                                value="JA3")
            e.setLinkLabel("JA3")
            self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def to_behashes(self):
        """ Get the behashes of the execution """

        try:
            url = f"{self.API_URL}files/{self.value}/behaviours"
            res = self._do_get_request(url)

            for d in res["data"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue(d["attributes"]["behash"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="behaviour.type",
                                    displayName="Behaviour type", 
                                    value="Behash")
                e.setLinkLabel("Behaviour hash")
                self.transform.addEntityToMessage(e)

        except:
            pass

        self.transform.returnOutput()

    def to_pcaps(self):
        """ Get the pcaps of the execution """

        url = f"{self.API_URL}files/{self.value}/behaviours"
        res = self._do_get_request(url)
        notes = []
        
        try:
            for d in res["data"]:
                if d["attributes"]["has_pcap"] == True:
                    
                    behaviour_path = os.path.join(tempfile.gettempdir(), f"behaviour_{self.parent_fields['entity.value']}")
                    sid = d["links"]["self"].split("/")[-1]
                    pcap_path = os.path.join(behaviour_path, sid + ".pcap")
                    
                    if not os.path.exists(behaviour_path): 
                        os.mkdir(behaviour_path)

                    url = "%sfile_behaviours/%s/pcap" % (self.API_URL, sid)
                    res = requests.get(url).content

                    with open(os.path.join(pcap_path), "wb") as f:
                        print("<!-- Pcap downloaded under {} -->".format())
                        f.write(res)

                    notes.append("Pcap downloaded under {}".format(pcap_path))
        
            if len (notes):
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue("Pcaps downloaded!")
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.setNote("\n".join(notes))
                self.transform.addEntityToMessage(e)
        except:
            pass
        
        self.transform.returnOutput()

    def to_evtx(self):
        """ Get the evtx of the execution """

        url = f"{self.API_URL}files/{self.value}/behaviours"
        res = self._do_get_request(url)
        notes = []
        
        try:
            for d in res["data"]:
                if d["attributes"]["has_evtx"] == True:
                    
                    behaviour_path = os.path.join(tempfile.gettempdir(), f"behaviour_{self.parent_fields['entity.value']}")
                    sid = d["links"]["self"].split("/")[-1]
                    evtx_path = os.path.join(behaviour_path, f"{sid}.evtx")
                    
                    if not os.path.exists(behaviour_path): 
                        os.mkdir(behaviour_path)

                    url = f"{self.API_URL}file_behaviours/{sid}/evtx"
                    res = requests.get(url).content

                    with open(os.path.join(evtx_path), "wb") as f:
                        print(f"<!-- Evtx downloaded under {evtx_path} -->")
                        f.write(res)

                    notes.append(f"Evtx downloaded under {evtx_path}")
            if len (notes):
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue("Evtx downloaded!")
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.setNote("\n".join(notes))
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def to_memdump(self):
        """ Get the memdump of the execution """

        url = f"{self.API_URL}files/{self.value}/behaviours"
        res = self._do_get_request(url)
        notes = []

        try:
            for d in res["data"]:
                if d["attributes"]["has_memdump"] == True:
                    
                    behaviour_path = os.path.join(tempfile.gettempdir(), f"behaviour_{self.parent_fields['entity.value']}")
                    sid = d["links"]["self"].split("/")[-1]
                    memdump_path = os.path.join(behaviour_path, f"{sid}.memdump")
                    
                    if not os.path.exists(behaviour_path): 
                        os.mkdir(behaviour_path)

                    url = f"{self.API_URL}file_behaviours/{sid}/memdump"
                    res = requests.get(url).content

                    with open(os.path.join(memdump_path), "wb") as f:
                        print(f"<!-- Memdump downloaded under {memdump_path} -->")
                        f.write(res)

                    notes.append(f"Memdump downloaded under {memdump_path}")

            if len (notes):
                e = MaltegoEntity()
                e.setType("maltego.custom.FileBehaviour")
                e.setValue("Memdump downloaded!")
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.setNote("\n".join(notes))
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

parser = argparse.ArgumentParser()
parser.add_argument('--method', type=str, help='The method to ask')
args = parser.parse_known_args()

method = args[0].method

t = Transform()
t.value = args[1][0].strip()

if re.match("[a-zA-Z\_]+", method):
    eval("t.%s()" % (method))
