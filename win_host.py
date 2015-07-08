#! /usr/bin/env python

import winrm
import base64
import sys
import re
import xml.etree.ElementTree as ET

class WinHost(object):
    """
    Models a remote windows machine that can be controlled through winrm
    """
    _defaults = {
                'host': '',
                'port': 5986,
                'scheme': 'https',
                'transport': 'plaintext',
                'username': '',
                'password': ''
            }

    _local_script = 'local.ps1'

    def __init__(self, address, username, password, scheme='https', 
                    port=5986, transport='plaintext'):
        """
        Create a model of a remote windows machine
        
        params:
            address - the address of the remote machine i.e 8.8.8.8 or some.domain.com
            username - the username used to run commands on the remote machine
            password - the password used to run commands on the remote machine
            scheme - the protocol scheme used to connect to winrm currently only http and https are supported
            port - the port used to connect to winrm, default is 5986
            transport - transport method used to connect to winrm currently only plaintext and ssl are supported
        returns:
            an object representing the remote machine
        raises:
            ValueError - one or more of the arguments passed were invalid
        """
        scheme = scheme.lower()
        if scheme not in  ['http', 'https']:
            raise ValueError
        transport = transport.lower()
        if transport not in ['ssl', 'plaintext']:
            raise ValueError
        if port < 0:
            raise ValueError
        self.endpoint = '%s://%s:%d/wsman' % (scheme, address, port)
        self.username = username
        self.password = password
        self.protocol = winrm.Protocol(self.endpoint, transport=transport,
                    username=self.username, password=self.password)
        self.shell_id = self.protocol.open_shell()

    def run_command(self, command, args=None, cleanup=True):
        """
        Run a command on the remote machine

        params:
            command - the command to be run
            args - a list of args to be passed to the command 
        returns:
            (stdout, stderr, code) - the stdout, stderr, and exit code produced by the command
        """
        if not self.shell_id:
            self.shell_id = protocol.open_shell()
        cmd_id = self.protocol.run_command(self.shell_id, command, args)
        out,err,code = self.protocol.get_command_output(self.shell_id, cmd_id)
        err = self.clean_error_msg(err)
        if cleanup:
            self.protocol.cleanup_command(self.shell_id, cmd_id)
        return (out,err,code)

    def copy_file(self, src, dest):
        """
        Copy a file from local machine to remote.

        params:
            src - the file to be copied
            dest - location of the file on the remote
        returns:
            Whether the copy was successful
        """
        success = True
        with open(src, 'r') as f:
            contents = f.read()
            step = 400
            for i in range(0, len(contents), step):
                success = success and self._do_put_file(dest, contents[i:i+step])
        return success

    def _do_put_file(self, location, contents):
        ps_script = """
$filePath = "{location}"
$s = @"
{b64_contents}
"@
$data = [System.Convert]::FromBase64String($s)
add-content -value $data -encoding byte -path $filePath
        """.format(location = location, b64_contents = base64.b64encode(contents))
        stdout, stderr, code = self.run_enc_command(ps_script)
        if code == 0:
            return True
        return False

    def run_enc_command(self, command, cleanup=True):
        enc_command = base64.b64encode(command.encode('utf_16_le'))
        return self.run_command("powershell -encodedcommand %s" % enc_command, cleanup=cleanup)

    def clean_error_msg(self, msg):
        """converts a Powershell CLIXML message to a more human readable string
        """
        # if the msg does not start with this, return it as is
        if msg.startswith("#< CLIXML\r\n"):
            # for proper xml, we need to remove the CLIXML part
            # (the first line)
            msg_xml = msg[11:]
            try:
                # remove the namespaces from the xml for easier processing
                msg_xml = self.strip_namespace(msg_xml)
                root = ET.fromstring(msg_xml)
                # the S node is the error message, find all S nodes
                nodes = root.findall("./S")
                new_msg = ""
                for s in nodes:
                    # append error msg string to result, also
                    # the hex chars represent CRLF so we replace with newline
                    new_msg += s.text.replace("_x000D__x000A_", "\n")
            except Exception as e:
                # if any of the above fails, the msg was not true xml
                # print a warning and return the orignal string
                print("Warning: there was a problem converting the Powershell"
                        " error message: %s" % (e))
            else:
                # if new_msg was populated, that's our error message
                # otherwise the original error message will be used
                if len(new_msg):
                    # remove leading and trailing whitespace while we are here
                    msg = new_msg.strip()
        return msg

    def run_local(self, command, args=[]):
        success = self.copy_file(_local_script, '$env:temp\local.ps1')
        if not success:
            raise WinRMTransportError(self.transport, "Error copying file %s to remote" % _local_script)
        command += ' '.join(args)
        enc_cmd = base64.b64encode(command.encode('utf_16_le'))
        res = self.run_enc_command('& $env:temp\local.ps1 -Command %s -User %s -Pass %s' % 
                (enc_cmd, self.username, self.password))
        self.run_enc_command('rm $env:temp\local.ps1')
        return res

    def strip_namespace(self, xml):
        """strips any namespaces from an xml string"""
        p = re.compile("xmlns=*[\"\"][^\"\"]*[\"\"]")
        allmatches = p.finditer(xml)
        for match in allmatches:
            xml = xml.replace(match.group(), "")
        return xml

    @staticmethod
    def from_dict(*dicts):
        """
        Create a WinHost from one or more dictionaries of arguments. If values are not found in
        the dictionary, default values are used instead.

        params:
            dicts: an array of dictionaries ordered by precedence
        return:
            a WinHost model of a remote windows machine
        """
        merged = {}
        for attr in WinHost._defaults.keys():
            merged[attr] = WinHost._defaults[attr]
            for dic in dicts:
                if dic.has_key(attr) and dic[attr]:
                    merged[attr] = dic[attr]
                    break
        return WinHost(merged['host'], merged['username'], merged['password'], 
                  merged['scheme'], merged['port'], merged['transport'])
