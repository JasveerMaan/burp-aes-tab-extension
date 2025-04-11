# -*- coding: utf-8 -*-

# Author: Jasveer Singh
# Final Version with Fix for group reference issue

import re
import binascii
from jarray import array
from java.util import Random
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec
from java.security import MessageDigest
from burp import IBurpExtender, IHttpListener, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import JScrollPane, JTextArea

class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Encrypt&Decrypt")
        callbacks.registerHttpListener(self)
        callbacks.registerMessageEditorTabFactory(self)
        print("[*] Encrypt&Decrypt Extension by Jasveer")

    def createNewInstance(self, controller, editable):
        return JSITab(self._callbacks, self._helpers, editable)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return

        request = messageInfo.getRequest()
        analyzed = self._helpers.analyzeRequest(messageInfo.getHttpService(), request)
        headers = analyzed.getHeaders()
        body = request[analyzed.getBodyOffset():].tostring()

        url = self._helpers.analyzeRequest(messageInfo).getUrl().getPath()
        host = messageInfo.getHttpService().getHost()

        if "127.0.0.1" not in host:
            return

        if not self._should_intercept(url):
            return

        content_type = next((h for h in headers if h.lower().startswith("content-type")), "").lower()
        is_multipart = "multipart/form-data" in content_type

        secretkey = self.extract_value(body, "secretkey", is_multipart)
        if not secretkey:
            return

        decrypted_data = JSITab.last_input_text
        if decrypted_data:
            try:
                updated_fields = self.parse_tab_content(decrypted_data)
                for field in updated_fields:
                    if updated_fields[field]:
                        encrypted_value = self.encrypt_field_static(updated_fields[field], secretkey)
                        body = self.safe_replace_value(body, field, encrypted_value, is_multipart)

                messageInfo.setRequest(self._helpers.buildHttpMessage(headers, body))
                print("[*] Updated request body sent from Repeater:\n{}".format(body))
            except Exception as e:
                print("[!] Encryption in processHttpMessage failed:", e)

    def _should_intercept(self, path):
        return any(path.endswith(x) for x in ["verifyMemberSSO", "getAccountActivity", "verifyLoginOTP", "CreateFormValues", "sendLoginOTP", "getdataformhtml"])

    def extract_value(self, body, name, is_multipart):
        if is_multipart:
            pattern = r'name="{}"\s*\r\n\r\n(.*?)(?=\r\n--|$)'.format(re.escape(name))
        else:
            pattern = r'(?:^|&){}=([^&]*)'.format(re.escape(name))
        match = re.search(pattern, body, re.DOTALL)
        return match.group(1).strip() if match else None

    def safe_replace_value(self, body, name, new_value, is_multipart):
        if is_multipart:
            pattern = r'(name="{}"\s*\r\n\r\n)(.*?)(?=\r\n--|$)'.format(re.escape(name))
            return re.sub(pattern, lambda m: m.group(1) + new_value, body, flags=re.DOTALL)
        else:
            pattern = r'({}=)[^&]*'.format(re.escape(name))
            return re.sub(pattern, lambda m: m.group(1) + new_value, body)

    def parse_tab_content(self, text):
        parsed = {}
        matches = re.split(r"===== (.*?) =====\n", text)
        for i in range(1, len(matches), 2):
            field = matches[i].strip()
            value = matches[i + 1].strip()
            parsed[field] = value
        return parsed

    @staticmethod
    def encrypt_field_static(data, secretkey):
        md = MessageDigest.getInstance("SHA-256")
        key_bytes = md.digest(secretkey.encode("utf-8"))
        iv = array([Random().nextInt(256) - 128 for _ in range(16)], 'b')
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key_bytes, "AES"), IvParameterSpec(iv))
        encrypted = cipher.doFinal(data.encode("utf-8"))
        return binascii.hexlify(bytearray(iv)).decode() + ":" + binascii.hexlify(encrypted).decode()

class JSITab(IMessageEditorTab):
    last_input_text = None

    def __init__(self, callbacks, helpers, editable):
        self._callbacks = callbacks
        self._helpers = helpers
        self._editable = editable
        self._txtInput = JTextArea()
        self._txtInput.setLineWrap(True)
        self._scrollPane = JScrollPane(self._txtInput)
        self._currentMessage = None

    def getTabCaption(self):
        return "SourceData (decrypted)"

    def getUiComponent(self):
        return self._scrollPane

    def isEnabled(self, content, isRequest):
        return isRequest

    def setMessage(self, content, isRequest):
        self._currentMessage = content
        if content is None:
            self._txtInput.setText("")
            self._txtInput.setEditable(False)
            return

        request_info = self._helpers.analyzeRequest(content)
        body = content[request_info.getBodyOffset():].tostring()

        headers = request_info.getHeaders()
        content_type = next((h for h in headers if h.lower().startswith("content-type")), "").lower()
        is_multipart = "multipart/form-data" in content_type

        secretkey = self.extract_value(body, "secretkey", is_multipart)
        decrypted_fields = []

        if secretkey:
            for field in ["sourceData", "crudFlag", "set", "Date", "condition", "UserID", "OffsetMinutes", "ProfileID", "mobile", "otp", "EmailID", "MemberLoginID", "MemberType", "FormID"]:
                val = self.extract_value(body, field, is_multipart)
                if val and ":" in val:
                    decrypted = self.decrypt_field(secretkey, val)
                    decrypted_fields.append("===== {} =====\n{}".format(field, decrypted))

        text = "\n\n".join(decrypted_fields)
        self._txtInput.setText(text)
        self._txtInput.setEditable(self._editable)
        JSITab.last_input_text = text
        print("[*] setMessage tab content updated")

    def getMessage(self):
        try:
            JSITab.last_input_text = self._txtInput.getText()
            print("[*] getMessage updated values:", JSITab.last_input_text)

            updated_values = self._parse_updated_values(JSITab.last_input_text)
            request_info = self._helpers.analyzeRequest(self._currentMessage)
            headers = request_info.getHeaders()
            body = self._currentMessage[request_info.getBodyOffset():].tostring()

            content_type = next((h for h in headers if h.lower().startswith("content-type")), "").lower()
            is_multipart = "multipart/form-data" in content_type

            secretkey = self.extract_value(body, "secretkey", is_multipart)
            if not secretkey:
                return self._currentMessage

            for k, v in updated_values.items():
                if k in ("secretkey", "raw_text"):
                    continue
                encrypted = BurpExtender.encrypt_field_static(v, secretkey)
                body = self.safe_replace_value(body, k, encrypted, is_multipart)

            body = self.safe_replace_value(body, "secretkey", secretkey, is_multipart)
            print("[*] getMessage re-encrypt updated body:\n{}".format(body))
            return self._helpers.buildHttpMessage(headers, body)
        except Exception as e:
            print("[!] getMessage exception:", e)
            return self._currentMessage

    def isModified(self):
        return True

    def getSelectedData(self):
        return self._txtInput.getSelectedText()

    def extract_value(self, body, name, is_multipart):
        if is_multipart:
            pattern = r'name="{}"\s*\r\n\r\n(.*?)(?=\r\n--|$)'.format(re.escape(name))
        else:
            pattern = r'(?:^|&){}=([^&]*)'.format(re.escape(name))
        match = re.search(pattern, body, re.DOTALL)
        return match.group(1).strip() if match else None

    def safe_replace_value(self, body, name, new_value, is_multipart):
        if is_multipart:
            pattern = r'(name="{}"\s*\r\n\r\n)(.*?)(?=\r\n--|$)'.format(re.escape(name))
            return re.sub(pattern, lambda m: m.group(1) + new_value, body, flags=re.DOTALL)
        else:
            pattern = r'({}=)[^&]*'.format(re.escape(name))
            return re.sub(pattern, lambda m: m.group(1) + new_value, body)

    def decrypt_field(self, secretkey, data):
        try:
            iv_hex, ciphertext_hex = data.split(":")
            iv = binascii.unhexlify(iv_hex)
            ciphertext = binascii.unhexlify(ciphertext_hex)
            md = MessageDigest.getInstance("SHA-256")
            key_bytes = md.digest(secretkey.encode("utf-8"))
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key_bytes, "AES"), IvParameterSpec(iv))
            decrypted_bytes = cipher.doFinal(ciphertext)
            return decrypted_bytes.tostring()
        except Exception as e:
            return "[!] Decryption error: {}".format(e)

    def _parse_updated_values(self, raw_text):
        parsed = {}
        matches = re.split(r"===== (.*?) =====\n", raw_text)
        for i in range(1, len(matches), 2):
            field = matches[i].strip()
            value = matches[i + 1].strip()
            parsed[field] = value
        parsed["raw_text"] = raw_text
        return parsed
