#!/usr/bin/python

# Copyright 2015, Axel Angel, under the GPLv3 license.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os, signal
import datetime, sys
import smtplib, poplib, imaplib
import base64
import yaml
import threading # FIXME: not needed with asyncore
import Queue
import socket
import time
import asyncore
import atexit
import tempfile
from parse import parse
from email.mime.text import MIMEText
from email.parser import Parser
from email.utils import formatdate
from smtpd import SMTPChannel, SMTPServer
from html2text import html2text

from yowsup.common import YowConstants
from yowsup import env
from yowsup.layers.auth import YowCryptLayer, YowAuthenticationProtocolLayer, \
        AuthError
from yowsup.layers.coder import YowCoderLayer
from yowsup.layers import YowLayerEvent
from yowsup.layers.interface import YowInterfaceLayer, ProtocolEntityCallback
from yowsup.layers.logger import YowLoggerLayer
from yowsup.layers.network import YowNetworkLayer
from yowsup.layers.protocol_acks import YowAckProtocolLayer
from yowsup.layers.protocol_acks.protocolentities \
        import OutgoingAckProtocolEntity
from yowsup.layers.protocol_media import YowMediaProtocolLayer
from yowsup.layers.protocol_media.protocolentities \
        import ImageDownloadableMediaMessageProtocolEntity
from yowsup.layers.protocol_media.protocolentities \
        import LocationMediaMessageProtocolEntity
from yowsup.layers.protocol_media.protocolentities \
        import VCardMediaMessageProtocolEntity
from yowsup.layers.protocol_media.protocolentities \
        import RequestUploadIqProtocolEntity
from yowsup.layers.protocol_presence.protocolentities \
        import AvailablePresenceProtocolEntity
from yowsup.layers.protocol_media.mediauploader import MediaUploader
from yowsup.layers.protocol_iq import YowIqProtocolLayer
from yowsup.layers.protocol_messages import YowMessagesProtocolLayer
from yowsup.layers.protocol_messages.protocolentities \
        import TextMessageProtocolEntity
from yowsup.layers.protocol_receipts import YowReceiptProtocolLayer
from yowsup.layers.protocol_receipts.protocolentities \
        import OutgoingReceiptProtocolEntity
from yowsup.layers.protocol_presence import YowPresenceProtocolLayer
from yowsup.layers.stanzaregulator import YowStanzaRegulator
#from yowsup.layers.axolotl import YowAxolotlLayer # FIXME
from yowsup.stacks import YowStack, YOWSUP_CORE_LAYERS


class MailLayer(YowInterfaceLayer):
    def __init__(self):
        YowInterfaceLayer.__init__(self)

    @ProtocolEntityCallback("success")
    def onSuccess(self, entity):
        print "<= WhatsApp: Logged in"
        self.toLower(AvailablePresenceProtocolEntity())

    @ProtocolEntityCallback("failure")
    def onFailure(self, entity):
        print "<= WhatsApp: Failure %s" % (entity)

    @ProtocolEntityCallback("notification")
    def onNotification(self, notification):
        print "<= WhatsApp: Notification %s" % (notification)

    @ProtocolEntityCallback("message")
    def onMessage(self, mEntity):
        if mEntity.getType() == 'text':
            self.onTextMessage(mEntity)
        elif mEntity.getType() == 'media':
            self.onMediaMessage(mEntity)

    @ProtocolEntityCallback("receipt")
    def onReceipt(self, entity):
        ack = OutgoingAckProtocolEntity(entity.getId(), "receipt",
                entity.getType(), entity.getFrom())
        if not args.dry:
            self.toLower(ack)

    def sendEmail(self, mEntity, subject, content):
        timestamp = catch(lambda: mEntity.getTimestamp(), time.time())
        isbroadcast = catch(lambda: mEntity.isBroadcast(), False)
        srclong = mEntity.getFrom(full = True)
        srcShort = mEntity.getFrom(full = False)
        niceName = mEntity.getNotify()
        participant = catch(lambda: mEntity.getParticipant(), None) or srcShort
        replyAddr = config['reply'].format(srcShort)
        dst = config['outgoing']['sendto']

        formattedDate = datetime.datetime.fromtimestamp(timestamp) \
                                         .strftime('%d/%m/%Y %H:%M')
        content2 = "%s\n\nAt %s by %s (%s) isBroadCast=%s" \
                % (content, formattedDate, niceName, participant,
                    isbroadcast)

        if args.debug:
            print "subject {%s}, content {%s}, content2 {%s}" % (subject, content, content2)

        msg = MIMEText(content2, 'plain', 'utf-8')
        msg['To'] = "WhatsApp <%s>" % (dst)
        msg['From'] = "%s <%s>" % (niceName, srclong)
        msg['Date'] = formatdate(timestamp)
        msg['Reply-To'] = "%s <%s>" % (niceName, replyAddr)
        msg['Subject'] = subject

        confout = config['outgoing']
        if confout.get('ssl', True):
            s_class = smtplib.SMTP_SSL
        else:
            s_class = smtplib.SMTP

        s = s_class(confout['host'], confout.get('port', 25))

        if confout.get('smtp_user', None):
            s.login(confout.get('smtp_user'), confout.get('smtp_pass'))

        if not confout.get('force_startssl', True):
            try:
                s.starttls() # Some servers require it, let's try
            except smtplib.SMTPException:
                print "<= Mail: Server doesn't support STARTTLS"
                if confout.get('force_starttls'):
                    raise

        if args.debug:
            print "dst {%s}, msg.as_string {%s}" % (dst, msg.as_string())
        s.sendmail(dst, [dst], msg.as_string())
        s.quit()
        print "=> Mail: %s -> %s" % (replyAddr, dst)

    def onTextMessage(self, mEntity):
        receipt = OutgoingReceiptProtocolEntity(mEntity.getId(),
                mEntity.getFrom())

        src = mEntity.getFrom()
        print("<= WhatsApp: <- %s Message" % (src))

        content = mEntity.getBody()
        self.sendEmail(mEntity, content, content)
        if not args.dry:
            self.toLower(receipt)

    def onMediaMessage(self, mEntity):
        id = mEntity.getId()
        src = mEntity.getFrom()
        tpe = mEntity.getMediaType()
        url = getattr(mEntity, 'url', None)

        print("<= WhatsApp: <- Media %s (%s)" % (tpe, src))

        content = "Received a media of type: %s\n" % (tpe)
        content += "URL: %s\n" % (url)
        content += str(mEntity)
        self.sendEmail(mEntity, "Media: %s" % (tpe), content)

        receipt = OutgoingReceiptProtocolEntity(id, src)
        if not args.dry:
            self.toLower(receipt)


class YowsupMyStack(object):
    def __init__(self, credentials):
        env.CURRENT_ENV = env.S40YowsupEnv()
        self.layer = MailLayer()
        layers = (
            self.layer,
            (YowPresenceProtocolLayer, YowAuthenticationProtocolLayer,
                YowMessagesProtocolLayer, YowReceiptProtocolLayer,
                YowAckProtocolLayer, YowMediaProtocolLayer, YowIqProtocolLayer,
            ),
            #YowAxolotlLayer, # FIXME: This prevents us from sending messages!
        ) + YOWSUP_CORE_LAYERS

        self.stack = YowStack(layers)
        self.stack.setProp(YowAuthenticationProtocolLayer.PROP_CREDENTIALS,
                credentials)
        self.stack.setProp(YowNetworkLayer.PROP_ENDPOINT,
                YowConstants.ENDPOINTS[0])
        self.stack.setProp(YowCoderLayer.PROP_DOMAIN, YowConstants.DOMAIN)
        self.stack.setProp(YowCoderLayer.PROP_RESOURCE,
                env.CURRENT_ENV.getResource())

    def startInputThread(self):
        print "Starting input thread"
        confinc = config['ingoing']
        if confinc['with'] == "LMTP":
            sockpath = confinc['socket']
            self.server = YoLMTPServer(self.layer, sockpath, None)
            atexit.register(clean_lmtp)
        elif confinc['with'] == "SMTP":
            host = confinc['host']
            port = confinc['port']
            self.server = YoSMTPServer(self.layer, (host, port), None)
        elif confinc['with'] == "POP3":
           self.server = Pop3Client(self.layer, confinc)
        elif confinc['with'] == "IMAP":
           self.server = ImapClient(self.layer, confinc)
        else:
            raise Exception("Unknown ingoing type")

    def start(self):
        self.startInputThread()
        self.server.start()

        self.stack.broadcastEvent(
                YowLayerEvent(YowNetworkLayer.EVENT_STATE_CONNECT))

        try:
            while True:
                # FIXME: polling for IMAP and POP3, use async instead
                self.stack.loop(timeout = 10, count = 1)
                self.server.loop()
        except AuthError as e:
            print("Authentication Error: %s" % e.message)


class LMTPChannel(SMTPChannel):
  # LMTP "LHLO" command is routed to the SMTP/ESMTP command
  def smtp_LHLO(self, arg):
    self.smtp_HELO(arg)

  def smtp_EHLO(self, arg):
    self.smtp_HELO(arg)


class MailParserMixin():
    def __init__(self, yowsup):
        self._yowsup = yowsup

    def loop(self): # FIXME: threads aren't needed with asyncore
        pass

    def send_yowsup(self, phone, data):
        m = Parser().parsestr(data)
        try:
            txt = mail_to_txt(m)
            if args.debug:
                print "! mail_to_txt: {%s}" % (txt)
        except Exception as e:
            return "501 malformed content: %s" % (str(e))

        jid = normalizeJid(phone)

        # send text, if any
        if len(txt.strip()) > 0:
            msg = TextMessageProtocolEntity(txt, to = jid)
            print "=> WhatsApp: -> %s" % (jid)
            self._yowsup.toLower(msg)

        # send media that were attached pieces
        if m.is_multipart():
            for pl in getattr(m, '_payload', []):
                self.handle_forward_media(jid, pl)
        return False


    def handle_forward_media(self, jid, pl):
            jid = normalizeJid(phone)
            # send text, if any
            if len(txt.strip()) > 0:
                msg = TextMessageProtocolEntity(txt, to = jid)
                print "=> WhatsApp: -> %s" % (jid)
                if not args.dry:
                    self._yowsup.toLower(msg)
                if args.debug:
                    print "! Message: {%s}" % (txt)
                    print "! from entity: {%s}" % (msg.getBody())

            # send media that were attached pieces
            if m.is_multipart():
                for pl in getattr(m, '_payload', []):
                    self.handle_forward_media(jid, pl)
                    if args.debug:
                        print "! Attachement: %s" % (pl)

    def handle_forward_media(self, jid, pl):
        ct = pl.get('Content-Type', 'None')
        ct1 = ct.split('/', 1)[0]
        iqtp = None
        if ct1 == 'text':
            return # this is the body, probably
        if ct1 == 'image':
            iqtp = RequestUploadIqProtocolEntity.MEDIA_TYPE_IMAGE
        if ct1 == 'audio':
            iqtp = RequestUploadIqProtocolEntity.MEDIA_TYPE_AUDIO
        if ct1 == 'video':
            iqtp = RequestUploadIqProtocolEntity.MEDIA_TYPE_VIDEO
        if ct.startswith('multipart/alternative'): # recursive content
            for pl2 in pl._payload:
                self.handle_forward_media(jid, pl2)
        if iqtp == None:
            print "<= Mail: Skip unsupported attachement type %s" % (ct)
            return

        print "<= Mail: Forward attachement %s" % (ct1)
        data = mail_payload_decoded(pl)
        tmpf = tempfile.NamedTemporaryFile(prefix='whatsapp-upload_',
                delete=False)
        tmpf.write(data)
        tmpf.close()
        fpath = tmpf.name
        # FIXME: need to close the file!

        entity = RequestUploadIqProtocolEntity(iqtp, filePath=fpath)
        def successFn(successEntity, originalEntity):
            return self.onRequestUploadResult(
                    jid, fpath, successEntity, originalEntity)
        def errorFn(errorEntity, originalEntity):
            return self.onRequestUploadError(
                    jid, fpath, errorEntity, originalEntity)

        self._yowsup._sendIq(entity, successFn, errorFn)

    def onRequestUploadResult(self, jid, fpath, successEntity, originalEntity):
        if successEntity.isDuplicate():
            url = successEntity.getUrl()
            ip = successEntity.getIp()
            print "<= WhatsApp: upload duplicate %s, from %s" % (fpath, url)
            self.send_uploaded_media(fpath, jid, url, ip)
        else:
            ownjid = self._yowsup.getOwnJid()
            mediaUploader = MediaUploader(jid, ownjid, fpath,
                                      successEntity.getUrl(),
                                      successEntity.getResumeOffset(),
                                      self.onUploadSuccess,
                                      self.onUploadError,
                                      self.onUploadProgress,
                                      async=False)
            print "<= WhatsApp: start upload %s, into %s" \
                    % (fpath, successEntity.getUrl())
            mediaUploader.start()

    def onUploadSuccess(self, fpath, jid, url):
        print "WhatsApp: -> upload success %s" % (fpath)
        self.send_uploaded_media(fpath, jid, url)

    def onUploadError(self, fpath, jid=None, url=None):
        print "WhatsApp: -> upload failed %s" % (fpath)
        ownjid = self._yowsup.getOwnJid()
        fakeEntity = TextMessageProtocolEntity("", _from = ownjid)
        self._yowsup.sendEmail(fakeEntity, "WhatsApp upload failed",
                "File: %s" % (fpath))

    def onUploadProgress(self, fpath, jid, url, progress):
        print "WhatsApp: -> upload progression %s for %s, %d%%" \
                % (fpath, jid, progress)

    def send_uploaded_media(self, fpath, jid, url, ip = None):
        entity = ImageDownloadableMediaMessageProtocolEntity.fromFilePath(
                fpath, url, ip, jid)
        if not args.dry:
            self._yowsup.toLower(entity)

    def onRequestUploadError(self, jid, fpath, errorEntity, originalEntity):
        print "WhatsApp: -> upload request failed %s" % (fpath)
        self._yowsup.sendEmail(errorEntity, "WhatsApp upload request failed",
                "File: %s" % (fpath))


class MailClient(MailParserMixin):
    def __init__(self, yowsup, confinc):
        self.host = confinc['host']
        self.port = confinc['port']
        self.user = confinc['user']
        self.password = confinc['pass']
        self.poll_wait = confinc.get('poll_wait', 60)
        self.ssl = confinc.get('ssl', True)

        self.messageQueue = Queue.Queue()
        self._yowsup = yowsup
        # FIXME: use asyncore instead
        self.thread = threading.Thread(target=self.worker)

    def start(self):
        self.thread.daemon = True
        self.thread.start()

    def loop(self): # FIXME: threads aren't needed with asyncore
        try:
            while True:
                m_str = self.messageQueue.get(block=False)
                m = Parser().parsestr(m_str)
                dst = m.get('to')
                try:
                    (phone,) = parse(config.get('reply'), dst)
                except TypeError:
                    if args.debug:
                        print "mail doesn't match reply: %s" % (dst)
                    break
                if args.debug:
                    print "got a message in MailClient's queue for:", phone
                self.send_yowsup(dest, msg)
        except Queue.Empty:
            pass


class Pop3Client(MailClient):
    def worker(self):
        while True:
            if self.ssl:
                pop_class = poplib.POP3_SSL
            else:
                pop_class = poplib.POP3

            pop3 = pop_class(self.host, self.port)
            pop3.user(self.user)
            pop3.pass_(self.password)

            numMessages = len(pop3.list()[1])
            for midx in range(1, numMessages+1):
                print "<= POP3: Mail id %i" % (midx)
                for msg in pop3.retr(midx)[1]:
                    self.messageQueue.put(msg)
                # to avoid resending
                pop3.dele(midx) # FIXME: shouldn't delete message

            pop3.quit()

            time.sleep(self.poll_wait)


class ImapClient(MailClient):
    def worker(self):
        while True:
            if self.ssl:
                imap_class = imaplib.IMAP4_SSL
            else:
                imap_class = imaplib.IMAP4

            imap = imaplib.IMAP4_SSL(self.host, self.port)
            imap.login(self.user, self.password)
            imap.select()

            typ, data = imap.search(None, '(UNSEEN)')
            for num in data[0].split():
                print "<= IMAP: Mail id %s" % (num)
                typ, data = imap.fetch(num, '(RFC822)')
                m_str = data[0][1]
                self.messageQueue.put(m_str)

            imap.close()
            imap.logout()

            time.sleep(self.poll_wait)


class MailServer(SMTPServer, MailParserMixin):
    def start(self):
        pass

    def handle_accept(self):
        conn, addr = self.accept()
        channel = LMTPChannel(self, conn, addr)

    def process_message(self, peer, mailfrom, rcpttos, data):
        m = Parser().parsestr(data)
        print "<= Mail: %s -> %s" % (mailfrom, rcpttos)

        try:
            txt = mail_to_txt(m)
            if args.debug:
                print "! mail_to_txt: {%s}" % (txt)
        except Exception as e:
            return "501 malformed content: %s" % (str(e))

        for dst in rcpttos:
            try:
                (phone,) = parse(config.get('reply'), dst)
            except TypeError:
                print "malformed dst: %s" % (dst)
                return "501 malformed recipient: %s" % (dst)

            ret = self.send_yowsup(phone, data)
            if ret:
                return ret


class YoLMTPServer(MailServer):
    def __init__(self, yowsup, localaddr, remoteaddr):
        # code taken from original SMTPServer code
        self._yowsup = yowsup
        self._localaddr = localaddr
        self._remoteaddr = remoteaddr
        asyncore.dispatcher.__init__(self)
        try:
            self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
            # try to re-use a server port if possible
            self.set_reuse_addr()
            self.bind(localaddr)
            self.listen(5)
        except:
            # cleanup asyncore.socket_map before raising
            self.close()
            raise

class YoSMTPServer(MailServer):
    def __init__(self, yowsup, localaddr, remoteaddr):
        # code taken from original SMTPServer code
        self._yowsup = yowsup
        self._localaddr = localaddr
        self._remoteaddr = remoteaddr
        asyncore.dispatcher.__init__(self)
        try:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            # try to re-use a server port if possible
            self.set_reuse_addr()
            self.bind(localaddr)
            self.listen(5)
        except:
            # cleanup asyncore.socket_map before raising
            self.close()
            raise


def mail_payload_decoded(pl):
    t = pl.get_payload()
    if pl.get('Content-Transfer-Encoding', None) == "base64":
        t = base64.b64decode(t)
    return t

def mail_to_txt(m):
    if not m.is_multipart():
        # simple case for text/plain
        return mail_payload_decoded(m)

    else:
        # handle when there are attachements (take first text/plain)
        for pl in m._payload:
            if "text/plain" in pl.get('Content-Type', None):
                return mail_payload_decoded(pl)
        # otherwise take first text/html
        for pl in m._payload:
            if "text/html" in pl.get('Content-Type', None):
                return html2text(mail_payload_decoded(pl))
        # otherwise search into recursive message
        for pl in m._payload:
            try:
                if "multipart/alternative" in pl.get('Content-Type', None):
                    return mail_to_txt(pl)
            except:
                continue # continue to next attachment

        raise Exception("No text could be extracted found")

def loadConfig(fpath):
    with open(fpath, 'rb') as fd:
        config = yaml.load(fd)
        return config

def normalizeJid(number):
    if '@' in number:
        return number
    elif "-" in number:
        return "%s@g.us" % number

    return "%s@s.whatsapp.net" % number

def clean_lmtp():
    try:
        os.unlink(config['ingoing'].get('socket'))
    except OSError:
        pass

def catch(f, default):
    try:
        return f()
    except:
        return default

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--config', default='config.yaml',
            help='configuration file path')
    p.add_argument('--debug', action='store_true', default=False,
            help='show more information during processing')
    p.add_argument('--dry', action='store_true', default=False,
            help='disable sending to WhatsApp')
    args = p.parse_args()

    print "Parsing config: %s" % (args.config)
    config = loadConfig(args.config)

    print "Starting"
    confwhats = config['whatsapp']
    stack = YowsupMyStack((confwhats.get('phone'), confwhats.get('password')))
    print "Connecting"
    try:
        stack.start()
    except KeyboardInterrupt:
        print "Terminated by user"
