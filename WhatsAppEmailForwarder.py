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
import smtplib
import base64
import yaml
import threading
import socket
import time
import asyncore
import atexit
from email.mime.text import MIMEText
from email.parser import Parser
from email.utils import formatdate
from smtpd import SMTPChannel, SMTPServer

from yowsup.common import YowConstants
from yowsup import env
from yowsup.layers.auth import YowCryptLayer, YowAuthenticationProtocolLayer, \
        AuthError
from yowsup.layers.axolotl import YowAxolotlLayer
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
from yowsup.layers.protocol_iq import YowIqProtocolLayer
from yowsup.layers.protocol_messages import YowMessagesProtocolLayer
from yowsup.layers.protocol_messages.protocolentities \
        import TextMessageProtocolEntity
from yowsup.layers.protocol_receipts import YowReceiptProtocolLayer
from yowsup.layers.protocol_receipts.protocolentities \
        import OutgoingReceiptProtocolEntity
from yowsup.layers.stanzaregulator import YowStanzaRegulator
from yowsup.stacks import YowStack

config_file = 'whatsapp_config'


class MailLayer(YowInterfaceLayer):
    def __init__(self):
        YowInterfaceLayer.__init__(self)
        self.startInputThread()

    def startInputThread(self):
        print "Starting input thread"
        server = LMTPServer(self, config.get('socket'), None)
        atexit.register(clean_socket)

    @ProtocolEntityCallback("success")
    def onSuccess(self, entity):
        print "<= WhatsApp: Logged in"

    @ProtocolEntityCallback("failure")
    def onFailure(self, entity):
        print "<= WhatsApp: Failure %s" % (entity)

    @ProtocolEntityCallback("notification")
    def onNotification(self, notification):
        print "<= WhatsApp: Notification %s" % (notification)

    @ProtocolEntityCallback("message")
    def onMessage(self, mEntity):
        if not mEntity.isGroupMessage():
            if mEntity.getType() == 'text':
                self.onTextMessage(mEntity)
            elif mEntity.getType() == 'media':
                self.onMediaMessage(mEntity)
        else:
            src = mEntity.getFrom()
            print "<= WhatsApp: <- %s GroupMessage" % (src)

    @ProtocolEntityCallback("receipt")
    def onReceipt(self, entity):
        ack = OutgoingAckProtocolEntity(entity.getId(), "receipt", "delivery")
        self.toLower(ack)

    def onTextMessage(self, mEntity):
        receipt = OutgoingReceiptProtocolEntity(mEntity.getId(),
                mEntity.getFrom())

        txt = mEntity.getBody()
        src = mEntity.getFrom()
        srcShort = mEntity.getFrom(full = False)
        print("<= WhatsApp: <- %s Message" % (src))

        timestamp = mEntity.getTimestamp()
        formattedDate = datetime.datetime.fromtimestamp(timestamp) \
                                         .strftime('%d/%m/%Y %H:%M')

        replyAddr = config.get('reply') % (srcShort)

        txt2 = "%s\n\nAt %s by %s (%s) isBroadCast=%s" \
                % (txt, formattedDate, srcShort, mEntity.getParticipant(),
                    mEntity.isBroadcast())

        dst = config.get('sendto')
        msg = MIMEText(txt2, 'plain', 'utf-8')
        msg['To'] = "WhatsApp <%s>" % (dst)
        msg['From'] = "%s <%s>" % (srcShort, mEntity.getParticipant())
        msg['Reply-To'] = "%s <%s>" % (mEntity.getParticipant(), replyAddr)
        msg['Subject'] = txt
        msg['Date'] = formatdate(timestamp)

        if config.get('smtp_ssl'):
            s_class = smtplib.SMTP_SSL
        else:
            s_class = smtplib.SMTP

        s = s_class(config.get('smtp'))

        if not config.get('smtp_ssl'):
            try:
                s.starttls() # Some servers require it, let's try
            except SMTPException:
                print "<= Mail: Server doesn't support STARTTLS"
                if config.get('force_starttls'):
                    raise

        s.sendmail(dst, [dst], msg.as_string())
        s.quit()
        print "=> Mail: %s -> %s" % (replyAddr, dst)

        self.toLower(receipt)

    def onMediaMessage(self, mEntity):
        id = mEntity.getId()
        src = mEntity.getFrom()
        tpe = mEntity.getMediaType()

        # TODO: Send media email for these
        if mEntity.getMediaType() == "image":
            url = mEntity.url
            print("<= WhatsApp: <- %s Image (%s)" % (src, url))

            receipt = OutgoingReceiptProtocolEntity(id, src)
            self.toLower(receipt)

        elif mEntity.getMediaType() == "location":
            lat = mEntity.getLatitude()
            lon = mEntity.getLongitude()
            print("<= WhatsApp: <- %s Location (%s, %s)" % (src, lat, lon))

            receipt = OutgoingReceiptProtocolEntity(id, src)
            self.toLower(receipt)

        elif mEntity.getMediaType() == "vcard":
            name = mEntity.getName()
            vcard = mEntity.getCardData()
            print("<= WhatsApp: <- %s vCard (%s)" % (src, vcard))

            receipt = OutgoingReceiptProtocolEntity(id, src)
            self.toLower(receipt)

        else:
            print("<= WhatsApp: <- %s Media (%s)" % (tpe, src))


class YowsupMyStack(object):
    def __init__(self, credentials):
        env.CURRENT_ENV = env.S40YowsupEnv()
        layers = (
            MailLayer,
            (YowAuthenticationProtocolLayer, YowMessagesProtocolLayer,
                YowReceiptProtocolLayer, YowAckProtocolLayer,
                YowMediaProtocolLayer, YowIqProtocolLayer),
            YowLoggerLayer,
            YowCoderLayer,
            YowCryptLayer,
            YowStanzaRegulator,
            YowNetworkLayer
        )

        self.stack = YowStack(layers)
        self.stack.setProp(YowAuthenticationProtocolLayer.PROP_CREDENTIALS,
                credentials)
        self.stack.setProp(YowNetworkLayer.PROP_ENDPOINT,
                YowConstants.ENDPOINTS[0])
        self.stack.setProp(YowCoderLayer.PROP_DOMAIN, YowConstants.DOMAIN)
        self.stack.setProp(YowCoderLayer.PROP_RESOURCE,
                env.CURRENT_ENV.getResource())

    def start(self):
        self.stack.broadcastEvent(
                YowLayerEvent(YowNetworkLayer.EVENT_STATE_CONNECT))

        try:
            self.stack.loop()
        except AuthError as e:
            print("Authentication Error: %s" % e.message)


class LMTPChannel(SMTPChannel):
  # LMTP "LHLO" command is routed to the SMTP/ESMTP command
  def smtp_LHLO(self, arg):
    self.smtp_HELO(arg)

  def smtp_EHLO(self, arg):
    self.smtp_HELO(arg)


class LMTPServer(SMTPServer):
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

    def handle_accept(self):
        conn, addr = self.accept()
        channel = LMTPChannel(self, conn, addr)

    def process_message(self, peer, mailfrom, rcpttos, data):
        # TODO: Add support for sending media as attached file
        m = Parser().parsestr(data)
        print "<= Mail: %s -> %s" % (mailfrom, rcpttos)

        try:
            txt = mail_to_txt(m)
        except e:
            return "501 raised exception: %s" % (str(e))

        for dst in rcpttos:
            parts = dst.split('@')[0].split('+', 1)
            if not (parts[0] == 'whatsapp' and len(parts) == 2):
                print "malformed dst: %s" % (dst)
                return "501 malformed recipient: %s" % (dst)

            jid = normalizeJid(parts[1])
            msg = TextMessageProtocolEntity(txt, to = jid)
            print "=> WhatsApp: -> %s" % (jid)
            self._yowsup.toLower(msg)


def mail_to_txt(m):
    if not m.is_multipart():
        # simple case for text/plain
        return m.get_payload()

    else:
        # handle when there are attachements (take first text/plain)
        for pl in m._payload:
            if "text/plain" in pl.get('Content-Type', None):
                return pl.get_payload()

        raise Exception("No text/plain found, but required by RFC 2046 5.1.4")

def loadConfig():
    with open(config_file, 'rb') as fd:
        config = yaml.load(fd)
        return config

def normalizeJid(number):
    if '@' in number:
        return number
    elif "-" in number:
        return "%s@g.us" % number

    return "%s@s.whatsapp.net" % number

def clean_socket():
    try:
        os.unlink(config.get('socket'))
    except OSError:
        pass

if __name__ == "__main__":
    print "Parsing config"
    config = loadConfig()

    print "Starting"
    stack = YowsupMyStack((config.get('phone'), config.get('password')))
    print "Connecting"
    try:
        stack.start()
    except KeyboardInterrupt:
        print "Terminated by user"
