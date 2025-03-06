# -*- coding: utf-8 -*-
"""
Created on Sat Mar  1 18:58:18 2025

@author: Алексей Черемных alekseycheremnykh.ru
"""

import os
import sys
import requests
import platform
import subprocess
import ctypes
import shutil
import tempfile
from urllib.parse import urlparse
import json

from PySide2.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, QPushButton, QLabel, QMessageBox, QMenuBar, QMenu
from PySide2.QtCore import Qt
from PySide2.QtUiTools import QUiLoader
from PySide2.QtGui import QIcon

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

def save_selected_lists(selected_lists):
    with open(CONFIG_FILE, "w") as f:
        json.dump({"selected_lists": selected_lists}, f)

def load_selected_lists():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                return config.get("selected_lists", [])
        except:
            return []
    return []

HOSTS_FILE = None

# Определение пути к файлу hosts в зависимости от ОС
def get_hosts_path():
    system = platform.system().lower()
    if system == "windows":
        return "C:\\Windows\\System32\\drivers\\etc\\hosts"
    elif system == "linux":
        return "/etc/hosts"
    else:
        raise OSError(f"Unsupported OS: {system}")

def is_admin():
    if platform.system().lower() == 'windows':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        return os.geteuid() == 0

def elevate_privileges():
    if platform.system().lower() == 'windows':
        if not is_admin():
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit()
    else:
        if not is_admin():
            try:
                os.execvp('sudo', ['sudo', sys.executable] + sys.argv)
            except:
                sys.exit(1)

HOSTS_FILE = get_hosts_path()

APP_NAME = "ZloBlocker"
APP_VERSION = "1.0"
APP_AUTHOR = "Алексей Черемных"
APP_SITE = "alekseycheremnykh.ru"

LIST_URLS = {
    "MVPS": "https://winhelp2002.mvps.org/hosts.txt",
    "StevenBlack_ADs": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "Abuse_urlhaus": "https://urlhaus.abuse.ch/downloads/hostfile/",
    "Yoyo": "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts",
    "Adaway": "https://adaway.org/hosts.txt",
    "D_Me_ADs": "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
    "D_Me_Tracking": "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "Edwin_Email": "https://raw.githubusercontent.com/edwin-zvs/email-providers/master/email-providers.csv",
    "SWC": "https://someonewhocares.org/hosts/hosts",
    "D_Me_Malv": "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt",
    "D_Me_Malw": "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt",
    "Maltrail_BD": "https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt",
    "Spam404": "https://raw.githubusercontent.com/Dawsey21/Lists/master/main-blacklist.txt",
    "SFS_Toxic_BD": "https://www.stopforumspam.com/downloads/toxic_domains_whole.txt",
    "BBcan177 MS_2": "https://gist.githubusercontent.com/BBcan177/4a8bf37c131be4803cb2/raw",
    "TheGreatWall_DoH": "https://raw.githubusercontent.com/Sekhan/TheGreatWall/master/TheGreatWall.txt",
    "Bambenek_DoH": "https://raw.githubusercontent.com/bambenek/block-doh/master/doh-hosts.txt",
    "Oneoffdallas_DoH": "https://raw.githubusercontent.com/oneoffdallas/dohservers/master/list.txt",
    "Abuse_ThreatFox": "https://threatfox.abuse.ch/downloads/hostfile/",
    "AntiSocial_UK_BD": "https://raw.githubusercontent.com/TheAntiSocialEngineer/AntiSocial-BlockList-UK-Community/main/UK-Community.txt",
    "AZORult_BD": "https://azorult-tracker.net/api/list/domain?format=plain",
    "Botvrij_Dom": "https://www.botvrij.eu/data/ioclist.domain.raw",
    "Magento": "https://raw.githubusercontent.com/gwillem/magento-malware-scanner/master/rules/burner-domains.txt",
    "Maltrail_Blackbook": "https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt",
    "StevenBlack_BD": "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts",
    "VXVault": "http://vxvault.net/URL_List.php",
    "Krog_BD": "https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts",
    "KAD_BD": "https://raw.githubusercontent.com/azet12/KADhosts/master/KADhosts.txt",
    "Kowabit": "https://list.kwbt.de/fritzboxliste.txt",
    "Joewein_base": "https://www.joewein.net/dl/bl/dom-bl-base.txt",
    "Joewein_new": "https://www.joewein.net/dl/bl/dom-bl.txt",
    "Piwik_Spam": "https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt",
    "Quidsup_Trackers": "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt",
    "Quidsup_Mal": "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt",
    "Yhonay_BD": "https://raw.githubusercontent.com/Yhonay/antipopads/master/hosts",
    "yHosts": "https://raw.githubusercontent.com/vokins/yhosts/master/hosts.txt",
    "MoneroMiner": "https://raw.githubusercontent.com/Hestat/minerchk/master/hostslist.txt",
    "NoCoin": "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
    "ENUMER_STUN": "https://enumer.org/public-stun.txt",
    "NGOSANG_TORRENT": "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt",
    "Prigent_Crypto": "https://v.firebog.net/hosts/Prigent-Crypto.txt",
    "PhishingArmy": "https://phishing.army/download/phishing_army_blocklist.txt",
    "Phishing_Army Расширенный": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "Prigent_Malware": "https://v.firebog.net/hosts/Prigent-Malware.txt",
    "Risky_Hosts": "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts",
    "APT1_Report": "https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt",    
    "KADhosts": "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
    "FM_Spam": "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
    "WaLLy3Ks": "https://v.firebog.net/hosts/static/w3kbl.txt",
    "Matomo_Spam": "https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt",
    "SWC Ad": "https://someonewhocares.org/hosts/zero/hosts",
    "neoHosts basic": "https://cdn.jsdelivr.net/gh/neoFelhz/neohosts@gh-pages/basic/hosts",
    "neoHosts Full": "https://cdn.jsdelivr.net/gh/neoFelhz/neohosts@gh-pages/full/hosts",
    "SNAFU_List": "https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt",
    "BarbBlock": "https://paulgb.github.io/BarbBlock/blacklists/hosts-file.txt",
    "Adguard_DNS": "https://v.firebog.net/hosts/AdguardDNS.txt",
    "LanikSJ": "https://v.firebog.net/hosts/Admiral.txt",
    "Anudeep_BL": "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "Easylist_FB": "https://v.firebog.net/hosts/Easylist.txt",
    "PL_Adservers": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    "Fademinds": "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts",
    "Ad_Wars": "https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts",
    "Easyprivacy": "https://v.firebog.net/hosts/Easyprivacy.txt",
    "Prigent_Ads": "https://v.firebog.net/hosts/Prigent-Ads.txt",
    "Fademind_2o7": "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts",
    "Max_MS": "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
    "Frogeye_First": "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
    "Frogeye_Multi": "https://hostfiles.frogeye.fr/multiparty-trackers-hosts.txt",
    "Lightswitch05": "https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
    "Perflyst_Android": "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt",
    "Perflyst_TV": "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt",
    "DandelionSprouts": "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
    "DigitalSide": "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
    "Chad_Mayfield": "https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list",
    "Chad_Mayfield_1M": "https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list",
    "Anudeep_Facebook": "https://raw.githubusercontent.com/anudeepND/blacklist/master/facebook.txt",
    "OpenPhish": "https://openphish.com/feed.txt",
}

# Описания для источников
LIST_DESCRIPTIONS = {
    "MVPS": "Популярный список для блокировки рекламы, вредоносных сайтов и трекеров",
    "StevenBlack_ADs": "Объединенный список от StevenBlack для блокировки рекламы и трекеров",
    "Abuse_urlhaus": "Список вредоносных доменов от abuse.ch",
    "Yoyo": "Список для блокировки рекламных серверов",
    "Adaway": "Список для блокировки мобильной рекламы",
    "D_Me_ADs": "Список рекламных доменов от Disconnect.me",
    "D_Me_Tracking": "Список трекеров от Disconnect.me",
    "Edwin_Email": "Список доменов популярных почтовых сервисов",
    "SWC": "Список от Dan Pollock для блокировки рекламы и вредоносных сайтов",
    "D_Me_Malv": "Список доменов для вредоносной рекламы от Disconnect.me",
    "D_Me_Malw": "Список вредоносных доменов от Disconnect.me",
    "Maltrail_BD": "Список вредоносных доменов от проекта Maltrail",
    "Spam404": "Список мошеннических и вредоносных доменов",
    "SFS_Toxic_BD": "Список токсичных доменов от StopForumSpam",
    "BBcan177 MS_2": "Список вредоносных доменов от BBcan177",
    "TheGreatWall_DoH": "Список доменных имен DoH-провайдеров",
    "Bambenek_DoH": "Список доменных имен DoH-провайдеров",
    "Oneoffdallas_DoH": "Список доменных имен DoH-провайдеров",
    "Abuse_ThreatFox": "Список индикаторов компрометации (IOCs) в формате host-файла, предоставляемый abuse.ch в рамках проекта ThreatFox",
    "AntiSocial_UK_BD": "Список доменов, связанных с вредоносной активностью, такой как фишинг и распространение вредоносного ПО",
    "AZORult_BD": "Список доменов, связанных с вредоносным ПО AZORult, который предоставляется AZORult Tracker",
    "Botvrij_Dom": "Список доменов, связанных с вредоносной деятельностью, предоставляемый Botvrij.eu",
    "Magento": "Список доменов, которые используются злоумышленниками для распространения вредоносного ПО или сбора данных со взломанных сайтов, работающих на платформе Magento",
    "Maltrail_Blackbook": "Список доменов, связанных с вредоносной деятельностью",
    "StevenBlack_BD": "Список доменов блокировки нежелательного контента, такого как реклама, вредоносное ПО и отслеживания",
    "VXVault": "Список последних 100 добавленных вредоносных URL-адресов. В HOSTS попадут только доменные имена",
    "Krog_BD": "Список доменов, связанных с вредоносным ПО, рекламным ПО, программами-вымогателями, порнографией и другими нежелательными веб-сайтами",
    "KAD_BD": "Список доменов, которые были идентифицированы как связанные с мошенничеством, вирусами, поддельными интернет-магазинами и другими онлайн-угрозами",
    "Kowabit": "Список потенциально опасных или нежелательных доменов, созданный проектом kowabit.de",
    "Joewein_base": "Список доменов, предназначенный для борьбы со спамом и онлайн-мошенничеством",
    "Joewein_new": "Список доменов, связанных со спамом, фишингом и другими видами вредоносной активности",
    "Piwik_Spam": "Список доменов, используемых для реферального спама (referrer spam), который искажает данные веб-аналитики",
    "Quidsup_Trackers": "Список доменов, связанных с отслеживанием пользователей (tracking) и рекламой",
    "Quidsup_Mal": "Список доменов, которые были классифицированы как вредоносные, фишинговые или рекламные",
    "Yhonay_BD": "Список доменов, которые были замечены в навязчивой и вредоносной всплывающей рекламе",
    "yHosts": "Список доменов для блокировки рекламы и трекеров, который создан и поддерживается сообществом на GitHub",
    "MoneroMiner": "Список доменов, связанных с криптоджекингом (cryptojacking).",
    "NoCoin": "Список доменов, связанных с криптоджекингом (cryptojacking).",
    "ENUMER_STUN":  "Список публичных STUN-серверов (Session Traversal Utilities for NAT).",
    "NGOSANG_TORRENT": "Список публичных BitTorrent трекеров.",
    "Prigent_Crypto": "Список доменов, связанных с криптоджекингом.",
    "PhishingArmy": "Список доменов, которые связаны с фишинговыми атаками.",
    "Phishing_Army Расширенный": "Расширенный список доменов, связанных с фишинговыми атаками.",
    "Prigent_Malware": "Список доменов, связанных с распространением вредоносного ПО.",
    "Risky_Hosts": "Список доменов, содержащих рискованный контент, включая вредоносное ПО.",
    "APT1_Report": "Cписок доменов, связанных с китайской кибершпионской группировкой APT1.",
    "KADhosts": "Список доменов, связанных с мошенничеством (например, фишинг, поддельные магазины), вредоносным ПО (вирусы, трояны, ransomware) и платными подписками на SMS (scam-сайты, обманные предложения). Список поддерживается Polish Filters Team.",
    "FM_Spam": "Список доменов, которые связаны со спамом и другими видами злоупотреблений.",
    "WaLLy3Ks": "Список доменов, связанных с рекламой, отслеживанием и фишингом.",
    "Matomo_Spam": "Список доменов, используемых для реферального спама (referrer spam), который искажает данные веб-аналитики.",
    "SWC Ad": "Список доменов, связанных с рекламой, отслеживанием и вредоносным ПО. Данный список отличается от указанного в разделе Зловредные ресурсы.",
    "neoHosts basic": "Список доменов, связанных с рекламой, отслеживанием и вредоносным ПО.",
    "neoHosts Full": "Подходит для пользователей, которые хотят максимальной защиты, но готовы столкнуться с повышенной нагрузкой на систему и к ложным сработкам.",
    "SNAFU_List": "Список доменов для блокировки рекламы и трекеров, созданный специально для использования с Pi-hole.",
    "BarbBlock": "Список доменов, которые используются для принудительного показа рекламы (например, реклама, которая обходит блокировщики рекламы).",
    "Adguard_DNS": "Список доменов, используемых для блокировки рекламы, трекеров и вредоносных ресурсов через DNS-фильтрацию.",
    "LanikSJ": "Список доменов для блокировки трекеров, телеметрии и рекламных сервисов, связанных с платформой Admiral и другими аналогичными системами.",
    "Anudeep_BL": "Список доменов для блокировки рекламных серверов, созданный разработчиком Anudeep ND.",
    "Easylist_FB": "Зеркало базового фильтра EasyList, который был адаптирован для DNS-фильтрации. Это однин из старейших и самых популярных списков для блокировки рекламы в браузерах.",
    "PL_Adservers": "Список доменов для блокировки рекламных серверов и трекеров, созданный Peter Lowe.",
    "Fademinds": "Список доменов для блокировки рекламы и нежелательного контента, связанного с установщиками программного обеспечения.",
    "Ad_Wars": "Список доменов, связанных с рекламой, трекерами и потенциально вредоносные домены.",
    "Easyprivacy": "Адаптированная версия популярного фильтра EasyPrivacy, который предназначен для блокировщиков рекламы (adblock) в браузерах.",
    "Prigent_Ads": "Список доменов, связанных с рекламными серверами, трекерами и другими нежелательными ресурсами.",
    "Fademind_2o7": "список доменов для блокировки отслеживания 2o7.",
    "Max_MS": "Список доменов для блокировки телеметрии, отслеживающих сервисов и других функций Windows, которые могут нарушать приватность пользователей.",
    "Frogeye_First": "Список доменов, связанных с трекерами первого уровня (first-party trackers), которые используются для сбора данных о пользователях непосредственно на сайте, который они посещают.",
    "Frogeye_Multi": "Список доменов, предназначенный для блокировки так называемых multi-party trackers (многосторонних трекеров).",
    "Lightswitch05": "Расширенный список доменов для блокировки рекламы и отслеживания.",
    "Perflyst_Android": "Список доменов для блокировки трекеров, рекламы и других элементов, связанных с Android-приложениями.",
    "Perflyst_TV": "Список доменов для блокировки метаданных, телеметрии и рекламы, связанных со Smart TV.",
    "DandelionSprouts": "Список доменов для блокировки вредоносного ПО. Список содержит спонсируемые Windows PUP nags (potentially unwanted programs).",
    "DigitalSide": "Список вредоносных доменов, используемыми в кибератаках. Он содержит домены за последние 7 дней.",
    "Chad_Mayfield": "Список доменов, связанных с порнографией, входящих в топ-1 миллион сайтов Alexa. Размер больше 45 MB.",
    "Chad_Mayfield_1M": "Список доменов, связанных с порнографией. Размер списка около 21 тысячи доменов.",
    "Anudeep_Facebook": "Список доменов, связанных с Facebook, который может использоваться для блокировки отслеживания, рекламы и другого нежелательного контента, связанного с Facebook.",
    "OpenPhish": "Список фишинговых сайтов от OpenPhish",
}

# Категории и соответствующие им источники
CATEGORIES = {
    "Реклама и трекеры": ["StevenBlack_ADs", "Quidsup_Trackers", "yHosts", "Yhonay_BD", 
                        "Yoyo", "MVPS", "Adaway", "D_Me_ADs", "D_Me_Tracking", 
                        "SWC Ad", "neoHosts basic", "neoHosts Full", "SNAFU_List",
                        "BarbBlock", "Adguard_DNS", "LanikSJ", "Anudeep_BL",
                        "Easylist_FB", "PL_Adservers", "Fademinds", "Ad_Wars",
                        "Easyprivacy", "Prigent_Ads", "Fademind_2o7", "Max_MS",
                        "Frogeye_First", "Frogeye_Multi", "Lightswitch05",
                        "Perflyst_Android", "Perflyst_TV", "Anudeep_Facebook"],
    "Зловредные ресурсы": ["Abuse_urlhaus", "BBcan177 MS_2", "SFS_Toxic_BD", "MVPS", "Spam404", "SWC", "Maltrail_BD", "D_Me_Malv", "D_Me_Malw",
                           "Abuse_ThreatFox", "AntiSocial_UK_BD", "AZORult_BD", "Botvrij_Dom", "Magento", "Maltrail_Blackbook", "StevenBlack_BD",
                           "VXVault", "Krog_BD", "KAD_BD", "Kowabit", "Joewein_base", "Joewein_new", "Piwik_Spam", "Quidsup_Trackers", "Quidsup_Mal",
                           "Yhonay_BD", "yHosts", "Prigent_Malware", "Risky_Hosts", "WaLLy3Ks",
                           "APT1_Report", "KADhosts", "FM_Spam", "DandelionSprouts",
                           "DigitalSide"],
    "Другое": ["Edwin_Email", "ENUMER_STUN", "NGOSANG_TORRENT", "Matomo_Spam",
                "Chad_Mayfield", "Chad_Mayfield_1M"],
    "Фишинг": ["PhishingArmy", "Phishing_Army Расширенный", "OpenPhish"],
    "DNS-over-HTTPS": ["TheGreatWall_DoH", "Bambenek_DoH", "Oneoffdallas_DoH"],
    "Cryptojacking": ["MoneroMiner", "NoCoin", "Prigent_Crypto"],
}

# Описания для категорий
CATEGORY_DESCRIPTIONS = {
    "Реклама и трекеры": "Блокировка рекламных сетей и сервисов отслеживания",
    "Зловредные ресурсы": "Блокировка вредоносных сайтов, вирусов и malware",
    "Другое": "Списки, которые не подходят под имеющиеся категории",
    "Фишинг": "Блокировка фишинговых сайтов",
    "DNS-over-HTTPS": "Блокировка серверов DNS-over-HTTPS для предотвращения обхода блокировок",
    "Cryptojacking": "Использование вычислительных ресурсов устройства пользователя (CPU/GPU) для майнинга криптовалют без его ведома.",
}

def update_hosts_file(domains):
    hosts_path = get_hosts_path()
    temp_hosts = os.path.join(os.path.expanduser("~"), ".hosts.tmp")
    
    try:
        with open(hosts_path, "r", encoding="utf-8") as f:
            original_content = f.readlines()

        start_marker = "# !!!! Начало зловредных доменов\n"
        end_marker = "# !!!! Конец зловредных доменов\n"
        
        if platform.system().lower() == 'linux':
            if not is_admin():
                content = []
                in_custom_section = False
                for line in original_content:
                    if line == start_marker:
                        in_custom_section = True
                        continue
                    if line == end_marker:
                        in_custom_section = False
                        continue
                    if not in_custom_section and "0.0.0.0" not in line:
                        content.append(line)
                
                content.append(start_marker)
                for domain in domains:
                    content.append(f"0.0.0.0 {domain}\n")
                content.append(end_marker)
                
                try:
                    with open(temp_hosts, 'w', encoding='utf-8') as tf:
                        tf.write(''.join(content))
                    
                    args = ['sudo', 'bash', '-c', f'cat "{temp_hosts}" > "{hosts_path}" && chmod 644 "{hosts_path}" && rm -f "{temp_hosts}"']
                    proc = subprocess.run(args, capture_output=True, text=True)
                    
                    if proc.returncode != 0:
                        raise Exception(f"Failed to update hosts file: {proc.stderr}")
                    
                    return True
                except Exception as e:
                    if os.path.exists(temp_hosts):
                        try:
                            os.unlink(temp_hosts)
                        except:
                            pass
                    raise Exception(f"Error updating hosts file: {str(e)}")
            else:
                with open(temp_hosts, "w", encoding="utf-8") as f:
                    in_custom_section = False
                    for line in original_content:
                        if line == start_marker:
                            in_custom_section = True
                            continue
                        if line == end_marker:
                            in_custom_section = False
                            continue
                        if not in_custom_section and "0.0.0.0" not in line:
                            f.write(line)
                    
                    f.write(start_marker)
                    for domain in domains:
                        f.write(f"0.0.0.0 {domain}\n")
                    f.write(end_marker)
                
                shutil.move(temp_hosts, hosts_path)
                os.chmod(hosts_path, 0o644)
        else:
            with open(temp_hosts, "w", encoding="utf-8") as f:
                in_custom_section = False
                for line in original_content:
                    if line == start_marker:
                        in_custom_section = True
                        continue
                    if line == end_marker:
                        in_custom_section = False
                        continue
                    if not in_custom_section and "0.0.0.0" not in line:
                        f.write(line)
                
                f.write(start_marker)
                for domain in domains:
                    f.write(f"0.0.0.0 {domain}\n")
                f.write(end_marker)
            
            shutil.move(temp_hosts, hosts_path)
        
        return True
    except Exception as e:
        if os.path.exists(temp_hosts):
            try:
                os.remove(temp_hosts)
            except:
                pass
        raise e

def create_scheduled_task():
    system = platform.system().lower()
    exe_path = os.path.abspath(sys.executable)
    
    if system == "windows":
        try:
            subprocess.run('schtasks /delete /tn "ZloBlockerUpdate" /f', shell=True, stderr=subprocess.DEVNULL)
            command = f'schtasks /create /tn "ZloBlockerUpdate" /tr "{exe_path} --update" /sc hourly /mo 4'
            subprocess.run(command, check=True, shell=True)
            return True
        except subprocess.CalledProcessError:
            return False
    elif system == "linux":
        if not is_admin():
            elevate_privileges()
            return False
            
        cron_job = f"0 */4 * * * sudo {exe_path} --update\n"
        temp_cron = "/tmp/zloblocker_cron"
        try:
            subprocess.run(f"crontab -l > {temp_cron} 2>/dev/null || touch {temp_cron}", shell=True)
            with open(temp_cron, "r") as f:
                lines = f.readlines()
            with open(temp_cron, "w") as f:
                for line in lines:
                    if exe_path not in line:
                        f.write(line)
                f.write(cron_job)
            subprocess.run(f"crontab {temp_cron}", shell=True, check=True)
            os.remove(temp_cron)
            return True
        except:
            if os.path.exists(temp_cron):
                os.remove(temp_cron)
            return False
    return False

def download_domains(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        # Отключаем проверку SSL для некоторых сайтов
        verify_ssl = not any(domain in url.lower() for domain in ['openphish.com', 'urlhaus.abuse.ch', 'abuse.ch', 'vxvault.net', 'azorult-tracker.net', 'list.kwbt.de', 'joewein.net', 'enumer.org', 'someonewhocares.org', 'osint.digitalside.it', 'hostfiles.frogeye.fr', 'www.botvrij.eu', 'pgl.yoyo.org', 'cdn.jsdelivr.net', 'adaway.org', 'winhelp2002.mvps.org', 'raw.githubusercontent.com', 'mirror.cedia.org.ec', 'malc0de.com'])
        
        # Отключаем предупреждения для незащищенных запросов
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        response = requests.get(url, timeout=30, headers=headers, verify=verify_ssl)
        response.raise_for_status()
        domains = []
        
        # Определяем, является ли это CSV файлом
        is_csv = url.endswith('.csv')
        
        # Используем UTF-8 кодировку для текста
        response.encoding = 'utf-8'
        
        for line in response.text.splitlines():
            line = line.strip()
            if not line:
                continue
                
            # Убираем комментарии, оставляя только домен
            if line.startswith('#'):
                continue
            
            # Обработка строк с комментариями после домена
            if '#' in line:
                line = line.split('#')[0].strip()
            
            if is_csv:
                try:
                    # Для CSV файла с email-провайдерами берем первую колонку
                    parts = line.split(',')
                    if len(parts) > 0:
                        domain = parts[0].strip()
                        if domain and domain != "domain" and "." in domain:  # Пропускаем заголовок и проверяем на валидность
                            domains.append(domain)
                except Exception:
                    continue
            else:
                # Для OpenPhish и подобных списков, содержащих полные URL
                if "://" in line:
                    try:
                        parsed = urlparse(line)
                        domain = parsed.netloc
                        # Убираем порт если есть
                        if ":" in domain:
                            domain = domain.split(":")[0]
                        if domain and "." in domain:
                            domains.append(domain)
                    except Exception:
                        continue
                # Для списков с IP-адресами (MVPS, StevenBlack, Abuse_urlhaus)
                elif line.startswith("0.0.0.0 ") or line.startswith("127.0.0.1 "):
                    try:
                        parts = line.split()
                        if len(parts) > 1:
                            domain = parts[1].strip()
                            if domain and domain != "localhost" and not domain.startswith("::"):
                                domains.append(domain)
                    except Exception:
                        continue
                # Для списков только с доменами (Yoyo, Quidsup)
                elif "." in line and " " not in line:
                    domain = line.strip()
                    if domain and domain != "localhost" and not domain.startswith("::"):
                        domains.append(domain)
                    
        return list(set(domains))  # Удаляем дубликаты
    except requests.exceptions.RequestException as e:
        print(f"Ошибка загрузки списка доменов: {e}")
        return None

def remove_custom_entries():
    hosts_path = get_hosts_path()
    temp_hosts = hosts_path + ".tmp"
    
    try:
        with open(hosts_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        with open(temp_hosts, "w", encoding="utf-8") as f:
            in_our_section = False
            for line in lines:
                if line.strip() == "# !!!! Начало зловредных доменов":
                    in_our_section = True
                    continue
                if line.strip() == "# !!!! Конец зловредных доменов":
                    in_our_section = False
                    continue
                if not in_our_section:
                    f.write(line)
        
        shutil.move(temp_hosts, hosts_path)
        return True
    except Exception as e:
        if os.path.exists(temp_hosts):
            os.remove(temp_hosts)
        raise e

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        
        if platform.system().lower() == 'linux':
            ui_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.ui")
            try:
                loader = QUiLoader()
                self.ui = loader.load(ui_file_path)
            except:
                self.ui = QWidget()
                loadUi(ui_file_path, self.ui)
        else:
            loader = QUiLoader()
            ui_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.ui")
            self.ui = loader.load(ui_file_path)
        
        # Установка иконки
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zloblocker.ico")
        if os.path.exists(icon_path):
            self.ui.setWindowIcon(QIcon(icon_path))
        
        # Подключение действий меню
        self.ui.actionAbout.triggered.connect(self.show_about)
        self.ui.actionExit.triggered.connect(self.ui.close)
        
        # Подключение сигналов
        self.ui.updateButton.clicked.connect(self.update_hosts)
        self.ui.scheduleButton.clicked.connect(self.schedule_task)
        self.ui.removeCustomEntriesButton.clicked.connect(self.remove_entries)
        self.ui.categoryComboBox.currentTextChanged.connect(self.update_visible_checkboxes)
        self.ui.categoryComboBox.currentTextChanged.connect(self.update_category_description)
        
        # Установка начального статуса и отображения чекбоксов
        self.set_status("готов к работе")
        self.update_visible_checkboxes(self.ui.categoryComboBox.currentText())
        self.update_category_description(self.ui.categoryComboBox.currentText())
        
        # Загружаем сохраненные списки
        selected_lists = load_selected_lists()
        if selected_lists:
            for checkbox in self.ui.findChildren(QCheckBox):
                if checkbox.text() in selected_lists:
                    checkbox.setChecked(True)
        
        # Отображаем главное окно
        self.ui.show()
        
    def show_about(self):
        QMessageBox.information(self.ui, "О программе", 
                              f"{APP_NAME}\nВерсия {APP_VERSION}\nАвтор {APP_AUTHOR}\nСайт {APP_SITE}\nЛицензия GNU GPL v2")
    
    def set_status(self, text):
        self.ui.statusLabel.setText(f"Статус: {text}")
        QApplication.processEvents()

    def update_visible_checkboxes(self, category):
        # Сначала скрываем все существующие чекбоксы
        for checkbox in self.ui.findChildren(QCheckBox):
            checkbox.hide()
            
        # Показываем чекбоксы для выбранной категории
        if category in CATEGORIES:
            for source in CATEGORIES[category]:
                checkbox = self.ui.findChild(QCheckBox, source)
                if not checkbox:
                    # Создаем новый чекбокс, если его еще нет
                    checkbox = QCheckBox(source)
                    checkbox.setObjectName(source)
                    checkbox.setFixedHeight(25)
                    self.ui.checkboxLayout.addWidget(checkbox)
                    description = LIST_DESCRIPTIONS.get(source, "")
                    checkbox.setToolTip(f"{description}\nURL: {LIST_URLS[source]}")
                    checkbox.stateChanged.connect(lambda state, name=source: self.save_checkbox_state(name, state))
                checkbox.show()
                
    def update_category_description(self, category):
        description = CATEGORY_DESCRIPTIONS.get(category, "")
        self.ui.categoryComboBox.setToolTip(description)

    def save_checkbox_state(self, name, state):
        """Сохраняет состояние чекбокса"""
        checkbox = self.ui.findChild(QCheckBox, name)
        if checkbox:
            checkbox.setChecked(state == Qt.Checked)

    def update_hosts(self):
        self.set_status("скачиваю списки доменов")
        selected_domains = []
        failed_downloads = []
        selected_lists = []
        
        try:
            for checkbox in self.ui.findChildren(QCheckBox):
                if checkbox.isChecked():
                    selected_lists.append(checkbox.text())
                    self.set_status(f"скачиваю список {checkbox.text()}")
                    try:
                        domains = download_domains(LIST_URLS[checkbox.text()])
                        if domains and isinstance(domains, list):
                            selected_domains.extend(domains)
                        else:
                            failed_downloads.append(checkbox.text())
                    except Exception as e:
                        print(f"Ошибка загрузки списка {checkbox.text()}: {str(e)}")
                        failed_downloads.append(checkbox.text())
            
            # Сохраняем выбранные списки
            save_selected_lists(selected_lists)
            
            if failed_downloads:
                error_msg = f"Не удалось загрузить следующие списки: {', '.join(failed_downloads)}"
                self.set_status(error_msg)
                return
            
            if not selected_domains:
                self.set_status("не выбраны списки или ошибка загрузки")
                return
            
            # Сначала удаляем старые записи
            remove_custom_entries()
            
            self.set_status("обновляю файл hosts")
            if update_hosts_file(selected_domains):
                self.set_status("готово! файл hosts обновлен")
            else:
                self.set_status("ошибка при обновлении файла")
        except Exception as e:
            self.set_status(f"ошибка: {str(e)}")

    def remove_entries(self):
        self.set_status("удаляю добавленные записи")
        if remove_custom_entries():
            self.set_status("готово! записи удалены")
        else:
            self.set_status("ошибка при удалении записей")

    def schedule_task(self):
        if create_scheduled_task():
            QMessageBox.information(None, "Успех", "Задание в планировщике создано. Обновление будет происходить каждые 4 часа.")
        else:
            QMessageBox.critical(None, "Ошибка", "Не удалось создать задание в планировщике.")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--update":
        if not is_admin():
            elevate_privileges()
            sys.exit(0)
        selected_lists = load_selected_lists()
        if selected_lists:
            domains = []
            for list_name in selected_lists:
                if list_name in LIST_URLS:
                    downloaded_domains = download_domains(LIST_URLS[list_name])
                    if downloaded_domains:
                        domains.extend(downloaded_domains)
            if domains:
                try:
                    update_hosts_file(list(set(domains)))
                except Exception as e:
                    print(f"Ошибка обновления файла hosts: {e}")
            sys.exit(0)
    else:
        if not is_admin():
            elevate_privileges()
            sys.exit(0)
        app = QApplication(sys.argv)
        window = MainWindow()
        sys.exit(app.exec_())

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--update":
        if not is_admin():
            elevate_privileges()
            sys.exit(0)
            
        try:
            selected_lists = load_selected_lists()
            all_domains = set()
            
            for list_name in selected_lists:
                if list_name in LIST_URLS:
                    domains = download_domains(LIST_URLS[list_name])
                    if domains:
                        all_domains.update(domains)
            
            if all_domains:
                update_hosts_file(list(all_domains))
        except Exception as e:
            pass
        finally:
            sys.exit(0)
    else:
        if is_admin():
            main()
        else:
            elevate_privileges()