import logging, paramiko, ConfigParser, time, datetime, subprocess, os, re
from stix.core import STIXPackage, STIXHeader
from cybox.common import Time
from stix.incident import Incident, ImpactAssessment
from stix.incident.impact_assessment import Effects
from stix.incident import Time as incidentTime
from stix.common import InformationSource
from stix.common import Identity, Indicator, Address
from cabby import create_client

generalSettingsFile = "settings.cfg"
watchSettingsFile = "watches.cfg"

def getGeneralSettings(path=generalSettingsFile):
    Config = ConfigParser.ConfigParser()
    Config.read(path)
    items = Config.items("Settings")
    settings = {}
    for i in items:
        newItem = {i[0] : i[1]}
        settings.update(newItem)
        newItem = {}
    return settings

def getWatchSettings(watchName, path=watchSettingsFile):
    Config = ConfigParser.ConfigParser()
    Config.read(path)
    items = Config.items(watchName)
    settings = {}
    for i in items:
        newItem = {i[0]:i[1]}
        settings.update(newItem)
        newItem = {}
    return settings

def getWatchNames(path=watchSettingsFile):
    Config = ConfigParser.ConfigParser()
    Config.read(path)
    watches = Config.sections()
    return watches

def getLastCheck(watchName, path=watchSettingsFile):
    Config = ConfigParser.ConfigParser()
    Config.read(path)
    lastCheck = Config.get(watchName, 'lastcheck')
    return lastCheck

def setLastCheck(watchName, newLastCheck, path=watchSettingsFile):
    Config = ConfigParser.ConfigParser()
    Config.read(path)
    oldLastCheck = Config.get(watchName, 'lastcheck')
    success = False
    if oldLastCheck != newLastCheck:
        try:
            Config.set(watchName, 'lastcheck', newLastCheck)
            with open(path, 'wb') as configFile:
                Config.write(configFile)
                success = True
        except:
            success = False
    return success

def getLastModificationTime(watchName):
    proc = subprocess.Popen("date -r " + getWatchSettings(watchName)["watchfilepath"], stdout=subprocess.PIPE)
    out, err = proc.communicate()
    logging.error(err)
    return out

def readLastModificationTime(watchName, path=watchSettingsFile):
    Config = ConfigParser.ConfigParser()
    Config.read(path)
    return Config.get(watchName, 'lastmodification')

def setLastModificationTime(watchName, path=watchSettingsFile):
    Config = ConfigParser.ConfigParser()
    Config.read(path)
    success = False
    if Config.get(watchName, 'lastmodification') != getLastModificationTime(watchName):
        try:
            Config.set(watchName, 'lastmodification', getLastModificationTime(watchName))
            with open(path, 'wb') as configFile:
                Config.write(configFile)
                success = True
        except:
            success = False
            logging.error("unable to write watch settings file (" + watchSettingsFile + ") @setLastModificationTime().")
    return success

def deleteNoticeFile(watchName):
    proc = subprocess.Popen("rm " + getWatchSettings(watchName)["watchfilepath"], stdout=subprocess.PIPE)
    out, err = proc.communicate()
    logging.error(err)
    logging.info(out)
    if os.path.exists(getWatchSettings(watchName)["watchfilepath"]):
        return False
    else:
        return True

def getNotices(watchName):
    notices = []
    if os.path.exists(getWatchSettings(watchName)["watchfilepath"]):
        f = open(getWatchSettings(watchName)["watchfilepath"], "r")
        content = f.read()
        f.close()
        if content is not None:
            for line in content.splitlines():
                if line.startswith("#fields"):
                    line = line.replace("#fields", "")
                    keys = line.split()
            for line in content.splitlines():
                if not line.startswith("#"):
                    values = line.split()
            notice = dict(zip(keys, values))
            notices.append(notice)
            return notices

def startWatch(watchName):
    startTime = time.time()
    while True:
        client = create_client(getGeneralSettings()["host"], use_https=getGeneralSettings()["use_https"], discovery_path=getGeneralSettings()["discoverypath"])
        if getNotices(watchName) is not None:
            for notice in getNotices(watchName):
                content = createSTIXMessage(notice)
                binding = getGeneralSettings()["binding"]
                uri = getGeneralSettings()["uri"]
                try:
                    client.push(content, binding, uri=uri)
                    setLastModificationTime(watchName)
                    deleteNoticeFile(watchName)
                except Exception as e:
                    print str(e)
                    logging.error("unable to push STIX message @startWatch().")
        setLastCheck(watchName, time.strftime('%Z %Y-%m-%d %H%:%M:%s', time.localtime(time.time())))
        time.sleep(int(getWatchSettings(watchName)["checkinterval"]) - ((time.time() - startTime) % int(getWatchSettings(watchName)["checkinterval"])))

def createSTIXMessage(notice={}):

    stix_package = STIXPackage()

    # add incident and confidence
    breach = Incident()
    breach.description = getGeneralSettings()["messagedescription"]
    breach.confidence = getGeneralSettings()["messageconfidence"]

    # stamp with reporter
    breach.reporter = InformationSource()
    breach.reporter.description = getGeneralSettings()["reporterdescription"]

    breach.reporter.time = Time()
    breach.reporter.time.produced_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(notice["ts"])))

    breach.reporter.identity = Identity()
    breach.reporter.identity.name = getGeneralSettings()["reporterdescription"]

    # set incident-specific timestamps
    breach.time = incidentTime()
    if "src" in notice.keys():
        breach.title = notice["src"] + " performed a port scan."
    elif "name" and "id.orig_h" in notice.keys():
        breach.title = notice["name"] + " from " + notice["id.orig_h"] 

    breach.time.initial_compromise = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(notice["ts"])))
    breach.time.incident_discovery = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(notice["ts"])))
    breach.time.restoration_achieved = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(notice["ts"])))
    breach.time.incident_reported = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(notice["ts"])))

    # add the impact
    impact = ImpactAssessment()
    impact.effects = Effects(getGeneralSettings()["incidenteffect"])
    breach.impact_assessment = impact

    # add the victim
    victim = Identity()
    victim.name = getGeneralSettings()["companyname"]
    breach.add_victim(victim)

    stix_package.add_incident(breach)
    return stix_package

def createSTIXMessage2(notice={}):
    header = STIXHeader()
    header.title = "" #

    pkg = STIXPackage()
    pkg.stix_header = header

    ind = Indicator()
    ind.title = "Port Scan Detection"
    ind.add_indicator_type("Port scan detection")

    addr = Address()
    if "src" in notice.keys():
        addr.address_value = notice["src"]
    elif "id.orig_h" in notice.keys():
        addr.address_value = notice["id.orig_h"]
    addr.category = 'ipv4-addr'
    addr.condition = "Equals"

def send():
    generalSettings = getGeneralSettings(generalSettingsFile)
    contentFile = generalSettings["contentfile"]
    host = generalSettings["host"]
    discovery = generalSettings["discovery"]
    binding = generalSettings["binding"]
    subtype = generalSettings["subtype"]
    command = ['taxii-push', '--host', host, '--https', '--discovery', discovery, '--content-file', contentFile, '--binding', binding, '--sbutype', subtype]
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    except:
        logging.error("unable to send the message @send().")
    return process.returncode

startWatch("weird")