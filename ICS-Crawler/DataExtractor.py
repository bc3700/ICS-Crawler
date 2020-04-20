from datetime import datetime, timedelta
import re

class DataExtractor:
    releaseDate = ""
    vendor = ""
    equipment = ""
    vulnerability = ""
    sector = ""
    deployed = ""
    headquarters = ""
    cweString = ""
    cveString = ""
    lastRevisedDate = None

    def __init__(self, soup):
        self.soup = soup

    def extractData(self):
        self.getReleaseDate()
        self.getGeneralInfo("li")
        self.getGeneralInfo("p")
        self.getVulnInfo()
        self.getCveInfo()

    def getReleaseDate(self):
        releaseDateTag = self.soup.findAll("div", {"class": "submitted meta-text"})[0]
        releaseDateString = releaseDateTag.text.strip()
        if("Last revised:" in releaseDateString):
            dateList = releaseDateString.strip().split("|")
            releaseDateString = dateList[0]
            lastRevisedDateString = dateList[1]
            lastRevisedDateList = lastRevisedDateString.split(":")
            lastRevisedDateString = lastRevisedDateList[-1].strip()
            lastRevisedDateString = lastRevisedDateString.replace(",", "")
            self.lastRevisedDate = datetime.strptime(lastRevisedDateString, "%B %d %Y")

        releaseDateList = releaseDateString.split(":")
        releaseDateString = releaseDateList[-1].strip()
        releaseDateString = releaseDateString.replace(",", "")
        self.releaseDate = datetime.strptime(releaseDateString, "%B %d %Y")

    def getGeneralInfo(self, tagName):
        foundVendor = False
        foundEquipment = False
        foundVulnerability = False
        foundSector = False
        foundDeployed = False
        foundHeadquarters = False

        if(self.vendor != ""):
            foundVendor = True
        if(self.equipment != ""):
            foundEquipment = True
        if(self.vulnerability != ""):
            foundVulnerability = True
        if(self.sector != ""):
            foundSector = True
        if(self.deployed != ""):
            foundDeployed = True
        if(self.headquarters != ""):
            foundHeadquarters = True

        if((foundVendor and foundEquipment and foundVulnerability and foundSector and foundDeployed and foundHeadquarters) == True):
            return

        mainContent = self.soup.findAll("div", {"id": "ncas-content"})[0]
        tags = mainContent.findAll(tagName)
        for tag in tags:
            upperTagText = tag.text.upper()
            if("VENDOR:" in upperTagText):
                vendorList = tag.text.split(":")
                self.vendor = vendorList[-1].strip()

            elif("EQUIPMENT:" in upperTagText):
                equipmentList = tag.text.split(":")
                self.equipment = equipmentList[-1].strip()

            elif (("VULNERABILITY:" in upperTagText or "VULNERABILITIES:" in upperTagText) and self.vulnerability == ""):
                vulnerabilityList = tag.text.split(":")
                self.vulnerability = vulnerabilityList[-1].strip()

            elif("CRITICAL INFRASTRUCTURE SECTOR:" in upperTagText or "CRITICAL INFRASTRUCTURE SECTORS:" in upperTagText):
                sectorListString = tag.text.split(":")[-1]
                sectorList = sectorListString.split(",")
                print(sectorList[-1])
                if(sectorList[-1].strip()[0:3] == "and"):
                    sectorList[-1] = sectorList[-1].strip()[3:]
                    sectorListString = ""
                    for i in range(len(sectorList)):
                        if(i == len(sectorList) -1):
                            sectorListString += sectorList[i]
                        else:
                            sectorListString += sectorList[i] + ","
                self.sector = sectorListString

            elif("COUNTRIES/AREAS DEPLOYED:" in upperTagText):
                deployedList = tag.text.split(":")
                self.deployed = deployedList[-1].strip()

            elif("COMPANY HEADQUARTERS LOCATION:" in upperTagText):
                headquartersList = tag.text.split(":")
                self.headquarters = headquartersList[-1].strip()

    def getVulnInfo(self):
        cweRegex = re.compile("CWE-[0-9]+")
        if (cweRegex.search(self.soup.text)):
            cweList = re.findall(cweRegex, self.soup.text)
            cweList = list(set(cweList))

            for cwe in cweList:
                self.cweString += cwe + ","

    def getCveInfo(self):
        cveRegex = re.compile("CVE-[0-9]+-[0-9]+")
        if (cveRegex.search(self.soup.text)):
            cveList = re.findall(cveRegex, self.soup.text)
            cveList = list(set(cveList))

            for cve in cveList:
                self.cveString += cve + ","