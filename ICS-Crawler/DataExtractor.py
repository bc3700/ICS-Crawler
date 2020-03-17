from datetime import datetime, timedelta
import re

class DataExtractor:
    releaseDate = ""
    vendor = ""
    equipment = ""
    sector = ""
    deployed = ""
    headquarters = ""
    cweString = ""


    def __init__(self, soup):
        self.soup = soup

    def extractData(self):
        self.getReleaseDate()
        self.getLiInfo()
        self.getVulnInfo()

    def getReleaseDate(self):
        releaseDateTag = self.soup.findAll("div", {"class": "submitted meta-text"})[0]
        releaseDateString = releaseDateTag.text.strip()
        if("Last revised:" in releaseDateString):
            return None #COME BACK TO
        else:
            releaseDateList = releaseDateString.split(":")
            releaseDateString = releaseDateList[-1].strip()
            releaseDateString = releaseDateString.replace(",", "")
            self.releaseDate = datetime.strptime(releaseDateString, "%B %d %Y")

    def getLiInfo(self):
        mainContent = self.soup.findAll("div", {"id": "ncas-content"})[0]
        liTags = mainContent.findAll("li")
        for tag in liTags:
            if("Vendor" in tag.text):
                vendorList = tag.text.split(":")
                self.vendor = vendorList[-1].strip()

            if("Equipment" in tag.text):
                equipmentList = tag.text.split(":")
                self.equipment = equipmentList[-1].strip()

            if("CRITICAL INFRASTRUCTURE SECTORS" in tag.text):
                sectorList = tag.text.split(":")
                self.sector = sectorList[-1].strip()

            if("COUNTRIES/AREAS DEPLOYED" in tag.text):
                deployedList = tag.text.split(":")
                self.deployed = deployedList[-1].strip()

            if("COMPANY HEADQUARTERS LOCATION" in tag.text):
                headquartersList = tag.text.split(":")
                self.headquarters = headquartersList[-1].strip()

    def getVulnInfo(self):
        cweRegex = re.compile("CWE-[0-9]+")
        if (cweRegex.search(self.soup.text)):
            cweList = re.findall(cweRegex, self.soup.text)

            for cwe in cweList:
                self.cweString += cwe + ","