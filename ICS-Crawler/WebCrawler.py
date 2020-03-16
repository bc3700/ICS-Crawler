import os
import sys
import threading, queue, multiprocessing
import requests
from bs4 import BeautifulSoup
import re
import sqlite3
from datetime import datetime, timedelta


class WebCrawler:
    """
    This class creates a webcrawler object that finds any instances of CVEs from links provided in a text file and saves it to a database

    Attributes:
        dbName (string): string containing the filename of the database for CVEs
        foundCVEs (array): array of CVEs already found by the webcrawler
        visited (array): array of URLs already visited by the webcrawler
    """
    dbName = "ICSDatabase.db"
    foundIcsaList = []
    visitedList = []
    crawlList = ["/icsa-20-072-01"]
    baseUrl = "https://www.us-cert.gov/ics/advisories"
    lastPage = 0

    def __init__(self):
        """
        Constructor for WebCrawler class
        """

        if not os.path.isfile(self.dbName):
            self.createDatabase()
        else:
            self.populateFoundICSAs()
            self.populateRecentlyCrawled(7)
        #self.getLastPageNum()
        #self.getLinksToCrawl()

    def createDatabase(self):
        """
        Creates a database to store the CVEs found during the _crawl function
        :return: None
        """
        conn = sqlite3.connect(self.dbName)
        c = conn.cursor()
        c.execute('''CREATE TABLE ICS (icsa_id text not null,
                                        full_page_url text not null, 
                                        crawl_date text not null, 
                                        content blob,
                                        PRIMARY KEY(icsa_id, full_page_url));''')
        conn.commit()
        conn.close()

    def populateFoundICSAs(self):
        """
        Searches the database for CVEs already listed
        :return:
        """
        conn = sqlite3.connect(self.dbName)
        c = conn.cursor()
        c.execute('SELECT icsa_id, full_page_url FROM ICS')
        self.foundIcsaList = c.fetchall()
        conn.close()

    def populateRecentlyCrawled(self, days):
        """
        Creates a list of recently crawled links that is populated from the database.
        Recently is determined by the number of days passed into the function
        :param days: Number of days back you want to exclude links from the crawl function
        :return:
        """
        crawlDateCheck = datetime.strftime(datetime.now() - timedelta(days = days), "%Y-%m-%d")

        conn = sqlite3.connect(self.dbName)
        conn.row_factory = lambda cursor, row: row[0]
        c = conn.cursor()
        c.execute('SELECT DISTINCT full_page_url FROM ICS WHERE crawl_date > ' + crawlDateCheck)
        self.visitedList = c.fetchall()
        conn.close()

    def getLastPageNum(self):
        pageList = []

        try:
            r = requests.get(self.baseUrl)
        except requests.exceptions.RequestException as e:
            print(e)
        html_content = r.text
        soup = BeautifulSoup(html_content)
        for link in soup.findAll('a'):
            fullLink = link.get('href')

            if fullLink != None:
                if fullLink.lower().startswith("?page="):
                    pageList.append(fullLink)
        lastPage = pageList[-1].strip("?page=")
        self.lastPage = int(lastPage)

    def getLinksToCrawl(self):
        for i in range(self.lastPage + 1):
            print("CRAWLING PAGE " + str(i))
            urlToCrawl = self.baseUrl + "?page=" + str(i)
            try:
                r = requests.get(urlToCrawl)
            except requests.exceptions.RequestException as e:
                print(e)
            html_content = r.text
            soup = BeautifulSoup(html_content)
            for link in soup.findAll('a'):
                fullLink = link.get('href')
                if fullLink != None:
                    if fullLink.lower().startswith("/ics/advisories/icsa"):
                        splitLink = fullLink.split("/")
                        self.crawlList.append("/" + splitLink[3])
                        print(splitLink[3])


    def crawl(self):
        """
        Goes through each link in the crawlList and checks for instances of CVEs. If found, the CVE is saved to a database along with the raw html
        :return: None
        """

        while len(self.crawlList) > 0:
            urlToCrawl = self.baseUrl + self.crawlList.pop(0)
            #splitUrlToCrawl = urlToCrawl.split("/")
            #cleanedCrawlUrl = splitUrlToCrawl[0] + "//" + splitUrlToCrawl[2]
            if urlToCrawl not in self.visitedList:
                try:
                    r = requests.get(urlToCrawl)
                except requests.exceptions.RequestException as e:
                    print(e)
                self.visitedList.append(urlToCrawl)
                html_content = r.text
                soup = BeautifulSoup(html_content)

                icsaRegex = re.compile("ICSA-[0-9]+-[0-9]+-[0-9]+")
                if(icsaRegex.search(html_content)):
                    icsaList = re.findall(icsaRegex, html_content)

                    for icsa in icsaList:
                        icsaCombo = (icsa,urlToCrawl)
                        if icsaCombo not in self.foundIcsaList:
                            self.foundIcsaList.append(icsaCombo)
                            print("Found " + icsa + " at " + urlToCrawl)

                            conn = sqlite3.connect(self.dbName)
                            threadCursor = conn.cursor()
                            dataTuple = (icsa, urlToCrawl, datetime.strftime(datetime.now(), "%Y-%m-%d"), html_content)
                            sqlite_insert_query = """INSERT INTO 'ICS' ('icsa_id', 'full_page_url', 'crawl_date', 'content') VALUES (?,?,?,?)"""
                            threadCursor.execute(sqlite_insert_query, dataTuple)
                            conn.commit()
                            conn.close()


if __name__ == "__main__":
    webcrawler = WebCrawler()
    webcrawler.crawl()