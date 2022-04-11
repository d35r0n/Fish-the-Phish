# ------------------------------------------------------------------------------
# Program Description
# ------------------------------------------------------------------------------
# This program handles the feature extraction from a provided URL. It is one of
# the most important part of our program because of the fact that it provides
# us with the data points of various websites both for testing the tool and to
# create a database of Phishing and Non-Phishing Website.
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Importing the Required Libraries
# ------------------------------------------------------------------------------

import ipaddress
import re
import requests
import socket
import time
import urllib.request
import whois

from bs4 import BeautifulSoup
from datetime import date, datetime
from dateutil.parser import parse as date_parse
from googlesearch import search

# ------------------------------------------------------------------------------


def diff_month(d1, d2):
    '''Returns the number of months between the two dates provided'''
    return (d1.year - d2.year) * 12 + d1.month - d2.month


def extract_features(url):
    '''Returns a list containing the features about the URL provided'''
    # Instantiating the Features List
    features = []

    # Adding http if https not found in URL
    if not re.match(r"^https?", url):
        url = "http://" + url

    # Getting the Requests & Soup Responses
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
    except:
        response = ""
        soup = -999

    # Getting Domain Information
    domain = re.findall(r"://([^/]+)/?", url)[0]
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    whois_response = whois.whois(domain)

    # Getting Global Rank
    rank_checker_response = requests.post(
        "https://www.checkpagerank.net/index.php",
        {"name": domain}
    )
    try:
        global_rank = int(re.findall(
            r"Global Rank: ([0-9]+)", rank_checker_response.text)[0]
        )
    except:
        global_rank = -1

    # Feature 01: UsingIP
    try:
        ipaddress.ip_address(url)
        features.append(-1)
    except:
        features.append(1)

    # Feature 02: LongURL
    if len(url) < 54:
        features.append(1)
    elif len(url) >= 54 and len(url) <= 75:
        features.append(0)
    else:
        features.append(-1)

    # Feature 03: ShortURL
    with open("./shorteners.txt", "r") as f:
        data = f.read()
    if data[-1] == '\n':
        data = data[:-1]
    pattern = data.replace('.', '\\.').replace('\n', '|')
    match = re.search(pattern, url)
    if match:
        features.append(-1)
    else:
        features.append(1)

    # Feature 04: Symbol@
    if re.findall("@", url):
        features.append(-1)
    else:
        features.append(1)

    # Feature 05: Redirecting//
    list = [x.start(0) for x in re.finditer('//', url)]
    if list[len(list)-1] > 6:
        features.append(-1)
    else:
        features.append(1)

    # Feature 06: PrefixSuffix-
    if re.findall(r"https?://[^\-]+-[^\-]+/", url):
        features.append(-1)
    else:
        features.append(1)

    # Feature 07: SubDomains
    if len(re.findall("\.", url)) == 1:
        features.append(1)
    elif len(re.findall("\.", url)) == 2:
        features.append(0)
    else:
        features.append(-1)

    # Feature 08: HTTPS
    try:
        if response.text:
            features.append(1)
    except:
        features.append(-1)

    # Feature 09: DomainRegLen
    expiration_date = whois_response.expiration_date
    registration_length = 0
    try:
        expiration_date = min(expiration_date)
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        registration_length = abs((expiration_date - today).days)

        if registration_length / 365 <= 1:
            features.append(-1)
        else:
            features.append(1)
    except:
        features.append(-1)

    # Feature 10: Favicon
    if soup == -999:
        features.append(-1)
    else:
        try:
            for head in soup.find_all('head'):
                for head.link in soup.find_all('link', href=True):
                    dots = [x.start(0)
                            for x in re.finditer('\.', head.link['href'])]
                    if url in head.link['href'] or len(dots) == 1 or domain \
                    in head.link['href']:
                        features.append(1)
                        raise StopIteration
                    else:
                        features.append(-1)
                        raise StopIteration
        except StopIteration:
            pass

    # Feature 11: NonStdPort
    try:
        port = domain.split(":")[1]
        if port:
            features.append(-1)
        else:
            features.append(1)
    except:
        features.append(1)

    # Feature 12: HTTPSDomainURL
    if re.findall(r"^https://", url):
        features.append(1)
    else:
        features.append(-1)

    # Feature 13: RequestURL
    i = 0
    success = 0
    if soup == -999:
        features.append(-1)
    else:
        for img in soup.find_all('img', src=True):
            dots = [x.start(0) for x in re.finditer('\.', img['src'])]
            if url in img['src'] or domain in img['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for audio in soup.find_all('audio', src=True):
            dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
            if url in audio['src'] or domain in audio['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for embed in soup.find_all('embed', src=True):
            dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
            if url in embed['src'] or domain in embed['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for iframe in soup.find_all('iframe', src=True):
            dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
            if url in iframe['src'] or domain in iframe['src'] or len(dots) ==1:
                success = success + 1
            i = i+1

        try:
            percentage = success/float(i) * 100
            if percentage < 22.0:
                features.append(1)
            elif((percentage >= 22.0) and (percentage < 61.0)):
                features.append(0)
            else:
                features.append(-1)
        except:
            features.append(1)

    # Feature 14: AnchorURL
    percentage = 0
    i = 0
    unsafe = 0
    ex = True
    if soup == -999:
        features.append(-1)
    else:
        for a in soup.find_all('a', href=True):
            # second condition was 'JavaScript ::void(0)' but we put JavaScript
            # because the space between javascript and :: might not be there in
            # the actual a['href']
            if "#" in a['href'] or "javascript" in a['href'].lower() or \
            "mailto" in a['href'].lower() or not (url in a['href'] or domain \
            in a['href']):
                unsafe = unsafe + 1
            i = i + 1
        # Calculating Percentage
        try:
            percentage = unsafe / float(i) * 100
        except:
            ex = False
            features.append(1)
        # Comparing and adding Feature
        if(ex):
            if percentage < 31.0:
                features.append(1)
            elif ((percentage >= 31.0) and (percentage < 67.0)):
                features.append(0)
            else:
                features.append(-1)

    # Feature 15: LinksInScriptTags
    i = 0
    success = 0
    if soup == -999:
        features.append(-1)
        features.append(0)
    else:
        for link in soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
            if url in link['href'] or domain in link['href'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for script in soup.find_all('script', src=True):
            dots = [x.start(0) for x in re.finditer('\.', script['src'])]
            if url in script['src'] or domain in script['src'] or len(dots) ==1:
                success = success + 1
            i = i+1
        try:
            percentage = success / float(i) * 100
        except:
            features.append(1)

        if percentage < 17.0:
            features.append(1)
        elif((percentage >= 17.0) and (percentage < 81.0)):
            features.append(0)
        else:
            features.append(-1)

        # Feature  16: ServerFormHandler
        if len(soup.find_all('form', action=True))==0:
            features.append(1)
        else :
            for form in soup.find_all('form', action=True):
                if form['action'] == "" or form['action'] == "about:blank":
                    features.append(-1)
                    break
                elif url not in form['action'] and domain not in form['action']:
                    features.append(0)
                    break
                else:
                    features.append(1)
                    break

    # Feature 17: InfoEmail
    if response == "":
        features.append(-1)
    else:
        if re.findall(r"[mail\(\)|mailto:?]", response.text):
            features.append(-1)
        else:
            features.append(1)

    # Feature 18: AbnormalURL
    if response == "":
        features.append(-1)
    else:
        if response.text == whois_response:
            features.append(1)
        else:
            features.append(-1)

    # Feature 19: WebsiteForwarding
    if response == "":
        features.append(-1)
    else:
        if len(response.history) <= 1:
            features.append(-1)
        elif len(response.history) <= 4:
            features.append(0)
        else:
            features.append(1)

    # Feature 20: StatusBarCust
    if response == "":
        features.append(-1)
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            features.append(1)
        else:
            features.append(-1)

    # Feature 21: DisableRightClick
    if response == "":
        features.append(-1)
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            features.append(1)
        else:
            features.append(-1)

    # Feature 22: UsingPopupWindow
    if response == "":
        features.append(-1)
    else:
        if re.findall(r"alert\(", response.text):
            features.append(1)
        else:
            features.append(-1)

    # Feature 23: IframeRedirection
    if response == "":
        features.append(-1)
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            features.append(1)
        else:
            features.append(-1)

    # Feature 24: AgeofDomain
    if response == "":
        features.append(-1)
    else:
        try:
            registration_date = re.findall(
                r'Registration Date:</div><div class="df-value">([^<]+)</div>',
                whois_response.text)[0]
            if diff_month(date.today(), date_parse(registration_date)) >= 6:
                features.append(-1)
            else:
                features.append(1)
        except:
            features.append(1)

    # Feature 25: DNSRecording
    dns = 1
    try:
        d = whois.whois(domain)
    except:
        dns = -1
    if dns == -1:
        features.append(-1)
    else:
        if registration_length / 365 <= 1:
            features.append(-1)
        else:
            features.append(1)

    # Feature 26: WebsiteTraffic
    try:
        rank = BeautifulSoup(urllib.request.urlopen(
            "http://data.alexa.com/data?cli=10&dat=s&url=" + url
        ).read(), "xml").find("REACH")['RANK']
        rank = int(rank)
        if (rank < 100000):
            features.append(1)
        else:
            features.append(0)
    except :
        features.append(-1)

    # Feature 27: PageRank
    try:
        if global_rank > 0 and global_rank < 100000:
            features.append(-1)
        else:
            features.append(1)
    except:
        features.append(1)

    # Feature 28: GoogleIndex
    site = search(url, 5)
    if site:
        features.append(1)
    else:
        features.append(-1)

    # Feature 29: LinksPointingToPage
    if response == "":
        features.append(-1)
    else:
        number_of_links = len(re.findall(r"<a href=", response.text))
        if number_of_links == 0:
            features.append(1)
        elif number_of_links <= 2:
            features.append(0)
        else:
            features.append(-1)

    # Feature 30: StatsReport
    url_match = re.search(
        'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|'
        'sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
    try:
        ip_address = socket.gethostbyname(domain)
        ip_match = re.search(
            '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185'
            '\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145'
            '\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
            '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199'
            '\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28'
            '\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
            '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157'
            '\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229'
            '\.108\.32|103\.232\.215\.140|69\.172\.201\.153|216\.218\.185'
            '\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170'
            '\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195'
            '\.16\.127\.102|195\.16\.127\.157|34\.196\.13\.28|103\.224\.212'
            '\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200'
            '\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87'
            '\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47'
            '\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37'
            '\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address
            )
        if url_match:
            features.append(-1)
        elif ip_match:
            features.append(-1)
        else:
            features.append(1)
    except:
        features.append(1)

    # Returning the final Features List
    return features
