# ----------------------------------------------------------------------------- 
# Program Description
# ----------------------------------------------------------------------------- 
# This program handles the feature extraction from a provided URL. It is one of
# the most important part of our program because of the fact that it provides
# us with the data points of various websites both for testing the tool and to
# create a database of Phishing and Non-Phishing Website.
# ----------------------------------------------------------------------------- 

# ----------------------------------------------------------------------------- 
# Importing the Required Libraries
# ----------------------------------------------------------------------------- 

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

# ----------------------------------------------------------------------------- 
# URL Based Features
# ----------------------------------------------------------------------------- 

def get_soup_response(url:str):
    '''Returns a tuple with two values:
    1. HTTP/S Response
    2. Beautiful Soup Processed Response'''
    if not re.match(r"^https?", url):
        url = "http://" + url
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
    except:
        response = ""
        soup = -999
    return (response, soup)


def domain_info(url:str) -> tuple:
    '''Returns a Tuple with three values:
    1. Domain
    2. Whois Response
    3. Page Rank'''
    domain = re.findall(r"://([^/]+)/?", url)[0]
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    whois_response = whois.whois(domain)
    rank_checker_response = requests.post(
        "https://www.checkpagerank.net/index.php",
        {"name": domain}
        )
    try:
        global_rank = int(
            re.findall(r"Global Rank: ([0-9]+)",
            rank_checker_response.text)[0]
        )
    except:
        global_rank = -1
    return (domain, whois_response, global_rank)


# Feature 01: UsingIP
def using_ip_address(url:str) -> int:
    try:
        ipaddress.ip_address(url)
        return -1
    except:
        return 1


# Feature 02: LongURL
def long_url(url:str) -> int:
    if len(url) < 54:
        return 1
    elif len(url) >= 54 and len(url) <= 75:
        return 0
    return -1


# Feature 03: ShortURL
def shortened_url(url:str) -> int:
    with open("./shorteners.txt","r") as f:
        data = f.read()
    if data[-1] == '\n':
        data = data[:-1]
    pattern = data.replace('.','\\.').replace('\n','|')
    match = re.search(pattern, url)
    if match:
        return -1
    else:
        return 1


# Feature 04: '@' Symbol
def at_symbol_present(url:str) -> int:
    return -1 if re.findall("@", url) else 1


# Feature 05: Redirecting '//'
def is_redirecting(url:str) -> int:
    list = [x.start(0) for x in re.finditer('//', url)]
    return -1 if list[len(list)-1] > 6 else 1


# Feature 06: Prefix Suffix '-'
def prefix_suffix(url:str) -> int:
    return -1 if re.findall(r"https?://[^\-]+-[^\-]+/", url) else 1


# Feature 07: Sub Domains
def sub_domains(url:str) -> int:
    if len(re.findall("\.", url)) == 1:
        return 1
    elif len(re.findall("\.", url)) == 2:
        return 0
    return -1


# Feature 08: HTTPS
def https(url:str, response) -> int:
    try:
        if response.text:
            return 1
    except:
        return -1


# Feature 09: DomainRegLen
def domain_registration_length(url:str, whois_response) -> tuple:
    '''Returns the Domain Registration Length and also if the Registration is
    less than a year.'''
    expiration_date = whois_response.expiration_date
    registration_length = 0
    try:
        expiration_date = min(expiration_date)
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        registration_length = abs((expiration_date - today).days)
        if registration_length / 365 <= 1:
            return (-1, registration_length)
        return (1, registration_length)
    except:
        return (-1, registration_length)


# Feature 10: Favicon
def fav_icon(url:str, soup) -> int:
    data_set = []
    if soup == -999:
        data_set.append(-1)
    else:
        try:
            for head in soup.find_all('head'):
                for head.link in soup.find_all('link', href=True):
                    dots = [x.start(0)
                            for x in re.finditer('\.', head.link['href'])]
                    if url in head.link['href'] or len(dots) == 1 or domain in head.link['href']:
                        data_set.append(1)
                        raise StopIteration
                    else:
                        data_set.append(-1)
                        raise StopIteration
        except StopIteration:
            pass
    return data_set[0]


# Feature 11: NonStdPort
def non_standard_port(url:str, domain) -> int:
    try:
        port = domain.split(":")[1]
        if port:
            return -1
        else:
            return 1
    except:
        return 1


# Feature 12: HTTPSDomainURL
def https_domain(url:str) -> int:
    return 1 if re.findall(r"^https://", url) else -1


# Feature 13: RequestURL
def request_url(url:str, soup, domain) -> int:
    i = 0
    success = 0
    if soup == -999:
        return -1
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
            if url in iframe['src'] or domain in iframe['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        try:
            percentage = success/float(i) * 100
            if percentage < 22.0:
                return 1
            elif((percentage >= 22.0) and (percentage < 61.0)):
                return 0
            else:
                return -1
        except:
            return 1


# Feature 14: AnchorURL
def anchor_url(url:str, soup, domain) -> int:
    percentage = 0
    i = 0
    unsafe = 0
    ex = True
    if soup == -999:
        return -1
    else:
        for a in soup.find_all('a', href=True):
            # 2nd condition was 'JavaScript ::void(0)' but we put JavaScript because the space between javascript and :: might not be there in the actual a['href']
            if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or domain in a['href']):
                unsafe = unsafe + 1
            i = i + 1

        try:
            percentage = unsafe / float(i) * 100
        except:
            ex = False
            return 1

        if(ex):
            if percentage < 31.0:
                return 1
            elif ((percentage >= 31.0) and (percentage < 67.0)):
                return 0
            else:
                return -1


# Feature 15: LinksInScriptTags
def links_in_script_tags(url:str, soup, domain) -> int:
    i = 0
    success = 0
    if soup == -999:
        return -1
    else:
        for link in soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
            if url in link['href'] or domain in link['href'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for script in soup.find_all('script', src=True):
            dots = [x.start(0) for x in re.finditer('\.', script['src'])]
            if url in script['src'] or domain in script['src'] or len(dots) == 1:
                success = success + 1
            i = i+1
        try:
            percentage = success / float(i) * 100
        except:
            return 1

        if percentage < 17.0:
            return 1
        elif((percentage >= 17.0) and (percentage < 81.0)):
            return 0
        else:
            return -1


# Feature 16: ServerFormHandler
def server_form_handler(url:str, soup, domain) -> int:
    if soup != -999:
        if len(soup.find_all('form', action=True))==0:
            return 1
        else:
            for form in soup.find_all('form', action=True):
                if form['action'] == "" or form['action'] == "about:blank":
                    return -1
                elif url not in form['action'] and domain not in form['action']:
                    return 0
                else:
                    return 1
    return 0


# Feature 17: InfoEmail
def has_email_info(url:str, response) -> int:
    '''Checks if the URL contains mailing protocol (one that takes your to your
    email and makes you send an email to a certain email address)'''
    if response != "":
        return -1 if re.findall(r"[mail\(\)|mailto:?]", response.text) else 1
    return -1


# Feature 18: AbnormalURL
def is_abnormal_url(url:str, response, whois_response) -> int:
    '''If the Response and Whois Response do not match, the url might be
    behaving abnormally. Returns 1 if the response match; -1 otherwise.'''
    if response != "":
        return 1 if response.text == whois_response else -1
    return -1


# Feature 19: WebsiteForwarding
def website_forwarding(url:str, response) -> int:
    '''This function counts how many times the URL tried to redirect the user.
    If the number is equal to or more than 4, it might be considered a phishing
    attempt.'''
    if response != "":
        if len(response.history) <= 1:
            return -1
        elif len(response.history) <= 4:
            return 0
        else:
            return 1
    return -1


# Feature 20: StatusBarCust
def address_bar_block(url:str, response) -> int:
    '''This function checks if the Address bar of the browser has been disabled
    when the URL was accessed. Some phishing websites tend to spoof this address
    bar in order to not let the user see the real address.'''
    if response != "":
        pattern = r"<script>.+onmouseover.+</script>"
        return 1 if re.findall(pattern, response.text) else -1
    return -1


# Feature 21: DisableRightClick
def right_click_disabled(url:str, response) -> int:
    '''Some Phishing website disallow the user to access the context menu by
    disabling the Rigth Click so that the user cannot see the Source Code.'''
    if response != "":
        return 1 if re.findall(r"event.button ?== ?2", response.text) else -1
    return -1


# Feature 22: UsingPopupWindow
def using_popup_window(url:str, response) -> int:
    '''Checks if the Webpage has 'alert' popups present. Popup windows are
    usually not used by actual websites any more. Phishing pages might use
    these popup windows for malicious purposes such as stealing passwords.'''
    if response != "":
        return 1 if re.findall(r"alert\(", response.text) else -1
    return -1


# Feature 23: IframeRedirection
def iframe_redirection(url:str, response) -> int:
    '''Iframe can be used to redirect the user to malicious counterpart of the
    intended webpage. Using iframe, the attacker can redirect the user without
    actually changing how the URL looks.'''
    if response != "":
        pattern = r"[<iframe>|<frameBorder>]"
        return 1 if re.findall(pattern, response.text) else -1
    return -1


# Feature 24: AgeofDomain
def age_of_domain(url:str, whois_response, response) -> int:
    '''If the age of the domain is less than 6 months, we are considering the
    domain as unsafe since it could potentially be a recent Phishing Attempt.'''
    diff_month = lambda d1,d2: ((d1.year - d2.year) * 12 + d1.month - d2.month)
    if response != "":
        registration_date = whois_response['creation_date']
        if isinstance(registration_date, list):
            registration_date = registration_date[0]
        # pattern = r'Registration Date:</div><div class="df-value">([^<]+)</div>'
        # registration_date = re.findall(pattern, whois_response.text)[0]
        if diff_month(date.today(), registration_date) >= 6:
            return -1
    return 1


# Feature 25: DNSRecording
def dns_recording(url:str, domain, whois, registration_length) -> int:
    dns = 1
    try:
        d = whois.whois(domain)
    except:
        dns = -1
    if dns != -1:
        return -1 if (registration_length / 365 <= 1) else 1
    return -1


# Feature 26: WebsiteTraffic
def website_traffic(url:str) -> int:
    '''If too less people access the website the user is trying to access, it
    could be a potential red flag. That's why we are getting the traffic of
    the url accessed.'''
    try:
        rank_url = "http://data.alexa.com/data?cli=10&dat=s&url="
        rank = BeautifulSoup(
            urllib.request.urlopen(rank_url + url).read(), "xml"
            ).find("REACH")['RANK']
        rank = int(rank)
        if (rank < 100000):
            return 1
        else:
            return 0
    except :
        return -1


# Feature 27: PageRank
def page_rank(url:str, global_rank):
    try:
        return -1 if (global_rank > 0 and global_rank < 100000) else 1
    except:
        return 1


# Feature 28: GoogleIndex
def google_index(url:str) -> int:
    return 1 if search(url, 5) else -1


# Feature 29: LinksPointingToPage
def links_pointing_to_page(url:str, response) -> int:
    if response != "":
        link_count = len(re.findall(r"<a href=", response.text))
        if link_count == 0:
            return 1
        elif link_count <= 2:
            return 0
    return -1


# Feature 30: StatsReport
def stats_report(url:str, domain) -> int:
    url_match = re.search(
        'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|'
        'sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url
        )
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
            return -1
        elif ip_match:
            return -1
        else:
            return 1
    except:
        return 1

# ----------------------------------------------------------------------------- 
# Main Function
# ----------------------------------------------------------------------------- 

def extract_features(url) -> list:
    # Getting the HTTP/S Response and Soup of the Source
    response, soup = get_soup_response(url)
    # Getting the Domain, Whois Response and the Global Rank
    domain, whois_response, global_rank = domain_info(url)
    # Getting Registration Information
    reg_len_feature, reg_len = domain_registration_length(url, whois_response)
    # Aggregating the Features in a List
    features = [
        using_ip_address(url),
        long_url(url),
        shortened_url(url),
        at_symbol_present(url),
        is_redirecting(url),
        prefix_suffix(url),
        sub_domains(url),
        https(url, response),
        reg_len_feature,
        fav_icon(url, soup),
        non_standard_port(url, domain),
        https_domain(url),
        request_url(url, soup, domain),
        anchor_url(url, soup, domain),
        links_in_script_tags(url, soup, domain),
        server_form_handler(url, soup, domain),
        has_email_info(url, response),
        is_abnormal_url(url, response, whois_response),
        website_forwarding(url, response),
        address_bar_block(url, response),
        right_click_disabled(url, response),
        using_popup_window(url, response),
        iframe_redirection(url, response),
        age_of_domain(url, whois_response, response),
        dns_recording(url, domain, whois, reg_len),
        website_traffic(url),
        page_rank(url, global_rank),
        google_index(url),
        links_pointing_to_page(url, response),
        stats_report(url, domain)
    ]
    # Returning the features list
    return features

new = extract_features('https://google.com/')

import feature

old = feature.generate_data_set('https://google.com/')

print(new, '\n', old)

for i in range(30):
    if new[i] != old[i]:
        print(i+1)