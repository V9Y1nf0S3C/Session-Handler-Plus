'''
This sample script is provided to test the Selenium login script being invoked by Session Handler Plus (SH+) extension and the web traffic proxied through Burp Suite port 8080. For more details, checkout "https://github.com/V9Y1nf0S3C/Session-Handler-Plus"

This script run in two modes. When the "burp" keyord received as an arg[1], mode-1 kick into action otherwise mode-2.

Note:
    1.Logs will be stored on "Chrome_Headless_AutoLogin_Logs.txt"
    2.When running the selenium web driver without internet (like Intranet web login), it may throw PATH related error. So, keep the chromedriver.exe handy and provide the path in this script. Download the web driver here https://chromedriver.chromium.org/home. You can read more about the path issue here https://bobbyhadz.com/blog/python-message-chromedriver-executable-needs-to-be-in-path  
    
Mode-1:
    Example Command: python3 "E:\Burp\Headless Login\GoogleSearch.py" burp
    
    1.Chrome browser will be headless. Means, you can't see the web browser trying to perform login actions
    2.Colors will not be displayed in the output. So you will not get strange characters in burp extension output section (when invoked by Burp >> SH+ >> 5.Invoke Custom Script)
    
Mode-2:
    Example Command: python3 "E:\Burp\Headless Login\GoogleSearch.py"
    
    1.Chrome browser will be not headless. Means, you can see the web browser trying to perform login actions. Good for your troubleshooting.
    2.Colors will be displayed in the output console. Better not to use this when invoked by Burp >> SH+ >> 5.Invoke Custom Script
'''

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
import time
from datetime import datetime
import logging
import sys

# Variable Declaration
headless = False    #Headless configuration (True/False)
colored_out = True  #Colored output in console (True/False). Keep it false if using Burp Suite Extension console
waiting_timer = True


# Check if the script launched from Burp or Directly 
if len(sys.argv) > 1:
    if "burp" in sys.argv[1:]:
        #Variable Declaration for Burp
        headless = True
        colored_out = False
        waiting_timer = False


# Set up Burp Suite proxy
PROXY_HOST = '127.0.0.1'
PROXY_PORT = 8080
PROXY = f"{PROXY_HOST}:{PROXY_PORT}"


# Write the output to the file
f = open("Chrome_Headless_AutoLogin_Logs.txt", "a")
f.write(f"\n{datetime.now()} : Script Execution Started\n")

# Print the timer
def timer(x):
    global waiting_timer
    remaining_time = x
    if waiting_timer:
        while remaining_time > 0:
            print(f"Waiting for {remaining_time} seconds...", end='\r')
            time.sleep(1)
            remaining_time -= 1
        print(" " * len(f"Waiting for {remaining_time + 1} seconds..."), end='\r')
    else:
        print(f"  {datetime.now()} : Waiting for {remaining_time} seconds:", end=" ")
        while remaining_time > 0:
            print(f"{remaining_time}", end=" ", flush=True)
            time.sleep(1)
            remaining_time -= 1
        print("\r")

# Print the text
def print_me(x):
    global f,colored_out
    if colored_out:
        print(f"\x1b[1;34;40m {datetime.now()} : {x} \x1b[0m")
    else:
        print(f"  {datetime.now()} : {x}")
    f.write(f"{datetime.now()} : {x}\n")            

# Configure Chrome options to use Burp proxy
chrome_options = Options()
chrome_options.add_argument(f"--proxy-server=http://{PROXY}")
chrome_options.add_argument('--log-level=3') #https://stackoverflow.com/questions/2031163/when-to-use-the-different-log-levels
if headless:
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--disable-gpu')
print_me(f"Selenium Config = Headless: {headless}, colored_out: {colored_out}, waiting_timer: {waiting_timer}")        
print_me("Launching the browser")

# Initialize a headless Chrome browser instance with Burp proxy settings. 
driver = webdriver.Chrome(options=chrome_options)
#Set to path when you use on offline login (for intranet portal login)
#driver = webdriver.Chrome(options=chrome_options, service=Service(r'D:/WorkSpace/Burp Workspace/chromedriver.exe')) 


# Navigate to the login page
print_me("Going to login URL")
driver.get('https://accounts.google.com/')

# Wait for the login page to load
#print_me("Waiting for few seconds ")
timer(3)
driver.implicitly_wait(50)

# Find the search field using the find_element method
print_me("Typing the search string")
search_input = driver.find_element('xpath', "//*[@id='identifierId']")

# Enter your login credentials
search_input.send_keys('iamnotexist')

# Submit the login form using the find_element method
#submit_button = driver.find_element('xpath', "//*[@id='search']")
#submit_button.click()

#print_me("Waiting for few seconds before exit")

# Wait for the web page to load after an action
timer(5)
driver.implicitly_wait(50)

# Do something on the logged-in page
# ...

print_me("Exiting now")

# Close the browser
driver.quit()
f.write(f"{datetime.now()} : Script Execution Completed\n")
f.close()
