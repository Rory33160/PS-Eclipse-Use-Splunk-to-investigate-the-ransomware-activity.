# PS-Eclipse-Use-Splunk-to-investigate-the-ransomware-activity.
This project is taken from the TryHackMe room challenge PS Ellipse. The challenge features the use of Splunk to investigate a possible ransomware attack. Other sources include Virustotal, Cyberchef .


You are a SOC Analyst for an MSSP (Managed Security Service Provider) company called TryNotHackMe.

A customer sent an email asking for an analyst to investigate the events that occurred on Keegan's machine on Monday, May 16th, 2022. The client noted that the machine is operational, but some files have a weird file extension. The client is worried that there was a ransomware attempt on Keegan's device. 

Your manager has tasked you to check the events in Splunk to determine what occurred in Keegan's device. 

Happy Hunting!


A suspicious binary was downloaded to the endpoint. What was the name of the binary?

Since this is a download , I can start the search with Sysmon Event ID 1 - Process creation  and Powershell. 


![image](https://github.com/Rory33160/PS-Eclipse-Use-Splunk-to-investigate-the-ransomware-activity./assets/47018034/109c81cb-0385-4b8a-bd86-b6feb806fc0d)

Answer:
OUTSTANDING_GUTTER.exe

What is the address the binary was downloaded from? Add http:// to your answer & defang the URL.

Taken from Splunk field CommandLine and convert the code on Cyberchef

![image](https://github.com/Rory33160/PS-Eclipse-Use-Splunk-to-investigate-the-ransomware-activity./assets/47018034/2aa4d17b-6750-4eef-ab49-2508a7784bfc)

Cyberchef returned :

![image](https://github.com/Rory33160/PS-Eclipse-Use-Splunk-to-investigate-the-ransomware-activity./assets/47018034/15b091bf-1192-4aa6-a504-89eeddb91fa4)

Next step is to defang url:

![image](https://github.com/Rory33160/PS-Eclipse-Use-Splunk-to-investigate-the-ransomware-activity./assets/47018034/6975026e-8d9b-4f6f-aa5b-3707d9742482)

Answer is: 
hxxp[://]886e-181-215-214-32[.]ngrok[.]io

What Windows executable was used to download the suspicious binary? Enter full path.

Adding on from previous search – I used 

![image](https://github.com/Rory33160/PS-Eclipse-Use-Splunk-to-investigate-the-ransomware-activity./assets/47018034/b0352d36-6f00-4a96-888c-cfdc4036d39d)

Answer:

![image](https://github.com/Rory33160/PS-Eclipse-Use-Splunk-to-investigate-the-ransomware-activity./assets/47018034/4c1efd62-5cbe-4eb4-983d-ab7d29780664)

What command was executed to configure the suspicious binary to run with elevated privileges?

Splunk: index=“main” commandline
Answer: 
"C:\\Windows\\system32\\schtasks.exe\" /Create /TN OUTSTANDING_GUTTER.exe /TR C:\\Windows\\Temp\\COUTSTANDING_GUTTER.exe /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU SYSTEM /f"

For context:
OUTSTANDING_GUTTER.exe" that is triggered by Event ID 777 in the "Application" event log. When this event occurs, the task runs the executable located at "C:\Windows\Temp\COUTSTANDING_GUTTER.exe" with the highest system privileges (SYSTEM account).

![image](https://github.com/Rory33160/PS-Eclipse-Use-Splunk-to-investigate-the-ransomware-activity./assets/47018034/754f1198-b881-4954-a633-b789c67e7082)


What permissions will the suspicious binary run as? What was the command to run the binary with elevated privileges? (Format: User + ; + CommandLine)
Answer:
NT AUTHORITY\SYSTEM;”C:\Windows\system32\schtasks.exe” /Run /TN OUTSTANDING_GUTTER.exe

The suspicious binary connected to a remote server. What address did it connect to? Add http:// to your answer & defang the URL.

Drawing from the question two answer of hxxp[://]886e-181-215-214-32[.]ngrok[.]io
Splunk search with ngrok.io and/or GUTTER.exe returned the following result:

![image](https://github.com/Rory33160/PS-Eclipse-Use-Splunk-to-investigate-the-ransomware-activity./assets/47018034/b250c575-3afd-426b-aa0e-46ffcd0ef97d)

With the full address we can defang in CyberChef
Answer:
hxxp[://]9030-181-215-214-32[.]ngrok[.]io

A PowerShell script was downloaded to the same location as the suspicious binary. What was the name of the file?
The malicious script was flagged as malicious. What do you think was the actual name of the malicious script?
With then MD5 search on Virustotal the answer is : BlackSun.ps1

![image](https://github.com/Rory33160/PS-Eclipse-Use-Splunk-to-investigate-the-ransomware-activity./assets/47018034/c05dadfb-b798-4b7d-b78c-c0812bd3bddb)

A ransomware note was saved to disk, which can serve as an IOC. What is the full path to which the ransom note was saved?

Searching with  : index="main" .txt*

Answer: C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt

The script saved an image file to disk to replace the user's desktop wallpaper, which can also serve as an IOC. What is the full path of the image?
Answer:
c:\users\public\pictures\blacksun.jpg

I read this VMware writeup about the ransomeware featured in this TryHackMe room https://blogs.vmware.com/security/2022/01/blacksun-ransomware-the-dark-side-of-powershell.html
![image](https://github.com/Rory33160/PS-Eclipse-Use-Splunk-to-investigate-the-ransomware-activity./assets/47018034/d5bafb34-85b3-44a2-8043-aec75ba31cbc)










