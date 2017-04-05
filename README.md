# TelescamBot
Telegram bot, grabs malicious APKs, saves them with their metadata and submits them to Koodous.com

## Introduction
This telegram bot is released as part of Telescam (http://telescam.ir) project where we analyze
specifically Iranian scam campaigns spreading their malware using Telegram messenger, this bot grabs APK files
from telegram groups and also the files directly sent to it.

A local copy of the APK samples are stored locally along with some metadata about when it was submitted, who sent it 
and if it was forwarded from a channel. It then also submits the samples to https://koodous.com for initial analysis.

## Required Modules
Prior to running the bot, you need to install the following modules:
* telebot
* sqlalchemy
* mkdir-p
* requests

## Setup
Then replace the two string values with your telegram bot and koodous api tokens:
```python
self.TELEGRAM_TOKEN = '...'
self.KOODOUS_API_TOKEN = '...' #Personal - MUST NOT BE SHARED
```
And then run the bot:
python Telescam_scanner_bot.py

Aforementioned metadata is stored in a sqlite database named telescam.db and APK samples are stored in ./apk/ directory
