#!/usr/bin/python
# -*- encoding: utf-8 -*-

import telebot, hashlib, requests, os, sqlite3, json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db import APK, Certificate, Submission, Base
from mkdir_p import mkdir_p

class Telescam_scanner_bot :
    def __init__(self) :
        self.TELEGRAM_TOKEN = 'ADD YOUR TELEGRAM BOT TOKEN HERE'
        self.KOODOUS_API_TOKEN = 'ADD YOUR KOODOUS.COM API TOKEN HERE - FOUND UNDER PROFILE'
        self.bot = telebot.TeleBot(self.TELEGRAM_TOKEN)
        self.FILES_DIR = './apk/'
    
    def run(self) :
        self.bot.polling()

    def valid_apk(self, file) :
        if file[0:2] == 'PK' : #Zip Archive (APK)
            return True
        return False

    def send_for_analysis(self, apk_file) :
        result = self.submit_to_koodous(apk_file)
        return result
        
    def submit_to_koodous(self, apk_file) :
        result_url = None
        sha256sum = hashlib.sha256(apk_file).hexdigest()
        upload_url = self.koodous_get_upload_token(sha256sum)
        if upload_url == None :
            #File Already Exists, Link existing report
            result_url = self.koodous_link_existing_analysis(sha256sum)
        else :
            # Check for possible errors
            requests.post(upload_url, files={'file' : apk_file})
        return sha256sum

    def koodous_get_upload_token(self, sha256sum) :
        url_koodous = "https://api.koodous.com/apks/%s/get_upload_url" % sha256sum
        r = requests.get(url = url_koodous, headers = { 'Authorization': 'Token %s' % self.KOODOUS_API_TOKEN })
        if r.status_code == 409 :
            return None
        else :
            return r.json().get('upload_url')

    def koodous_link_existing_analysis(self, sha256sum) :
        return 'https://koodous.com/apks/%s' % sha256sum

    def koodous_link_existing_analysis_json(self, sha256sum) :
        r = requests.get('https://api.koodous.com/apks/%s/analysis' % sha256sum)
        return r.json()

    def save(self, sha256sum, message, file) :
        engine = create_engine('sqlite:///telescam.db')
        Base.metadata.bind = engine
        DBSession = sessionmaker(bind=engine)
        session = DBSession()
        data = self.koodous_link_existing_analysis_json(sha256sum)
        koodous_url = self.koodous_link_existing_analysis(sha256sum)
        try :
            new_certificate = session.query(Certificate).filter(Certificate.sha1 == data['androguard']['certificate']['sha1']).first()
            if new_certificate == None :
                new_certificate = Certificate(sha1=data['androguard']['certificate']['sha1'],
                    not_before=data['androguard']['certificate']['not_before'],
                    not_after=data['androguard']['certificate']['not_after'],
                    subjectdn=data['androguard']['certificate']['subjectDN'],
                    issuerdn=data['androguard']['certificate']['issuerDN'],
                    serial=data['androguard']['certificate']['serial'])
                session.add(new_certificate)
                session.commit()

            new_apk = session.query(APK).filter(APK.sha256 == data['sha256']).first()
            if new_apk == None :
                # Save apk
                local_filename = self.FILES_DIR + message.document.file_id + '.apk'
                mkdir_p(os.path.dirname(local_filename))
                with open(local_filename, 'wb') as new_file:
                    new_file.write(file)
                new_apk = APK(app_name=data['androguard']['app_name'],
                    package_name=data['androguard']['package_name'],
                    version_code=data['androguard']['version_code'],
                    displayed_version=data['androguard']['displayed_version'],
                    local_package=local_filename,
                    koodous_url=koodous_url,
                    sha256=data['sha256'],
                    certificate=new_certificate)
                session.add(new_apk)
                session.commit()

            new_submission = Submission(submitted_to_username=message.chat.username,
                submitted_to_title=message.chat.title,
                submitted_to_id=message.chat.id,
                forwarded_from_username= message.forward_from.username if message.forward_from != None else None,
                forwarded_from_firstname=message.forward_from.first_name if message.forward_from != None else None,
                forwarded_from_lastname=message.forward_from.last_name if message.forward_from != None else None,
                forwarded_from_id=message.forward_from.id if message.forward_from != None else None,
                submitted_by_username=message.from_user.username,
                submitted_by_firstname=message.from_user.first_name,
                submitted_by_lastname=message.from_user.last_name,
                submitted_by_id=message.from_user.id,
                message_text=message.text,
                filename=message.document.file_name,
                apk=new_apk)
            session.add(new_submission)
            session.commit()
        except Exception as e :
            print e

if __name__ == '__main__' :
    telegram_bot = Telescam_scanner_bot()
    bot = telegram_bot.bot

    # Register message handlers
    # Handle '/help'
    @bot.message_handler(commands=['help'])
    def send_welcome(message):
        bot.reply_to(message, u"""\
Welcome to TeleScam ‌Bot, Submit your malicious APK samples here.
For more information about our project visit http://telescam.ir
سلام به بات دیده بان تلگرام خوش آمدید، نمونه apk های مشکوک خود را از این طریق برای ما ارسال کنید.
برای کسب اطلاعات بیشتر در خصوص این پروژه به وبسایت http://telescam.ir مراجعه کنید.
کانال تلگرام پروژه
@teleScam
""")

    @bot.message_handler(func=lambda message: True, content_types=['document'])
    def on_receive_file(message):
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        if telegram_bot.valid_apk(downloaded_file) :
            sha256sum = telegram_bot.send_for_analysis(downloaded_file)
            #Save file save(sha256sum, message, file)
            telegram_bot.save(sha256sum, message, downloaded_file)
            bot.reply_to(message, u'''فایل ارسالی جهت بررسی ثبت شد.
لینک آنالیز اولیه: %s
@telescam''' % telegram_bot.koodous_link_existing_analysis(sha256sum))
                #Save link for our analysis + some metadata
        elif "apk" in os.path.splitext(message.document.file_name)[1].lower() : #if file extension is apk, but the content shows otherwise
            bot.reply_to(message, 'فایل ارسالی APK نیست.')

    telegram_bot.run()
    
