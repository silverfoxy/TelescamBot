#!/usr/bin/python
# -*- encoding: utf-8 -*-

import telebot, hashlib, requests, os, sqlite3, json, logging, logging.handlers, time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db import APK, Certificate, Submission, Base
from mkdir_p import mkdir_p

class Telescam_scanner_bot :
    def __init__(self) :
        self.TELEGRAM_TOKEN = 'ADD YOUR TELEGRAM BOT TOKEN HERE' # Personal - MUST NOT BE SHARED
        self.KOODOUS_API_TOKEN = 'ADD YOUR KOODOUS.COM API TOKEN HERE - FOUND UNDER PROFILE' # Personal - MUST NOT BE SHARED
        self.bot = telebot.TeleBot(self.TELEGRAM_TOKEN)
        self.FILES_DIR = './apk/'
    
    def run(self) :
        while True :
            try :
                logger.debug('Started Polling')
                self.bot.polling(none_stop=True)
            except Exception as e :
                logger.error('Error occured during polling', exc_info=True)
            self.bot.stop_polling()
            time.sleep(10)

    def valid_apk(self, file) :
        if file[0:2] == 'PK' : #Zip Archive (APK)
            return True
        logging.debug('Received a malformed APK.')
        return False

    def send_for_analysis(self, apk_file) :
        result = self.submit_to_koodous(apk_file)
        return result
        
    def submit_to_koodous(self, apk_file) :
        result_url = None
        sha256sum = hashlib.sha256(apk_file).hexdigest()
        upload_url = self.koodous_get_upload_token(sha256sum)
        if upload_url == None :
            # File Already Exists, Link existing report
            try :
                result = self.koodous_link_existing_analysis_json(sha256sum)
                analysis_result_status = self.koodous_analyze(sha256sum)
                # If File Was Uploaded But Not Analyzed, Handle Here
                if result == None :
                    if not analysis_result_status :
                        return None
                    # Wait for analysis to be completed
                    self.koodous_wait_for_result(sha256sum)
                logger.debug('Analysis result is available: %s' % self.koodous_link_existing_analysis(sha256sum))
            except Exception as e:
                logger.error('Failed to link the file on koodous at submit_to_koodous with sha256: %s' % sha256sum, exc_info=True)
                return None
        else :
            # New File, Upload and Request Analysis
            try :
                logger.debug('Uploading the file')
                requests.post(upload_url, files={'file' : apk_file})
                analysis_result_status = self.koodous_analyze(sha256sum)
                if not analysis_result_status :
                    return None
                # Wait for analysis to be completed
                self.koodous_wait_for_result(sha256sum)
            except Exception as e:
                logger.error('Failed to send the file to koodous for analysis at submit_to_koodous with sha256: %s' % sha256sum, exc_info=True)
                return None
        return sha256sum

    def koodous_analyze(self, sha256sum) :
        try :
            logger.debug('Requesting new analysis to be done for %s' % sha256sum)
            requests.get(url='https://api.koodous.com/apks/%s/analyze' % sha256sum, headers={'Authorization': 'Token %s' % self.KOODOUS_API_TOKEN})
            return True
        except Exception as e:
            logger.error('Error while requesting analysis for sha256: %s' % sha256sum, exc_info=True)
            return False


    def koodous_wait_for_result(self, sha256sum) :
        timeout = 15
        result = None
        while result == None and timeout > 0 :
            logger.debug('Analysis in progress')
            result = self.koodous_link_existing_analysis_json(sha256sum)
            timeout = timeout - 1
            time.sleep(120)
        if timeout <= 0 :
             logger.debug('Analysis Timed out')
             return False
        elif result != None :
            logger.debug('Analysis completed')
            return True
        logger.debug('Analysis Failed')
        return False

    def koodous_get_upload_token(self, sha256sum) :
        url_koodous = "https://api.koodous.com/apks/%s/get_upload_url" % sha256sum
        try :
            logger.debug('Getting upload token for %s' % sha256sum)
            r = requests.get(url = url_koodous, headers = { 'Authorization': 'Token %s' % self.KOODOUS_API_TOKEN })
        except Exception as e :
            logger.error('Failed to get upload_url at koodous_get_upload_token with sha256: %s' % sha256sum, exc_info=True)
            return None
        if r.status_code == 409 :
            logger.debug('File already analyzed sha256: %s, got 409' % sha256sum)
            return None
        else :
            try :
                return r.json().get('upload_url')
            except Exception as e :
                logger.error('Failed to parse json (upload_url) at koodous_get_upload_token with sha256: %s' % sha256sum, exc_info=True)
                return None

    def koodous_link_existing_analysis(self, sha256sum) :
        return 'https://koodous.com/apks/%s' % sha256sum

    def koodous_link_existing_analysis_json(self, sha256sum) :
        try :
            logger.debug('Requesting json for available analysis for %s' % sha256sum)
            r = requests.get('https://api.koodous.com/apks/%s/analysis' % sha256sum)
            if r.json() == {}:
                logger.debug('Received Empty json response in koodous_link_existing_analysis_json with sha256 %s' % sha256sum)
                return None
            return r.json()
        except Exception as e :
            logger.error('Failed to link existing json at koodous_link_existing_analysis_json with sha256: %s' % sha256sum, exc_info=True)
            return None

    def save(self, sha256sum, message, file) :
        engine = create_engine('sqlite:///telescam.db')
        Base.metadata.bind = engine
        DBSession = sessionmaker(bind=engine)
        session = DBSession()
        data = self.koodous_link_existing_analysis_json(sha256sum)
        koodous_url = self.koodous_link_existing_analysis(sha256sum)
        if data == None:
            logger.debug('Received empty json response at save from koodous_link_existing_analysis_json')
            return False
        try :
            new_certificate = None
            try :
                new_certificate = session.query(Certificate).filter(Certificate.sha1 == data['androguard']['certificate']['sha1']).first()
                logger.debug("Checking if current certificate exists in the database")
            except KeyError, e :
                logger.debug("Koodous couldn't exctract the certificate, Corrupted APK, using default certificate")
                new_certificate = session.query(Certificate).filter(Certificate.sha1 == '-').first()
            if new_certificate == None :
                logger.debug("Certificate didn't exist")
                new_certificate = Certificate(sha1=data['androguard']['certificate']['sha1'],
                    not_before=data['androguard']['certificate']['not_before'],
                    not_after=data['androguard']['certificate']['not_after'],
                    subjectdn=data['androguard']['certificate']['subjectDN'],
                    issuerdn=data['androguard']['certificate']['issuerDN'],
                    serial=data['androguard']['certificate']['serial'])
                session.add(new_certificate)

            new_apk = session.query(APK).filter(APK.sha256 == data['sha256']).first()
            logger.debug("Checking if current apk exists in the database")
            if new_apk == None :
                logger.debug("apk didn't exist")
                # Save apk
                local_filename = self.FILES_DIR + message.document.file_id + '.apk'
                try :
                    logger.debug("Saving to disk")
                    mkdir_p(os.path.dirname(local_filename))
                    with open(local_filename, 'wb') as new_file:
                        new_file.write(file)
                except Exception as e :
                        logger.error('Failed to save apk to disk: %s' % local_filename, exc_info=True)
                        raise
                new_apk = APK(app_name=data['androguard']['app_name'],
                    package_name=data['androguard']['package_name'],
                    version_code=data['androguard']['version_code'],
                    displayed_version=data['androguard']['displayed_version'],
                    local_package=local_filename,
                    koodous_url=koodous_url,
                    sha256=data['sha256'],
                    certificate=new_certificate)
                session.add(new_apk)

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
            logger.debug("Adding submission details to database")
            try :
                session.commit()
                logger.debug("Saved changes to database")
                return True
            except Exception as e :
                logger.error('Failed to save changes to the database', exc_info=True)
                raise
        except KeyError, e :
            logger.error('Corrupted APK', exc_info=True)
            return False
        except Exception as e :
            logger.error('Failed to save apk information', exc_info=True)
            logger.error('Json to process: %s' % data)
            return False

if __name__ == '__main__' :

    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.ERROR) #urllib3 spams the log, since telegram is polling for new messages
    logger = logging.getLogger(__name__)
    log_handler = logging.handlers.WatchedFileHandler('log.txt')
    log_handler.setFormatter(logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    logger.addHandler(log_handler)

    telegram_bot = Telescam_scanner_bot()
    bot = telegram_bot.bot

    # Register message handlers
    # Handle '/help'
    @bot.message_handler(commands=['help'])
    def send_welcome(message):
        try :
            bot.reply_to(message, u"""\
Welcome to TeleScam ‌Bot, Submit your malicious APK samples here.
For more information about our project visit http://telescam.ir
سلام به بات دیده بان تلگرام خوش آمدید، نمونه apk های مشکوک خود را از این طریق برای ما ارسال کنید.
برای کسب اطلاعات بیشتر در خصوص این پروژه به وبسایت http://telescam.ir مراجعه کنید.
کانال تلگرام پروژه
@teleScam
""")
        except Exception as e :
            logger.error('Failed to reply with help message', exc_info=True)

    @bot.message_handler(func=lambda message: True, content_types=['document'])
    def on_receive_file(message) :
        bot.send_chat_action(message.chat.id, 'typing')
        try :
            file_info = bot.get_file(message.document.file_id)
            downloaded_file = bot.download_file(file_info.file_path)
        except Exception as e :
            try :
                bot.reply_to(message, u'دریافت فایل ارسالی از سرور های تلگرام با مشکل مواجه شد.')
            except Exception as e :
                logger.error('Failed to reply with "Failed to analyze"', exc_info=True)
            logger.error('Failed to download_file', exc_info=True)
            return None
        if telegram_bot.valid_apk(downloaded_file) :
            try :
                bot.reply_to(message, u'فایل دریافت شد و آنالیز اولیه فایل در حال انجام است، پس از اتمام کار از همین طریق به شما اطلاع داده خواهد شد.')
                telegram_bot.bot.send_chat_action(message.chat.id, 'typing')
            except Exception as e :
                logger.error('Failed to reply with starting analysis', exc_info=True)
            sha256sum = telegram_bot.send_for_analysis(downloaded_file)
            if sha256sum == None :
                try :
                    bot.reply_to(message, u'آنالیز فایل ارسالی با مشکل مواجه شد، لطفا دوباره سعی کنید.')
                except Exception as e :
                    logger.error('Failed to reply with "Failed to analyze"', exc_info=True)
            else :
                #Save file save(sha256sum, message, file)
                if telegram_bot.save(sha256sum, message, downloaded_file):
                    try :
                        bot.reply_to(message, u'''فایل ارسالی جهت بررسی ثبت شد.
لینک آنالیز اولیه: %s
@telescam''' % telegram_bot.koodous_link_existing_analysis(sha256sum))
                    except Exception as e :
                        logger.error('Failed to reply with "Failed to analyze"', exc_info=True)
                else :
                    try :
                        bot.reply_to(message, u'''آنالیز فایل ارسالی با مشکل مواجه شد، لطفا دوباره سعی کنید.
دلایل این مشکل می تواند از دسترس خارج بودن سرویس آنالیز koodous.com و یا خراب بودن فایل APK ارسالی باشد.
%s''' % telegram_bot.koodous_link_existing_analysis(sha256sum))
                    except Exception as e :
                        logger.error('Failed to reply with "Failed to analyze"', exc_info=True)
        elif "apk" in os.path.splitext(message.document.file_name)[1].lower() : #if file extension is apk, but the content shows otherwise
            try :
                bot.reply_to(message, 'فایل ارسالی APK نیست.')
            except Exception as e :
                logger.error('Failed to reply with "File not APK"', exc_info=True)
    
    telegram_bot.run()

    
