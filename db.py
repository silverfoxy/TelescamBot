
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
import datetime

Base = declarative_base()

class Certificate(Base) :
	__tablename__ = 'tbl_certificates'
	id = Column(Integer, primary_key=True)
	sha1 = Column(String(40), nullable=False)
	not_before = Column(String(40), nullable=False)
	not_after = Column(String(40), nullable=False)
	subjectdn = Column(String(250), nullable=False)
	issuerdn = Column(String(250), nullable=False)
	serial = Column(String(50), nullable=False)

class APK(Base) :
	__tablename__ = 'tbl_apks'
	id = Column(Integer, primary_key=True)
	app_name = Column(String(250), nullable=False)
	package_name = Column(String(250), nullable=False)
	version_code = Column(String(50), nullable=False)
	displayed_version = Column(String(50), nullable=False)
	local_package = Column(String(250), nullable=False)
	koodous_url = Column(String(250), nullable=False)
	sha256 = Column(String(64), nullable=False)
	certificate_id = Column(Integer, ForeignKey('tbl_certificates.id'))
	certificate = relationship(Certificate)

class Submission(Base) :
	__tablename__ = 'tbl_submissions'
	id = Column(Integer, primary_key=True)
	submitted_to_username = Column(String(250), nullable=True)
	submitted_to_title = Column(String(250), nullable=True)
	submitted_to_id = Column(String(250), nullable=False)
	forwarded_from_username = Column(String(250), nullable=True)
	forwarded_from_firstname = Column(String(250), nullable=True)
	forwarded_from_lastname = Column(String(250), nullable=True)
	forwarded_from_id = Column(String(250), nullable=True)
	submitted_by_username = Column(String(250), nullable=True)
	submitted_by_firstname = Column(String(250), nullable=True)
	submitted_by_lastname = Column(String(250), nullable=True)
	submitted_by_id = Column(String(250), nullable=False)
	message_text = Column(String(1000), nullable=True)
	filename = Column(String(250), nullable=False)
	apk_id = Column(Integer, ForeignKey('tbl_apks.id'))
	apk = relationship(APK)
	date = Column(DateTime, default=datetime.datetime.utcnow)

# engine = create_engine('sqlite:///telescam.db')
engine = create_engine('mysql://telescam_user:YP7NQ30D@localhost:3306/telescam_analysis', echo=False)
Base.metadata.create_all(engine)

# Create empty certificate for corrupted APKs
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
new_certificate = session.query(Certificate).filter(Certificate.sha1 == '-').first()
if new_certificate == None :
	new_certificate = Certificate(sha1='-',
	                    not_before='-',
	                    not_after='-',
	                    subjectdn='-',
	                    issuerdn='-',
	                    serial='-')
	session.add(new_certificate)
	session.commit()

