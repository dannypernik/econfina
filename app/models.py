from datetime import datetime
from time import time
import jwt
from app import db, login, app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(32), index=True)
    last_name = db.Column(db.String(32), index=True)
    email = db.Column(db.String(64), index=True)
    phone = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(128))
    timezone = db.Column(db.Integer)
    location = db.Column(db.String(128))
    status = db.Column(db.String(24), default = "active", index=True)
    tutor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    students = db.relationship('User', backref='tutor', lazy='dynamic')
    parents = db.relationship('User', backref='child', lazy='dynamic')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    last_viewed = db.Column(db.DateTime, default=datetime.utcnow)
    role = db.Column(db.String(24), index=True)
    is_admin = db.Column(db.Boolean)
    test_dates = db.relationship('UserTestDate',
                                foreign_keys=[UserTestDate.student_id],
                                backref=db.backref('student', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')

    def __repr__(self):
        return '<User {}>'.format(self.email)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')
    
    def add_test_date(self, test_date):
        if not self.is_testing(test_date):
            t = UserTestDate(student_id=self.id, test_date_id=test_date.id)
            db.session.add(t)
            db.session.commit()

    def remove_test_date(self, test_date):
        f = self.test_dates.filter_by(test_date_id=test_date.id).first()
        if f:
            db.session.delete(f)
            

    def is_testing(self, test_date):
        return self.test_dates.filter(
            UserTestDate.test_date_id == test_date.id).count() > 0
    
    def get_dates(self):
        return TestDate.query.join(
                UserTestDate, (UserTestDate.test_date_id == TestDate.id)
            ).filter(UserTestDate.student_id == self.id)

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)


class TestDate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date)
    test = db.Column(db.String(24))
    status = db.Column(db.String(24), default = "confirmed")
    reg_date = db.Column(db.Date)
    late_date = db.Column(db.Date)
    other_date = db.Column(db.Date)
    score_date = db.Column(db.Date)
    #students = db.relationship('UserTestDate', backref=db.backref('dates_interested'), lazy='dynamic')

    def __repr__(self):
        return '<TestDate {}>'.format(self.date)


class UserTestDate(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    test_date_id = db.Column(db.Integer, db.ForeignKey('test_date.id'), primary_key=True)
    is_registered = db.Column(db.Boolean)
    users = db.relationship("User", backref=db.backref('planned_tests', lazy='dynamic'))
    test_dates = db.relationship("TestDate", backref=db.backref('users_interested', lazy='dynamic'))


@login.user_loader
def load_user(id):
    return User.query.get(int(id))
