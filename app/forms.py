from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, BooleanField, PasswordField, TextAreaField, \
    SubmitField, IntegerField, SelectField, DecimalField, validators
from wtforms.fields.html5 import DateField, EmailField
from wtforms.validators import ValidationError, InputRequired, DataRequired, \
    Email, EqualTo, Length
from app.models import User, Item, ItemCategory, Faq, FaqCategory, Review


def validate_email(self, email):
    user = User.query.filter_by(email=email.data).first()
    if user is not None:
        raise ValidationError('An account already exists for ' + user.email + '.')


class ContactForm(FlaskForm):
    first_name = StringField('First name', render_kw={"placeholder": "First name"}, \
        validators=[InputRequired()])
    email = EmailField('Email address', render_kw={"placeholder": "Email address"}, \
        validators=[InputRequired(), Email(message="Please enter a valid email address")])
    phone = StringField('Phone number (optional)', render_kw={"placeholder": "Phone number (optional)"})
    subject = StringField('Subject', render_kw={'placeholder': 'Subject'}, default='Message')
    message = TextAreaField('Message', render_kw={"placeholder": "Message"}, \
        validators=[InputRequired()])
    submit = SubmitField('Submit')


class ItemForm(FlaskForm):
    name = StringField('Item name', render_kw={'placeholder': 'Item name'}, \
        validators=[InputRequired()])
    price = StringField('Price', render_kw={'placeholder': 'Price'}, \
        validators=[InputRequired()])
    description = TextAreaField('Description', render_kw={'placeholder': 'Description'})
    category_id = SelectField('Category', coerce=int)
    status = SelectField('Status', choices=[('active','Active'),('inactive','Inactive')])
    order = DecimalField('Order', render_kw={'placeholder': 'Order'}, \
        validators=(validators.Optional(),))
    save = SubmitField('Save')


class ItemCategoryForm(FlaskForm):
    name = StringField('Category name', render_kw={'placeholder': 'Category name'}, \
        validators=[InputRequired()])
    order = DecimalField('Order', render_kw={'placeholder': 'Order'}, \
        validators=(validators.Optional(),))
    save = SubmitField('Save')


class ReviewForm(FlaskForm):
    message = TextAreaField('Share your experience', render_kw={'placeholder': 'Share your experience'})
    name = StringField('Your name (optional)', render_kw={'placeholder': 'Your name (optional)'})
    order = DecimalField('Order', render_kw={'placeholder': 'Order'}, \
        validators=(validators.Optional(),))
    save = SubmitField('Save')


class FaqForm(FlaskForm):
    question = TextAreaField('Question', render_kw={'placeholder': 'Question'})
    answer = StringField('Answer', render_kw={'placeholder': 'Answer'})
    category_id = SelectField('Category', coerce=int)
    order = DecimalField('Order', render_kw={'placeholder': 'Order'}, \
        validators=(validators.Optional(),))
    save = SubmitField('Save')


class FaqCategoryForm(FlaskForm):
    name = StringField('Category name', render_kw={'placeholder': 'Category name'}, \
        validators=[InputRequired()])
    order = DecimalField('Order', render_kw={'placeholder': 'Order'}, \
        validators=(validators.Optional(),))
    save = SubmitField('Save')


class EmailListForm(FlaskForm):
    first_name = StringField('First name', render_kw={"placeholder": "First name"}, \
        validators=[InputRequired()])
    email = EmailField('Email address', render_kw={"placeholder": "Email address"}, \
        validators=[InputRequired(), Email(message="Please enter a valid email address"), \
            validate_email])
    submit = SubmitField()


class SignupForm(FlaskForm):
    email = EmailField('Email address', render_kw={"placeholder": "Email address"}, \
        validators=[InputRequired(), Email(message="Please enter a valid email address"), \
            validate_email])
    first_name = StringField('First name', render_kw={"placeholder": "First name"}, \
        validators=[InputRequired()])
    last_name = StringField('Last name', render_kw={"placeholder": "Last name"}, \
        validators=[InputRequired()])
    password = PasswordField('Password', render_kw={"placeholder": "Password"}, \
        validators=[InputRequired()])
    password2 = PasswordField('Repeat Password', render_kw={"placeholder": "Repeat Password"}, \
        validators=[InputRequired(), EqualTo('password',message="Passwords do not match.")])
    submit = SubmitField('Sign up')


class LoginForm(FlaskForm):
    email = EmailField('Email address', render_kw={"placeholder": "Email address"}, \
        validators=[InputRequired(), Email(message="Please enter a valid email address")])
    password = PasswordField('Password', render_kw={"placeholder": "Password"}, \
        validators=[InputRequired()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Log in')


class RequestPasswordResetForm(FlaskForm):
    email = EmailField('Email address', render_kw={"placeholder": "Email address"}, \
        validators=[InputRequired(), Email(message="Please enter a valid email address")])
    submit = SubmitField('Request password reset')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', render_kw={"placeholder": "New password"}, \
        validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', render_kw={"placeholder": "Verify password"}, \
        validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset password')


def full_name(User):
    return User.first_name + " " + User.last_name


class UserForm(FlaskForm):
    first_name = StringField('First name', render_kw={"placeholder": "First name"}, \
        validators=[InputRequired()])
    last_name = StringField('Last name', render_kw={"placeholder": "Last name"}, \
        validators=[InputRequired()])
    email = EmailField('Email address', render_kw={"placeholder": "Email address"}, \
        validators=[InputRequired(), Email(message="Please enter a valid email address")])
    phone = StringField('Phone', render_kw={"placeholder": "Phone"})
    location = StringField('Location', render_kw={"placeholder": "Location"})
    status = SelectField('Status', choices=[('none','None'),('active', 'Active'),('paused','Paused'),('inactive','Inactive')])
    role = SelectField('Role', choices=[('student', 'Student'),('parent', 'Parent'),('admin','Admin')])
    parent_id = SelectField('Parent', coerce=int)
    is_admin = BooleanField('Admin')
    submit = SubmitField('Save')

    def __init__(self, original_email, *args, **kwargs):
        super(UserForm, self).__init__(*args, **kwargs)
        self.original_email = original_email
    
    def validate_email(self, email):
        if email.data != self.original_email:
            user = User.query.filter_by(email=email.data).first()
            if user is not None:
                raise ValidationError('An account already exists for ' + user.email + '.')