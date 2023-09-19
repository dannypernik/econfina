from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, BooleanField, PasswordField, TextAreaField, \
    SubmitField, IntegerField, SelectField, DecimalField, validators
from wtforms.fields.html5 import DateField, EmailField
from wtforms.validators import ValidationError, InputRequired, DataRequired, \
    Email, EqualTo, Length
from flask_wtf.file import FileField, FileAllowed
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
    message = TextAreaField('Message', render_kw={"placeholder": "Message"}, \
        validators=[InputRequired()])
    submit = SubmitField('Submit')


class ItemForm(FlaskForm):
    name = StringField('Item name', render_kw={'placeholder': 'Item name'}, \
        validators=[InputRequired()])
    price = StringField('Price', render_kw={'placeholder': 'Price'}, \
        validators=[InputRequired()])
    description = TextAreaField('Description', render_kw={'placeholder': 'Description'})
    image_path = FileField('Update image',validators=[FileAllowed(['jpg', 'jpeg', 'png', 'webp'], \
        'Please upload a .jpg, .png, or .webp image')])
    category_id = SelectField('Category', coerce=int)
    status = SelectField('Status', choices=[('active','Active'),('inactive','Inactive')])
    order = DecimalField('Order', render_kw={'placeholder': 'Order'}, \
        validators=(validators.Optional(),))
    booqable_id = StringField('Booqable ID', render_kw={'placeholder': 'Booqable ID'}, \
        validators=[InputRequired()])
    save = SubmitField('Save')

    def validate_image(self, image_path):
        if image_path.errors:
            raise ValidationError("Images only!")


class ItemCategoryForm(FlaskForm):
    name = StringField('Category name', render_kw={'placeholder': 'Category name'}, \
        validators=[InputRequired()])
    order = DecimalField('Order', render_kw={'placeholder': 'Order'}, \
        validators=(validators.Optional(),))
    save = SubmitField('Save')


class ReviewForm(FlaskForm):
    message = TextAreaField('Share your experience', render_kw={'placeholder': 'What did you think?'}, \
        validators=[InputRequired()])
    name = StringField('Name', render_kw={'placeholder': 'Name'})
    order = DecimalField('Order', render_kw={'placeholder': 'Order'}, \
        validators=(validators.Optional(),))
    email = EmailField('Email', render_kw={'placeholder': 'Email'}, validators=[InputRequired()])
    is_approved = BooleanField('Approved')
    save = SubmitField('Send review')


class FaqForm(FlaskForm):
    question = TextAreaField('Question', render_kw={'placeholder': 'Question'})
    answer = TextAreaField('Answer', render_kw={'placeholder': 'Answer'})
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