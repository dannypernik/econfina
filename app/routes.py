import os
from flask import Flask, render_template, flash, Markup, redirect, url_for, \
    request, send_from_directory, send_file, make_response
from app import app, db, login, hcaptcha
from app.forms import ContactForm, ItemForm, ItemCategoryForm, FaqForm, FaqCategoryForm, ReviewForm, \
    EmailListForm, LoginForm, UserForm, RequestPasswordResetForm, ResetPasswordForm
from flask_login import current_user, login_user, logout_user, login_required, login_url
from app.models import User, Item, ItemCategory, Faq, FaqCategory, Review
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename
from datetime import datetime
from app.email import send_contact_email, send_verification_email, send_password_reset_email, \
    send_confirmation_email, send_review_approval_email
from functools import wraps
import requests

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_viewed = datetime.utcnow()
        db.session.commit()

def dir_last_updated(folder):
    return str(max(os.path.getmtime(os.path.join(root_path, f))
                   for root_path, dirs, files in os.walk(folder)
                   for f in files))

@app.context_processor
def inject_values():
    return dict(last_updated=dir_last_updated('app/static'))

def admin_required(f):
    @login_required
    @wraps(f)
    def wrap(*args, **kwargs):
        if current_user.is_admin:
            return f(*args, **kwargs)
        else:
            flash('You must have administrator privileges to access this page.', 'error')
            logout_user()
            return redirect(login_url('login', next_url=request.url))
    return wrap


def get_quote():
    try:
        quote = requests.get("https://zenquotes.io/api/today")

        message = "\u301D" + quote.json()[0]['q'] + "\u301E"
        author = "\u2013 " + quote.json()[0]['a']
    except requests.exceptions.RequestException:
        message = ""
        author = ""
    return message, author

message, author = get_quote()

admin_email = app.config['ADMIN_EMAIL']


@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
    form = ContactForm()
    vessels = Item.query.filter_by(category_id=1)
    categories = ItemCategory.query.order_by(ItemCategory.order).all()
    booqable_id = request.args.get('id', None)
    if form.validate_on_submit():
        if hcaptcha.verify():
            pass
        else:
            flash('A computer has questioned your humanity. Please try again.', 'error')
            return redirect(url_for('index'))
        user = User(first_name=form.first_name.data, email=form.email.data, phone=form.phone.data)
        message = form.message.data
        subject = 'message'
        email_status = send_contact_email(user, message, subject.title())
        if email_status == 200:
            send_confirmation_email(user, message, subject)
            flash('Please check ' + user.email + ' for a confirmation email. Thank you for reaching out!')
            return redirect(url_for('index', _anchor="home"))
        else:
            flash('Email failed to send, please contact ' + admin_email + \
                ' and paste your message: ' + message, 'error')
    return render_template('index.html', form=form, vessels=vessels, categories=categories, booqable_id=booqable_id)


@app.route('/about')
def about():
    return render_template('about.html', title="About")


@app.route('/reviews', methods=['GET', 'POST'])
def reviews():
    form = ReviewForm()
    reviews = Review.query.filter_by(is_approved=True).order_by(Review.order)

    if form.validate_on_submit():
        review = Review(message=form.message.data, name=form.name.data, email=form.email.data, \
            is_approved=False)
        user = User(first_name=form.name.data, email=form.email.data)
        subject='review'
        try:
            db.session.add(review)
            db.session.flush()
            review.order = float(review.id)
            db.session.add(review)
            db.session.commit()
        except:
            flash('Email failed to send. Please copy your review and email to ' + admin_email + \
                ': ' + review.message, 'error')
            return redirect(url_for('reviews'))
        email_check = send_review_approval_email(review)
        if email_check == 200:
            send_confirmation_email(user, review.message, subject)
            flash('Your review was emailed to the team. Thank you!')
            return redirect(url_for('index'))
    return render_template('reviews.html', title="Reviews", form=form, reviews=reviews)


@app.route('/choose-your-vessel')
def choose_your_vessel():
    vessels = Item.query.filter_by(category_id=1)
    return render_template('choose-your-vessel.html', title="Choose Your Vessel", vessels=vessels)


@app.route('/vessel-selected')
def vessel_selected():
    booqable_id = request.args.get('id', None)
    sale_items = Item.query.filter(Item.booqable_id != booqable_id).order_by(Item.order)
    return render_template('vessel-selected.html', title="Pickup time", booqable_id=booqable_id, sale_items=sale_items)


@app.route('/faq', methods=['GET', 'POST'])
def faq():
    form = ContactForm()
    faqs = Faq.query.order_by(Faq.order).all()
    categories = FaqCategory.query.order_by(FaqCategory.order).distinct()
    if form.validate_on_submit():
        if hcaptcha.verify():
            pass
        else:
            flash('A computer has questioned your humanity. Please try again.', 'error')
            return redirect(url_for('index'))
        user = User(first_name=form.first_name.data, email=form.email.data, phone=form.phone.data)
        message = form.message.data
        subject = 'question'
        email_status = send_contact_email(user, message, subject.title())
        if email_status == 200:
            send_confirmation_email(user, message, subject)
            flash('Please check ' + user.email + ' for a confirmation email. Thank you for reaching out!')
            return redirect(url_for('index', _anchor="home"))
        else:
            flash('Email failed to send, please contact ' + admin_email + \
                ' and paste your message: ' + message, 'error')
    return render_template('faq.html', title="FAQ", form=form, faqs=faqs, categories=categories)


@app.route('/landing-page')
def landing_page():
    return render_template('landing-page.html', title="")


@app.route('/admin')
@admin_required
def admin():
    message, author = get_quote()
    return render_template('admin.html', title="Admin", message=message, author=author)


@app.route('/edit-items', methods=['GET', 'POST'])
@admin_required
def edit_items():
    form = ItemForm()
    category_form = ItemCategoryForm()
    items = Item.query.order_by(Item.order).all()
    categories = ItemCategory.query.order_by(ItemCategory.order).distinct()
    category_list = [(c.id, c.name.title()) for c in categories]
    form.category_id.choices = category_list

    return render_template('edit-items.html', title="Menu items", form=form, \
        category_form=category_form, items=items, categories=categories)


@app.route('/new-item', methods=['POST'])
@admin_required
def new_item():
    form = ItemForm(request.form)
    categories = ItemCategory.query.order_by(ItemCategory.order).distinct()
    category_list = [(c.id, c.name.title()) for c in categories]
    form.category_id.choices = category_list
    if form.category_id.data == 0:
        flash('Please select a category', 'error')
        return redirect(url_for('edit_items'))
    if form.validate_on_submit():
        item = Item(name=form.name.data.lower(), category_id=form.category_id.data, price=form.price.data, \
            description=form.description.data, status=form.status.data, booqable_id=form.booqable_id.data)

        uploaded_file = request.files['image_path']
        filename = secure_filename(uploaded_file.filename)
        if filename != '':
            uploaded_file.save(os.path.join(app.root_path, 'static/img/items', filename))
            item.image_path = filename
        
        try:
            db.session.add(item)
            db.session.flush()
            item.order = float(item.id)
            db.session.add(item)
            db.session.commit()
            flash(item.name.title() + ' added')
        except:
            db.session.rollback()
            flash(item.name.title() + ' could not be added', 'error')
    return redirect(url_for('edit_items'))


@app.route('/new-item-category', methods=['POST'])
@admin_required
def new_item_category():
    category_form = ItemCategoryForm()
    if category_form.validate_on_submit():
        category = ItemCategory(name=category_form.name.data)
        try:
            db.session.add(category)
            db.session.flush()
            category.order = category.id
            db.session.commit()
            flash(category.name.title() + ' added')
        except:
            db.session.rollback()
            flash(category.name.title() + ' could not be added', 'error')
    return redirect(url_for('edit_items'))


@app.route('/edit-item/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_item(id):
    form = ItemForm()
    item = Item.query.get_or_404(id)
    categories = ItemCategory.query.order_by(ItemCategory.order).distinct()
    category_list = [(c.id, c.name.title()) for c in categories]
    form.category_id.choices = category_list
    if form.validate_on_submit():
        if 'save' in request.form:
            item.name=form.name.data.lower()
            item.description=form.description.data
            item.price=form.price.data
            item.category_id=form.category_id.data
            item.status=form.status.data
            item.order=form.order.data
            item.booqable_id=form.booqable_id.data

            uploaded_file = request.files['image_path']
            filename = secure_filename(uploaded_file.filename)
            if filename != '':
                full_path = os.path.join(app.root_path, 'static/img/items', item.image_path)
                if os.path.exists(full_path):
                    os.remove(full_path)
                uploaded_file.save(os.path.join(app.root_path, 'static/img/items', filename))
                item.image_path = filename

            try:
                db.session.add(item)
                db.session.commit()
                flash(item.name.title() + ' updated')
            except:
                db.session.rollback()
                flash(item.name.title() + ' could not be updated', 'error')
        elif 'delete' in request.form:
            db.session.delete(item)
            db.session.commit()
            flash('Deleted ' + item.name.title())
        else:
            flash('Code error in POST request', 'error')
        return redirect(url_for('edit_items'))
    elif request.method == "GET":
        form.name.data=item.name
        form.category_id.data=item.category_id
        form.price.data=item.price
        form.image_path.data=item.image_path
        form.description.data=item.description
        form.order.data=item.order
        form.status.data=item.status
        form.booqable_id.data=item.booqable_id

    return render_template('edit-item.html', title="Edit item", form=form, item=item)


@app.route('/edit-item-category/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_item_category(id):
    form = ItemCategoryForm()
    category = ItemCategory.query.get_or_404(id)
    items = Item.query.filter_by(category_id=id)
    if form.validate_on_submit():
        if 'save' in request.form:
            category.name=form.name.data
            category.order=form.order.data
            try:
                db.session.add(category)
                db.session.commit()
                flash(category.name.title() + ' updated')
            except:
                db.session.rollback()
                flash(category.name.title() + ' could not be updated', 'error')
        elif 'delete' in request.form:
            db.session.delete(category)
            db.session.commit()
            flash('Deleted ' + category.name.title())
        else:
            flash('Code error in POST request', 'error')
        return redirect(url_for('edit_items'))
    elif request.method == "GET":
        form.name.data=category.name
        form.order.data=category.order
    return render_template('edit-item-category.html', title="Edit item category", form=form, \
        category=category, items=items)


@app.route('/edit-faqs', methods=['GET', 'POST'])
@admin_required
def edit_faqs():
    form = FaqForm()
    category_form = FaqCategoryForm()
    faqs = Faq.query.order_by(Faq.order).all()
    categories = FaqCategory.query.order_by(FaqCategory.order).distinct()
    category_list = [(c.id, c.name.title()) for c in categories]
    form.category_id.choices = category_list

    return render_template('edit-faqs.html', title="FAQs", form=form, \
        category_form=category_form, faqs=faqs, categories=categories)


@app.route('/new-faq', methods=['POST'])
@admin_required
def new_faq():
    form = FaqForm()
    categories = FaqCategory.query.order_by(FaqCategory.order).distinct()
    category_list = [(c.id, c.name.title()) for c in categories]
    form.category_id.choices = category_list
    if form.category_id.data == 0:
        flash('Please select a category', 'error')
        return redirect(url_for('edit_faqs'))
    if form.validate_on_submit():
        faq = Faq(question=form.question.data, answer=form.answer.data, category_id=form.category_id.data)
        try:
            db.session.add(faq)
            db.session.flush()
            faq.order = float(faq.id)
            db.session.add(faq)
            db.session.commit()
            flash('FAQ added')
        except:
            db.session.rollback()
            flash('FAQ could not be added', 'error')
    return redirect(url_for('edit_faqs'))


@app.route('/new-faq-category', methods=['POST'])
@admin_required
def new_faq_category():
    category_form = FaqCategoryForm()
    if category_form.validate_on_submit():
        category = FaqCategory(name=category_form.name.data.lower())
        try:
            db.session.add(category)
            db.session.flush()
            category.order = category.id
            db.session.commit()
            flash(category.name.title() + ' added')
        except:
            db.session.rollback()
            flash(category.name.title() + ' could not be added', 'error')
    return redirect(url_for('edit_faqs'))


@app.route('/edit-faq/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_faq(id):
    form = FaqForm()
    faq = Faq.query.get_or_404(id)
    categories = FaqCategory.query.order_by(FaqCategory.order).distinct()
    category_list = [(c.id, c.name.title()) for c in categories]
    form.category_id.choices = category_list
    if form.validate_on_submit():
        if 'save' in request.form:
            faq.question=form.question.data
            faq.answer=form.answer.data
            faq.category_id=form.category_id.data
            faq.order=form.order.data

            try:
                db.session.add(faq)
                db.session.commit()
                flash('FAQ updated')
            except:
                db.session.rollback()
                flash('FAQ could not be updated', 'error')
        elif 'delete' in request.form:
            db.session.delete(faq)
            db.session.commit()
            flash('Deleted FAQ')
        else:
            flash('Code error in POST request', 'error')
        return redirect(url_for('edit_faqs'))
    elif request.method == "GET":
        form.question.data=faq.question
        form.answer.data=faq.answer
        form.category_id.data=faq.category_id
        form.order.data=faq.order

    return render_template('edit-faq.html', title="Edit FAQ", form=form, faq=faq)


@app.route('/edit-faq-category/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_faq_category(id):
    form = FaqCategoryForm()
    category = FaqCategory.query.get_or_404(id)
    faqs = Faq.query.filter_by(category_id=id)
    if form.validate_on_submit():
        if 'save' in request.form:
            category.name=form.name.data.lower()
            category.order=form.order.data
            try:
                db.session.add(category)
                db.session.commit()
                flash(category.name.title() + ' updated')
            except:
                db.session.rollback()
                flash(category.name.title() + ' could not be updated', 'error')
        elif 'delete' in request.form:
            db.session.delete(category)
            db.session.commit()
            flash('Deleted ' + category.name.title())
        else:
            flash('Code error in POST request', 'error')
        return redirect(url_for('edit_faqs'))
    elif request.method == "GET":
        form.name.data=category.name
        form.order.data=category.order
    return render_template('edit-faq-category.html', title="Edit FAQ category", form=form, \
        category=category, faqs=faqs)


@app.route('/edit-reviews', methods=['GET', 'POST'])
@admin_required
def edit_reviews():
    form = ReviewForm()
    approved_reviews = Review.query.filter_by(is_approved=True).order_by(Review.order)
    pending_reviews = Review.query.filter_by(is_approved=False).order_by(Review.order)

    if form.validate_on_submit():
        review = Review(name=form.name.data, message=form.message.data, email=form.email.data)
        try:
            db.session.add(review)
            db.session.flush()
            review.order = float(review.id)
            db.session.add(review)
            db.session.commit()
            flash('Review added')
        except:
            db.session.rollback()
            flash('Review could not be added', 'error')
        return redirect(url_for('edit_reviews'))
    return render_template('edit-reviews.html', title="Reviews", form=form, \
        approved_reviews=approved_reviews, pending_reviews=pending_reviews)


@app.route('/edit-review/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_review(id):
    form = ReviewForm()
    review = Review.query.get_or_404(id)

    if form.validate_on_submit():
        if 'save' in request.form:
            review.name=form.name.data
            review.email=form.email.data
            review.message=form.message.data
            review.is_approved=form.is_approved.data
            review.order=form.order.data
            try:
                db.session.add(review)
                db.session.commit()
                flash('Review updated')
            except:
                db.session.rollback()
                flash('Review could not be updated', 'error')
        elif 'delete' in request.form:
            db.session.delete(review)
            db.session.commit()
            flash('Deleted review')
        else:
            flash('Code error in POST request', 'error')
        return redirect(url_for('edit_reviews'))
    elif request.method == "GET":
        form.name.data=review.name
        form.email.data=review.email
        form.message.data=review.message
        form.order.data=review.order
        form.is_approved.data=review.is_approved
    return render_template('edit-review.html', title="Edit review", form=form, review=review)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        flash('You are already signed in.')
        return redirect(url_for('start_page'))
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))
        login_user(user)
        if user.is_verified != True:
            email_status = send_verification_email(user)
            if email_status == 200:
                flash('Please check your inbox to verify your email.')
            else:
                flash('Verification email did not send. Please contact ' + admin_email, 'error')
        next_page = request.args.get('next')
        print('next:', next_page)
        if not next_page or url_parse(next_page).netloc != '':
            return redirect(url_for('start_page'))
        return redirect(next_page)
    return render_template('login.html', title='Log in', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/start-page')
def start_page():
    if current_user.is_admin:
        return redirect(url_for('admin'))
    else:
        return redirect(url_for('index'))


@app.route('/verify-email/<token>', methods=['GET', 'POST'])
def verify_email(token):
    logout_user()
    user = User.verify_email_token(token)
    if user:
        login_user(user)
        user.is_verified = True
        db.session.add(user)
        db.session.commit()
        if not user.password_hash:
            flash('Please choose a password to complete verification')
            return redirect(url_for('set_password', token=token))
        flash('Thank you for verifying your account.')
        return redirect(url_for('start_page'))
    else:
        flash('Your verification link is expired or invalid. Log in to receive a new link.')
        return redirect(url_for('login'))


@app.route('/request-password-reset', methods=['GET', 'POST'])
def request_password_reset():
    form = RequestPasswordResetForm()
    if form.validate_on_submit():
        if hcaptcha.verify():
            pass
        else:
            flash('A computer has questioned your humanity. Please try again.', 'error')
            return redirect(url_for('request_password_reset'))
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            email_status = send_password_reset_email(user)
            if email_status == 200:
                flash('Check your email for instructions to reset your password.')
            else:
                flash('Email failed to send, please contact ' + admin_email, 'error')
        else:
            flash('Check your email for instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('request-password-reset.html', title='Reset password', form=form)


@app.route('/set-password/<token>', methods=['GET', 'POST'])
def set_password(token):
    user = User.verify_email_token(token)
    if not user:
        flash('The password reset link is expired or invalid. Please try again.')
        return redirect(url_for('request_password_reset'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.is_verified = True
        db.session.commit()
        login_user(user)
        flash('Your password has been saved.')
        return redirect(url_for('start_page'))
    return render_template('set-password.html', form=form)


@app.route('/edit-users', methods=['GET', 'POST'])
@admin_required
def edit_users():
    form = UserForm(None)
    admins = User.query.filter_by(is_admin=True)
    not_admins = User.query.filter_by(is_admin=False)
    if form.validate_on_submit():
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, \
            email=form.email.data, is_admin=form.is_admin.data)
        try:
            db.session.add(user)
            db.session.commit()
            flash(user.first_name + ' added')
        except:
            db.session.rollback()
            flash(user.first_name + ' could not be added', 'error')
            return redirect(url_for('edit_users'))
        email_status = send_verification_email(user)
        if email_status == 200:
            flash("Verification email sent to " + user.email)
        else:
            flash('Verification email failed to send', 'error')
    return render_template('edit-users.html', title="Users", form=form, admins=admins, not_admins=not_admins)


@app.route('/edit-user/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_user(id):
    user = User.query.get_or_404(id)
    form = UserForm(user.email, obj=user)
    if form.validate_on_submit():
        if 'save' in request.form:
            user.first_name=form.first_name.data
            user.last_name=form.last_name.data
            user.email=form.email.data
            user.is_admin=form.is_admin.data

            try:
                db.session.add(user)
                db.session.commit()
                flash(user.first_name + ' updated')
            except:
                db.session.rollback()
                flash(user.first_name + ' could not be updated', 'error')
                return redirect(url_for('edit_users'))
        elif 'delete' in request.form:
            db.session.delete(user)
            db.session.commit()
            flash('Deleted ' + user.first_name)
        else:
            flash('Code error in POST request', 'error')
        return redirect(url_for('edit_users'))
    elif request.method == "GET":
        form.first_name.data=user.first_name
        form.last_name.data=user.last_name
        form.email.data=user.email
        form.is_admin.data=user.is_admin
    return render_template('edit-user.html', title='Edit User', form=form, user=user)


@app.route("/download/<filename>")
def download_file (filename):
    path = os.path.join(app.root_path, 'static/files/')
    return send_from_directory(path, filename, as_attachment=False)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'img/favicons/favicon.ico')

@app.route('/manifest.webmanifest')
def webmanifest():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'img/favicons/manifest.webmanifest')

@app.route('/robots.txt')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])

@app.route("/sitemap")
@app.route("/sitemap/")
@app.route("/sitemap.xml")
def sitemap():
    """
        Route to dynamically generate a sitemap of your website/application.
        lastmod and priority tags omitted on static pages.
        lastmod included on dynamic content such as blog posts.
    """
    #from urllib.parse import urlparse

    host_components = url_parse(request.host_url)
    host_base = host_components.scheme + "://" + host_components.netloc

    # Static routes with static content
    static_urls = list()
    for rule in app.url_map.iter_rules():
        if not str(rule).startswith("/admin") and not str(rule).startswith("/user"):
            if "GET" in rule.methods and len(rule.arguments) == 0:
                url = {
                    "loc": f"{host_base}{str(rule)}"
                }
                static_urls.append(url)

    # # Dynamic routes with dynamic content
    # dynamic_urls = list()
    # blog_posts = Post.objects(published=True)
    # for post in blog_posts:
    #     url = {
    #         "loc": f"{host_base}/blog/{post.category.name}/{post.url}",
    #         "lastmod": post.date_published.strftime("%Y-%m-%dT%H:%M:%SZ")
    #         }
    #     dynamic_urls.append(url)

    xml_sitemap = render_template('sitemap/sitemap.xml', static_urls=static_urls, host_base=host_base) #dynamic_urls=dynamic_urls)
    response = make_response(xml_sitemap)
    response.headers["Content-Type"] = "application/xml"

    return response
