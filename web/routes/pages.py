import logging
import smtplib

from flask import Blueprint, render_template, request

import config

pages_bp = Blueprint("pages", __name__)


@pages_bp.route("/")
def index():
    return render_template("index.html")


@pages_bp.route("/pricing")
def pricing():
    return render_template("pricing.html")


@pages_bp.route("/resources")
def resources():
    return render_template("resources.html")


@pages_bp.route("/guide")
def guide():
    return render_template("guide.html")


@pages_bp.route("/about")
def about():
    return render_template("about.html")


@pages_bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "Anonymous")
        email = request.form.get("email", "No email provided")
        message = request.form.get("message", "").strip()

        if not message:
            return '<script>alert("Message cannot be empty."); window.history.back();</script>'

        subject = f"Contact Form Submission: {name}"
        body = f"Name: {name}\nEmail: {email}\nMessage:\n{message}"
        raw_msg = f"Subject: {subject}\n\n{body}"

        if not config.SMTP_USER or not config.SMTP_PASS:
            logging.warning("Contact form submitted but SMTP is not configured.")
            return '<script>alert("Contact form is not configured yet. Please reach out directly."); window.location.href="/contact";</script>'

        try:
            server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT)
            server.starttls()
            server.login(config.SMTP_USER, config.SMTP_PASS)
            server.sendmail(config.SMTP_USER, config.CONTACT_EMAIL, raw_msg)
            server.quit()
            logging.info(f"Contact form submitted by {name} ({email})")
            return '<script>alert("Message sent successfully! Thank you."); window.location.href="/contact";</script>'
        except Exception as e:
            logging.error(f"Failed to send contact email: {e}")
            return '<script>alert("Failed to send message. Please try again later."); window.location.href="/contact";</script>'

    return render_template("contact.html")
