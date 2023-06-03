import os
import re

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required


# Configure app
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///data.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    # Getting the data issue, description, comments
    tickets = db.execute("SELECT * FROM tickets")
    # TODO need to get the id
    users = db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],))
    username = users[0]["username"].capitalize()

    return render_template("index.html", tickets=tickets, username=username)


@app.route("/register", methods=["GET", "POST"])
def register():
    # Clear active sessions
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Check id forms are blank
        if not username:
            return apology("Username in required", 400)

        elif not password:
            return apology("Password required", 400)

        elif not confirmation:
            return apology("Must confrim password", 400)

        # Check if password matched
        elif password != confirmation:
            return apology("Password did not match")

        # Check password requirements
        if (
            len(password) < 8
            or not re.search(r"\d", password)
            or not re.search(r"[A-Z]", password)
        ):
            return apology(
                "Password must be at least 8 characters long and contain at least one capital letter and one number",
                400,
            )

        # Username query
        user = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Check if the user exist
        if len(user) != 0:
            return apology("User already exist", 400)

        # Adding user to data.db
        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)",
            username,
            generate_password_hash(password),
        )

        user = db.execute("SELECT * FROM users WHERE username = ?", username)

        # User logged in
        session["user_id"] = user[0]["id"]

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/create", methods=["GET", "POST"])
def create():
    if request.method == "POST":
        issue = request.form.get("issue")
        description = request.form.get("description")
        comments = request.form.get("comments")

        # Check if input and textarea are blank
        if not issue:
            return apology("Issue required", 400)

        elif not description:
            return apology("Description required", 400)

        # Add the ticket to database
        db.execute(
            "INSERT INTO tickets (user_id, issue, description, comments) VALUES (:user_id, :issue, :description, :comments)",
            user_id=session["user_id"],
            issue=issue,
            description=description,
            comments=comments,
        )

        flash("A ticket has been created!")
        return redirect("/")
    else:
        return render_template("create.html")


@app.route("/open", methods=["GET", "POST"])
def open():
    # Getting the data issue, description, comments...
    tickets = db.execute(
        "SELECT * FROM tickets WHERE user_id = :user_id", user_id=session["user_id"]
    )

    return render_template("open.html", tickets=tickets)


@app.route("/update", methods=["GET", "POST"])
def update():
    if request.method == "GET":
        ticket_id = request.args.get("ticket_id")
        tickets = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,))
        comments = db.execute(
            "SELECT * FROM comments WHERE ticket_id = ?", (ticket_id,)
        )
        return render_template("update.html", tickets=tickets, comments=comments)

    action = request.form.get("action")
    ticket_id = request.form.get("ticket_id")

    if action == "update":
        # Get the updated issue, description, and comments from the form
        updated_comments = request.form.get("comments")

        # Update the ticket's comments in the comments table
        db.execute(
            "INSERT INTO comments (comment) VALUES (?)",
            (updated_comments),
        )

        flash("Comment added!!")
        # Redirect to a success page or display a success message
        return redirect("/")

    elif action == "resolve":
        # Update the ticket's state to 'close' in the database
        db.execute(
            "UPDATE tickets SET state = 'close' WHERE id = ?",
            (ticket_id,),
        )

        flash("Ticket resolved!")
        # Redirect to the ticket details page or display a success message
        return redirect("/", ticket_id=ticket_id)

    return render_template("update.html", tickets=tickets, comments=comments)


@app.route("/closed")
def close():
    return apology("TODO")


@app.route("/history")
def history():
    tickets = db.execute(
        "SELECT * FROM tickets WHERE user_id = :user_id", user_id=session["user_id"]
    )

    users = db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],))
    username = users[0]["username"].capitalize()

    return render_template("history.html", tickets=tickets, username=username)
