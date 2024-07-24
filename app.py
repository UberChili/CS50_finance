# from _typeshed import NoneType
import os

from cs50 import SQL
from flask import Flask, flash, get_flashed_messages, message_flashed, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


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
    """Show portfolio of stocks"""
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        # Get form info and validate symbol using lookup
        symbol = request.form.get("symbol")
        shares_to_buy = float(request.form.get("shares"))
        symbol_info = lookup(symbol)
        if symbol_info == None:
            return apology("Invalid symbol")
        else:
            amount_to_spend = shares_to_buy * symbol_info["price"]
            print(symbol, shares_to_buy, amount_to_spend)

            # Getting user's balance
            user_cash = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])

            # User can afford the shares
            if user_cash >= amount_to_spend:
                # Add transaction
                db.execute(
                    "INSERT INTO transactions (user_id, type, symbol, amount, price) VALUES (?, ?, ?, ?, ?)",
                    session['user_id'],
                    "buy",
                    shares_to_buy,
                    symbol_info['price']
                )
                # Check if user already has holdings and update accordingly
            else:
                return apology("Can't afford")

        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")
        if symbol == "":
            return apology("Must provide symbol")

        symbol_info = lookup(symbol)
        if symbol_info != None:
            return render_template("quoted.html", symbol=symbol_info["symbol"], price=symbol_info["price"])
        else:
            return apology("Could not find symbol or invalid symbol")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")

    if request.method == "POST":
        print("Oh, a post!")
        # Get username and check if it is valid
        username = request.form.get("username")
        if username == None:
            return apology("Error in username")
        elif username == "":
            return apology("Must provide username")
        # Get password and confirmation and check
        password = str(request.form.get("password"))
        confirmation = request.form.get("confirmation")
        if password == "" or confirmation == "":
            return apology("Must provide password and confirmation")
        elif password != confirmation:
            return apology("Password and confirmation don't match")

        # Create hash
        hash = generate_password_hash(password, method='pbkdf2', salt_length=16)

        # Insert values to database
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        except ValueError:
            return apology("Username already exists!")

        # Log in and remember which user has logged in
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        session["user_id"] = rows[0]["id"]

    # Flash message and redirect to homepage
    flash("Registered!")
    return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")
