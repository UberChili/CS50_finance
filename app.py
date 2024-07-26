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
    cash = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])[0]['cash']
    grand_total = 0
    rows = db.execute("SELECT * FROM holdings WHERE user_id = ?", session['user_id'])
    holdings = []
    for row in rows:
        total = 0
        looked_info = lookup(row['symbol'])
        if looked_info == None:
            return apology("Error looking up symbol")
        else:
            price = looked_info['price']
            total = price * row['amount']
            holdings.append({'symbol': row['symbol'], 'amount': row['amount'], 'price': usd(price), 'total': usd(total)})
        grand_total += total

    return render_template("index.html", holdings=holdings, cash=usd(round(cash, 2)), grand_total=usd(round(grand_total+cash)))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        # Get form info and validate symbol using lookup
        symbol = request.form.get("symbol", "", type=str)
        if symbol == "":
            return apology("Invalid symbol", 400)
        # shares_to_buy = float(request.form.get("shares"))
        shares_to_buy = request.form.get('shares', -1, type=float)
        if shares_to_buy == -1:
            return apology("Error in shares to buy", 400)
        symbol_info = lookup(symbol)
        if symbol_info == None:
            return apology("Invalid symbol", 400)
        else:
            amount_to_spend = shares_to_buy * symbol_info["price"]
            print(symbol, shares_to_buy, amount_to_spend)

            # Getting user's balance
            user_cash = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])[0]["cash"] # Calling the dict key after selecting the first row, clever

            # User can afford the shares
            if float(user_cash) >= amount_to_spend:
                # Add transaction to transactions table
                db.execute(
                    "INSERT INTO transactions (user_id, type, symbol, amount, price) VALUES (?, ?, ?, ?, ?)",
                    session['user_id'],
                    "buy",
                    symbol.upper(),
                    shares_to_buy,
                    symbol_info['price']
                )
                # Check if user already has holdings and update accordingly
                # Need to use a SELECT statement to check if the symbol is already owned by the user
                amount = db.execute("SELECT amount FROM holdings WHERE user_id = ? AND symbol = ?", session["user_id"], symbol.upper())
                if len(amount) == 0:
                    # User doesn't own any shares of the symbol
                    db.execute("INSERT INTO holdings (user_id, symbol, amount) VALUES (?, ?, ?)", session['user_id'], symbol.upper(), shares_to_buy)
                    # Update user's cash
                    db.execute("UPDATE users SET cash = ? WHERE id = ?",
                                               float(user_cash) - amount_to_spend,
                                               session['user_id'])
                else:
                    # User owns the symbol, need to update
                    db.execute("UPDATE holdings SET amount = ? WHERE user_id = ? AND symbol = ?",
                               float(amount[0]['amount']) + shares_to_buy,
                               session['user_id'],
                               symbol.upper())
                    # Also update user's cash
                    db.execute("UPDATE users SET cash = ? WHERE id = ?",
                                               float(user_cash) - amount_to_spend,
                                               session['user_id'])
            else:
                return apology("Can't afford", 400)

        flash("Bought!")
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT * FROM transactions WHERE user_id = ?", session['user_id'])
    if len(rows) < 1:
        return apology("No transactions yet!")
    else:
        transactions = []
        for row in rows:
            transactions.append({'symbol': row['symbol'], 'amount': row['amount'], 'price': usd(row['price']), 'transacted': row['datetime']})
        return render_template("history.html", transactions=transactions)


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

    # Get curent user's cash 
    cash_row = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])
    if cash_row == None:
        return apology("Can't find cash", 400)
    else:
        actual_user_cash = float(round(cash_row[0]['cash'], 2))

    # Get current user's holdings
    holdings = {}
    rows = db.execute("SELECT * FROM holdings WHERE user_id = ?", session['user_id'])
    if len(rows) < 1:
        return apology("User has no holdings", 400)
    else:
        for row in rows:
            # holdings.append({'symbol': row['symbol'], 'shares': row['amount']})
            holdings[row['symbol']] = {'amount': int(row['amount'])}

    if request.method == "GET":
        # Display menu of shares available to sell
        return render_template("sell.html", holdings=holdings)
    else:
        symbol_to_sell = request.form.get('symbol', type=str)
        shares_to_sell = request.form.get('shares', type=float)
        if symbol_to_sell == None or shares_to_sell == None:
            return apology("Error with provided symbol", 400)
        else:
        
            # Check if valid number of shares to sell
            if shares_to_sell > holdings[symbol_to_sell]['amount']:
                return apology("Not enough shares to sell", 400)
            else:
                symbol_info = lookup(symbol_to_sell)
                if symbol_info == None:
                    return apology("Error looking up price", 400)
                else:
                    db.execute(
                        "INSERT INTO transactions (user_id, type, symbol, amount, price) VALUES (?, ?, ?, ?, ?)",
                        session['user_id'],
                        "sell",
                        symbol_to_sell.upper(),
                        -shares_to_sell,
                        symbol_info['price']
                    )
                    if shares_to_sell == holdings[symbol_to_sell]['amount']:
                        db.execute("DELETE FROM holdings WHERE user_id = ? AND symbol = ?", session['user_id'], symbol_to_sell)
                        db.execute("UPDATE users SET cash = ? WHERE id = ?", actual_user_cash + (symbol_info['price'] * shares_to_sell), session['user_id'])
                    else:
                        db.execute("UPDATE holdings SET amount = ? WHERE user_id = ? AND symbol = ?",
                                   holdings[symbol_to_sell]['amount'] - shares_to_sell,
                                   session['user_id'],
                                   symbol_to_sell)
                        db.execute("UPDATE users SET cash = ? WHERE id = ?", actual_user_cash + (symbol_info['price'] * shares_to_sell), session['user_id'])
                    flash("Sold!")
                    return redirect("/")
