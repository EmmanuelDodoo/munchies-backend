from db import db, User, DiningHall, Review, Token
import google_auth
from flask import Flask, request, redirect
import json
import re
from datetime import datetime

app = Flask(__name__)
db_filename = "munchies.db"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///%s" % db_filename
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = False

db.init_app(app)

# ==============================Prepopoulate===================================


def prepopulate_halls():
    """ Adds dining halls to the database"""

    names = ["Morrison", "Okenshields", "Carl Becker", "North Star"]

    for n in names:
        hall = DiningHall(n, "")
        db.session.add(hall)
        db.session.commit()


def prepopulate_users():
    """ Adds dummy users to the database"""
    names = ["Janett", "Andre", "Emmanuel", "Joyce"]
    emails = ["jn23@cornell.edu", "af6@cornell.edu",
              "end25@cornell.edu", "jye12@cornell.edu"]

    for n, e in zip(names, emails):
        user = User(n, e)
        db.session.add(user)
        db.session.commit()


def prepopulate():
    """ Prepopulates all tables with dummy data mainly for testing database"""

    prepopulate_halls()
    prepopulate_users()
# ==============================================================================


# with app.app_context():
#     db.drop_all()
#     db.create_all()
#     prepopulate()


# ==============================Helpers=========================================

def success_response(load, code=200):
    """
        Return a success response with given load `load` and 
        code, `code`. Code defaults to 200
    """

    return json.dumps(load), code


def failure_response(msg, code=404):
    """
        Return a failure response with the given error message, `msg` and
        code, `code`. Code defaults to 404.

        Example: failure_response("test", 400) returns json.dumps({"error": "test"}), 400
    """
    return json.dumps({"error": msg}), code


def extract_token(request):
    """ Returns the token associated with `request`"""
    header = request.headers.get("Authorization")

    if not header:
        return False, failure_response("Missing Authorization", 400)

    token = header.replace("Bearer", "").strip()

    if not token:
        return False, failure_response("Missing token", 400)

    return True, token


def verify_email(email: str):
    """ Returns true if `email` is a valid Cornell email."""

    # So I got fed up trying to figure out a way to do this in the
    # redirect clause in login(). Basically, the same status code is returned
    # whether or not the email was valid but the actions afterwards where different
    #

    pattern = r"cornell\.edu$"

    re_match = re.search(pattern, email)

    return True if re_match else False


# ==========================================================================

@app.route("/")
@app.route("/api/")
def home():
    """ Home route. Returns all data on dining halls """

    halls = [h.simple_serialize() for h in DiningHall.query.all()]
    return success_response({"dining_halls": halls})


@app.route("/api/hall/<int:hid>/")
def get_specific_hall(hid: int):
    """ Returns information about a specific dining hall."""

    hall: DiningHall = DiningHall.query.filter_by(id=hid).first()

    if not hall:
        return failure_response("Hall not round")

    return success_response(hall.full_serialize())


@app.route("/api/login/", methods=["POST"])
def login():
    """ Attempts to login a user. If the user has not
        been created, redirects to google for authentication.

        Returns a combined json of user and session token
    """

    if not request.data:
        return failure_response("Missing request body", 400)

    req_body: dict = json.loads(request.data)

    if not req_body.get("user_email") or not isinstance(req_body["user_email"], str):
        return failure_response("Bad request body", 400)

    if not verify_email(req_body.get("user_email")):
        return failure_response("Only Cornell accounts Allowed", 403)

    # Check if the user already exists
    user: User = User.query.filter_by(email=req_body.get("user_email")).first()

    # If this is a new user, redirect for authentication.
    if not user:
        redirect_to = "https://127.0.0.1:8000/api/login" + "/callback/"
        return redirect(google_auth.login_redirect_uri(redirect_to))

    # If pre-existing user, get them a token.
    token: Token = Token(user.id)
    db.session.add(token)
    db.session.commit()

    output = {
        "userid": user.id,
        "username": user.name,
        "user_email": user.email,
        "tokenid": token.id,
        "session_token": token.value,
        "created_at": token.created_at,
        "expires_at": token.expires_at
    }

    return success_response(output, 201)


@app.route("/api/login/callback/")
def login_callback():
    """ Handle callback after logging in with google."""

    code = request.args.get("code")
    redirect_to = "https://127.0.0.1:8000/api/login" + "/callback/"

    google_auth.send_tokens(
        code=code, request_url=request.url, redirect_url=redirect_to)

    data = google_auth.get_user_data()

    return success_response({"data": data})


@app.route("/api/hall/<int:hall_id>/rate/", methods=["POST"])
def rate_hall(hall_id: int):
    """
        Rate a hall
    """

    hall: DiningHall = DiningHall.query.filter_by(id=hall_id).first()

    if not hall:
        return failure_response("No such dining hall")

    if not request.data:
        return failure_response("Missing request body", 400)

    req_body: dict = json.loads(request.data)

    if not req_body.get("rating") or not isinstance(req_body.get("rating"), int | float):
        return failure_response("Bad request body", 400)

    if not req_body.get("userid") or not isinstance(req_body.get("userid"), int):
        return failure_response("Bad request body", 400)

    user: User = User.query.filter_by(id=req_body.get("userid")).first()
    if not user:
        return failure_response("No such user", 404)

    success, message = extract_token(request)

    if not success:
        return message

    token: Token = Token.query.filter_by(value=message).first()
    if not token:
        return failure_response("Invalid token", 401)

    if not token.verify(user.id):
        return failure_response("Invalid session token", 401)

    user.rate_hall(hall_id, req_body.get("rating"))

    db.session.commit()

    return success_response(hall.simple_serialize(), 201)


@app.route("/api/hall/<int:hid>/reviews/", methods=["POST"])
def create_review(hid: int):
    """
        Create a review on a specific hall.
    """

    hall: DiningHall = DiningHall.query.filter_by(id=hid).first()

    if not hall:
        return failure_response("Dining hall not found")

    if not request.data:
        return failure_response("Missing request body", 400)

    req_body: dict = json.loads(request.data)

    if not req_body.get("userid") or not isinstance(req_body.get("userid"), int):
        return failure_response("Incorrect user id", 400)
    if req_body.get("contents") == None or not isinstance(req_body.get("contents"), str):
        return failure_response("Incorrect contents", 400)
    if req_body.get("with_image") == None or not isinstance(req_body.get("with_image"), bool):
        return failure_response("Incorrect with image field", 400)
    if req_body.get("with_image"):
        if not req_body.get("image_url") or not isinstance(req_body.get("image_url"), str):
            return failure_response("Incorrect image url field", 400)

    user: User = User.query.filter_by(id=req_body.get("userid")).first()
    if not user:
        return failure_response("User does not exist", 404)

    success, message = extract_token(request)

    if not success:
        return message

    token: Token = Token.query.filter_by(value=message).first()
    if not token:
        return failure_response("Invalid token", 401)

    review: Review = Review(
        hall_id=hid,
        userid=req_body.get("userid"),
        contents=req_body.get("contents"),
        date=round(datetime.now().timestamp(), 1),
        with_image=req_body.get("with_image"),
        image_url=req_body.get("image_url", "")
    )

    db.session.add(review)
    db.session.commit()

    return success_response(review.serialize(), 201)


@app.route("/api/hall/<int:hid>/reviews/<int:rid>/")
def get_specific_review(hid: int, rid: int):
    """
        Returns a json view of a particular review on a dining hall
    """

    hall: DiningHall = DiningHall.query.filter_by(id=hid).first()
    if not hall:
        return failure_response("Hall does not exist")

    review: Review = Review.query.filter_by(id=rid).first()
    if not review:
        return failure_response("Review does not exist")

    return success_response(review.serialize())


@app.route("/api/hall/<int:hid>/reviews/<int:rid>/", methods=["PATCH"])
def update_review(hid: int, rid: int):
    """ Update the contents of a review"""

    review: Review = Review.query.filter_by(id=rid).first()

    if not review:
        return failure_response("Review not found")

    if not request.data:
        return failure_response("Missing request body", 400)

    req_body: dict = json.loads(request.data)

    if req_body.get("contents") == None or not isinstance(req_body.get("contents"), str):
        return failure_response("Missing review contents", 400)

    success, message = extract_token(request)

    if not success:
        return message

    token: Token = Token.query.filter_by(value=message).first()

    if not token:
        return failure_response("Invalid token", 401)

    if token.userid != review.userid:
        return failure_response("Unauthorized access", 401)

    review.update_contents(req_body.get("contents"))
    db.session.commit()

    return success_response(review.serialize())


@app.route("/api/hall/<int:hid>/reviews/<int:rid>/", methods=["DELETE"])
def delete_review(hid: int, rid: int):
    """ Delete a specifc review from the database"""

    review: Review = Review.query.filter_by(id=rid).first()

    if not review:
        return failure_response("Review not found")

    success, message = extract_token(request)

    if not success:
        return message

    token: Token = Token.query.filter_by(value=message).first()

    if not token:
        return failure_response("Invalid token", 401)

    if token.userid != review.userid:
        return failure_response("Unauthorized access", 401)

    Review.query.filter(Review.id == rid).delete()
    db.session.commit()

    return success_response(review.serialize())


# ===================================================================================
if __name__ == "__main__":
    # Use this to request a proper certificate:
    # https://blog.miguelgrinberg.com/post/running-your-flask-application-over-https
    app.run(host="0.0.0.0", port=8000, debug=True, ssl_context="adhoc")
