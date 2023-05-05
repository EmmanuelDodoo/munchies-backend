from db import db, DiningHall, Review, Token, User, Asset
import google_auth
from flask import Flask, request, redirect
import json
import re
from datetime import datetime
import os

app = Flask(__name__)
db_filename = "munchies.db"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///%s" % db_filename
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = False

db.init_app(app)

# ==============================Prepopoulate===================================


def prepopulate_halls():
    """ Adds dining halls to the database"""
    S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")
    base_url = f"https://{S3_BUCKET_NAME}.s3.us-east-1.amazonaws.com/dininghalls/"

    halls: list[tuple[str, str, str]] = [("Morrison Dining", "morrison.jpg", 4.0),
                                         ("North Star Dining",
                                          "northstar.jpg", 2.5),
                                         ("Risley Dining", "risley.jpg", 4.5),
                                         ("Okenshields", "okenshields.webp", 3.5),
                                         ("Becker House Dining",
                                          "becker.jpg", 3.5),
                                         ("Cook House Dining", "cook.webp", 3.5),
                                         ("Jansens Dining at Hans Bethe",
                                          "bethes.jpg", 3.0),
                                         ("Keeton House Dining",
                                          "keeton.jpg", 3.5),
                                         ("Rose House Dining", "rose.jpg", 4.0),
                                         ("104West", "104west.png", 3.5),
                                         ("Bear Necessities", "bear.jpg", 5),
                                         ("Amit Bhatia Libe Cafe",
                                          "amit-bhatia-libe.jpg", 4.0),
                                         ("Big Red Barn", "brbarn.jpg", 4.0),
                                         ("Bus Stop Bagels",
                                          "bus-stop-bagels", 3.5),
                                         ("Cafe Jennie", "cafe-jennie.webp", 4.0),
                                         ("Franny's Food Truck",
                                          "franny.webp", 4.0),
                                         ("Goldie's", "goldies.jpg", 3.5),
                                         ("Mattin's Cafe", "mattins.jpg", 4.0),
                                         ("Rusty's", "rustys.jpg", 3.0),
                                         ("Trillium", "trillium.jpg", 4.0),
                                         ("Temple of Zeus", "zeus.jpg", 4.0)
                                         ]

    for hall in halls:
        dHall = DiningHall(hall[0], f"{base_url}{hall[1]}")
        db.session.add(dHall)

    db.session.commit()


def prepopulate():
    """ Prepopulates all tables with dummy data mainly for testing database"""

    prepopulate_halls()
# ==============================================================================


with app.app_context():
    db.drop_all()
    db.create_all()
    prepopulate()


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
        return False, failure_response("Missing session token", 400)

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
        return failure_response("Hall not found")

    return success_response(hall.full_serialize())


@app.route("/api/experimental/login/", methods=["POST"])
def google_login():
    """ Attempts to login a user. If the user has not
        been created, redirects to google for authentication.

        Returns a combined json of user and session token
    """

    if not request.data:
        return failure_response("Missing request body", 400)

    req_body: dict = json.loads(request.data)

    if not req_body.get("email") or not isinstance(req_body["email"], str):
        return failure_response("Bad request body", 400)

    if not verify_email(req_body.get("email")):
        return failure_response("Only Cornell accounts allowed", 403)

    # Check if the user already exists
    user: GUser = GUser.query.filter_by(email=req_body.get("email")).first()

    # If this is a new user, redirect for authentication.
    if not user:
        redirect_to = "https://127.0.0.1:8000/api/experimental/login" + "/callback/"
        return redirect(google_auth.login_redirect_uri(redirect_to))

    # If pre-existing user, get them a token.
    token: Token = Token(user.id)
    db.session.add(token)
    db.session.commit()

    output = {
        "userid": user.id,
        "username": user.name,
        "email": user.email,
        "tokenid": token.id,
        "session_token": token.value,
        "created_at": token.created_at,
        "expires_at": token.expires_at
    }

    return success_response(output, 201)


@app.route("/api/login/experimental/callback/")
def google_login_callback():
    """ Handle callback after logging in with google."""

    code = request.args.get("code")
    redirect_to = "https://127.0.0.1:8000/api/experimental/login" + "/callback/"

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
        return failure_response("Dining hall not found")

    if not request.data:
        return failure_response("Missing request body", 400)

    req_body: dict = json.loads(request.data)

    if not req_body.get("rating") or not isinstance(req_body.get("rating"), int | float):
        return failure_response("Bad request body", 400)

    if not req_body.get("userid") or not isinstance(req_body.get("userid"), int):
        return failure_response("Bad request body", 400)

    user: User = User.query.filter_by(id=req_body.get("userid")).first()
    if not user:
        return failure_response("User not found", 404)

    success, message = extract_token(request)

    if not success:
        return message

    token: Token = Token.query.filter_by(value=message).first()
    if not token:
        return failure_response("Invalid session token", 401)

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
        return failure_response("Hall not found")

    if not request.data:
        return failure_response("Missing request body", 400)

    req_body: dict = json.loads(request.data)

    if not req_body.get("userid") or not isinstance(req_body.get("userid"), int):
        return failure_response("Bad request body", 400)
    if req_body.get("contents") == None or not isinstance(req_body.get("contents"), str):
        return failure_response("Bad request body", 400)
    if req_body.get("with_image") == None or not isinstance(req_body.get("with_image"), bool):
        return failure_response("Bad request body", 400)
    if req_body.get("with_image"):
        if not req_body.get("image_data") or not isinstance(req_body.get("image_data"), str):
            return failure_response("Bad request body", 400)

    user: User = User.query.filter_by(id=req_body.get("userid")).first()
    if not user:
        return failure_response("User not found", 404)

    success, message = extract_token(request)

    if not success:
        return message

    token: Token = Token.query.filter_by(value=message).first()
    if not token or not token.verify(user.id):
        return failure_response("Invalid session token", 401)

    if req_body.get("with_image"):
        img = Asset(req_body.get("image_data"))
        db.session.add(img)
        db.session.commit()
        review: Review = Review(
            hall_id=hid,
            userid=req_body.get("userid"),
            contents=req_body.get("contents"),
            date=round(datetime.now().timestamp(), 1),
            with_image=req_body.get("with_image"),
            image_url=img.serialize().get("url")
        )

    else:
        review: Review = Review(
            hall_id=hid,
            userid=req_body.get("userid"),
            contents=req_body.get("contents"),
            date=round(datetime.now().timestamp(), 1),
            with_image=req_body.get("with_image"),
            image_url=""
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
        return failure_response("Dining hall not found")

    review: Review = Review.query.filter_by(id=rid).first()
    if not review:
        return failure_response("Review not found")

    return success_response(review.serialize())


@app.route("/api/hall/<int:hid>/reviews/<int:rid>/", methods=["PATCH"])
def update_review(hid: int, rid: int):
    """ Update the contents of a review"""

    hall: DiningHall = DiningHall.query.filter_by(id=hid).first()
    if not hall:
        return failure_response("Dining hall not found")

    review: Review = Review.query.filter_by(id=rid).first()

    if not review:
        return failure_response("Review not found")

    if not request.data:
        return failure_response("Missing request body", 400)

    req_body: dict = json.loads(request.data)

    if req_body.get("contents") == None or not isinstance(req_body.get("contents"), str):
        return failure_response("Bad request body", 400)

    success, message = extract_token(request)

    if not success:
        return message

    token: Token = Token.query.filter_by(value=message).first()

    if not token:
        return failure_response("Invalid session token", 401)

    if not token.verify(review.userid):
        return failure_response("Unauthorized access", 401)

    review.update_contents(req_body.get("contents"))
    db.session.commit()

    return success_response(review.serialize())


@app.route("/api/hall/<int:hid>/reviews/<int:rid>/", methods=["DELETE"])
def delete_review(hid: int, rid: int):
    """ Delete a specifc review from the database"""

    hall: DiningHall = DiningHall.query.filter_by(id=hid).first()
    if not hall:
        return failure_response("Dining hall not found")

    review: Review = Review.query.filter_by(id=rid).first()

    if not review:
        return failure_response("Review not found")

    success, message = extract_token(request)

    if not success:
        return message

    token: Token = Token.query.filter_by(value=message).first()

    if not token:
        return failure_response("Invalid session token", 401)

    if not token.verify(review.userid):
        return failure_response("Unauthorized access", 401)

    Review.query.filter(Review.id == rid).delete()
    db.session.commit()

    return success_response(review.serialize())


@app.route("/api/login/", methods=["POST"])
def login():
    """ Logs in an existing user"""

    if not request.data:
        return failure_response("Missing request body", 400)

    req_body: dict = json.loads(request.data)

    if not req_body.get("email") or not isinstance(req_body.get("email"), str):
        return failure_response("Bad request body", 400)

    if not req_body.get("password") or not isinstance(req_body.get("password"), str):
        return failure_response("Bad request body", 400)

    user: User = User.query.filter_by(email=req_body.get("email")).first()

    if not user:
        return failure_response("User not found")

    if not user.verify(req_body.get("password")):
        return failure_response("Incorrect password", 401)

    token = Token(user.id)

    db.session.add(token)
    db.session.commit()

    output = {
        "userid": user.id,
        "username": user.name,
        "email": user.email,
        "tokenid": token.id,
        "session_token": token.value,
        "created_at": token.created_at,
        "expires_at": token.expires_at
    }

    return success_response(output, 201)


@app.route("/api/signup/", methods=["POST"])
def signup():
    """ Create a new user from signup"""

    if not request.data:
        return failure_response("Missing request body", 400)

    req_body: dict = json.loads(request.data)

    if not req_body.get("email") or not isinstance(req_body.get("email"), str):
        return failure_response("Bad request body", 400)
    if not req_body.get("password") or not isinstance(req_body.get("password"), str):
        return failure_response("Bad request body", 400)
    if not req_body.get("username") or not isinstance(req_body.get("username"), str):
        return failure_response("Bad request body", 400)

    if not verify_email(req_body.get("email")):
        return failure_response("Only Cornell accounts allowed", 403)

    existing_user: User = User.query.filter_by(
        email=req_body.get("email")).first()
    if existing_user:
        return failure_response("User already exists", 400)

    new_user: User = User(req_body.get("username"), req_body.get(
        "email"), req_body.get("password"))
    db.session.add(new_user)
    db.session.commit()

    token = Token(new_user.id)
    db.session.add(token)
    db.session.commit()

    output = {
        "userid": new_user.id,
        "username": new_user.name,
        "email": new_user.email,
        "tokenid": token.id,
        "session_token": token.value,
        "created_at": token.created_at,
        "expires_at": token.expires_at
    }

    return success_response(output, 201)


# ===================================================================================
if __name__ == "__main__":
    # Use this to request a proper certificate:
    # https://blog.miguelgrinberg.com/post/running-your-flask-application-over-https
    # app.run(host="0.0.0.0", port=8000, debug=True, ssl_context="adhoc") this is for running on https
    app.run(host="0.0.0.0", port=8000, debug=True)  # for running on http
