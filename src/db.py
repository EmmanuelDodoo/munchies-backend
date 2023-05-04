from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os
import hashlib
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
import json

db = SQLAlchemy()


class DiningHall(db.Model):
    """
        Table representing a dining hall.
    """

    __tablename__ = "dininghall"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    image = db.Column(db.String, nullable=False)
    reviews = db.relationship("Review", cascade="delete")
    rating_sum = db.Column(db.Float, default=0.0)
    rating_number = db.Column(db.Integer, default=0)

    @hybrid_method
    def get_rating(self):
        """ Get the rating of this dining hall"""

        if self.rating_number == 0.0:
            return 0.0

        return round(self.rating_sum/self.rating_number, 1)

    def __init__(self, name: str, image: str):
        """
            Create a new dining hall entry with `name`, and `image` url
        """

        self.name = name
        self.image = image

    def add_rating(self, rating):
        """
            Add a new rating to this dinning hall, changing the 
            overall rating
        """

        self.rating_sum += rating
        self.rating_number += 1
        db.session.commit()

    def simple_serialize(self):
        """
            Return a partial dictionary representation of this dining hall
        """

        return {
            "id": self.id,
            "name": self.name,
            "image": self.image,
            "rating": self.get_rating(),
            "review_number": len(self.reviews)
        }

    def full_serialize(self):
        """
            Return a full python dictionary representation of this dining hall
        """

        return {
            "id": self.id,
            "name": self.name,
            "image": self.image,
            "rating": self.get_rating(),
            "reviews": [r.serialize() for r in self.reviews]
        }


class User(db.Model):
    """ Table representing users not registered with google authentication"""

    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    _passoword = db.Column(db.String, nullable=False)
    rated = db.Column(db.String, nullable=False)

    @hybrid_property
    def previous_rating(self):
        return json.loads(self.rated)

    @previous_rating.setter
    def previous_rating(self, value):
        self.rated = json.dumps(value)

    @hybrid_property
    def _password(self):
        raise Exception("Cannot directly access password")

    def __init__(self, name: str, email: str, password: str):
        """ Create a new User entry"""

        self.name = name
        self.email = email
        self.previous_rating = {}
        # Salt and hashes password before setting it
        salt: str = os.getenv("SALT")
        salted = salt+password+salt
        hash = hashlib.sha256()
        hash.update(salted.encode("utf-8"))
        self._passoword = hash.hexdigest()

    def serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email
        }

    def rate_hall(self, hid: int, new_rating: int | float):
        """ Rate a hall given an id. Cancels any previous rating

            Requires: `new_rating` is a number in range [0,5] inclusive with steps of 0.5"""

        prev_rating = self.previous_rating.get(str(hid))

        hall: DiningHall = DiningHall.query.filter_by(id=hid).first()

        # No previous
        if prev_rating == None:
            self.previous_rating = (self.previous_rating | {
                                    str(hid): new_rating})
            hall.add_rating(new_rating)
            db.session.commit()
            return

        # Previous rating
        hall.rating_sum += new_rating - prev_rating
        self.previous_rating = (self.previous_rating | {str(hid): new_rating})
        db.session.commit()
        return

    def hash_and_verify(self, password: str):
        """ Checks if this `password` is the password of this user. 

            Requires: `password` is not hashed
        """

        salt: str = os.getenv("SALT")
        salted: str = salt+password+salt
        hash = hashlib.sha256(salted.encode("utf-8"))

        return self._passoword == (hash.hexdigest())

    def verify(self, password: str):
        """ Checks if this `password` is the password of this user"""
        return self._passoword == password


class GUser(db.Model):
    """ Table representing users registered using google authentication"""

    __tablename__ = "gusers"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    rated = db.Column(db.String, nullable=False)

    @hybrid_property
    def previous_rating(self):
        return json.loads(self.rated)

    @previous_rating.setter
    def previous_rating(self, value):
        self.rated = json.dumps(value)

    def __init__(self, name: str, email: str):
        """ Create a new GUser entry"""

        self.name = name
        self.email = email
        self.previous_rating = {}

    def serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email
        }

    def rate_hall(self, hid: int, new_rating: int | float):
        """ Rate a hall given an id. Cancels any previous rating

            Requires: `new_rating` is a number in range [0,5] inclusive with steps of 0.5"""

        prev_rating = self.previous_rating.get(str(hid))

        hall: DiningHall = DiningHall.query.filter_by(id=hid).first()

        # No previous
        if prev_rating == None:
            self.previous_rating = (self.previous_rating | {
                                    str(hid): new_rating})
            hall.add_rating(new_rating)
            db.session.commit()
            return

        # Previous rating
        hall.rating_sum += new_rating - prev_rating
        self.previous_rating = (self.previous_rating | {str(hid): new_rating})
        db.session.commit()
        return


class Review(db.Model):
    """
        Table representing Reviews
    """

    __tablename__ = "reviews"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    hall_id = db.Column(db.Integer, db.ForeignKey(
        "dininghall.id"), nullable=False)
    userid = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    date = db.Column(db.Integer, nullable=False)
    contents = db.Column(db.Text, nullable=False)
    with_image = db.Column(db.Boolean, nullable=False, default=False)
    image_url = db.Column(db.String, nullable=True)

    def __init__(self, **kwargs):
        """
            Create a new Review
        """

        self.hall_id = kwargs.get("hall_id")
        self.userid = kwargs.get("userid")
        self.contents = kwargs.get("contents")
        self.date = kwargs.get("date")
        self.with_image = kwargs.get("with_image")
        self.image_url = kwargs.get("image_url", "")

    def update_contents(self, new_contents):
        """
            Replace the contents of a Review with `new_contents`
        """

        self.contents = new_contents
        db.session.commit()

    def serialize(self):
        """
            Return a python dictionary representation of this review.
            User name is included 
        """

        return {
            "id": self.id,
            "hall_id": self.hall_id,
            "userid": self.userid,
            "username": User.query.filter_by(id=self.userid).first().serialize().get("name"),
            "date": self.date,
            "contents": self.contents,
            "with_image": self.with_image,
            "image_url": self.image_url,
        }


class Token(db.Model):
    """ Table for session tokens"""

    __tablename__ = "tokens"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    userid = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    value = db.Column(db.String, nullable=False)
    created_at = db.Column(db.Integer, nullable=False)
    expires_at = db.Column(db.Integer, nullable=False)

    def __init__(self, userid: int):
        """ Create a new session token for user with id `userid` """

        self.userid = userid
        self.value = self._maketoken()
        self.created_at = int(datetime.now().timestamp())
        self.expires_at = int((datetime.now() + timedelta(days=1)).timestamp())

    def _maketoken(self):
        """ Produce a token value"""

        return hashlib.sha256(os.urandom(64)).hexdigest()

    def renew_token(self, uid: int):
        """
            Extends the expiration date of this token by 1 day.
            Will not be renewed if the token cannot be verified.

            Returns True if successful
        """
        if not self.verify(uid):
            return False

        self.expires_at = (datetime.now() + timedelta(days=1)).timestamp()
        db.session.commit()
        return True

    def verify(self, uid: int):
        """
            Checks if this token is valid for user with id, `uid`
        """

        return self.userid == uid and (self.expires_at > datetime.now().timestamp())

    def serialize(self):
        """
            Returns a python dictionary representation of this token
        """
        return {
            "id": self.id,
            "userid": self.userid,
            "token": self.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at
        }
