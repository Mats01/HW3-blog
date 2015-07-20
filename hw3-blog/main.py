#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
__author__ = 'Matej'

import os
import webapp2
import jinja2
import re
import hashlib
import hmac

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


SECRET = 'imsosecret'
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return PASS_RE.match(password)


EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


def valid_email(email):
    return EMAIL_RE.match(email)


class BlogPost(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post1.html", p=self)

class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.EmailProperty(required=False)



class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class MainHandler(Handler):
    def render_post(self, posts):
        posts = db.GqlQuery("SELECT * FROM BlogPost ORDER BY created DESC")

        self.render('blogs.html', posts=posts)

    def get(self):
        self.render_post("")


class PostHandler(Handler):
    def render_error(self, subject, content, error):
        self.render('post.html', subject=subject, content=content, error=error)

    def get(self):
        self.render('post.html')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = BlogPost(parent=blog_key(), subject=subject, content=content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = 'You need to both write a title and post in order to blog!'
            self.render_error(subject, content, error)


class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('BlogPost', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class SingUpHandler(Handler):
    def re_render(self, username, username_error,
                  username_exsists, password_error,
                  verification_error, email, email_error):
        self.render('singup.html', username=username, username_error=username_error,
                    username_exsists=username_exsists, password_error=password_error,
                    verification_error=verification_error, email=email, email_error=email_error)

    def get(self):
        self.render("singup.html")

    def post(self):
        username = valid_username(self.request.get('username'))
        password = valid_password(self.request.get('password'))
        verify_password = self.request.get('verify')
        email = valid_email(self.request.get('email'))
        input_username = self.request.get('username')

        passwords_match = False
        check = False
        email_error = ''
        input_email = self.request.get('email')
        username_exsists = ''
        if self.request.get('email'):
            if not email:
                check = True
                email_error = 'Invalid email'
        if self.request.get('password') == verify_password:
            passwords_match = True
        if not (username and password and passwords_match):
            if not username:
                if not password:
                    self.re_render(username=input_username, username_error="Invalid username",
                                   password_error="That's not a valid password", verification_error='',
                                   email=input_email, email_error=email_error, username_exsists=username_exsists)
                elif not passwords_match:
                    self.re_render(username=input_username, username_error="Invalid username",
                                   password_error='',
                                   verification_error="Passwords don't match",
                                   email=input_email, email_error=email_error, username_exsists=username_exsists)
                else:
                    self.re_render(username=input_username, username_error="Invalid username",
                                   password_error='', verification_error='',
                                   email=input_email, email_error=email_error, username_exsists=username_exsists)
            elif not password:
                self.re_render(username=input_username, password_error="That's not a valid password",
                               verification_error='', username_error='',
                               email=input_email, email_error=email_error, username_exsists=username_exsists)
            elif not passwords_match:
                self.re_render(username=input_username, verification_error="Passwords don't match",
                               username_error='', password_error='',
                               email=input_email, email_error=email_error, username_exsists=username_exsists)
        else:
            if check:
                self.re_render(username=input_username, email=input_email, email_error=email_error,
                               username_error='', password_error='', verification_error='', username_exsists=username_exsists)
            else:
                if not input_email:
                    input_email = None
                u = User(username=input_username, password=verify_password, email=input_email)
                u.put()
                new_cookie = make_secure_val(str(u.key().id()))
                self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % new_cookie)
                self.redirect('/blog/welcome')

class WelcomeHandler(Handler):
    def get(self):
        user_id = self.request.cookies.get('user_id')
        id = check_secure_val(user_id)
        key = db.Key.from_path('User', int(id))
        if key:
            user = db.get(key)
            self.write('Welcome, %s!' % user.username)
        else:
            self.redirect('/blog/signup')


app = webapp2.WSGIApplication([
    ('/blog', MainHandler), ('/blog/newpost', PostHandler), ('/blog/([0-9]+)', PostPage),
    ('/blog/signup', SingUpHandler), ('/blog/welcome', WelcomeHandler)
], debug=True)
