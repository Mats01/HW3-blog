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
import webapp2

form = """
<form action="/" method="post">
    <b>Singup</b>
    <br/>
    Username
    <input type="text" name="username" value="%(username)s"/>
    <div style="color: red">%(username_error)s</div>
    <br/>
    Password
    <input type="password" name="password"/>
    <div style="color: red">%(password_error)s</div>
    <br/>
    Verify password
    <input type="password" name="verify"/>
    <div style="color: red">%(verification_error)s</div>
    <br/>
    Email (optional)
    <input type="text" name="email" value="%(email)s"/>
    <div style="color: red">%(email_error)s</div>
    <br/>
    <input type="submit"/>
</form>
"""
import cgi


def escape_html(s):
    return cgi.escape(s, quote=True)

import re

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return PASS_RE.match(password)


EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


def valid_email(email):
    return EMAIL_RE.match(email)


class MainHandler(webapp2.RequestHandler):
    def write_form(self, username_error="", username="", email="", password_error="", verification_error="",
                   email_error=""):
        self.response.out.write(form % {"username": username,
                                        "email": email,
                                        "username_error": username_error,
                                        "password_error": password_error,
                                        "verification_error": verification_error,
                                        "email_error": email_error})
    def get(self):
        self.write_form("")

    def post(self):
        user_username = valid_username(self.request.get('username'))
        user_password = valid_password(self.request.get('password'))
        user_verify_password = self.request.get('verify')
        user_email = valid_email(self.request.get('email'))
        input_username = self.request.get('username')
        input_email = self.request.get('email')

        passwords_match = False
        check = False
        w_email_error = ''
        input_email = ''
        if self.request.get('email'):
                if not user_email:
                    check = True
                    w_email_error = 'Invalid email'
                    input_email = self.request.get('email')
        if self.request.get('password') == user_verify_password:
            passwords_match = True
        if not (user_username and user_password and passwords_match):
            if not user_username:
                if not user_password:
                    self.write_form(username=input_username, username_error="Invalid username",
                                    password_error="That's not a valid password",
                                    email=input_email, email_error=w_email_error)
                elif not passwords_match:
                    self.write_form(username=input_username, username_error="Invalid username",
                                    verification_error="Passwords don't match",
                                    email=input_email, email_error=w_email_error)
                else:
                    self.write_form(username=input_username, username_error="Invalid username",
                                    email=input_email, email_error=w_email_error)
            elif not user_password:
                self.write_form(username=input_username, password_error="That's not a valid password",
                                email=input_email, email_error=w_email_error)
            elif not passwords_match:
                self.write_form(username=input_username, verification_error="Passwords don't match",
                                email=input_email, email_error=w_email_error)
        else:
            if check:
                self.write_form(username=input_username, email=input_email, email_error=w_email_error)
            else:
                username_print = self.request.get('username')
                self.redirect("/welcome?username=" + username_print)

class SuccessHandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write('Welcome ')
        self.response.out.write(self.request.get('username'))


app = webapp2.WSGIApplication([('/', MainHandler), ('/welcome', SuccessHandler)], debug=True)