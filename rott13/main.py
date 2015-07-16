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
__author__ = 'Matej Butkovic'
import webapp2
form="""
<form action="/rot13" method="post">
    Write your text below
    <br/>
    <textarea rows="4" cols="50" name="text">%(user_text)s</textarea>
    <input type="submit">
</form>
"""
letter = [x for x in range(97, 123)]

import cgi
def escape_html(s):
  return cgi.escape(s, quote = True)

class MainHandler(webapp2.RequestHandler):
    def fill_form(self, user_text=""):
        self.response.out.write(form % {"user_text": user_text})
		
    def get(self):
        self.fill_form("")
    def post(self):
        a = self.request.get('text')
        b = self.encript_text(a)
        self.fill_form(b)

    def encript_text(self, text):
        l_text = list(text)
        position = -1
        for i in l_text:
            position = position + 1
            y = ''
            x = False
            if i.isupper():
                x = True
            i = i.lower()
            if ord(i) in letter:
                if (ord(i) + 13) <= 122:
                    y = chr(ord(i) + 13)
                else:
                    z = (ord(i) + 13) % 122
                    y = chr(96 + z)
            else:
                y = i
            if x:
                y = y.upper()
                i = i.upper()
            l_text.insert((position + 1), y)
            del l_text[position]
        text = "".join(l_text)
        return text
    


app = webapp2.WSGIApplication([('/rot13', MainHandler)], debug=True)