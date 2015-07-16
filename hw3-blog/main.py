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

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class BlogPost(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post1.html", p = self)

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

        #if subject and content:
        #    a = BlogPost(subject = subject, content = content)
        #    a.put()

        #    self.redirect("/blog")

        if subject and content:
            p = BlogPost(parent = blog_key(), subject = subject, content = content)
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

        self.render("permalink.html", post = post)


app = webapp2.WSGIApplication([
    ('/blog', MainHandler), ('/blog/newpost', PostHandler), ('/blog/([0-9]+)', PostPage)
], debug=True)


