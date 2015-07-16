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

form="""
<form  action="/date_input" method="post">
	What is your birthay?
	<br>
	
	<label>Month
		<input type="text" name="month" value="%(month)s">
	</label>
	
	<label>Day
		<input type="text" name="day" value="%(day)s">
	</label>
	
	<label>Year
		<input type="text" name="year" value="%(year)s">	
	</label>
	<div style="color: red">%(error)s</div>
	<br>
	<br>
	<input type="submit">
</form>
"""
months = ['January',
          'February',
          'March',
          'April',
          'May',
          'June',
          'July',
          'August',
          'September',
          'October',
          'November',
          'December']

month_abbvs = dict((m[:3].lower(), m) for m in months)
          
def valid_month(month):
  if month:
    short_month = month[:3].lower()
    return month_abbvs.get(short_month)

def valid_day(day):
  if day.isdigit():
    a = int(day)
    if a > 0 and a <= 31:  
      return day
		  
def valid_year(year):
  if year.isdigit():
    b = int(year)
    if b > 1900 and b <= 2015:
      return year	  

import cgi
def escape_html(s):
  return cgi.escape(s, quote = True)

class MainHandler(webapp2.RequestHandler):
  def write_form(self, error="", month="", day="", year=""):
    self.response.out.write(form % {"error": error, "month": escape_html(month), "day": escape_html(day), "year": escape_html(year)})
  
  def get(self):
    self.write_form("")
  
  def post(self):
    user_month = valid_month(self.request.get('month'))
    user_day = valid_day(self.request.get('day'))
    user_year = valid_year(self.request.get('year'))
    
    month = self.request.get('month')
    day = self.request.get('day')
    year = self.request.get('year')
	
    if not (user_month and user_day and user_year):
      self.write_form("Invalid date!", month, day, year)
    
    else:
      self.redirect("/date_input/thanks")
	  
class ThanksHandler(webapp2.RequestHandler):
  def get(self):
    self.response.out.write('Date valid, thanks!')

app = webapp2.WSGIApplication([('/date_input', MainHandler), ('/date_input/thanks', ThanksHandler)], debug=True)
