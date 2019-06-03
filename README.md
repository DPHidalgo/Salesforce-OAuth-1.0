# Salesforce-OAuth-1.0

Salesforce OAuth 1.0 is a class that handles HttpRequest signatures in an automated way.


# Release 1.0

  - Support to signature method HMAC-SHA1


Next steps:
  - Handle HttpRequest body parameters.
  - Include RSA-SHA1, PLAINTEXT as signature methods.
 
# Usage
```ruby
HttpRequest h = new HttpRequest();
h.setEndpoint(EndpointURL);
h.setMethod(RequestMethod);

OAuth oauth = new OAuth(consumerKey, consumerSecret, oAuthToken, secretAccessToken);
h = oauth.sign(h);

Http s = new Http();
HttpResponse r = s.send(h);
```