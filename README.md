# Okta OAuth2 Java Resource Server
This project is intended to be used with Okta w/ AppAuth OAuth2 [iOS](https://github.com/oktadeveloper/okta-openidconnect-appauth-sample-swift) and [Android](https://github.com/oktadeveloper/okta-openidconnect-appauth-sample-android) samples.

## Running the Sample with your Okta Organization

###Pre-requisites
This sample application was tested with an Okta org. If you do not have an Okta org, you can easily [sign up for a free Developer Okta org](https://www.okta.com/developer/signup/).

To test out the [custom claims/scopes](http://openid.net/specs/openid-connect-core-1_0.html#AdditionalClaims) ability with the returned `accessToken`, additionally configure the following:

1. Select the configured **OpenID Connect Application**
2. In the **Authorization Server** screen, click the **OAuth 2.0 Access Token** *Edit* button
3. Add the custom scope `gravatar`.
4. Add the custom claim *name* `user_email` and *value* `appuser.email`
5. Add the **gravatar** scope to your defined scopes:

## Setup
This SDK currently must be added as a `.jar` to the sample project. 

Using `maven`, run the following command in the root SDK repository to build:
```
  $ mvn package
```

This will create a `.jar` file in the `/target` directory of your project.

Add the file `/oauth2-okta-resource-server-0.0.1.jar` to your list of approved JARs.

For example: To add it to an [IntelliJ IDEA project](https://www.jetbrains.com/idea/) simply:

`Project Structure` -> `Modules` -> `Dependencies` -> `+` -> `JARs or directories...` -> `/path/to/jar/oauth2-okta-resource-server-0.0.1.jar`
