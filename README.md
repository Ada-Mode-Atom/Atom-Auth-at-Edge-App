# Authorization with Lambda@Edge

Easily add OAuth2 flows to apply authorization to any content served through AWS Cloudfront.

Note: This application must be deployed in us-east-1. You can deploy instances of the app [here](https://us-east-1.console.aws.amazon.com/serverlessrepo/home?region=us-east-1#/published-applications/arn:aws:serverlessrepo:us-east-1:539182614893:applications~Atom-Auth-at-Edge).

New instances of the application template can be published as follows (Note that you may want to increment the version in the *template.yaml* beforehand):

```bash
uv run sam package --output-template-file .aws-sam/packaged.yaml --s3-bucket ada-mode-atom
uv run sam publish --template .aws-sam/packaged.yaml --region us-east-1
```

If you cannot find the application to deploy on the serverless application repository then it likely needs the sharing policy adjusting. It is quite unreliable that your application actually shows up as available.

Instead you can create a cloudformation stack directly:
```bash
aws serverlessrepo create-cloud-formation-template --region us-east-1 --application-id arn:aws:serverlessrepo:us-east-1:539182614893:applications/Atom-Auth-at-Edge --semantic-version 1.0.1
```
From which go to the cloudformation console -> create stack (new resources) -> from url -> past generated url from command above.

The same process can be used to pick up new versions of the auth app and apply them to an existing stack. It can be a bit circular, its best to put dummy values in the stack on init (`ClientId` and `DiscoveryDocument` and replace them with the actuals once they are ready).



## Requirements

* OIDC dicsovery document url such as `.../.well-known/openid-configuration`
* Cloudfront distribution (for deployment of the application)

If the openid configuration is taken from a cognito userpool it must have a corresponding domain with a managed login UI.


A deployed instance of the application creates the following resources:
* Auth Handler: A lambda function in a python runtime suitable to running on the edge and initiate oauth2 flows and coordinate sign-in, refresh or permit access
* Callback Handler: A lambda function in a python runtime suitable to running on the edge and respond to IdP auth code provision and collect tokens
* ReWrite Handler: A commonly required index.html rewrite handler to support access static content by appending index.html (to be used on origin-request actions)
* SSM Parameters: A set of parameters controlling the IdP including the client Id, Callback path & discovery document URL

## Integration

The deployed application will return the ARN of the two created lambda handlers, these can now be integrated into you Cloudfront distribution.

This may look like this:
* Add a lambda@edge integration to all user-request actions to each non-public behaviour
* Create a custom origin (named something like `auth-callback-origin`)
* Create a behaviour on path `/auth/callback` pointing to your custom origin (or matching whatver value was used for the callback stack parameter) with caching disabled
* Add a lambda@edge integration to this new bevahiour to use the callback handler
* Optionally apply the index.html rewrite handler to any behaviours that use (such as those acting as entrypoints to static sites.)

This will now enforce authentication on each configured behaviour.

## Limitations

This application is only suitable for a single App Client, multiple instances will need to be configured for additional client support.

## Updates

When integrating a lambda function on edge use must specify a versioned function ARN such as `arn:aws:lambda:us-east-1:{AccountId}:function:{StackName}-AuthorizeFunction-...:1`, hence if you deploy an updated instance of this application you will need to increment the ARN within the cloudfront behaviour integrations.
