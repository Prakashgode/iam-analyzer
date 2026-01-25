# IAM Analyzer
- read cloudtrail logs to find what permissions are actually used
- compare against existing policy
- generate tighter policy
- look at IAM Access Analyzer API
- cloudtrail event format: eventName = the action
- userIdentity.arn = who did it
- need to handle assumed roles vs users
- sts:AssumeRole changes the principal arn format
