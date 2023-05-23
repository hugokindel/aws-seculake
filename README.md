# Seculake

For more details, take a look at the diagram.  
Disclaimer: Some values have been REDACTED, the configuration needs to be changed in order to work.

## How to deploy

- Make sure the [security-core](https://github.com/hugokindel/aws-security-core) project is deployed.
- Make sure the `Security Lake` service on AWS is deployed.
- Make sure `awscli` and `serverless` (through `npm`) are installed.
- Configure your credentials with `aws configure`.
- Run `./deploy.sh`.

## Dependencies

- [Boto3](https://pypi.org/project/boto3/)
- [Botocore](https://pypi.org/project/botocore/)
- [MSAL](https://github.com/AzureAD/microsoft-authentication-library-for-python)
- [Requests](https://pypi.org/project/requests/)
- [UUID](https://pypi.org/project/uuid/)
