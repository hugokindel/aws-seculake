#!/bin/sh

# Deploy backup infrastructure

cd backup-region-1

serverless deploy

cd ..

# Deploy main Seculake infrastructure

cd seculake

serverless deploy

cd ..

# Deploy AWS Log Puller infrastructure on all available regions

cd aws-log-puller

serverless deploy
