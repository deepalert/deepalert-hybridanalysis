import * as cdk from '@aws-cdk/core';
import * as lambda from '@aws-cdk/aws-lambda';
import * as iam from '@aws-cdk/aws-iam';
import * as sns from '@aws-cdk/aws-sns';
import * as sqs from '@aws-cdk/aws-sqs';
import { SqsEventSource } from '@aws-cdk/aws-lambda-event-sources';
import { SqsSubscription } from '@aws-cdk/aws-sns-subscriptions';

import * as path from 'path';

export interface HybridAnalysisProperty extends cdk.StackProps {
  lambdaRoleARN?: string;

  // Set either one:
  taskTopic?: sns.ITopic;
  taskTopicARN?: string;

  // Set either one:
  findingQueue?: sqs.IQueue;
  findingQueueARN?: string;

  // Set either one:
  attributeQueue?: sqs.IQueue;
  attributeQueueARN?: string;

  secretARN: string;

  // Optional properties
  sentryDsn?: string;
  sentryEnv?: string;
  logLevel?: string;
}

export class HybridAnalysisStack extends cdk.Stack {
  readonly inspector: lambda.Function;
  readonly deadLetterQueue: sqs.Queue;

  constructor(scope: cdk.Construct, id: string, props: HybridAnalysisProperty) {
    super(scope, id, props);
    // Validate input properties
    if (props.taskTopic === undefined && props.taskTopicARN === undefined) {
      throw Error('Either one of taskTopic and taskTopicARN must be set');
    }
    if (props.findingQueue === undefined && props.findingQueueARN === undefined) {
      throw Error('Either one of findingQueue and findingQueueARN must be set');
    }
    if (props.attributeQueue === undefined && props.attributeQueueARN === undefined) {
      throw Error('Either one of attributeQueue and attributeQueueARN must be set');
    }

    // Setup task SNS topic and SQS queue
    this.deadLetterQueue = new sqs.Queue(this, 'DeadLetterQueue')

    const taskQueueTimeout = cdk.Duration.seconds(30);
    const taskQueue = new sqs.Queue(this, 'taskQueue', {
      visibilityTimeout: taskQueueTimeout,
      deadLetterQueue: {
        maxReceiveCount: 3,
        queue: this.deadLetterQueue,
      },
    });
    const taskTopic = (props.taskTopic) ? props.taskTopic : sns.Topic.fromTopicArn(this, 'taskTopic', props.taskTopicARN!);
    taskTopic.addSubscription(new SqsSubscription(taskQueue));

    // Setup feedback queues
    const findingQueue = (props.findingQueueARN) ? sqs.Queue.fromQueueArn(this, 'findingQueue', props.findingQueueARN) : props.findingQueue!;
    const attributeQueue = (props.attributeQueueARN) ? sqs.Queue.fromQueueArn(this, 'attributeQueue', props.attributeQueueARN) : props.attributeQueue!;

    // Setup IAM role if required
    const lambdaRole = props.lambdaRoleARN ? iam.Role.fromRoleArn(this, 'LambdaRole', props.lambdaRoleARN, { mutable: false }) : undefined;

    // Setup lambda code
    const rootPath = path.resolve(__dirname, '..');
    const asset = lambda.Code.fromAsset(rootPath, {
      bundling: {
        image: lambda.Runtime.GO_1_X.bundlingDockerImage,
        user: 'root',
        command: ['go', 'build', '-o', '/asset-output/inspector', './src'],
        environment: {
          GOARCH: 'amd64',
          GOOS: 'linux',
        },
      },
    });

    this.inspector = new lambda.Function(this, 'inspector', {
      runtime: lambda.Runtime.GO_1_X,
      handler: 'inspector',
      code: asset,
      role: lambdaRole,
      events: [new SqsEventSource(taskQueue)],
      timeout: taskQueueTimeout,
      environment: {
        FINDING_QUEUE_URL: findingQueue.queueUrl,
        ATTRIBUTE_QUEUE_URL: attributeQueue.queueUrl,

        SECRET_ARN: props.secretARN,

        SENTRY_DSN: props.sentryDsn || "",
        SENTRY_ENVIRONMENT: props.sentryEnv || "",
        LOG_LEVEL: props.logLevel || "",
      },
    });
  }
}
