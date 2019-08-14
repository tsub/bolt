import { Receiver, ReceiverEvent, ReceiverAckTimeoutError } from './types';
import axios from 'axios';
import rawBody from 'raw-body';
import querystring from 'querystring';
import crypto from 'crypto';
import tsscmp from 'tsscmp';
import { ErrorCode, errorWithCode } from './errors';
import { Logger, ConsoleLogger } from '@slack/logger';
import Emittery from 'emittery'
import { IncomingMessage, ServerResponse } from 'http';

// TODO: we throw away the key names for endpoints, so maybe we should use this interface. is it better for migrations?
// if that's the reason, let's document that with a comment.
export interface ServerlessReceiverOptions {
  signingSecret: string;
  logger?: Logger;
  endpoints?: string | {
    [endpointType: string]: string;
  };
}

interface EventDataMap {
  error: Error | ReceiverAckTimeoutError,
  message: ReceiverEvent
}

/**
 * Receives HTTP requests with Events, Slash Commands, and Actions
 */
export default class ServerlessReceiver implements Receiver {
  signingSecret: string;
  logger: Logger;
  emitter: Emittery.Typed<EventDataMap>;

  constructor({
    signingSecret = '',
    logger = new ConsoleLogger(),
  }: ServerlessReceiverOptions) {
    this.signingSecret = signingSecret;
    this.logger = logger;
    this.emitter = new Emittery.Typed<EventDataMap>()
  }

  async start(..._args: any[]): Promise<unknown> {
    // noop
    return;
  }
  async stop(..._args: any[]): Promise<unknown> {
    // noop
    return;
  }

  on(event: 'message'|'error', listener: any) {
    this.emitter.on(event, listener)
  }

  public async requestHandler(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      let timer: NodeJS.Timer | undefined = setTimeout(
        () => {
          this.emitter.emit('error', receiverAckTimeoutError(
            'An incoming event was not acknowledged before the timeout. ' +
            'Ensure that the ack() argument is called in your listeners.',
          ));
          timer = undefined;
        },
        2800,
      );

      const body = await this.verifySignatureAndParseBody(req)

      if (body && body.ssl_check) {
        res.end();
        return;
      }

      if (body && body.type && body.type === 'url_verification') {
        res.end(JSON.stringify({ challenge: body.challenge }));
        return;
      }

      this.logger.info(`body: ${JSON.stringify(body)}`)

      let ackResponse;
      const event: ReceiverEvent = {
        body: body as { [key: string]: any },
        ack: (response: any): void => {
          ackResponse = response
        },
        respond: undefined,
      };

      if (body && body.response_url) {
        const response_url = body.response_url;
        event.respond = async (response): Promise<void> => {
          await axios.post(response_url, response)
            .catch((e) => {
              this.emitter.emit('error', e);
            });
        };
      }

      this.logger.info("emitting message");
      await this.emitter.emit('message', event);
      this.logger.info("done emitting message");

      clearTimeout(timer)
      res.statusCode = 200;
      if (!ackResponse) {
        res.end('')
      }
      else if (typeof ackResponse === 'string') {
        res.end(ackResponse);
      } else {
        res.setHeader('Content-Type', 'application/json')
        res.end(ackResponse);
      }
    } catch (err) {
      this.logger.error(err);
      await this.emitter.emit('error', err);
      res.statusCode = 500;
      res.end('');
    }
  }

  /**
   * This method has two responsibilities:
   * - Verify the request signature
   * - Parse request.body 
   */
  async verifySignatureAndParseBody(req: IncomingMessage): Promise<any> {
    try {
      // *** Request verification ***
      let stringBody: string;
      // On some environments like GCP (Google Cloud Platform),
      // req.body can be pre-parsed and be passed as req.rawBody here
      const preparsedRawBody: any = (req as any).rawBody;
      if (preparsedRawBody !== undefined) {
        stringBody = preparsedRawBody.toString();
      } else {
        stringBody = (await rawBody(req)).toString();
      }
      const signature = req.headers['x-slack-signature'] as string;
      const ts = Number(req.headers['x-slack-request-timestamp']);

      await verifyRequestSignature(this.signingSecret, stringBody, signature, ts);

      // *** Parsing body ***
      // As the verification passed, parse the body as an object and assign it to req.body
      // Following middlewares can expect `req.body` is already a parsed one.

      // This handler parses `req.body` or `req.rawBody`(on Google Could Platform)
      // and overwrites `req.body` with the parsed JS object.
      const contentType = req.headers['content-type'];
      const body = parseRequestBody(this.logger, stringBody, contentType);
      return body;
    } catch (error) {
      throw error;
    }
  }
}


// TODO: this should be imported from another package
async function verifyRequestSignature(
  signingSecret: string,
  body: string,
  signature: string,
  requestTimestamp: number): Promise<void> {
  if (!signature || !requestTimestamp) {
    const error = errorWithCode(
      'Slack request signing verification failed. Some headers are missing.',
      ErrorCode.ExpressReceiverAuthenticityError,
    );
    throw error;
  }

  // Divide current date to match Slack ts format
  // Subtract 5 minutes from current time
  const fiveMinutesAgo = Math.floor(Date.now() / 1000) - (60 * 5);

  if (requestTimestamp < fiveMinutesAgo) {
    const error = errorWithCode(
      'Slack request signing verification failed. Timestamp is too old.',
      ErrorCode.ExpressReceiverAuthenticityError,
    );
    throw error;
  }

  const hmac = crypto.createHmac('sha256', signingSecret);
  const [version, hash] = signature.split('=');
  hmac.update(`${version}:${requestTimestamp}:${body}`);

  if (!tsscmp(hash, hmac.digest('hex'))) {
    const error = errorWithCode(
      'Slack request signing verification failed. Signature mismatch.',
      ErrorCode.ExpressReceiverAuthenticityError,
    );
    throw error;
  }
}

function parseRequestBody(
  logger: Logger,
  stringBody: string,
  contentType: string | undefined) {
  if (contentType === 'application/x-www-form-urlencoded') {
    const parsedBody = querystring.parse(stringBody);
    if (typeof parsedBody.payload === 'string') {
      return JSON.parse(parsedBody.payload);
    } else {
      return parsedBody;
    }
  } else if (contentType === 'application/json') {
    return JSON.parse(stringBody);
  } else {
    logger.warn(`Unexpected content-type detected: ${contentType}`);
    try {
      // Parse this body anyway
      return JSON.parse(stringBody);
    } catch (e) {
      logger.error(`Failed to parse body as JSON data for content-type: ${contentType}`)
      throw e;
    }
  }
}

function receiverAckTimeoutError(message: string): ReceiverAckTimeoutError {
  const error = new Error(message);
  (error as ReceiverAckTimeoutError).code = ErrorCode.ReceiverAckTimeoutError;
  return (error as ReceiverAckTimeoutError);
}
