const packageJson = require('../package.json'); // tslint:disable-line:no-require-imports no-var-requires
import pleaseUpgradeNode from 'please-upgrade-node';

pleaseUpgradeNode(packageJson);

export {
  default as App,
  AppOptions,
  Authorize,
  AuthorizeSourceData,
  AuthorizeResult,
  AuthorizationError,
  ActionConstraints,
  LogLevel,
  Logger,
} from './App';

export { ErrorCode } from './errors';

export {
  default as ServerlessReceiver,
  ServerlessReceiverOptions,
} from './ServerlessReceiver';

export * from './middleware/builtin';
export * from './types';

export {
  ConversationStore,
  MemoryStore,
} from './conversation-store';
