import { ServerClient } from "../api/server";
import { ZodeApplication } from "./application";
import { BrowserCursorStore, BrowserNavigation, browserClock } from "./browser";

export { type RecentSession, ZodeApplication } from "./application";
export { Endpoint, EndpointRegistrationWorkflow, endpointIsUsable } from "./endpoint";
export {
  type ExecutionChoice,
  type ModelExecutionGroup,
  executionChoiceMatches,
} from "./execution";
export { Navigation, type Route, type View } from "./navigation";
export {
  AuthRefreshOperation,
  AuthProfile,
  OAuthAttempt,
  OAuthAttemptCreationWorkflow,
  ProfileCreationWorkflow,
  Provider,
  ProviderConfigurationWorkflow,
  profileIsUsableOnEndpoint,
} from "./provider";
export {
  Session,
  SessionExecutionWorkflow,
  ToolCall,
  type ToolCallAction,
  type TranscriptMessage,
} from "./session";
export { Settings } from "./settings";
export { NewSessionWorkflow } from "./workflows";

const serverClient = new ServerClient();

export const application = new ZodeApplication(
  serverClient,
  new BrowserNavigation(),
  new BrowserCursorStore(),
  browserClock,
  () => crypto.randomUUID(),
);

application.start();
window.addEventListener("pagehide", (event) => {
  if (!event.persisted) application.dispose();
});
