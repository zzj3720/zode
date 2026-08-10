import "@phosphor-icons/web/regular";

import { Global } from "@emotion/react";
import { useSignals } from "@preact/signals-react/runtime";
import * as Dialog from "@radix-ui/react-dialog";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import * as Select from "@radix-ui/react-select";
import * as Slider from "@radix-ui/react-slider";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";

import {
  createApiKeyProfile,
  createEndpoint,
  createSession,
  eventStreamUrl,
  getEndpoint,
  getSession,
  getSystem,
  listEndpoints,
  listProfiles,
  listProviders,
  listSessions,
  deleteProfile,
  putProvider,
  probeEndpoint,
  selectSessionModel,
  setDefaultProfile,
  sendMessage,
  ServerClientError,
  type AuthProfile,
  type Endpoint,
  type Provider,
  type PublicEvent,
  type Session,
  type SessionSummary,
} from "./api/server";
import * as appState from "./state";
import { globalStyles } from "./styles";
import type { ElementType, FormEvent, MouseEvent, ReactNode, RefObject } from "react";

const rootElement = document.querySelector<HTMLDivElement>("#app");
if (!rootElement) throw new Error("application root is missing");

const viewPaths: Record<Exclude<appState.View, "session" | "not_found">, string> = {
  sessions: "/",
  endpoints: "/endpoints",
  providers: "/providers",
  settings: "/settings",
};

let eventStreamAbortController: AbortController | null = null;
let eventStreamKey: string | null = null;
let eventStreamRetryTimer: number | null = null;
let eventStreamRetryAttempt = 0;
const eventStreamCursors = new Map<string, string>();
const EVENT_STREAM_IDLE_TIMEOUT_MS = 20_000;
let accessReentryStarted = false;
let navigationGeneration = 0;
let activeSessionRequestGeneration = 0;

const eventStreamKinds = new Set([
  "assistant_message_committed",
  "message_appended",
  "status_changed",
  "activation_started",
  "activation_finished",
  "model_step_retrying",
  "model_attempts_exhausted",
  "wait_set",
  "wait_cleared",
  "wait_expired",
  "async_tool_call_started",
  "async_tool_call_running",
  "async_tool_call_completed",
  "async_tool_call_failed",
  "async_tool_call_unknown_outcome",
]);

type IconProps = { name: string; className?: string; navIcon?: boolean };

function Icon({ name, className, navIcon = false }: IconProps) {
  return (
    <i
      className={`ph ph-${name}${className ? ` ${className}` : ""}`}
      aria-hidden="true"
      data-zode-nav-icon={navIcon ? "true" : undefined}
    />
  );
}

function IconButton({
  label,
  iconName,
  onClick,
  disabled = false,
  buttonRef,
}: {
  label: string;
  iconName: string;
  onClick: () => void;
  disabled?: boolean;
  buttonRef?: RefObject<HTMLButtonElement | null>;
}) {
  return (
    <button
      className="icon-button"
      type="button"
      ref={buttonRef}
      aria-label={label}
      title={label}
      disabled={disabled}
      onClick={onClick}
    >
      <Icon name={iconName} />
    </button>
  );
}

function ActionButton({
  label,
  iconName,
  onClick,
  kind = "quiet",
  type = "button",
  disabled = false,
  id,
  buttonRef,
  ariaExpanded,
  ariaControls,
  ariaDescribedBy,
}: {
  label: string;
  iconName: string;
  onClick?: () => void;
  kind?: "primary" | "quiet" | "danger";
  type?: "button" | "submit";
  disabled?: boolean;
  id?: string;
  buttonRef?: RefObject<HTMLButtonElement | null>;
  ariaExpanded?: boolean;
  ariaControls?: string;
  ariaDescribedBy?: string;
}) {
  return (
    <button
      id={id}
      className={`button button-${kind}`}
      type={type}
      ref={buttonRef}
      disabled={disabled}
      aria-expanded={ariaExpanded}
      aria-controls={ariaControls}
      aria-describedby={ariaDescribedBy}
      onClick={onClick}
    >
      <Icon name={iconName} />
      <span>{label}</span>
    </button>
  );
}

function TextInput({
  label,
  type = "text",
  placeholder,
  value,
  onChange,
  required = false,
}: {
  label: string;
  type?: string;
  placeholder?: string;
  value: string;
  onChange: (value: string) => void;
  required?: boolean;
}) {
  return (
    <input
      className="input"
      type={type}
      aria-label={label}
      placeholder={placeholder}
      value={value}
      required={required}
      aria-required={required || undefined}
      autoComplete={type === "password" ? "new-password" : "off"}
      onChange={(event) => onChange(event.target.value)}
    />
  );
}

type SelectOption = { value: string; label: string; disabled?: boolean };

function SelectInput({
  label,
  value,
  options,
  onChange,
  disabled = false,
  placeholder = "Select",
  className = "select",
  selectedLabel,
  focusStart = false,
}: {
  label: string;
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
  disabled?: boolean;
  placeholder?: string;
  className?: string;
  selectedLabel?: string;
  focusStart?: boolean;
}) {
  const currentLabel =
    selectedLabel ?? options.find((option) => option.value === value)?.label ?? placeholder;
  return (
    <Select.Root value={value} onValueChange={onChange} disabled={disabled}>
      <Select.Trigger
        className={className}
        aria-label={label}
        aria-description={`Current selection: ${currentLabel}`}
        title={currentLabel}
        data-focus-start={focusStart || undefined}
        onFocus={(event) => {
          const scrollParent = event.currentTarget.closest<HTMLElement>(
            ".home-composer-footer, .home-composer-utility-bar, .composer-footer",
          );
          if (scrollParent)
            event.currentTarget.scrollIntoView({ block: "nearest", inline: "nearest" });
        }}
      >
        {selectedLabel ? (
          <Select.Value>{selectedLabel}</Select.Value>
        ) : (
          <Select.Value placeholder={placeholder} />
        )}
        <Select.Icon>
          <Icon name="caret-down" />
        </Select.Icon>
      </Select.Trigger>
      <Select.Portal>
        <Select.Content className="select-content" position="popper" sideOffset={4}>
          <Select.Viewport>
            {options.map((option) => (
              <Select.Item
                className="select-item"
                key={option.value}
                value={option.value}
                disabled={option.disabled}
                data-value={option.value}
              >
                <Select.ItemText>{option.label}</Select.ItemText>
                <Select.ItemIndicator>
                  <Icon name="check" />
                </Select.ItemIndicator>
              </Select.Item>
            ))}
          </Select.Viewport>
        </Select.Content>
      </Select.Portal>
    </Select.Root>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
    </label>
  );
}

function Notice({ role }: { role?: "status" | "alert" } = {}) {
  useSignals();
  const value = appState.notice.value;
  if (!value) return null;
  const retryEntries = [...appState.retryActions.value.entries()].filter(
    ([owner]) =>
      !(
        appState.view.value === "session" &&
        appState.activeSession.value !== null &&
        (owner === "session" || owner === "session-stream")
      ),
  );
  const resolvedRole =
    role ??
    (retryEntries.length > 0 ||
    /\b(unavailable|unreachable|offline|error|failed|failure|could not|not authoritative|conflict|rejected|pending|stale|disconnected)\b/i.test(
      value,
    )
      ? "alert"
      : "status");
  return (
    <div
      className={`notice notice-${resolvedRole}`}
      role={resolvedRole}
      aria-live={resolvedRole === "alert" ? "assertive" : "polite"}
    >
      <Icon name={resolvedRole === "alert" ? "warning" : "info"} />
      <div className="notice-copy">
        <span>{value}</span>
      </div>
      {retryEntries.map(([owner, action]) => (
        <button
          className="notice-action"
          key={owner}
          type="button"
          aria-label={retryLabel(owner)}
          onClick={action}
        >
          <Icon name="arrows-clockwise" />
          <span>{retryLabel(owner)}</span>
        </button>
      ))}
    </div>
  );
}

function retryLabel(owner: string): string {
  return (
    {
      bootstrap: "Retry setup",
      endpoints: "Retry Endpoints",
      providers: "Retry providers",
      profiles: "Retry profiles",
      sessions: "Retry sessions",
      session: "Retry session",
      "session-stream": "Reconnect",
      mutation: "Retry",
    }[owner] ?? "Retry"
  );
}

function setRetryAction(owner: string, action: () => void): void {
  const actions = new Map(appState.retryActions.value);
  actions.set(owner, action);
  appState.retryActions.value = actions;
}

function clearRetryAction(owner?: string): void {
  if (owner === undefined) {
    appState.retryActions.value = new Map();
    return;
  }
  if (!appState.retryActions.value.has(owner)) return;
  const actions = new Map(appState.retryActions.value);
  actions.delete(owner);
  appState.retryActions.value = actions;
}

function StatusBadge({ value }: { value: string }) {
  const normalized = value.toLowerCase().replaceAll("_", "-").replaceAll(" ", "-");
  const errorState =
    /unavailable|unreachable|rejected|unknown|error|failed|offline|disconnected|stale|disabled|removed/.test(
      normalized,
    );
  const pendingState = /reconnect|connecting|wait|pending|degraded|warning/.test(normalized);
  const labelMap: Record<string, string> = {
    provider_auth_rejected: "Auth rejected",
    "provider-auth-rejected": "Auth rejected",
    "auth-profile-pending": "Profile pending",
    "auth-profile-stale": "Profile stale",
    unknown_outcome: "Unknown outcome",
    "unknown-outcome": "Unknown outcome",
  };
  const label =
    labelMap[value] ??
    labelMap[normalized] ??
    value
      .replaceAll("_", " ")
      .replace(/\s+/g, " ")
      .trim()
      .replace(/^./, (character) => character.toUpperCase());
  return (
    <span
      className={`status-badge status-${normalized}`}
      data-zode-attention={errorState || pendingState ? "true" : undefined}
      data-zode-severity={errorState ? "error" : pendingState ? "pending" : undefined}
    >
      {label}
    </span>
  );
}

function EmptyState({
  iconName,
  title,
  detail,
  role,
  state = "empty",
}: {
  iconName: string;
  title: string;
  detail: string;
  role?: "status" | "alert";
  state?: "empty" | "loading" | "error";
}) {
  return (
    <div
      className={`empty-state empty-state-${state}`}
      role={role}
      aria-live={role === "alert" ? "assertive" : role ? "polite" : undefined}
    >
      <Icon name={iconName} />
      <div className="empty-state-copy">
        <h2>{title}</h2>
        <p>{detail}</p>
      </div>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="fact-row">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

const navigationEntries = [location.pathname + location.search + location.hash];
let navigationIndex = 0;

function currentNavigationPath(): string {
  return location.pathname + location.search + location.hash;
}

function updateNavigationState() {
  appState.canGoBack.value = navigationIndex > 0;
  appState.canGoForward.value = navigationIndex < navigationEntries.length - 1;
}

function recordNavigation(path: string): boolean {
  if (currentNavigationPath() === path) {
    updateNavigationState();
    return false;
  }
  navigationEntries.splice(navigationIndex + 1);
  navigationEntries.push(path);
  navigationIndex = navigationEntries.length - 1;
  history.pushState(null, "", path);
  updateNavigationState();
  return true;
}

function syncNavigationState() {
  const path = currentNavigationPath();
  const knownIndex = navigationEntries.indexOf(path);
  if (knownIndex >= 0) navigationIndex = knownIndex;
  else {
    navigationEntries.push(path);
    navigationIndex = navigationEntries.length - 1;
  }
  updateNavigationState();
}

function navigate(path: string) {
  if (window.matchMedia("(max-width: 760px)").matches) {
    appState.sidebarCollapsed.value = true;
  }
  const target = new URL(path, window.location.origin);
  appState.homeEndpointSelection.value =
    target.pathname === "/" ? target.searchParams.get("endpoint") : null;
  recordNavigation(path);
  void routeFromLocation().catch(showError);
}

function handleNavigation(event: MouseEvent<HTMLAnchorElement>, path: string) {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey)
    return;
  event.preventDefault();
  appState.managementMenuOpen.value = false;
  navigate(path);
}

function sessionTitle(session: Session | SessionSummary, fallback = "New session"): string {
  const transcript = "transcript" in session ? session.transcript : undefined;
  const firstUserMessage = transcript?.find((message) => message.role === "user");
  const title = firstUserMessage?.content.replace(/\s+/g, " ").trim();
  return title ? title : fallback;
}

function InlineMarkdown({ text }: { text: string }) {
  const parts = text.split(
    /(\*\*[^*]+\*\*|__[^_]+__|~~[^~]+~~|`[^`]+`|\[[^\]]+\]\((?:https?:\/\/|mailto:)[^)]+\)|https?:\/\/[^\s<]+|\*[^*]+\*|(?<!\w)_[^_]+_(?!\w))/g,
  );
  return (
    <>
      {parts.map((part, index) => {
        if (
          (part.startsWith("**") && part.endsWith("**")) ||
          (part.startsWith("__") && part.endsWith("__"))
        ) {
          return <strong key={`${part}:${index}`}>{part.slice(2, -2)}</strong>;
        }
        if (
          (part.startsWith("~~") && part.endsWith("~~")) ||
          (part.startsWith("*") && part.endsWith("*") && !part.startsWith("**")) ||
          (part.startsWith("_") && part.endsWith("_") && !part.startsWith("__"))
        ) {
          const isStrike = part.startsWith("~~");
          return isStrike ? (
            <del key={`${part}:${index}`}>{part.slice(2, -2)}</del>
          ) : (
            <em key={`${part}:${index}`}>{part.slice(1, -1)}</em>
          );
        }
        if (part.startsWith("`") && part.endsWith("`")) {
          return <code key={`${part}:${index}`}>{part.slice(1, -1)}</code>;
        }
        const link = /^\[([^\]]+)\]\(((?:https?:\/\/|mailto:)[^)]+)\)$/.exec(part);
        if (link) {
          return (
            <a href={link[2]} key={`${part}:${index}`} target="_blank" rel="noreferrer">
              {link[1]}
            </a>
          );
        }
        if (/^https?:\/\//.test(part)) {
          return (
            <a href={part} key={`${part}:${index}`} target="_blank" rel="noreferrer">
              {part}
            </a>
          );
        }
        return part;
      })}
    </>
  );
}

function splitTableRow(line: string): string[] {
  const trimmed = line.trim().replace(/^\|/, "").replace(/\|$/, "");
  return trimmed.split("|").map((cell) => cell.trim());
}

function isTableSeparator(line: string): boolean {
  const cells = splitTableRow(line);
  return cells.length > 0 && cells.every((cell) => /^:?-{3,}:?$/.test(cell));
}

function MessageTable({ lines }: { lines: string[] }) {
  const header = splitTableRow(lines[0]);
  const rows = lines.slice(2).map(splitTableRow);
  return (
    <div className="message-table-container">
      <div className="message-table-scroller" tabIndex={0} aria-label="Scrollable table">
        <table>
          <thead>
            <tr>
              {header.map((cell, index) => (
                <th scope="col" key={`heading:${index}`}>
                  <InlineMarkdown text={cell} />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, rowIndex) => (
              <tr key={`row:${rowIndex}`}>
                {header.map((_, cellIndex) => (
                  <td key={`cell:${rowIndex}:${cellIndex}`}>
                    <InlineMarkdown text={row[cellIndex] ?? ""} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

type MarkdownBlock =
  | { type: "code"; content: string; language?: string }
  | { type: "heading"; level: number; content: string }
  | { type: "table"; lines: string[] }
  | { type: "blockquote"; lines: string[] }
  | { type: "list"; lines: string[] }
  | { type: "rule" }
  | { type: "paragraph"; lines: string[] };

function parseMarkdownBlocks(content: string): MarkdownBlock[] {
  const lines = content.replace(/\r\n?/g, "\n").split("\n");
  const blocks: MarkdownBlock[] = [];
  let paragraph: string[] = [];
  const flushParagraph = () => {
    if (paragraph.length > 0) {
      blocks.push({ type: "paragraph", lines: paragraph });
      paragraph = [];
    }
  };

  let index = 0;
  while (index < lines.length) {
    const line = lines[index];
    if (!line.trim()) {
      flushParagraph();
      index += 1;
      continue;
    }

    const fence = /^\s{0,3}(`{3,}|~{3,})\s*([^`]*)$/.exec(line);
    if (fence) {
      flushParagraph();
      const marker = fence[1][0];
      const codeLines: string[] = [];
      index += 1;
      while (
        index < lines.length &&
        !new RegExp(`^\\s{0,3}${marker}{3,}\\s*$`).test(lines[index])
      ) {
        codeLines.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) index += 1;
      blocks.push({
        type: "code",
        content: codeLines.join("\n"),
        language: fence[2].trim() || undefined,
      });
      continue;
    }

    const heading = /^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$/.exec(line);
    if (heading) {
      flushParagraph();
      blocks.push({ type: "heading", level: heading[1].length, content: heading[2] });
      index += 1;
      continue;
    }

    if (/^\s{0,3}((\*\s*){3,}|(-\s*){3,}|(_\s*){3,})$/.test(line)) {
      flushParagraph();
      blocks.push({ type: "rule" });
      index += 1;
      continue;
    }

    if (index + 1 < lines.length && line.includes("|") && isTableSeparator(lines[index + 1])) {
      flushParagraph();
      const tableLines = [line, lines[index + 1]];
      index += 2;
      while (index < lines.length && lines[index].trim() && lines[index].includes("|")) {
        tableLines.push(lines[index]);
        index += 1;
      }
      blocks.push({ type: "table", lines: tableLines });
      continue;
    }

    if (/^\s{0,3}>\s?/.test(line)) {
      flushParagraph();
      const quoteLines: string[] = [];
      while (index < lines.length && /^\s{0,3}>\s?/.test(lines[index])) {
        quoteLines.push(lines[index].replace(/^\s{0,3}>\s?/, ""));
        index += 1;
      }
      blocks.push({ type: "blockquote", lines: quoteLines });
      continue;
    }

    if (/^\s*(?:[-+*]|\d+[.)])\s+/.test(line)) {
      flushParagraph();
      const listLines: string[] = [];
      while (index < lines.length && /^\s*(?:[-+*]|\d+[.)])\s+/.test(lines[index])) {
        listLines.push(lines[index]);
        index += 1;
      }
      blocks.push({ type: "list", lines: listLines });
      continue;
    }

    paragraph.push(line);
    index += 1;
  }
  flushParagraph();
  return blocks;
}

type MarkdownListItem = {
  content: string;
  ordered: boolean;
  task?: boolean;
  checked?: boolean;
  children: MarkdownListItem[];
};

function parseMarkdownList(lines: string[]): MarkdownListItem[] {
  const roots: MarkdownListItem[] = [];
  const stack: Array<{ indent: number; item: MarkdownListItem }> = [];
  for (const line of lines) {
    const item = /^(\s*)([-+*]|\d+[.)])\s+(.+)$/.exec(line);
    if (!item) continue;
    const task = /^\[([ xX])\]\s+/.exec(item[3]);
    const node: MarkdownListItem = {
      content: task ? item[3].slice(task[0].length) : item[3],
      ordered: /^\d/.test(item[2]),
      task: Boolean(task),
      checked: task ? task[1].toLowerCase() === "x" : undefined,
      children: [],
    };
    const indent = item[1].replaceAll("\t", "    ").length;
    while (stack.length > 0 && indent <= stack[stack.length - 1].indent) stack.pop();
    if (stack.length === 0) roots.push(node);
    else stack[stack.length - 1].item.children.push(node);
    stack.push({ indent, item: node });
  }
  return roots;
}

function MarkdownList({ items }: { items: MarkdownListItem[] }) {
  const Tag = items[0]?.ordered ? "ol" : "ul";
  return (
    <Tag>
      {items.map((item, index) => (
        <li className={item.task ? "task-list-item" : undefined} key={`${item.content}:${index}`}>
          {item.task ? (
            <input
              type="checkbox"
              checked={item.checked}
              disabled
              aria-label={item.checked ? "Completed task" : "Incomplete task"}
            />
          ) : null}
          <InlineMarkdown text={item.content} />
          {item.children.length > 0 ? <MarkdownList items={item.children} /> : null}
        </li>
      ))}
    </Tag>
  );
}

function MessageContent({ content }: { content: string }) {
  const blocks = parseMarkdownBlocks(content);
  return (
    <div className="message-content">
      {blocks.map((block, index) => {
        if (block.type === "code") {
          return (
            <pre
              key={`${index}:code`}
              data-language={block.language}
              tabIndex={0}
              aria-label={`${block.language || "Code"} block`}
            >
              <code>{block.content}</code>
            </pre>
          );
        }
        if (block.type === "table") {
          return <MessageTable key={`${index}:table`} lines={block.lines} />;
        }
        if (block.type === "list") {
          return <MarkdownList key={`${index}:list`} items={parseMarkdownList(block.lines)} />;
        }
        if (block.type === "blockquote") {
          return (
            <blockquote key={`${index}:quote`}>
              {block.lines.map((line, lineIndex) => (
                <span key={`${line}:${lineIndex}`}>
                  {lineIndex > 0 ? <br /> : null}
                  <InlineMarkdown text={line} />
                </span>
              ))}
            </blockquote>
          );
        }
        if (block.type === "rule") return <hr key={`${index}:rule`} />;
        if (block.type === "heading") {
          const Heading = `h${block.level}` as ElementType;
          return (
            <Heading key={`${index}:heading`}>
              <InlineMarkdown text={block.content} />
            </Heading>
          );
        }
        return (
          <p key={`${index}:paragraph`}>
            {block.lines.map((line, lineIndex) => (
              <span key={`${line}:${lineIndex}`}>
                {lineIndex > 0 ? <br /> : null}
                <InlineMarkdown text={line} />
              </span>
            ))}
          </p>
        );
      })}
    </div>
  );
}

function readableToolStatus(status?: string): string | undefined {
  return status?.replaceAll("_", " ");
}

function toolIdentity(summary?: string, toolCallId?: string): string {
  const name = summary?.trim();
  if (name) return name;
  if (!toolCallId) return "Tool activity";
  const compactId =
    toolCallId.length > 16 ? `${toolCallId.slice(0, 8)}…${toolCallId.slice(-6)}` : toolCallId;
  return `Tool call ${compactId}`;
}

function ToolMessage({
  content,
  summary,
  status,
  toolCallId,
}: {
  content: string;
  summary?: string;
  status?: string;
  toolCallId?: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const bodyId = `tool-activity-${useId().replaceAll(":", "")}`;
  const bodyRef = useRef<HTMLDivElement>(null);
  const label = toolIdentity(summary, toolCallId);
  const readableStatus = readableToolStatus(status);
  const accessibleToolName = [label, readableStatus].filter(Boolean).join(" ");
  useEffect(() => {
    if (bodyRef.current) bodyRef.current.inert = !expanded;
  }, [expanded]);
  return (
    <div
      className="tool-disclosure"
      role="listitem"
      aria-label={accessibleToolName}
      data-zode-tool-row="true"
      data-zode-tool-status={status}
    >
      <button
        className="tool-disclosure-header"
        type="button"
        aria-expanded={expanded}
        aria-controls={bodyId}
        aria-label={`${expanded ? "Collapse" : "Expand"} ${label} details${readableStatus ? `, status ${readableStatus}` : ""}`}
        onClick={() => setExpanded((value) => !value)}
      >
        <Icon name="wrench" className="tool-disclosure-icon" />
        <span className="tool-disclosure-summary">{label}</span>
        {readableStatus ? <span className="tool-disclosure-status">{readableStatus}</span> : null}
        <Icon
          name="caret-right"
          className={`tool-disclosure-chevron${expanded ? " is-expanded" : ""}`}
        />
      </button>
      <div
        id={bodyId}
        ref={bodyRef}
        className={`tool-disclosure-body${expanded ? " is-expanded" : ""}`}
        aria-hidden={!expanded}
        data-zode-expanded={String(expanded)}
      >
        <div className="tool-disclosure-body-inner">
          <MessageContent content={content} />
        </div>
      </div>
    </div>
  );
}

function transcriptRoleLabel(role: Session["transcript"][number]["role"]): string {
  return role === "assistant"
    ? "Agent"
    : role === "tool"
      ? "Tool"
      : role === "runtime"
        ? "Runtime"
        : role === "system"
          ? "System"
          : "You";
}

function InlineToolCalls({
  message,
  session,
}: {
  message: Session["transcript"][number];
  session: Session;
}) {
  if (!message.tool_calls || message.tool_calls.length === 0) return null;
  return (
    <div className="inline-tool-activity" role="list" aria-label="Tool calls">
      {message.tool_calls.map((call) => {
        const record = session.tool_calls.find((tool) => tool.tool_call_id === call.tool_call_id);
        const detail =
          record?.error?.message ?? record?.reconciliation?.reason ?? record?.status ?? "pending";
        return (
          <ToolMessage
            key={call.tool_call_id}
            content={detail}
            summary={call.tool_name}
            status={record?.status}
            toolCallId={call.tool_call_id}
          />
        );
      })}
    </div>
  );
}

function sessionKey(endpointId: string, sessionId: string): string {
  return `${endpointId}:${sessionId}`;
}

function resizeComposerInput(
  input: HTMLTextAreaElement,
  maxHeight: number,
  minHeight: number,
): void {
  input.style.height = "auto";
  const height = Math.min(Math.max(input.scrollHeight, minHeight), maxHeight);
  input.style.height = `${height}px`;
  input.style.overflowY = input.scrollHeight > maxHeight ? "auto" : "hidden";
}

function NavigationItem({
  label,
  view,
  iconName,
}: {
  label: string;
  view: Exclude<appState.View, "session" | "not_found">;
  iconName: string;
}) {
  useSignals();
  const selected = appState.view.value === view;
  return (
    <DropdownMenu.Item asChild>
      <a
        className={`nav-item${selected ? " is-selected" : ""}`}
        data-zode-nav-row="true"
        data-zode-selected={String(selected)}
        data-zode-state={selected ? "selected" : "idle"}
        href={viewPaths[view]}
        aria-current={selected ? "page" : undefined}
        onClick={(event) => handleNavigation(event, viewPaths[view])}
      >
        <Icon name={iconName} navIcon />
        <span>{label}</span>
      </a>
    </DropdownMenu.Item>
  );
}

function sessionStatusState(status: string): "active" | "inactive" | "needs-resume" {
  const normalized = status.toLowerCase();
  if (
    /error|failed|unreachable|offline|disconnected|reconnect|unknown|wait|waiting|pending|stale/.test(
      normalized,
    )
  ) {
    return "needs-resume";
  }
  if (/active|working|stream|streaming|running|tool|activating/.test(normalized)) return "active";
  return "inactive";
}

function sessionStatusIcon(state: "active" | "inactive" | "needs-resume"): string {
  if (state === "active") return "spinner-gap";
  if (state === "needs-resume") return "warning";
  return "circle";
}

function endpointIsUsable(endpoint: Endpoint): boolean {
  const status = endpoint.status.toLowerCase();
  return (
    !endpoint.disabled &&
    !/offline|unreachable|unavailable|disconnected|error|failed|stale|pending|connecting|unknown|unconfigured/.test(
      status,
    )
  );
}

function profileIsUsableOnEndpoint(profile: AuthProfile, endpointId: string): boolean {
  if (
    profile.status !== "ready" ||
    profile.sharing.mode !== "selected" ||
    !profile.sharing.endpoint_ids.includes(endpointId)
  ) {
    return false;
  }
  const replica = profile.distribution.find((candidate) => candidate.endpoint_id === endpointId);
  return (
    replica?.status === "ready" &&
    (replica.installed_revision === null || replica.installed_revision >= profile.revision)
  );
}

function SidebarSessionRow({ endpoint, session }: { endpoint: Endpoint; session: SessionSummary }) {
  useSignals();
  const path = `/endpoints/${encodeURIComponent(endpoint.endpoint_id)}/sessions/${encodeURIComponent(session.session_id)}`;
  const activeSession = appState.activeSession.value;
  const selected =
    appState.view.value === "session" &&
    activeSession?.session_id === session.session_id &&
    appState.activeEndpointId.value === endpoint.endpoint_id;
  const cachedTitle = appState.sessionTitles.value.get(
    sessionKey(endpoint.endpoint_id, session.session_id),
  );
  const titleError = appState.sessionTitleErrors.value.get(
    sessionKey(endpoint.endpoint_id, session.session_id),
  );
  const activeTitle =
    activeSession?.session_id === session.session_id ? sessionTitle(activeSession, "") : "";
  const title = titleError
    ? "Session details unavailable"
    : activeTitle || cachedTitle || "New session";
  const stale = appState.sessionListErrors.value.has(endpoint.endpoint_id);
  const statusState = stale ? "needs-resume" : sessionStatusState(session.status);
  const statusContext =
    statusState === "inactive" ? "" : `; status: ${stale ? "unavailable" : session.status}`;
  const endpointContext = `; environment: ${endpoint.kind === "local" ? "This machine" : endpoint.label}`;
  const modelContext = session.model?.model ? `; model: ${session.model.model}` : "";
  const staleContext = stale ? "; showing cached session data" : "";
  return (
    <a
      className={`sidebar-session-row${selected ? " is-selected" : ""}`}
      data-zode-nav-row="true"
      data-zode-selected={String(selected)}
      data-zode-state={selected ? "selected" : "idle"}
      data-zode-session-title-error={titleError ? "true" : undefined}
      data-zode-session-stale={stale ? "true" : undefined}
      aria-label={`${title}${statusContext}${endpointContext}${modelContext}${staleContext}`}
      href={path}
      aria-current={selected ? "page" : undefined}
      onClick={(event) => handleNavigation(event, path)}
    >
      <span className="sidebar-session-copy" data-zode-primary-text="true">
        {title}
      </span>
      {statusState !== "inactive" ? (
        <span
          className="sidebar-session-status"
          data-zode-session-status={session.status.toLowerCase().replaceAll(" ", "-")}
          data-zode-session-state={statusState}
          aria-hidden="true"
          title={session.status}
        >
          <Icon
            name={stale ? "warning" : sessionStatusIcon(statusState)}
            className="sidebar-session-status-icon"
          />
        </span>
      ) : null}
    </a>
  );
}

function SidebarSessionUnavailableRow({
  endpoint,
  onRetry,
}: {
  endpoint: Endpoint;
  onRetry: () => void;
}) {
  return (
    <div className="sidebar-session-unavailable" role="status" aria-live="polite">
      <span className="sidebar-session-status sidebar-session-status-needs-resume">
        <Icon name="warning" className="sidebar-session-status-icon" />
      </span>
      <span className="sidebar-session-copy">
        <strong>{endpoint.kind === "local" ? "This machine" : endpoint.label}</strong>
        <span>Sessions unavailable</span>
      </span>
      <button
        className="sidebar-session-retry"
        type="button"
        aria-label={`Retry sessions for ${endpoint.label}`}
        onClick={onRetry}
      >
        <Icon name="arrows-clockwise" />
      </button>
    </div>
  );
}

function Shell({
  children,
  title,
  subtitle,
  headerIconName,
}: {
  children: ReactNode;
  title?: string;
  subtitle?: string;
  headerIconName?: string;
}) {
  useSignals();
  const endpoints = appState.endpoints.value;
  const endpointGroups = endpoints.map((endpoint) => ({
    endpoint,
    sessions: appState.sessions.value.get(endpoint.endpoint_id) ?? [],
  }));
  const sessionListErrors = appState.sessionListErrors.value;
  const endpointGroupsLoading = appState.endpointsLoading.value || appState.sessionsLoading.value;
  const endpointInventoryError = appState.endpointInventoryError.value;
  const collapsed = appState.sidebarCollapsed.value;
  const [compact, setCompact] = useState(() => window.matchMedia("(max-width: 760px)").matches);
  const managementOpen = appState.managementMenuOpen.value;
  const appReady = appState.bootstrapReady.value && !appState.bootstrapError.value;
  const collapseButtonRef = useRef<HTMLButtonElement>(null);
  const openButtonRef = useRef<HTMLButtonElement>(null);
  const managementTriggerRef = useRef<HTMLButtonElement>(null);
  const previousCollapsed = useRef(collapsed);
  const previousManagementOpen = useRef(managementOpen);
  const compactState = useRef(compact);
  const desktopCollapsePreference = useRef(compact ? false : collapsed);
  useEffect(() => {
    const mediaQuery = window.matchMedia("(max-width: 760px)");
    const handleViewportChange = () => {
      const nextCompact = mediaQuery.matches;
      if (nextCompact === compactState.current) return;
      if (nextCompact) {
        desktopCollapsePreference.current = appState.sidebarCollapsed.value;
        appState.sidebarCollapsed.value = true;
      } else {
        appState.sidebarCollapsed.value = desktopCollapsePreference.current;
      }
      compactState.current = nextCompact;
      setCompact(nextCompact);
    };
    mediaQuery.addEventListener("change", handleViewportChange);
    return () => mediaQuery.removeEventListener("change", handleViewportChange);
  }, []);
  useEffect(() => {
    if (previousCollapsed.current !== collapsed) {
      (collapsed ? openButtonRef : collapseButtonRef).current?.focus();
      previousCollapsed.current = collapsed;
    }
  }, [collapsed]);
  useEffect(() => {
    if (previousManagementOpen.current && !managementOpen) {
      window.requestAnimationFrame(() => managementTriggerRef.current?.focus());
    }
    previousManagementOpen.current = managementOpen;
  }, [managementOpen]);
  return (
    <div className={`app-shell${collapsed ? " sidebar-collapsed" : ""}`} data-zode-shell="true">
      <aside
        className="sidebar"
        data-zode-shell-sidebar="true"
        aria-hidden={collapsed}
        inert={collapsed}
      >
        <DropdownMenu.Root
          open={managementOpen}
          onOpenChange={(open) => {
            appState.managementMenuOpen.value = open;
          }}
        >
          <div className="sidebar-content">
            <div className="sidebar-toolbar">
              <IconButton
                label="Collapse sidebar"
                iconName="sidebar-simple"
                buttonRef={collapseButtonRef}
                onClick={() => {
                  appState.sidebarCollapsed.value = !appState.sidebarCollapsed.value;
                }}
              />
              <IconButton
                label="Back"
                iconName="arrow-left"
                disabled={!appState.canGoBack.value}
                onClick={() => history.back()}
              />
              <IconButton
                label="Forward"
                iconName="arrow-right"
                disabled={!appState.canGoForward.value}
                onClick={() => history.forward()}
              />
            </div>
            <div className="brand">
              <span className="brand-name">Zode</span>
            </div>
            {appReady ? (
              <>
                <nav className="primary-nav" aria-label="Primary">
                  <button
                    className="new-session-button nav-item"
                    type="button"
                    data-zode-nav-row="true"
                    data-zode-selected="false"
                    data-zode-state="idle"
                    onClick={() => {
                      navigate("/");
                      queueMicrotask(() => document.getElementById("home-session-input")?.focus());
                    }}
                  >
                    <Icon name="note-pencil" navIcon />
                    <span>New session</span>
                  </button>
                </nav>
                <div className="sidebar-endpoint-groups">
                  {endpointGroups.length > 0 ? (
                    endpointGroups.map(({ endpoint, sessions }) => {
                      const headingId = `sidebar-environment-${endpoint.endpoint_id.replaceAll(
                        /[^a-zA-Z0-9_-]/g,
                        "-",
                      )}`;
                      const unavailable = sessionListErrors.has(endpoint.endpoint_id);
                      const loading =
                        endpointGroupsLoading ||
                        (appState.sessionLoadingByEndpoint.value.get(endpoint.endpoint_id) ?? 0) >
                          0;
                      return (
                        <section
                          className="sidebar-environment-group"
                          aria-labelledby={headingId}
                          key={endpoint.endpoint_id}
                        >
                          <a
                            className="sidebar-environment-heading"
                            id={headingId}
                            href={`/?endpoint=${encodeURIComponent(endpoint.endpoint_id)}`}
                            onClick={(event) =>
                              handleNavigation(
                                event,
                                `/?endpoint=${encodeURIComponent(endpoint.endpoint_id)}`,
                              )
                            }
                          >
                            <Icon name="folder-simple" />
                            <span>
                              {endpoint.kind === "local" ? "This machine" : endpoint.label}
                            </span>
                          </a>
                          {sessions.length > 0 ? (
                            sessions.map((session) => (
                              <SidebarSessionRow
                                key={`${endpoint.endpoint_id}:${session.session_id}`}
                                endpoint={endpoint}
                                session={session}
                              />
                            ))
                          ) : unavailable ? (
                            <SidebarSessionUnavailableRow
                              endpoint={endpoint}
                              onRetry={() =>
                                void refreshSessions(endpoint.endpoint_id).catch(showError)
                              }
                            />
                          ) : loading ? (
                            <p className="sidebar-empty" role="status">
                              Loading sessions…
                            </p>
                          ) : (
                            <p className="sidebar-empty">No sessions</p>
                          )}
                        </section>
                      );
                    })
                  ) : endpointGroupsLoading ? (
                    <p className="sidebar-empty" role="status">
                      Loading Endpoints…
                    </p>
                  ) : !endpointInventoryError ? (
                    <p className="sidebar-empty">No Endpoints</p>
                  ) : endpointInventoryError ? (
                    <p className="sidebar-empty sidebar-empty-error" role="status">
                      Endpoint inventory unavailable
                    </p>
                  ) : null}
                </div>
              </>
            ) : null}
          </div>
          {appReady ? (
            <div className="sidebar-management-footer">
              <DropdownMenu.Trigger asChild>
                <button
                  ref={managementTriggerRef}
                  className="sidebar-management-trigger"
                  type="button"
                  aria-label="Manage Zode"
                >
                  <Icon name="gear" />
                  <span>Manage</span>
                </button>
              </DropdownMenu.Trigger>
            </div>
          ) : null}
          <DropdownMenu.Portal>
            <DropdownMenu.Content
              className="management-menu"
              side="top"
              align="start"
              sideOffset={4}
              onCloseAutoFocus={(event) => {
                event.preventDefault();
                managementTriggerRef.current?.focus();
              }}
            >
              <div className="management-menu-items">
                <div className="management-menu-title">Manage</div>
                <NavigationItem label="Endpoints" view="endpoints" iconName="devices" />
                <NavigationItem label="Providers" view="providers" iconName="key" />
                <NavigationItem label="Settings" view="settings" iconName="gear" />
              </div>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      </aside>
      <main
        className="main-surface"
        aria-label="Main content"
        data-zode-shell-main="true"
        aria-hidden={compact && !collapsed}
        inert={compact && !collapsed}
      >
        <header className="main-header" data-zode-shell-header="true">
          <div className="header-copy">
            {collapsed ? (
              <IconButton
                label="Open sidebar"
                iconName="sidebar-simple"
                buttonRef={openButtonRef}
                onClick={() => {
                  appState.sidebarCollapsed.value = false;
                }}
              />
            ) : null}
            {headerIconName ? <Icon name={headerIconName} className="header-context-icon" /> : null}
            {title ? <h1 data-zode-primary-text="true">{title}</h1> : null}
            {subtitle ? (
              <p className="header-subtitle" data-zode-secondary-text="true">
                {subtitle}
              </p>
            ) : null}
          </div>
        </header>
        {children}
      </main>
    </div>
  );
}

type SettingsView = "endpoints" | "providers" | "settings";

function SettingsShell({
  active,
  title,
  subtitle,
  children,
}: {
  active: SettingsView;
  title: string;
  subtitle?: string;
  children: ReactNode;
}) {
  return (
    <Shell title={title} subtitle={subtitle}>
      <div data-zode-settings-view={active}>{children}</div>
    </Shell>
  );
}

function ProvidersPage() {
  useSignals();
  const providers = appState.providers.value;
  const configureProviderButtonRef = useRef<HTMLButtonElement>(null);
  const providerFormOpen = appState.panel.value === "provider";
  function closeProviderForm() {
    appState.panel.value = null;
    queueMicrotask(() => {
      window.requestAnimationFrame(() => configureProviderButtonRef.current?.focus());
    });
  }
  const partialProfileFailure =
    appState.profileListErrors.value.size > 0 && appState.retryActions.value.size === 0;
  return (
    <SettingsShell
      active="providers"
      title="Providers"
      subtitle={providers.length > 0 ? `${providers.length} configured` : undefined}
    >
      <section className="settings-content-page">
        <header className="settings-page-header">
          <div>
            <p>Configure execution and share ready profiles with Endpoints.</p>
          </div>
          <ActionButton
            label="Configure provider"
            iconName="plus"
            kind="quiet"
            buttonRef={configureProviderButtonRef}
            ariaExpanded={providerFormOpen}
            ariaControls="provider-editor"
            onClick={() => {
              appState.panel.value = "provider";
              appState.notice.value = null;
            }}
          />
        </header>
        <Notice role={partialProfileFailure ? "status" : undefined} />
        {providerFormOpen ? <ProviderForm onClose={closeProviderForm} /> : null}
        {appState.providersLoading.value ? (
          <EmptyState
            iconName="spinner-gap"
            title="Loading providers"
            detail="Reading provider configuration from the management Server."
            role="status"
            state="loading"
          />
        ) : appState.providerListError.value ? (
          <EmptyState
            iconName="warning"
            title="Providers unavailable"
            detail="The management Server did not return the provider inventory."
            role="alert"
            state="error"
          />
        ) : providers.length === 0 ? (
          <EmptyState
            iconName="key"
            title="No providers configured"
            detail="Add an OpenAI-compatible endpoint to start a session."
          />
        ) : null}
        {providers.map((provider) => (
          <ProviderCard key={provider.provider} provider={provider} />
        ))}
      </section>
    </SettingsShell>
  );
}

function ProviderForm({ onClose }: { onClose: () => void }) {
  useSignals();
  const [provider, setProvider] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [models, setModels] = useState("");
  const mutationKey = useRef<string | null>(null);
  const busy = appState.busy.value;
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const id = provider.trim();
    const modelList = models
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    if (!id) return;
    const key = mutationKey.current ?? crypto.randomUUID();
    mutationKey.current = key;
    await withBusy(async () => {
      await putProvider(
        id,
        {
          kind: "openai_compatible",
          base_url: baseUrl.trim(),
          models: modelList,
          options: {},
        },
        key,
      );
      onClose();
      appState.notice.value = `${id} is ready for an auth profile.`;
      await refreshProviders();
      mutationKey.current = null;
    });
  }
  return (
    <form
      id="provider-editor"
      className="editor-panel"
      aria-labelledby="provider-editor-title"
      onSubmit={(event) => void submit(event)}
    >
      <div className="panel-title">
        <div>
          <h2 id="provider-editor-title">Configure provider</h2>
          <p>Store only non-secret execution details here.</p>
        </div>
      </div>
      <div className="form-grid">
        <Field label="Provider ID">
          <TextInput
            label="Provider ID"
            placeholder="openai-compatible"
            value={provider}
            onChange={setProvider}
            required
          />
        </Field>
        <Field label="Provider kind">
          <span className="field-readonly">OpenAI compatible</span>
        </Field>
        <Field label="Base URL">
          <TextInput
            label="Base URL"
            type="url"
            placeholder="https://provider.example/v1"
            value={baseUrl}
            onChange={setBaseUrl}
            required
          />
        </Field>
        <Field label="Models">
          <TextInput
            label="Models"
            placeholder="model-a, model-b"
            value={models}
            onChange={setModels}
            required
          />
        </Field>
      </div>
      <div className="panel-actions">
        <ActionButton label="Cancel" iconName="x" onClick={onClose} />
        <ActionButton
          label="Save provider"
          iconName="check"
          type="submit"
          kind="primary"
          disabled={busy}
        />
      </div>
    </form>
  );
}

function ProviderCard({ provider }: { provider: Provider }) {
  useSignals();
  const providerHeadingId = `provider-heading-${useId().replaceAll(":", "")}`;
  const profileEditorId = `profile-editor-${useId().replaceAll(":", "")}`;
  const profileEditorTitleId = `${profileEditorId}-title`;
  const addProfileButtonRef = useRef<HTMLButtonElement>(null);
  const profiles = appState.profiles.value.get(provider.provider) ?? [];
  const profileError = appState.profileListErrors.value.get(provider.provider);
  const profilePanelOpen =
    appState.panel.value === "profile" && appState.panelProvider.value === provider.provider;
  function closeProfileForm() {
    appState.panel.value = null;
    queueMicrotask(() => {
      window.requestAnimationFrame(() => addProfileButtonRef.current?.focus());
    });
  }
  return (
    <article className="resource-card" aria-labelledby={providerHeadingId}>
      <div className="resource-heading">
        <div className="resource-heading-main">
          <Icon name="key" className="resource-heading-icon" />
          <div>
            <h2 id={providerHeadingId}>{provider.provider}</h2>
            <p>{provider.descriptor.base_url}</p>
          </div>
        </div>
        <StatusBadge value={provider.auth_status} />
      </div>
      <dl className="facts">
        <Fact label="Adapter" value={provider.descriptor.kind} />
        <Fact label="Revision" value={String(provider.descriptor.revision)} />
        <Fact label="Models" value={provider.descriptor.models.join(", ")} />
      </dl>
      <div className="resource-actions">
        <ActionButton
          label="Add API key profile"
          iconName="key"
          kind="quiet"
          buttonRef={addProfileButtonRef}
          ariaExpanded={profilePanelOpen}
          ariaControls={profileEditorId}
          ariaDescribedBy={providerHeadingId}
          onClick={() => {
            appState.panel.value = "profile";
            appState.panelProvider.value = provider.provider;
            appState.notice.value = null;
          }}
        />
      </div>
      {profilePanelOpen ? (
        <ProfileForm
          provider={provider}
          id={profileEditorId}
          titleId={profileEditorTitleId}
          onClose={closeProfileForm}
        />
      ) : null}
      {profileError ? (
        <div className="notice notice-alert inline-error" role="alert" aria-live="assertive">
          <Icon name="warning" />
          <div className="notice-copy">
            <span>{profileError}</span>
          </div>
          <button
            className="notice-action"
            type="button"
            disabled={appState.busy.value}
            onClick={() => void refreshProviderProfiles(provider.provider).catch(showError)}
          >
            <Icon name="arrows-clockwise" />
            <span>Retry</span>
          </button>
        </div>
      ) : null}
      {profiles.length === 0 ? (
        <p className="inline-empty">
          {profileError ? "Cached profiles unavailable." : "No auth profiles yet."}
        </p>
      ) : (
        <div className="profile-list" data-zode-stale={profileError ? "true" : undefined}>
          {profiles.map((profile) => (
            <ProfileRow
              key={profile.auth_profile_id}
              profile={profile}
              stale={Boolean(profileError)}
            />
          ))}
        </div>
      )}
    </article>
  );
}

function ProfileForm({
  provider,
  id,
  titleId,
  onClose,
}: {
  provider: Provider;
  id: string;
  titleId: string;
  onClose: () => void;
}) {
  useSignals();
  const [label, setLabel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [makeDefault, setMakeDefault] = useState(true);
  const [endpointIds, setEndpointIds] = useState<string[]>([]);
  const mutationKey = useRef<string | null>(null);
  const endpoints = appState.endpoints.value;
  const busy = appState.busy.value;
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const secret = apiKey;
    setApiKey("");
    const key = mutationKey.current ?? crypto.randomUUID();
    mutationKey.current = key;
    await withBusy(async () => {
      await createApiKeyProfile(
        provider.provider,
        {
          label: label.trim(),
          apiKey: secret,
          endpointIds,
          makeDefault,
        },
        key,
      );
      onClose();
      appState.notice.value =
        endpointIds.length > 0
          ? "Profile sharing requested; installation status is shown below."
          : "Profile saved without Endpoint sharing.";
      await refreshProviders();
      mutationKey.current = null;
    });
  }
  function toggleEndpoint(endpointId: string, checked: boolean) {
    setEndpointIds((current) =>
      checked ? [...current, endpointId] : current.filter((value) => value !== endpointId),
    );
  }
  return (
    <form
      id={id}
      className="nested-editor"
      aria-labelledby={titleId}
      onSubmit={(event) => void submit(event)}
    >
      <h3 id={titleId}>
        Add API key profile<span className="sr-only"> for {provider.provider}</span>
      </h3>
      <div className="form-grid">
        <Field label="Profile label">
          <TextInput
            label="Profile label"
            placeholder="Production key"
            value={label}
            onChange={setLabel}
            required
          />
        </Field>
        <Field label="API key">
          <TextInput label="API key" type="password" value={apiKey} onChange={setApiKey} required />
        </Field>
      </div>
      <label className="checkbox-row">
        <input
          type="checkbox"
          aria-label="Make this the default profile"
          checked={makeDefault}
          onChange={(event) => setMakeDefault(event.target.checked)}
        />
        <span>Make this the default profile</span>
      </label>
      <fieldset className="endpoint-choices">
        <legend>Share with Endpoints</legend>
        {endpoints.map((endpoint) => {
          const labelText =
            endpoint.kind === "local" ? "Share with this machine" : `Share with ${endpoint.label}`;
          return (
            <label className="checkbox-row" key={endpoint.endpoint_id}>
              <input
                type="checkbox"
                aria-label={labelText}
                checked={endpointIds.includes(endpoint.endpoint_id)}
                onChange={(event) => toggleEndpoint(endpoint.endpoint_id, event.target.checked)}
              />
              <span>{endpoint.kind === "local" ? "This machine" : endpoint.label}</span>
            </label>
          );
        })}
      </fieldset>
      <div className="panel-actions">
        <ActionButton label="Cancel" iconName="x" onClick={onClose} />
        <ActionButton
          label="Create profile"
          iconName="check"
          type="submit"
          kind="primary"
          disabled={busy}
        />
      </div>
    </form>
  );
}

function ProfileRow({ profile, stale }: { profile: AuthProfile; stale: boolean }) {
  useSignals();
  const profileContextId = `profile-context-${useId().replaceAll(":", "")}`;
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const deleteButtonRef = useRef<HTMLButtonElement>(null);
  const targets = profile.sharing.endpoint_ids
    .map(
      (id) =>
        appState.endpoints.value.find((endpoint) => endpoint.endpoint_id === id)?.label ??
        "Endpoint unavailable",
    )
    .join(", ");
  const distribution = profile.distribution
    .map((replica) => {
      const endpointLabel =
        appState.endpoints.value.find((endpoint) => endpoint.endpoint_id === replica.endpoint_id)
          ?.label ?? "Endpoint unavailable";
      return `${endpointLabel} · ${replica.status.replaceAll("_", " ")}`;
    })
    .join(", ");
  function closeDelete() {
    setDeleteOpen(false);
    setAcknowledged(false);
    queueMicrotask(() => deleteButtonRef.current?.focus());
  }
  async function makeDefault() {
    await withBusy(async () => {
      await setDefaultProfile(profile.provider, profile.profile_id);
      appState.notice.value = `${profile.label} is now the default profile.`;
      await refreshProviders();
    });
  }
  async function confirmDelete() {
    await withBusy(async () => {
      const result = await deleteProfile(profile.provider, profile.profile_id);
      closeDelete();
      appState.notice.value =
        result.status === "deleted"
          ? `${profile.label} was deleted and Endpoint revocation was acknowledged.`
          : `${profile.label} was deleted; Endpoint revocation is still pending.`;
      await refreshProviders();
    });
  }
  return (
    <Dialog.Root
      open={deleteOpen}
      onOpenChange={(nextOpen) => {
        if (nextOpen) {
          setAcknowledged(false);
          setDeleteOpen(true);
        } else {
          closeDelete();
        }
      }}
    >
      <div className="profile-row">
        <span id={profileContextId} className="sr-only">
          {profile.label} for {profile.provider}
        </span>
        <div>
          <strong>{profile.label}</strong>
          <span>{`${profile.kind.replace("_", " ")} · revision ${profile.revision}`}</span>
        </div>
        <span className="profile-default">
          {profile.is_default ? "Default profile" : "Not default"}
        </span>
        <span className="profile-targets">
          {distribution || targets || "Not shared"}
          {stale ? <em className="profile-freshness">Cached while unavailable</em> : null}
        </span>
        <StatusBadge value={profile.status} />
        <div className="profile-actions">
          {!profile.is_default ? (
            <ActionButton
              label="Set as default"
              iconName="star"
              ariaDescribedBy={profileContextId}
              onClick={() => void makeDefault()}
              disabled={appState.busy.value || stale}
            />
          ) : null}
          <Dialog.Trigger asChild>
            <ActionButton
              label="Delete profile"
              iconName="trash"
              kind="danger"
              ariaDescribedBy={profileContextId}
              buttonRef={deleteButtonRef}
              onClick={() => setAcknowledged(false)}
              disabled={appState.busy.value || stale}
            />
          </Dialog.Trigger>
        </div>
      </div>
      {deleteOpen ? (
        <Dialog.Portal>
          <Dialog.Overlay className="dialog-overlay" />
          <Dialog.Content
            className="profile-delete-dialog"
            aria-label="Delete profile"
            onCloseAutoFocus={(event) => {
              event.preventDefault();
              deleteButtonRef.current?.focus();
            }}
          >
            <div className="panel-title">
              <div>
                <Dialog.Title asChild>
                  <h3>Delete profile</h3>
                </Dialog.Title>
                <Dialog.Description asChild>
                  <p>
                    Removing the copied API key from an Endpoint is best-effort; provider-side
                    revocation may require key rotation.
                  </p>
                </Dialog.Description>
              </div>
            </div>
            <label className="checkbox-row">
              <input
                type="checkbox"
                aria-label="I understand the revocation warning"
                checked={acknowledged}
                onChange={(event) => setAcknowledged(event.target.checked)}
              />
              <span>I understand that provider-side revocation may require key rotation.</span>
            </label>
            <div className="panel-actions">
              <Dialog.Close asChild>
                <ActionButton label="Cancel" iconName="x" />
              </Dialog.Close>
              <ActionButton
                label="Delete profile permanently"
                iconName="trash"
                kind="danger"
                onClick={() => void confirmDelete()}
                disabled={!acknowledged || appState.busy.value}
              />
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      ) : null}
    </Dialog.Root>
  );
}

function EndpointsPage() {
  useSignals();
  const endpoints = appState.endpoints.value;
  return (
    <SettingsShell
      active="endpoints"
      title="Endpoints"
      subtitle={endpoints.length > 0 ? `${endpoints.length} available` : undefined}
    >
      <section className="settings-content-page">
        <header className="settings-page-header">
          <div>
            <p>Devices that can run Zode sessions.</p>
          </div>
          <ActionButton
            id="add-remote-endpoint"
            label="Add remote Endpoint"
            iconName="plus"
            kind="quiet"
            onClick={() => {
              appState.panel.value = "endpoint";
              appState.notice.value = null;
            }}
          />
        </header>
        <Notice />
        <EndpointDialog />
        {appState.endpointsLoading.value ? (
          <EmptyState
            iconName="spinner-gap"
            title="Loading Endpoints"
            detail="Reading device inventory from the management Server."
            role="status"
            state="loading"
          />
        ) : appState.endpointInventoryError.value ? (
          <EmptyState
            iconName="warning"
            title="Endpoints unavailable"
            detail="The management Server did not return the Endpoint inventory."
            role="alert"
            state="error"
          />
        ) : endpoints.length === 0 ? (
          <EmptyState
            iconName="devices"
            title="No Endpoints"
            detail="Connect a device before creating a session."
          />
        ) : null}
        {endpoints.map((endpoint) => (
          <EndpointCard key={endpoint.endpoint_id} endpoint={endpoint} />
        ))}
      </section>
    </SettingsShell>
  );
}

function EndpointDialog() {
  useSignals();
  const open = appState.panel.value === "endpoint";
  const [label, setLabel] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [credential, setCredential] = useState("");
  const mutationKey = useRef<string | null>(null);
  const busy = appState.busy.value;
  function close() {
    setLabel("");
    setBaseUrl("");
    setCredential("");
    mutationKey.current = null;
    appState.panel.value = null;
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const request = {
      label: label.trim(),
      baseUrl: baseUrl.trim(),
      controllerCredential: credential,
    };
    setCredential("");
    const key = mutationKey.current ?? crypto.randomUUID();
    mutationKey.current = key;
    await withBusy(async () => {
      await createEndpoint(request, key);
      appState.endpoints.value = await listEndpoints();
      appState.endpointInventoryError.value = null;
      close();
      appState.notice.value = `${request.label} is connected.`;
      mutationKey.current = null;
    });
  }
  return (
    <Dialog.Root
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) close();
      }}
    >
      {open ? (
        <Dialog.Portal>
          <Dialog.Overlay className="dialog-overlay" />
          <Dialog.Content
            className="dialog-panel"
            aria-label="Add remote Endpoint"
            aria-modal="true"
            onCloseAutoFocus={(event) => {
              event.preventDefault();
              document.getElementById("add-remote-endpoint")?.focus();
            }}
          >
            <form className="editor-panel" onSubmit={(event) => void submit(event)}>
              <div className="panel-title">
                <div>
                  <Dialog.Title asChild>
                    <h2>Add remote Endpoint</h2>
                  </Dialog.Title>
                  <Dialog.Description asChild>
                    <p>The credential is sent once and is never rendered back.</p>
                  </Dialog.Description>
                </div>
              </div>
              <div className="form-grid">
                <Field label="Endpoint label">
                  <TextInput
                    label="Endpoint label"
                    placeholder="Studio machine"
                    value={label}
                    onChange={setLabel}
                    required
                  />
                </Field>
                <Field label="Endpoint URL">
                  <TextInput
                    label="Endpoint URL"
                    type="url"
                    placeholder="https://device.example"
                    value={baseUrl}
                    onChange={setBaseUrl}
                    required
                  />
                </Field>
                <Field label="Controller credential">
                  <TextInput
                    label="Controller credential"
                    type="password"
                    value={credential}
                    onChange={setCredential}
                    required
                  />
                </Field>
              </div>
              <div className="panel-actions">
                <ActionButton label="Cancel" iconName="x" onClick={close} />
                <ActionButton
                  label={busy ? "Connecting…" : "Add Endpoint"}
                  iconName={busy ? "spinner-gap" : "check"}
                  type="submit"
                  kind="primary"
                  disabled={busy}
                />
              </div>
            </form>
          </Dialog.Content>
        </Dialog.Portal>
      ) : null}
    </Dialog.Root>
  );
}

function EndpointCard({ endpoint }: { endpoint: Endpoint }) {
  useSignals();
  const endpointHeadingId = `endpoint-heading-${useId().replaceAll(":", "")}`;
  const sessionListUnavailable = appState.sessionListErrors.value.has(endpoint.endpoint_id);
  const endpointSessions = (appState.sessions.value.get(endpoint.endpoint_id) ?? [])
    .slice()
    .sort(
      (left, right) =>
        (right.updated_at_ms ?? right.created_at_ms) - (left.updated_at_ms ?? left.created_at_ms),
    );
  const sessionListLoading =
    (appState.sessionLoadingByEndpoint.value.get(endpoint.endpoint_id) ?? 0) > 0 &&
    endpointSessions.length === 0;
  const sessionCount =
    sessionListUnavailable || sessionListLoading ? undefined : endpointSessions.length;
  const installedProfiles = Array.from(appState.profiles.value.values())
    .flatMap((profiles) => profiles)
    .filter((profile) =>
      profile.distribution.some(
        (replica) => replica.endpoint_id === endpoint.endpoint_id && replica.status === "ready",
      ),
    )
    .map((profile) => profile.label);
  async function refresh() {
    await withBusy(async () => {
      try {
        const observed = await probeEndpoint(endpoint.endpoint_id);
        appState.endpoints.value = appState.endpoints.value.map((item) =>
          item.endpoint_id === observed.endpoint_id ? observed : item,
        );
        await Promise.all([refreshSessions(endpoint.endpoint_id), refreshProviders()]);
        appState.notice.value = appState.sessionListErrors.value.has(endpoint.endpoint_id)
          ? `${endpoint.label} is reachable; sessions are unavailable.`
          : `${endpoint.label} is reachable.`;
      } catch (error) {
        if (error instanceof ServerClientError && error.code === "endpoint_unavailable") {
          appState.endpoints.value = appState.endpoints.value.map((item) =>
            item.endpoint_id === endpoint.endpoint_id ? { ...item, status: "unreachable" } : item,
          );
          appState.notice.value = "Endpoint unavailable; state is non-authoritative.";
          return;
        }
        throw error;
      }
    });
  }
  return (
    <article className="resource-card" aria-labelledby={endpointHeadingId}>
      <div className="resource-heading">
        <div className="resource-heading-main">
          <Icon
            name={endpoint.kind === "local" ? "desktop" : "globe"}
            className="resource-heading-icon"
          />
          <div>
            <h2 id={endpointHeadingId}>{endpoint.label}</h2>
            <p>{endpoint.kind === "local" ? "Built-in local Endpoint" : "Remote Endpoint"}</p>
          </div>
        </div>
        <StatusBadge value={endpoint.status} />
      </div>
      <dl className="facts">
        <Fact label="Protocol" value={endpoint.capabilities.protocol_version} />
        <Fact label="Providers" value={endpoint.capabilities.providers.join(", ") || "None"} />
        <Fact label="Tools" value={endpoint.capabilities.tools.join(", ") || "None"} />
        <Fact
          label="Sessions"
          value={
            sessionListLoading
              ? "Loading"
              : sessionListUnavailable || sessionCount === undefined
                ? "Unavailable"
                : String(sessionCount)
          }
        />
        <Fact
          label="Last observed"
          value={
            endpoint.last_observed_at_ms
              ? new Date(endpoint.last_observed_at_ms).toLocaleString()
              : "Unavailable"
          }
        />
        <Fact
          label="Auth replicas"
          value={`Ready ${endpoint.auth_replica_summary.ready} · Pending ${endpoint.auth_replica_summary.pending} · Stale ${endpoint.auth_replica_summary.stale}`}
        />
        <Fact label="Installed profiles" value={installedProfiles.join(", ") || "None"} />
      </dl>
      <div className="card-actions">
        <ActionButton
          label="Refresh Endpoint status"
          iconName="arrows-clockwise"
          ariaDescribedBy={endpointHeadingId}
          onClick={() => void refresh()}
          disabled={appState.busy.value}
        />
      </div>
    </article>
  );
}

function HomePage() {
  return (
    <Shell>
      <section className="home-page" data-zode-thread-column="true">
        <Notice />
        <div className="home-intro">
          <div className="home-hero" data-zode-hero="true">
            <h1 className="home-hero-placeholder" aria-hidden="true">
              What do you want to work on?
            </h1>
            <h1 data-zode-primary-text="true">What do you want to work on?</h1>
          </div>
        </div>
        <HomeComposer />
      </section>
    </Shell>
  );
}

function HomeComposer() {
  useSignals();
  const endpoints = appState.endpoints.value;
  const providers = appState.providers.value;
  const profiles = appState.profiles.value;
  const endpointsLoading = appState.endpointsLoading.value;
  const providersLoading = appState.providersLoading.value;
  const endpointInventoryError = appState.endpointInventoryError.value;
  const providerListError = appState.providerListError.value;
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const createMutationKey = useRef<string | null>(null);
  const messageMutation = useRef<{ content: string; key: string } | null>(null);
  const endpointOptions = useMemo(
    () =>
      endpoints.map((endpoint) => ({
        value: endpoint.endpoint_id,
        label: `${endpoint.kind === "local" ? "This machine" : endpoint.label}${
          endpointIsUsable(endpoint) ? "" : " · unavailable"
        }`,
        disabled: !endpointIsUsable(endpoint),
      })),
    [endpoints],
  );
  const providerOptions = useMemo(
    () => providers.map((provider) => ({ value: provider.provider, label: provider.provider })),
    [providers],
  );
  const [endpointSelection, setEndpointSelection] = useState("");
  const [providerSelection, setProviderSelection] = useState("");
  const [modelSelection, setModelSelection] = useState("");
  const [profileSelection, setProfileSelection] = useState("");
  // Visual-only until the public provider/session contract exposes reasoning effort.
  const [reasoningEffort, setReasoningEffort] = useState<ReasoningEffort>("high");
  const [input, setInput] = useState("");
  const requestedEndpointId = appState.homeEndpointSelection.value;
  useEffect(() => {
    if (inputRef.current) resizeComposerInput(inputRef.current, 180, 44);
  }, [input]);
  const endpointId = endpointOptions.some(
    (option) => option.value === endpointSelection && !option.disabled,
  )
    ? endpointSelection
    : (endpointOptions.find((option) => !option.disabled)?.value ?? "");
  useEffect(() => {
    if (
      requestedEndpointId &&
      endpointOptions.some((option) => option.value === requestedEndpointId)
    ) {
      setEndpointSelection(requestedEndpointId);
    }
  }, [endpointOptions, requestedEndpointId]);
  const providerId = providerOptions.some((option) => option.value === providerSelection)
    ? providerSelection
    : (providerOptions[0]?.value ?? "");
  const selectedProvider = providers.find((provider) => provider.provider === providerId);
  const modelOptions = useMemo(
    () =>
      selectedProvider?.descriptor.models.map((model) => ({ value: model, label: model })) ?? [],
    [selectedProvider],
  );
  const modelId = modelOptions.some((option) => option.value === modelSelection)
    ? modelSelection
    : (modelOptions[0]?.value ?? "");
  const profileOptions = useMemo(() => {
    const eligibleProfiles = (profiles.get(providerId) ?? []).filter((profile) =>
      profileIsUsableOnEndpoint(profile, endpointId),
    );
    return eligibleProfiles.map((profile) => ({
      value: profile.profile_id,
      label: profileOptionLabel(profile, eligibleProfiles),
      profile,
    }));
  }, [profiles, providerId, endpointId]);
  const profileId = profileOptions.some((option) => option.value === profileSelection)
    ? profileSelection
    : (profileOptions.find((option) => option.value === selectedProvider?.default_profile_id)
        ?.value ??
      profileOptions.find((option) => option.profile.is_default)?.value ??
      profileOptions[0]?.value ??
      "");
  const modelGroups = useMemo(
    () => modelExecutionGroups(providers, profiles, endpointId),
    [providers, profiles, endpointId],
  );
  const selectedProfile = profileOptions.find((option) => option.value === profileId)?.profile;
  const selectedExecution: ExecutionChoice | undefined =
    selectedProvider && selectedProfile && modelId
      ? { provider: selectedProvider, model: modelId, profile: selectedProfile }
      : undefined;
  const profileListError = appState.profileListErrors.value.get(providerId);
  const pendingSharedProfile = (profiles.get(providerId) ?? []).find(
    (profile) =>
      profile.sharing.mode === "selected" &&
      profile.sharing.endpoint_ids.includes(endpointId) &&
      !profileIsUsableOnEndpoint(profile, endpointId),
  );
  const pendingReplica = pendingSharedProfile?.distribution.find(
    (replica) => replica.endpoint_id === endpointId,
  );
  const pendingProfileState = pendingReplica?.status ?? pendingSharedProfile?.status;
  const composerNeedsSetup =
    endpointsLoading ||
    providersLoading ||
    (Boolean(endpointInventoryError) && endpoints.length === 0) ||
    Boolean(providerListError) ||
    Boolean(profileListError) ||
    endpoints.length === 0 ||
    providers.length === 0 ||
    modelGroups.length === 0 ||
    profileOptions.length === 0;
  const setupHint = endpointsLoading
    ? "Loading Endpoints…"
    : endpointInventoryError && endpoints.length === 0
      ? "Endpoint inventory is unavailable. Try again from Manage."
      : providersLoading
        ? "Loading providers…"
        : providerListError
          ? "Provider inventory is unavailable. Try again from Manage."
          : profileListError
            ? "Auth profiles are unavailable. Try again from Manage."
            : endpoints.length === 0
              ? "Add an Endpoint from Manage to start a session."
              : !endpointId
                ? "No reachable Endpoint is available."
                : providers.length === 0
                  ? "Configure a provider from Manage to start a session."
                  : modelGroups.length === 0
                    ? "The selected provider has no available models."
                    : pendingSharedProfile
                      ? `${pendingSharedProfile.label} is ${
                          pendingProfileState?.replaceAll("_", " ") ?? "not ready"
                        } on this Endpoint.`
                      : "Share a ready auth profile with this Endpoint to start a session.";
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (composerNeedsSetup) return;
    const profile = profileOptions.find((option) => option.value === profileId)?.profile;
    if (!selectedProvider || !profile || !endpointId || !modelId) return;
    const message = input.trim();
    if (messageMutation.current && messageMutation.current.content !== message) {
      messageMutation.current = null;
    }
    const createKey = createMutationKey.current ?? crypto.randomUUID();
    createMutationKey.current = createKey;
    const messageKey = message ? (messageMutation.current?.key ?? crypto.randomUUID()) : null;
    if (message && !messageMutation.current) {
      messageMutation.current = { content: message, key: messageKey as string };
    }
    await withBusy(async () => {
      const created = await createSession(
        endpointId,
        { provider: selectedProvider, model: modelId, profile },
        createKey,
      );
      recordNavigation(`/endpoints/${endpointId}/sessions/${created.session_id}`);
      await openSession(endpointId, created.session_id);
      await refreshSessions();
      if (message) {
        await sendMessage(endpointId, created.session_id, message, messageKey as string);
        await loadActiveSession();
        await refreshSessions();
      }
      createMutationKey.current = null;
      messageMutation.current = null;
    });
  }
  return (
    <form
      id="home-session-composer"
      className="home-composer"
      aria-label="Message composer"
      onSubmit={(event) => void submit(event)}
    >
      <div
        className="home-composer-body"
        data-zode-composer="true"
        role="group"
        aria-label="Message composer"
      >
        <textarea
          id="home-session-input"
          ref={inputRef}
          className="home-composer-input"
          rows={1}
          placeholder="Message"
          aria-label="New session message"
          aria-describedby={composerNeedsSetup ? "home-composer-empty" : undefined}
          value={input}
          onChange={(event) => setInput(event.target.value)}
          onKeyDown={(event) => {
            if (!event.nativeEvent.isComposing && event.key === "Enter" && !event.shiftKey) {
              event.preventDefault();
              event.currentTarget.form?.requestSubmit();
            }
          }}
        />
        {composerNeedsSetup ? (
          <p id="home-composer-empty" className="home-composer-empty" role="status">
            {setupHint}
          </p>
        ) : null}
        <div className="home-composer-footer" role="group" aria-label="Environment and execution">
          <div className="composer-utility-bar">
            <label className="composer-context-field">
              <Icon name="desktop" />
              <SelectInput
                label="Environment"
                value={endpointId}
                options={endpointOptions}
                onChange={(value) => {
                  setEndpointSelection(value);
                  appState.homeEndpointSelection.value = value;
                }}
                disabled={endpoints.length === 0}
                placeholder="No environment available"
                className="select composer-select composer-environment-select"
              />
            </label>
            <ModelExecutionMenu
              groups={modelGroups}
              profiles={profiles}
              selected={selectedExecution}
              modelLabel={modelId || "Choose model"}
              reasoningEffort={reasoningEffort}
              onReasoningSelect={setReasoningEffort}
              ariaLabel="Choose model and reasoning"
              title="Choose model and reasoning"
              disabled={composerNeedsSetup || appState.busy.value}
              onSelect={(choice) => {
                setProviderSelection(choice.provider.provider);
                setModelSelection(choice.model);
                setProfileSelection(choice.profile.profile_id);
              }}
            />
          </div>
          <button
            className="composer-submit"
            type="submit"
            aria-label="Start session"
            title="Start session"
            disabled={
              composerNeedsSetup ||
              appState.busy.value ||
              !endpointId ||
              !providerId ||
              !modelId ||
              !profileId
            }
          >
            <Icon name="arrow-up" />
          </button>
        </div>
      </div>
    </form>
  );
}

function sessionVisualState(
  session: Session,
):
  | "streaming"
  | "waiting"
  | "tool"
  | "error"
  | "connecting"
  | "reconnecting"
  | "disconnected"
  | undefined {
  if (appState.connection.value === "Connecting") return "connecting";
  if (appState.connection.value === "Reconnecting") return "reconnecting";
  if (appState.connection.value === "Disconnected") return "disconnected";
  if (session.last_model_attempts_exhausted) return "error";
  if (session.tool_calls?.some((tool) => ["failed", "unknown_outcome"].includes(tool.status)))
    return "error";
  if (session.wait) return "waiting";
  if (
    session.tool_calls?.some(
      (tool) => !["completed", "failed", "cancelled", "unknown_outcome"].includes(tool.status),
    )
  )
    return "tool";
  if (session.active_activation) return "streaming";
  return undefined;
}

function RuntimeActivity({ session }: { session: Session }) {
  useSignals();
  const declaredToolCallIds = new Set(
    session.transcript.flatMap((message) =>
      (message.tool_calls ?? []).map((call) => call.tool_call_id),
    ),
  );
  const lines: Array<{
    icon?: string;
    title: string;
    state?: string;
    detail: string;
    toolCallId?: string;
    attention?: boolean;
    alert?: boolean;
  }> = [];
  if (session.active_model_round?.attempt?.outcome === "failed") {
    const retry = session.active_model_round.retry;
    lines.push({
      icon: "arrows-clockwise",
      title: "Retrying",
      detail: retry
        ? `${retry.error_class ?? "Model error"} · attempt ${retry.next_attempt_number ?? "?"}/${retry.maximum_attempts ?? "?"}`
        : "Model request failed; preparing a retry",
      attention: true,
      alert: true,
    });
  }
  if (session.wait)
    lines.push({
      icon: "clock",
      title: "Waiting",
      detail: session.wait.deadline_ms
        ? `${session.wait.reason ?? "Awaiting an external result"} · until ${new Date(session.wait.deadline_ms).toLocaleTimeString()}`
        : (session.wait.reason ?? "Awaiting an external result"),
    });
  for (const tool of (session.tool_calls ?? []).filter(
    (tool) => !["completed"].includes(tool.status) && !declaredToolCallIds.has(tool.tool_call_id),
  ))
    lines.push({
      icon: tool.status === "unknown_outcome" ? "warning" : "wrench",
      title: toolIdentity(tool.tool_name ?? tool.name, tool.tool_call_id),
      state: readableToolStatus(tool.status),
      detail:
        tool.status === "unknown_outcome"
          ? (tool.error?.message ?? "Unable to determine tool outcome")
          : (tool.error?.message ?? tool.reconciliation?.reason ?? ""),
      toolCallId: tool.tool_call_id,
      attention: ["unknown_outcome", "failed"].includes(tool.status),
      alert: ["unknown_outcome", "failed"].includes(tool.status),
    });
  if (session.active_activation && !session.last_model_attempts_exhausted)
    lines.push({ icon: "spinner-gap", title: "Working", detail: "Model activation in progress" });
  if (lines.length === 0) return null;
  return (
    <aside className="runtime-activity" aria-label="Run status">
      <div className="activity-list" role="list">
        {lines.map((line) => (
          <div
            className="status-line"
            role="listitem"
            aria-label={[line.title, line.state, line.detail].filter(Boolean).join(", ")}
            data-zode-attention={line.attention || line.title === "Waiting" ? "true" : undefined}
            data-zode-alert={line.alert ? "true" : undefined}
            data-zode-tool-row={line.toolCallId ? "true" : undefined}
            data-zode-tool-status={line.toolCallId ? line.state?.replaceAll(" ", "_") : undefined}
            key={line.toolCallId ?? `${line.title}:${line.detail}`}
          >
            {line.icon ? <Icon name={line.icon} /> : null}
            <div>
              <strong>{line.title}</strong>
              {line.state ? <span className="status-line-state">{line.state}</span> : null}
              {line.alert ? (
                <span className="status-line-detail" role="alert" aria-live="assertive">
                  {line.detail}
                </span>
              ) : line.detail ? (
                <span className="status-line-detail" role="status" aria-live="polite">
                  {line.detail}
                </span>
              ) : null}
            </div>
          </div>
        ))}
      </div>
    </aside>
  );
}

function TurnErrorCard({
  exhausted,
}: {
  exhausted: NonNullable<Session["last_model_attempts_exhausted"]>;
}) {
  const attempts = exhausted.attempt_number;
  const maximumAttempts = exhausted.maximum_attempts;
  const message =
    attempts !== undefined && maximumAttempts !== undefined
      ? `Model attempts exhausted (${attempts}/${maximumAttempts})`
      : "Model activation failed";
  return (
    <div
      className="status-line turn-error-line"
      role="alert"
      aria-live="assertive"
      aria-label={message}
      data-zode-attention="true"
      data-zode-alert="true"
    >
      <Icon name="warning" />
      <span className="turn-error-message">{message}</span>
    </div>
  );
}

function profileOptionLabel(profile: AuthProfile, candidates: AuthProfile[]): string {
  const duplicates = candidates.filter((candidate) => candidate.label === profile.label);
  if (duplicates.length < 2) return profile.label;
  const sameKind = duplicates.filter((candidate) => candidate.kind === profile.kind);
  const ordinal =
    sameKind.length > 1
      ? ` ${sameKind.findIndex((candidate) => candidate.profile_id === profile.profile_id) + 1}`
      : "";
  return `${profile.label} · ${profile.kind === "api_key" ? "API key" : "OAuth"}${ordinal}`;
}

type ExecutionChoice = {
  provider: Provider;
  model: string;
  profile: AuthProfile;
};

type ModelExecutionGroup = {
  model: string;
  choices: ExecutionChoice[];
};

type ReasoningEffort = "minimal" | "low" | "medium" | "high" | "xhigh" | "max";

const reasoningEffortOptions: ReadonlyArray<{ value: ReasoningEffort; label: string }> = [
  { value: "minimal", label: "Minimal" },
  { value: "low", label: "Light" },
  { value: "medium", label: "Medium" },
  { value: "high", label: "High" },
  { value: "xhigh", label: "Extra High" },
  { value: "max", label: "Max" },
];

function isReasoningEffort(value: string): value is ReasoningEffort {
  return reasoningEffortOptions.some((option) => option.value === value);
}

function modelExecutionGroups(
  providers: Provider[],
  profiles: Map<string, AuthProfile[]>,
  endpointId: string,
): ModelExecutionGroup[] {
  const groups = new Map<string, ExecutionChoice[]>();
  for (const provider of providers) {
    const candidates = profiles.get(provider.provider) ?? [];
    const eligibleProfiles = candidates.filter((profile) =>
      profileIsUsableOnEndpoint(profile, endpointId),
    );
    for (const model of provider.descriptor.models) {
      const choices = groups.get(model) ?? [];
      for (const profile of eligibleProfiles) {
        if (
          choices.some(
            (choice) =>
              choice.provider.provider === provider.provider &&
              choice.profile.auth_profile_id === profile.auth_profile_id,
          )
        ) {
          continue;
        }
        choices.push({ provider, model, profile });
      }
      if (choices.length > 0) groups.set(model, choices);
    }
  }
  return [...groups].map(([model, choices]) => ({ model, choices }));
}

function executionChoiceMatches(
  choice: ExecutionChoice | undefined,
  provider: string | undefined,
  model: string | undefined,
  profileId: string | undefined,
): boolean {
  return Boolean(
    choice &&
    choice.provider.provider === provider &&
    choice.model === model &&
    (choice.profile.auth_profile_id === profileId || choice.profile.profile_id === profileId),
  );
}

function executionChoiceLabel(
  choice: ExecutionChoice,
  group: ModelExecutionGroup,
  profiles: Map<string, AuthProfile[]>,
): string {
  const providerCount = new Set(group.choices.map((candidate) => candidate.provider.provider)).size;
  const profileLabel = profileOptionLabel(
    choice.profile,
    profiles.get(choice.provider.provider) ?? [],
  );
  return providerCount > 1 ? `${choice.provider.provider} · ${profileLabel}` : profileLabel;
}

function CodexPowerSlider({
  value,
  onValueChange,
  onInteractionChange,
}: {
  value: number;
  onValueChange: (value: number) => void;
  onInteractionChange: (active: boolean) => void;
}) {
  const lastIndex = reasoningEffortOptions.length - 1;
  const [keyboardFocused, setKeyboardFocused] = useState(false);
  return (
    <div
      className="power-slider-container"
      data-keyboard-focused={keyboardFocused ? "true" : "false"}
      data-model-picker-power-slider
    >
      <Slider.Root
        className="power-slider-root"
        min={0}
        max={lastIndex}
        step={1}
        value={[value]}
        aria-label="Power"
        onPointerDown={() => {
          setKeyboardFocused(false);
          onInteractionChange(true);
        }}
        onPointerUp={() => onInteractionChange(false)}
        onPointerCancel={() => onInteractionChange(false)}
        onValueCommit={() => onInteractionChange(false)}
        onKeyDown={(event) => {
          if (event.key.startsWith("Arrow") || event.key === "Home" || event.key === "End") {
            setKeyboardFocused(true);
          }
        }}
        onBlur={() => setKeyboardFocused(false)}
        onValueChange={([nextValue]) => {
          if (nextValue !== undefined) onValueChange(nextValue);
        }}
      >
        <Slider.Track className="power-slider-track">
          <Slider.Range className="power-slider-range" />
          <span className="power-slider-ticks" aria-hidden="true">
            {reasoningEffortOptions.map((option, index) => (
              <span
                className="power-slider-tick"
                key={option.value}
                data-selected={String(index <= value)}
                style={{ left: `${(index / lastIndex) * 100}%` }}
              />
            ))}
          </span>
        </Slider.Track>
        <Slider.Thumb className="power-slider-thumb" aria-label="Power" />
      </Slider.Root>
    </div>
  );
}

function ModelExecutionMenu({
  groups,
  profiles,
  selected,
  modelLabel,
  reasoningEffort,
  onReasoningSelect,
  onSelect,
  disabled = false,
  ariaLabel = "Choose model",
  title,
  recovery = false,
}: {
  groups: ModelExecutionGroup[];
  profiles: Map<string, AuthProfile[]>;
  selected?: ExecutionChoice;
  modelLabel: string;
  reasoningEffort: ReasoningEffort;
  onReasoningSelect: (value: ReasoningEffort) => void;
  onSelect: (choice: ExecutionChoice) => void | Promise<void>;
  disabled?: boolean;
  ariaLabel?: string;
  title?: string;
  recovery?: boolean;
}) {
  const [menuView, setMenuView] = useState<"simple" | "advanced">("simple");
  const [powerInteractionActive, setPowerInteractionActive] = useState(false);
  const selectedReasoning =
    reasoningEffortOptions.find((option) => option.value === reasoningEffort) ??
    reasoningEffortOptions[3];
  const selectedReasoningIndex = Math.max(
    0,
    reasoningEffortOptions.findIndex((option) => option.value === selectedReasoning.value),
  );
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          className="composer-execution-trigger"
          type="button"
          aria-label={ariaLabel}
          disabled={disabled || groups.length === 0}
          data-zode-execution-state={recovery ? "needs-recovery" : "ready"}
          data-zode-reasoning-effort={reasoningEffort}
          data-zode-ui-only="true"
          title={title ?? ariaLabel}
        >
          {recovery ? <Icon name="warning" /> : null}
          <span className="composer-execution-model">{modelLabel}</span>
          <span className="composer-execution-effort">{selectedReasoning.label}</span>
          <Icon name="caret-down" />
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          className="model-menu-content"
          data-zode-menu-view={menuView}
          side="top"
          align="start"
          sideOffset={8}
          collisionPadding={8}
        >
          {menuView === "simple" ? (
            <>
              <CodexPowerSlider
                value={selectedReasoningIndex}
                onInteractionChange={setPowerInteractionActive}
                onValueChange={(nextValue) => {
                  const option = reasoningEffortOptions[nextValue];
                  if (option) onReasoningSelect(option.value);
                }}
              />
              <div className="power-view-controls" data-expanded="false">
                {powerInteractionActive ? (
                  <span className="power-slider-endpoints" aria-hidden="true">
                    <span>Faster</span>
                    <span>Smarter</span>
                  </span>
                ) : (
                  <DropdownMenu.Item
                    className="model-menu-item power-advanced-toggle"
                    data-model-picker-view-toggle="true"
                    aria-label="Show advanced options"
                    onSelect={(event) => {
                      event.preventDefault();
                      setMenuView("advanced");
                    }}
                  >
                    <span className="power-advanced-toggle-content">
                      <span>Advanced</span>
                      <Icon name="caret-right" className="advanced-toggle-icon" />
                    </span>
                  </DropdownMenu.Item>
                )}
              </div>
            </>
          ) : (
            <>
              <DropdownMenu.Sub>
                <DropdownMenu.SubTrigger className="model-menu-item intelligence-menu-row">
                  <span>Model</span>
                  <span className="intelligence-menu-value">{modelLabel}</span>
                  <Icon name="caret-right" />
                </DropdownMenu.SubTrigger>
                <DropdownMenu.Portal>
                  <DropdownMenu.SubContent
                    className="model-menu-content model-menu-subcontent"
                    sideOffset={6}
                    collisionPadding={8}
                  >
                    {groups.map((group) => {
                      const direct = group.choices.length === 1;
                      if (direct) {
                        const choice = group.choices[0];
                        const isSelected = executionChoiceMatches(
                          selected,
                          choice.provider.provider,
                          choice.model,
                          choice.profile.auth_profile_id,
                        );
                        return (
                          <DropdownMenu.Item
                            className="model-menu-item"
                            key={group.model}
                            data-zode-model={group.model}
                            data-zode-selected={String(isSelected)}
                            onSelect={() => void onSelect(choice)}
                          >
                            <span>{group.model}</span>
                            {isSelected ? <Icon name="check" /> : null}
                          </DropdownMenu.Item>
                        );
                      }
                      return (
                        <DropdownMenu.Sub key={group.model}>
                          <DropdownMenu.SubTrigger
                            className="model-menu-item model-menu-subtrigger"
                            data-zode-model={group.model}
                          >
                            <span>{group.model}</span>
                            <Icon name="caret-right" />
                          </DropdownMenu.SubTrigger>
                          <DropdownMenu.Portal>
                            <DropdownMenu.SubContent
                              className="model-menu-content model-menu-subcontent"
                              sideOffset={6}
                              collisionPadding={8}
                            >
                              {group.choices.map((choice) => {
                                const isSelected = executionChoiceMatches(
                                  selected,
                                  choice.provider.provider,
                                  choice.model,
                                  choice.profile.auth_profile_id,
                                );
                                return (
                                  <DropdownMenu.Item
                                    className="model-menu-item"
                                    key={`${choice.provider.provider}:${choice.profile.auth_profile_id}`}
                                    data-zode-selected={String(isSelected)}
                                    onSelect={() => void onSelect(choice)}
                                  >
                                    <span>{executionChoiceLabel(choice, group, profiles)}</span>
                                    {isSelected ? <Icon name="check" /> : null}
                                  </DropdownMenu.Item>
                                );
                              })}
                            </DropdownMenu.SubContent>
                          </DropdownMenu.Portal>
                        </DropdownMenu.Sub>
                      );
                    })}
                  </DropdownMenu.SubContent>
                </DropdownMenu.Portal>
              </DropdownMenu.Sub>
              <DropdownMenu.Sub>
                <DropdownMenu.SubTrigger className="model-menu-item intelligence-menu-row">
                  <span>Effort</span>
                  <span className="intelligence-menu-value">{selectedReasoning.label}</span>
                  <Icon name="caret-right" />
                </DropdownMenu.SubTrigger>
                <DropdownMenu.Portal>
                  <DropdownMenu.SubContent
                    className="model-menu-content model-menu-subcontent reasoning-menu-subcontent"
                    sideOffset={6}
                    collisionPadding={8}
                  >
                    <DropdownMenu.Label className="reasoning-menu-label">Effort</DropdownMenu.Label>
                    <DropdownMenu.RadioGroup
                      value={reasoningEffort}
                      onValueChange={(nextValue) => {
                        if (isReasoningEffort(nextValue)) onReasoningSelect(nextValue);
                      }}
                    >
                      {reasoningEffortOptions.map((option) => (
                        <DropdownMenu.RadioItem
                          className="model-menu-item reasoning-menu-item"
                          key={option.value}
                          value={option.value}
                          data-zode-reasoning-effort={option.value}
                          data-zode-selected={String(option.value === reasoningEffort)}
                        >
                          <span>{option.label}</span>
                          {option.value === reasoningEffort ? <Icon name="check" /> : null}
                        </DropdownMenu.RadioItem>
                      ))}
                    </DropdownMenu.RadioGroup>
                  </DropdownMenu.SubContent>
                </DropdownMenu.Portal>
              </DropdownMenu.Sub>
              <div className="power-advanced-controls">
                <DropdownMenu.Item
                  className="model-menu-item power-advanced-toggle is-expanded"
                  data-model-picker-view-toggle="true"
                  aria-label="Show compact options"
                  onSelect={(event) => {
                    event.preventDefault();
                    setMenuView("simple");
                  }}
                >
                  <span className="power-advanced-toggle-content">
                    <span>Advanced</span>
                    <Icon name="caret-right" className="advanced-toggle-icon" />
                  </span>
                </DropdownMenu.Item>
              </div>
            </>
          )}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

function sessionExecutionNeedsRecovery(
  session: Session,
  endpointId: string,
  providers: Provider[],
  profiles: Map<string, AuthProfile[]>,
  providerListError?: string | null,
  profileListError?: string | null,
): boolean {
  if (providerListError || profileListError) return true;
  const model = session.model;
  if (!model) return true;
  const provider = providers.find((candidate) => candidate.provider === model.provider);
  if (!provider || !provider.descriptor.models.includes(model.model)) return true;

  const hasExecutionDescriptor =
    model.provider_execution_schema !== undefined ||
    model.provider_execution_revision !== undefined ||
    model.provider_execution_kind !== undefined ||
    model.provider_execution_base_url !== undefined ||
    model.provider_execution_options !== undefined;
  if (
    hasExecutionDescriptor &&
    (model.provider_execution_schema !== "zode.provider-execution.v1" ||
      model.provider_execution_revision !== provider.descriptor.revision ||
      model.provider_execution_kind !== provider.descriptor.kind ||
      model.provider_execution_base_url !== provider.descriptor.base_url ||
      JSON.stringify(model.provider_execution_options ?? {}) !==
        JSON.stringify(provider.descriptor.options))
  ) {
    return true;
  }

  const profile = (profiles.get(model.provider) ?? []).find(
    (candidate) =>
      candidate.auth_profile_id === model.auth_profile_id ||
      candidate.profile_id === model.auth_profile_id,
  );
  return !profile || !profileIsUsableOnEndpoint(profile, endpointId);
}

function sessionExecutionUnavailableForSending(
  session: Session,
  endpointId: string,
  providers: Provider[],
  profiles: Map<string, AuthProfile[]>,
  providerListError?: string | null,
  profileListError?: string | null,
): boolean {
  if (providerListError || profileListError || !session.model) return true;
  const provider = providers.find((candidate) => candidate.provider === session.model?.provider);
  if (!provider || !provider.descriptor.models.includes(session.model.model)) return true;
  const profile = (profiles.get(session.model.provider) ?? []).find(
    (candidate) =>
      candidate.auth_profile_id === session.model?.auth_profile_id ||
      candidate.profile_id === session.model?.auth_profile_id,
  );
  return !profile || !profileIsUsableOnEndpoint(profile, endpointId);
}

function executionSessionKey(endpointId: string, sessionId: string): string {
  return `${endpointId}:${sessionId}`;
}

function isExecutionRecoveryAcknowledged(
  endpointId: string,
  sessionId: string,
  provider: Provider | undefined,
): boolean {
  const acknowledgement = appState.executionRecoveryAcknowledgement.value;
  return Boolean(
    acknowledgement &&
    provider &&
    acknowledgement.sessionKey === executionSessionKey(endpointId, sessionId) &&
    acknowledgement.providerRevision === provider.descriptor.revision,
  );
}

function acknowledgeExecutionRecovery(
  endpointId: string,
  sessionId: string,
  provider: Provider,
): void {
  appState.executionRecoveryAcknowledgement.value = {
    sessionKey: executionSessionKey(endpointId, sessionId),
    providerRevision: provider.descriptor.revision,
  };
}

function clearExecutionRecoveryAcknowledgement(endpointId: string, sessionId: string): void {
  if (
    appState.executionRecoveryAcknowledgement.value?.sessionKey ===
    executionSessionKey(endpointId, sessionId)
  ) {
    appState.executionRecoveryAcknowledgement.value = null;
  }
}

function SessionPage() {
  useSignals();
  const transcriptRef = useRef<HTMLDivElement>(null);
  const session = appState.activeSession.value;
  const activeEndpointId = appState.activeEndpointId.value;
  const activeSessionId = appState.activeSessionId.value;
  const endpoint = appState.endpoints.value.find((item) => item.endpoint_id === activeEndpointId);
  useEffect(() => {
    if (!session || !window.matchMedia("(max-width: 760px)").matches) return;
    const frame = window.requestAnimationFrame(() => {
      if (transcriptRef.current)
        transcriptRef.current.scrollTop = transcriptRef.current.scrollHeight;
    });
    return () => window.cancelAnimationFrame(frame);
  }, [session?.session_id, session?.transcript.length]);
  if (!session || !endpoint) {
    return (
      <Shell title="Session">
        <section
          className="session-workspace"
          data-zode-thread-column="true"
          data-zode-session-state={appState.sessionLoading.value ? undefined : "error"}
        >
          {appState.sessionLoading.value ? (
            <EmptyState
              iconName="spinner-gap"
              title="Opening session"
              detail="Reading the durable session from its Endpoint."
              role="status"
              state="loading"
            />
          ) : (
            <div className="session-error-state" role="alert" aria-live="assertive">
              <Icon name="warning" />
              <div className="session-error-copy">
                <h2>Session unavailable</h2>
                <p>
                  {appState.sessionError.value ?? "The Endpoint could not provide this session."}
                </p>
              </div>
              {appState.sessionRetryAvailable.value && activeEndpointId && activeSessionId ? (
                <ActionButton
                  label="Retry"
                  iconName="arrows-clockwise"
                  onClick={() => {
                    void openSession(activeEndpointId, activeSessionId).catch(showError);
                  }}
                />
              ) : null}
            </div>
          )}
        </section>
      </Shell>
    );
  }
  const title = sessionTitle(session);
  const state = sessionVisualState(session);
  const latestDurableMessage = session.transcript.at(-1);
  const durableTranscriptAnnouncement = latestDurableMessage
    ? `${session.transcript.length} messages. Latest from ${transcriptRoleLabel(latestDurableMessage.role)}.`
    : "Session ready.";
  return (
    <Shell title={title} headerIconName={endpoint.kind === "local" ? "desktop" : "globe"}>
      <section
        className="session-workspace"
        data-zode-thread-column="true"
        data-zode-session-state={state}
      >
        <Notice />
        <div className="sr-only" role="status" aria-live="polite" aria-atomic="true">
          {durableTranscriptAnnouncement}
        </div>
        <div className="transcript" ref={transcriptRef} aria-label="Conversation">
          {session.transcript.length === 0 && !appState.provisionalAssistant.value ? (
            <div className="transcript-empty" role="status">
              <span>Ready when you are</span>
            </div>
          ) : null}
          {session.transcript.map((message, index) => (
            <article
              className={`message message-${message.role}${
                index > 0 && session.transcript[index - 1].role === message.role
                  ? " is-grouped"
                  : ""
              }`}
              aria-label={transcriptRoleLabel(message.role)}
              data-zode-secondary-surface={message.role === "user" ? "true" : undefined}
              key={message.message_id ?? `${message.role}-${index}`}
            >
              {message.role === "tool" ? (
                (() => {
                  const tool = message.tool_call_id
                    ? session.tool_calls.find(
                        (candidate) => candidate.tool_call_id === message.tool_call_id,
                      )
                    : undefined;
                  return (
                    <div
                      className="inline-tool-activity is-standalone"
                      role="list"
                      aria-label="Tool calls"
                    >
                      <ToolMessage
                        content={message.content}
                        summary={tool?.tool_name ?? tool?.name}
                        status={tool?.status}
                        toolCallId={message.tool_call_id ?? undefined}
                      />
                    </div>
                  );
                })()
              ) : (
                <>
                  <MessageContent content={message.content} />
                  <InlineToolCalls message={message} session={session} />
                </>
              )}
            </article>
          ))}
          {appState.provisionalAssistant.value?.sessionId === session.session_id &&
          appState.provisionalAssistant.value.text ? (
            <article
              className="message message-assistant message-provisional"
              aria-label="Agent"
              aria-live="off"
              data-zode-provisional="true"
            >
              <MessageContent content={appState.provisionalAssistant.value.text} />
            </article>
          ) : null}
          {session.last_model_attempts_exhausted ? (
            <TurnErrorCard exhausted={session.last_model_attempts_exhausted} />
          ) : null}
        </div>
        <RuntimeActivity session={session} />
        {appState.connection.value !== "Live" ? (
          <div className="session-meta" data-zode-attention="true" role="status" aria-live="polite">
            <Icon name="wifi-slash" />
            <span>{appState.sessionError.value ?? appState.connection.value}</span>
            {appState.sessionRetryAvailable.value ||
            appState.connection.value === "Connecting" ||
            appState.connection.value === "Reconnecting" ? (
              <button
                className="session-reconnect-button"
                type="button"
                disabled={appState.busy.value}
                onClick={() => {
                  if (
                    appState.connection.value === "Connecting" ||
                    appState.connection.value === "Reconnecting"
                  ) {
                    closeEventStream();
                  } else {
                    void withBusy(() => reconnectSession(endpoint.endpoint_id, session.session_id));
                  }
                }}
              >
                <Icon
                  name={
                    appState.connection.value === "Connecting" ||
                    appState.connection.value === "Reconnecting"
                      ? "stop"
                      : "arrows-clockwise"
                  }
                />
                <span>
                  {appState.connection.value === "Connecting" ||
                  appState.connection.value === "Reconnecting"
                    ? "Stop"
                    : "Reconnect"}
                </span>
              </button>
            ) : null}
          </div>
        ) : null}
        <SessionComposer endpointId={endpoint.endpoint_id} sessionId={session.session_id} />
      </section>
    </Shell>
  );
}

function SessionExecutionPicker({
  endpointId,
  sessionId,
  reasoningEffort,
  onReasoningSelect,
}: {
  endpointId: string;
  sessionId: string;
  reasoningEffort: ReasoningEffort;
  onReasoningSelect: (value: ReasoningEffort) => void;
}) {
  useSignals();
  const session = appState.activeSession.value;
  const providers = appState.providers.value;
  const profiles = appState.profiles.value;
  const providerListError = appState.providerListError.value;
  const profileListError = appState.profileListErrors.value.get(session?.model?.provider ?? "");
  const modelGroups = useMemo(
    () => modelExecutionGroups(providers, profiles, endpointId),
    [providers, profiles, endpointId],
  );
  const executionDataUnavailable =
    appState.providersLoading.value || Boolean(providerListError) || Boolean(profileListError);
  const executionUnavailable =
    executionDataUnavailable ||
    appState.connection.value === "Reconnecting" ||
    appState.connection.value === "Disconnected";
  const currentProvider = providers.find(
    (provider) => provider.provider === session?.model?.provider,
  );
  const recoveryRequired =
    session !== null &&
    !appState.providersLoading.value &&
    sessionExecutionNeedsRecovery(
      session,
      endpointId,
      providers,
      profiles,
      providerListError,
      appState.profileListErrors.value.get(session.model?.provider ?? ""),
    );
  const recovery =
    recoveryRequired &&
    session !== null &&
    !isExecutionRecoveryAcknowledged(endpointId, sessionId, currentProvider);
  const selectedExecution = session?.model
    ? modelGroups
        .flatMap((group) => group.choices)
        .find((choice) =>
          executionChoiceMatches(
            choice,
            session.model?.provider,
            session.model?.model,
            session.model?.auth_profile_id,
          ),
        )
    : undefined;
  const mutationKey = useRef<string | null>(null);

  async function selectExecution(choice: ExecutionChoice) {
    if (!session || executionUnavailable) return;
    const isCurrentSelection = executionChoiceMatches(
      choice,
      session.model?.provider,
      session.model?.model,
      session.model?.auth_profile_id,
    );
    if (isCurrentSelection) {
      acknowledgeExecutionRecovery(endpointId, sessionId, choice.provider);
      appState.notice.value =
        "Session execution is already current. Existing history was preserved.";
      return;
    }
    const idempotencyKey = mutationKey.current ?? crypto.randomUUID();
    mutationKey.current = idempotencyKey;
    await withBusy(async () => {
      await selectSessionModel(
        endpointId,
        sessionId,
        { provider: choice.provider, model: choice.model, profile: choice.profile },
        idempotencyKey,
      );
      clearExecutionRecoveryAcknowledgement(endpointId, sessionId);
      await loadActiveSession();
      await refreshSessions(endpointId);
      appState.notice.value = "Execution updated. This session and its history were preserved.";
      mutationKey.current = null;
    });
  }

  return (
    <ModelExecutionMenu
      groups={modelGroups}
      profiles={profiles}
      selected={selectedExecution}
      modelLabel={recovery ? "Choose execution" : (session?.model?.model ?? "Choose model")}
      reasoningEffort={reasoningEffort}
      onReasoningSelect={onReasoningSelect}
      ariaLabel={recovery ? "Choose execution" : "Choose model"}
      title={recovery ? "Choose a current execution" : "Choose model"}
      recovery={recovery}
      disabled={executionUnavailable || appState.busy.value || !session}
      onSelect={selectExecution}
    />
  );
}

function SessionComposer({ endpointId, sessionId }: { endpointId: string; sessionId: string }) {
  useSignals();
  const [input, setInput] = useState(() => {
    const draft = appState.composerDraft.value;
    return draft?.endpointId === endpointId && draft.sessionId === sessionId ? draft.text : "";
  });
  // Visual-only until the public provider/session contract exposes reasoning effort.
  const [reasoningEffort, setReasoningEffort] = useState<ReasoningEffort>("high");
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const messageMutation = useRef<{ content: string; key: string } | null>(null);
  const busy = appState.busy.value;
  const endpoint = appState.endpoints.value.find((item) => item.endpoint_id === endpointId);
  const session = appState.activeSession.value;
  const sessionProviderListError = appState.providerListError.value;
  const sessionProfileListError = appState.profileListErrors.value.get(
    session?.model?.provider ?? "",
  );
  const executionUnavailableForSending =
    session === null ||
    appState.providersLoading.value ||
    (session !== null &&
      sessionExecutionUnavailableForSending(
        session,
        endpointId,
        appState.providers.value,
        appState.profiles.value,
        sessionProviderListError,
        sessionProfileListError,
      ));
  useEffect(() => {
    const draft = appState.composerDraft.value;
    setInput(draft?.endpointId === endpointId && draft.sessionId === sessionId ? draft.text : "");
  }, [endpointId, sessionId]);
  useEffect(() => {
    if (!inputRef.current) return;
    resizeComposerInput(inputRef.current, 180, 46);
    const frame = window.requestAnimationFrame(() => {
      const surface = document.querySelector<HTMLElement>(".main-surface");
      const runtime = surface?.querySelector<HTMLElement>(".runtime-activity");
      const composer = inputRef.current?.form;
      if (!surface || !runtime || !composer) return;
      const overlap = runtime.getBoundingClientRect().bottom - composer.getBoundingClientRect().top;
      if (overlap > 0) {
        const amount = overlap + 12;
        if (surface.scrollHeight > surface.clientHeight) {
          surface.scrollBy({ top: amount, behavior: "auto" });
        } else {
          window.scrollBy({ top: amount, behavior: "auto" });
        }
      }
    });
    return () => window.cancelAnimationFrame(frame);
  }, [input]);
  async function submit() {
    const content = input.trim();
    if (!content || busy || executionUnavailableForSending || appState.connection.value !== "Live")
      return;
    if (messageMutation.current && messageMutation.current.content !== content) {
      messageMutation.current = null;
    }
    const idempotencyKey = messageMutation.current?.key ?? crypto.randomUUID();
    messageMutation.current ??= { content, key: idempotencyKey };
    await withBusy(async () => {
      await sendMessage(endpointId, sessionId, content, idempotencyKey);
      const currentDraft = appState.composerDraft.value;
      if (
        currentDraft?.endpointId === endpointId &&
        currentDraft.sessionId === sessionId &&
        currentDraft.text === content
      ) {
        appState.composerDraft.value = null;
        setInput("");
      }
      if (messageMutation.current?.content === content) messageMutation.current = null;
      await loadActiveSession();
      await refreshSessions();
    });
  }
  return (
    <form
      className="composer"
      data-zode-composer="true"
      aria-label="Message composer"
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <textarea
        className="composer-input"
        ref={inputRef}
        rows={1}
        placeholder="Message"
        aria-label="Message"
        value={input}
        onChange={(event) => {
          const text = event.target.value;
          setInput(text);
          appState.composerDraft.value = text ? { endpointId, sessionId, text } : null;
        }}
        onKeyDown={(event) => {
          if (!event.nativeEvent.isComposing && event.key === "Enter" && !event.shiftKey) {
            event.preventDefault();
            event.currentTarget.form?.requestSubmit();
          }
        }}
      />
      <div className="composer-footer">
        <div className="composer-utility-bar">
          <span className="composer-context-readonly">
            <Icon name="desktop" />
            {endpoint?.kind === "local" ? "This machine" : endpoint?.label}
          </span>
          <SessionExecutionPicker
            endpointId={endpointId}
            sessionId={sessionId}
            reasoningEffort={reasoningEffort}
            onReasoningSelect={setReasoningEffort}
          />
        </div>
        <span className="sr-only" role="status" aria-live="polite">
          {appState.connection.value === "Live"
            ? "Connected to Endpoint"
            : appState.connection.value}
        </span>
        {busy ? (
          <span className="composer-hint" aria-live="polite">
            Submitting…
          </span>
        ) : null}
        <div className="composer-options">
          <button
            className="composer-submit"
            type="submit"
            aria-label="Send"
            title={
              executionUnavailableForSending
                ? "Choose an available execution before sending"
                : busy
                  ? "Sending"
                  : "Send"
            }
            disabled={
              busy || appState.connection.value !== "Live" || executionUnavailableForSending
            }
          >
            <Icon name="arrow-up" />
          </button>
        </div>
      </div>
    </form>
  );
}

function SettingsPage() {
  useSignals();
  const system = appState.system.value;
  return (
    <SettingsShell active="settings" title="Settings" subtitle="Safe deployment details">
      <section className="settings-content-page">
        <header className="settings-page-header">
          <div>
            <p>Safe information about this Zode deployment.</p>
          </div>
        </header>
        <section className="settings-section">
          <header className="settings-section-header">
            <div>
              <h2>Deployment</h2>
              <p>Management and local execution state.</p>
            </div>
          </header>
          <div className="settings-section-content">
            <dl className="facts">
              <Fact
                label="Mode"
                value={
                  system?.deployment === "all_in_one"
                    ? "All-in-one"
                    : system?.deployment === "server_only"
                      ? "Server only"
                      : "Unavailable"
                }
              />
              <Fact label="Management admission" value="Cloudflare Access" />
              <Fact
                label="Local Endpoint"
                value={system?.local_endpoint_id ? "Available" : "Not configured"}
              />
            </dl>
          </div>
        </section>
      </section>
    </SettingsShell>
  );
}

function Loading() {
  return (
    <Shell>
      <section className="bootstrap-state content-page" role="status" aria-live="polite">
        <Icon name="spinner-gap" />
        <div>
          <h1>Opening Zode</h1>
          <p>Reading the management Server.</p>
        </div>
      </section>
    </Shell>
  );
}

function BootstrapError() {
  return (
    <Shell>
      <section
        className="bootstrap-state bootstrap-state-error content-page"
        role="alert"
        aria-live="assertive"
      >
        <Icon name="warning" />
        <div>
          <h1>Unable to open Zode</h1>
          <p>{appState.bootstrapError.value}</p>
        </div>
        <ActionButton label="Retry" iconName="arrows-clockwise" onClick={() => void initialize()} />
      </section>
    </Shell>
  );
}

function NotFound() {
  return (
    <Shell title="Page not found">
      <section className="content-page">
        <EmptyState
          iconName="warning"
          title="This page does not exist"
          detail="Use an Endpoint group or the management menu to open a Zode resource."
        />
      </section>
    </Shell>
  );
}

function App() {
  useSignals();
  useEffect(() => {
    syncNavigationState();
    const onPopState = () => {
      if (window.matchMedia("(max-width: 760px)").matches) {
        appState.sidebarCollapsed.value = true;
      }
      syncNavigationState();
      void routeFromLocation().catch(showError);
    };
    window.addEventListener("popstate", onPopState);
    void initialize();
    return () => {
      window.removeEventListener("popstate", onPopState);
      closeEventStream();
    };
  }, []);
  const content = appState.bootstrapError.value ? (
    <BootstrapError />
  ) : !appState.system.value || !appState.bootstrapReady.value ? (
    <Loading />
  ) : appState.view.value === "providers" ? (
    <ProvidersPage />
  ) : appState.view.value === "endpoints" ? (
    <EndpointsPage />
  ) : appState.view.value === "settings" ? (
    <SettingsPage />
  ) : appState.view.value === "session" ? (
    <SessionPage />
  ) : appState.view.value === "not_found" ? (
    <NotFound />
  ) : (
    <HomePage />
  );
  return (
    <>
      <Global styles={globalStyles} />
      {content}
    </>
  );
}

async function refreshProviders() {
  appState.providersLoading.value = true;
  appState.providerListError.value = null;
  appState.profileListErrors.value = new Map();
  try {
    const providers = await listProviders();
    appState.providers.value = providers;
    clearRetryAction("providers");
    const errors = new Map<string, string>();
    const entries = await Promise.all(
      providers.map(async (provider) => {
        try {
          return [provider.provider, await listProfiles(provider.provider)] as const;
        } catch (error) {
          if (error instanceof ServerClientError && error.status === 401) throw error;
          errors.set(provider.provider, friendlyErrorCode(error));
          return [provider.provider, appState.profiles.value.get(provider.provider) ?? []] as const;
        }
      }),
    );
    appState.profiles.value = new Map(entries);
    appState.profileListErrors.value = errors;
    if (errors.size > 0) {
      appState.notice.value = "Some provider profiles are unavailable.";
      setRetryAction("profiles", () => void refreshProviders().catch(showError));
    } else {
      appState.notice.value = null;
      clearRetryAction("providers");
      clearRetryAction("profiles");
    }
  } catch (error) {
    appState.providerListError.value = friendlyErrorCode(error);
    appState.notice.value = friendlyErrorCode(error);
    if (error instanceof ServerClientError && error.retryable) {
      setRetryAction("providers", () => void refreshProviders().catch(showError));
    }
    throw error;
  } finally {
    appState.providersLoading.value = false;
  }
}

async function refreshProviderProfiles(providerName: string): Promise<void> {
  try {
    const profiles = await listProfiles(providerName);
    const nextProfiles = new Map(appState.profiles.value);
    nextProfiles.set(providerName, profiles);
    appState.profiles.value = nextProfiles;

    const nextErrors = new Map(appState.profileListErrors.value);
    nextErrors.delete(providerName);
    appState.profileListErrors.value = nextErrors;
    appState.notice.value = nextErrors.size > 0 ? "Some provider profiles are unavailable." : null;
    if (nextErrors.size > 0) {
      setRetryAction("profiles", () => void refreshProviderProfiles(providerName).catch(showError));
    } else {
      clearRetryAction("profiles");
    }
  } catch (error) {
    if (error instanceof ServerClientError && error.status === 401) throw error;
    const nextProfiles = new Map(appState.profiles.value);
    nextProfiles.set(providerName, nextProfiles.get(providerName) ?? []);
    appState.profiles.value = nextProfiles;

    const nextErrors = new Map(appState.profileListErrors.value);
    nextErrors.set(providerName, friendlyErrorCode(error));
    appState.profileListErrors.value = nextErrors;
    appState.notice.value = "Some provider profiles are unavailable.";
    setRetryAction("profiles", () => void refreshProviderProfiles(providerName).catch(showError));
  }
}

async function refreshSessions(endpointId?: string) {
  const endpointsToRefresh = appState.endpoints.value.filter(
    (endpoint) => endpointId === undefined || endpoint.endpoint_id === endpointId,
  );
  const requestedEndpointIds = new Set(endpointsToRefresh.map((endpoint) => endpoint.endpoint_id));
  const errors = new Map(appState.sessionListErrors.value);
  for (const requestedId of requestedEndpointIds) errors.delete(requestedId);
  const loadingCounts = new Map(appState.sessionLoadingByEndpoint.value);
  for (const requestedId of requestedEndpointIds) {
    loadingCounts.set(requestedId, (loadingCounts.get(requestedId) ?? 0) + 1);
  }
  appState.sessionLoadingByEndpoint.value = loadingCounts;
  appState.sessionsLoading.value = true;
  try {
    const entries = await Promise.all(
      endpointsToRefresh.map(async (endpoint) => {
        try {
          const items: SessionSummary[] = [];
          const cursors = new Set<string>();
          let cursor: string | undefined;
          while (true) {
            const page = await listSessions(endpoint.endpoint_id, cursor);
            items.push(...page.items);
            const next = page.next_cursor ?? undefined;
            if (!next || cursors.has(next)) break;
            cursors.add(next);
            cursor = next;
          }
          return [endpoint.endpoint_id, items] as const;
        } catch (error) {
          if (error instanceof ServerClientError && error.status === 401) throw error;
          errors.set(
            endpoint.endpoint_id,
            error instanceof ServerClientError ? error.code : "request_failed",
          );
          return [
            endpoint.endpoint_id,
            appState.sessions.value.get(endpoint.endpoint_id) ?? [],
          ] as const;
        }
      }),
    );
    const sessionMap = new Map(appState.sessions.value);
    for (const [id, items] of entries) sessionMap.set(id, items);
    appState.sessions.value = sessionMap;
    appState.sessionListErrors.value = errors;
    const preserveSessionRecovery =
      appState.view.value === "session" &&
      appState.activeSession.value !== null &&
      appState.connection.value !== "Live";
    if (!preserveSessionRecovery) {
      if (errors.size > 0) {
        appState.notice.value =
          errors.size === appState.endpoints.value.length
            ? "Endpoint sessions could not be loaded."
            : "Some sessions are unavailable.";
        setRetryAction("sessions", () => void refreshSessions(endpointId).catch(showError));
      } else if (!appState.endpointInventoryError.value) {
        clearRetryAction("sessions");
      }
    }

    const visible = appState.endpoints.value
      .flatMap((endpoint) =>
        (sessionMap.get(endpoint.endpoint_id) ?? []).map((session) => ({ endpoint, session })),
      )
      .sort((left, right) => {
        const time =
          (right.session.updated_at_ms ?? right.session.created_at_ms ?? 0) -
          (left.session.updated_at_ms ?? left.session.created_at_ms ?? 0);
        return time || right.session.session_id.localeCompare(left.session.session_id);
      })
      .slice(0, 20);
    const visibleKeys = new Set(
      visible.map(({ endpoint, session }) => sessionKey(endpoint.endpoint_id, session.session_id)),
    );
    const titleErrors = new Map(
      [...appState.sessionTitleErrors.value].filter(([key]) => visibleKeys.has(key)),
    );
    const titleTargets = visible.filter(
      ({ endpoint }) => endpointId === undefined || endpoint.endpoint_id === endpointId,
    );
    const titleEntries = await Promise.all(
      titleTargets.map(async ({ endpoint, session }) => {
        const key = sessionKey(endpoint.endpoint_id, session.session_id);
        const active = appState.activeSession.value;
        const detail =
          active?.session_id === session.session_id &&
          appState.activeEndpointId.value === endpoint.endpoint_id
            ? active
            : await getSession(endpoint.endpoint_id, session.session_id).catch((error) => {
                if (error instanceof ServerClientError && error.status === 401) throw error;
                titleErrors.set(key, friendlyErrorCode(error));
                return null;
              });
        const title = detail ? sessionTitle(detail, "") : "";
        if (title) titleErrors.delete(key);
        return title ? ([key, title] as const) : null;
      }),
    );
    const titles = new Map(
      [...appState.sessionTitles.value].filter(([key]) => visibleKeys.has(key)),
    );
    for (const entry of titleEntries) {
      if (entry) titles.set(entry[0], entry[1]);
    }
    appState.sessionTitles.value = titles;
    appState.sessionTitleErrors.value = titleErrors;
  } finally {
    const nextLoadingCounts = new Map(appState.sessionLoadingByEndpoint.value);
    for (const requestedId of requestedEndpointIds) {
      const count = (nextLoadingCounts.get(requestedId) ?? 1) - 1;
      if (count > 0) nextLoadingCounts.set(requestedId, count);
      else nextLoadingCounts.delete(requestedId);
    }
    appState.sessionLoadingByEndpoint.value = nextLoadingCounts;
    appState.sessionsLoading.value = nextLoadingCounts.size > 0;
  }
}

async function openSession(endpointId: string, sessionId: string) {
  const generation = ++navigationGeneration;
  const requestGeneration = ++activeSessionRequestGeneration;
  closeEventStream();
  appState.activeEndpointId.value = endpointId;
  appState.activeSessionId.value = sessionId;
  appState.activeSession.value = null;
  appState.view.value = "session";
  appState.notice.value = null;
  clearRetryAction("session");
  appState.sessionRetryAvailable.value = false;
  appState.sessionError.value = null;
  appState.sessionLoading.value = true;
  try {
    if (!appState.endpoints.value.some((endpoint) => endpoint.endpoint_id === endpointId)) {
      const endpoint = await getEndpoint(endpointId);
      appState.endpoints.value = [...appState.endpoints.value, endpoint];
      appState.endpointInventoryError.value = null;
    }
    const next = await getSession(endpointId, sessionId);
    if (
      generation !== navigationGeneration ||
      requestGeneration !== activeSessionRequestGeneration
    ) {
      return;
    }
    appState.activeSession.value = next;
    appState.sessionRetryAvailable.value = false;
    connectEventStream(endpointId, sessionId, generation);
  } catch (error) {
    if (
      generation === navigationGeneration &&
      requestGeneration === activeSessionRequestGeneration
    ) {
      appState.sessionError.value = friendlyErrorCode(error);
      appState.sessionRetryAvailable.value = error instanceof ServerClientError && error.retryable;
      if (appState.sessionRetryAvailable.value) {
        setRetryAction("session", () => void openSession(endpointId, sessionId).catch(showError));
      }
    }
    throw error;
  } finally {
    if (generation === navigationGeneration) appState.sessionLoading.value = false;
  }
}

async function reconnectSession(endpointId: string, sessionId: string) {
  await loadActiveSession();
  if (
    appState.activeEndpointId.value !== endpointId ||
    appState.activeSession.value?.session_id !== sessionId
  ) {
    return;
  }
  closeEventStream();
  connectEventStream(endpointId, sessionId, navigationGeneration);
}

async function loadActiveSession() {
  const endpointId = appState.activeEndpointId.value;
  const session = appState.activeSession.value;
  if (!endpointId || !session) return;
  const generation = navigationGeneration;
  const requestGeneration = ++activeSessionRequestGeneration;
  const sessionId = session.session_id;
  const next = await getSession(endpointId, sessionId);
  if (
    generation === navigationGeneration &&
    requestGeneration === activeSessionRequestGeneration &&
    appState.activeEndpointId.value === endpointId &&
    appState.activeSession.value?.session_id === sessionId
  ) {
    appState.activeSession.value = next;
  }
}

function closeEventStream() {
  eventStreamAbortController?.abort();
  eventStreamAbortController = null;
  eventStreamKey = null;
  if (eventStreamRetryTimer !== null) {
    window.clearTimeout(eventStreamRetryTimer);
    eventStreamRetryTimer = null;
  }
  appState.connection.value = "Disconnected";
  appState.provisionalAssistant.value = null;
}

function connectEventStream(endpointId: string, sessionId: string, generation: number) {
  const key = `${endpointId}:${sessionId}`;
  if (eventStreamKey === key && eventStreamAbortController) return;
  if (eventStreamKey !== key) eventStreamRetryAttempt = 0;
  closeEventStream();
  appState.connection.value = "Connecting";
  eventStreamKey = key;
  const controller = new AbortController();
  eventStreamAbortController = controller;
  void consumeEventStream(endpointId, sessionId, generation, key, controller);
}

function eventCursorStorageKey(key: string): string {
  return `zode.sse.cursor:${key}`;
}

function readEventCursor(key: string): string {
  const memoryCursor = eventStreamCursors.get(key);
  if (memoryCursor) return memoryCursor;
  try {
    const storedCursor = sessionStorage.getItem(eventCursorStorageKey(key)) ?? "";
    if (storedCursor) eventStreamCursors.set(key, storedCursor);
    return storedCursor;
  } catch {
    return "";
  }
}

function writeEventCursor(key: string, id: string): void {
  if (!id) return;
  eventStreamCursors.set(key, id);
  try {
    sessionStorage.setItem(eventCursorStorageKey(key), id);
  } catch {
    // A session-storage failure must not interrupt durable event delivery.
  }
}

function isCurrentEventStream(
  key: string,
  generation: number,
  controller: AbortController,
): boolean {
  return (
    eventStreamKey === key &&
    eventStreamAbortController === controller &&
    generation === navigationGeneration &&
    !controller.signal.aborted
  );
}

function handleEventStreamFrame(frame: string, key: string, sessionId: string): void {
  let eventName = "message";
  let eventId = "";
  const data: string[] = [];
  for (const line of frame.split(/\r?\n/)) {
    if (!line || line.startsWith(":")) continue;
    const separator = line.indexOf(":");
    const field = separator === -1 ? line : line.slice(0, separator);
    const value = separator === -1 ? "" : line.slice(separator + 1).replace(/^ /, "");
    if (field === "event") eventName = value;
    else if (field === "id") eventId = value;
    else if (field === "data") data.push(value);
  }
  if (eventName === "assistant_message_delta") {
    try {
      const payload = JSON.parse(data.join("\n")) as {
        schema?: string;
        session_id?: string;
        text?: string;
      };
      if (
        payload.schema !== "zode.transient-event.v1" ||
        payload.session_id !== sessionId ||
        typeof payload.text !== "string" ||
        payload.text.length === 0
      ) {
        return;
      }
      const previous = appState.provisionalAssistant.value;
      appState.provisionalAssistant.value = {
        sessionId,
        text: previous?.sessionId === sessionId ? previous.text + payload.text : payload.text,
      };
    } catch {
      appState.notice.value = "A transient model update could not be read.";
    }
    return;
  }
  if (eventId) writeEventCursor(key, eventId);
  if (data.length === 0 || !eventStreamKinds.has(eventName)) return;
  try {
    const payload = JSON.parse(data.join("\n")) as PublicEvent;
    if (payload.session_id !== sessionId) return;
    const message = payload.data?.message;
    const assistantMessageAppended =
      eventName === "message_appended" &&
      typeof message === "object" &&
      message !== null &&
      "role" in message &&
      (message as { role?: unknown }).role === "assistant";
    if (
      eventName === "assistant_message_committed" ||
      assistantMessageAppended ||
      eventName === "model_step_retrying" ||
      eventName === "model_attempt_failed" ||
      eventName === "model_attempt_interrupted" ||
      eventName === "model_attempts_exhausted" ||
      eventName === "activation_finished"
    ) {
      appState.provisionalAssistant.value = null;
    }
    void loadActiveSession().catch(showError);
  } catch {
    appState.notice.value = "A durable event could not be read.";
  }
}

async function readEventStream(
  body: ReadableStream<Uint8Array>,
  key: string,
  sessionId: string,
): Promise<void> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (true) {
      let timeoutHandle: number | undefined;
      const result = await Promise.race([
        reader.read(),
        new Promise<never>((_, reject) => {
          timeoutHandle = window.setTimeout(
            () => reject(new Error("session event stream idle timeout")),
            EVENT_STREAM_IDLE_TIMEOUT_MS,
          );
        }),
      ]).finally(() => {
        if (timeoutHandle !== undefined) window.clearTimeout(timeoutHandle);
      });
      if (result.done) break;
      buffer += decoder.decode(result.value, { stream: true });
      const frames = buffer.split(/\r?\n\r?\n/);
      buffer = frames.pop() ?? "";
      for (const frame of frames) handleEventStreamFrame(frame, key, sessionId);
    }
    buffer += decoder.decode();
    if (buffer.trim()) handleEventStreamFrame(buffer, key, sessionId);
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

function scheduleEventStreamReconnect(
  endpointId: string,
  sessionId: string,
  generation: number,
  key: string,
): void {
  if (eventStreamRetryTimer !== null) return;
  const delay = Math.min(1000 * 2 ** eventStreamRetryAttempt, 10_000);
  eventStreamRetryAttempt += 1;
  eventStreamRetryTimer = window.setTimeout(() => {
    eventStreamRetryTimer = null;
    if (eventStreamKey !== key || generation !== navigationGeneration) return;
    connectEventStream(endpointId, sessionId, generation);
  }, delay);
}

async function consumeEventStream(
  endpointId: string,
  sessionId: string,
  generation: number,
  key: string,
  controller: AbortController,
): Promise<void> {
  let reconnect = false;
  try {
    const cursor = readEventCursor(key);
    const headers: Record<string, string> = { Accept: "text/event-stream" };
    if (cursor) headers["Last-Event-ID"] = cursor;
    const response = await fetch(eventStreamUrl(endpointId, sessionId), {
      headers,
      credentials: "same-origin",
      cache: "no-store",
      signal: controller.signal,
    });
    if (response.status === 401) {
      showError(new ServerClientError("access_required", response.status));
      return;
    }
    if (response.status === 404) {
      let responseCode: string | null = null;
      try {
        const payload = (await response.clone().json()) as {
          error?: { code?: unknown };
        };
        responseCode = typeof payload.error?.code === "string" ? payload.error.code : null;
      } catch {
        // An unclassified 404 may be a transient proxy response.
      }
      const retryable = responseCode === null;
      if (isCurrentEventStream(key, generation, controller)) {
        appState.connection.value = "Disconnected";
        appState.sessionRetryAvailable.value = retryable;
        const code = responseCode ?? "session_stream_unavailable";
        appState.notice.value = friendlyError(code);
        appState.sessionError.value = friendlyError(code);
        if (retryable) {
          setRetryAction(
            "session-stream",
            () => void reconnectSession(endpointId, sessionId).catch(showError),
          );
        } else {
          clearRetryAction("session-stream");
        }
      }
      return;
    }
    if (!response.ok) {
      const retryable =
        response.status === 408 || response.status === 429 || response.status >= 500;
      let responseCode: string | null = null;
      try {
        const payload = (await response.clone().json()) as {
          error?: { code?: unknown };
        };
        responseCode = typeof payload.error?.code === "string" ? payload.error.code : null;
      } catch {
        // The status code remains the safe fallback when the proxy did not return JSON.
      }
      if (!retryable) {
        appState.connection.value = "Disconnected";
        appState.sessionRetryAvailable.value = false;
        appState.notice.value = friendlyError(responseCode ?? "session_stream_unavailable");
        appState.sessionError.value = friendlyError(responseCode ?? "session_stream_unavailable");
        return;
      }
      throw new ServerClientError(responseCode ?? `http_${response.status}`, response.status, true);
    }
    if (!response.body) {
      throw new ServerClientError("network_error", 0, true);
    }
    if (!isCurrentEventStream(key, generation, controller)) return;
    appState.connection.value = "Live";
    appState.sessionRetryAvailable.value = false;
    appState.sessionError.value = null;
    eventStreamRetryAttempt = 0;
    await readEventStream(response.body, key, sessionId);
    reconnect = true;
  } catch (error) {
    if (controller.signal.aborted || !isCurrentEventStream(key, generation, controller)) return;
    const code = error instanceof ServerClientError ? error.code : "network_error";
    appState.sessionRetryAvailable.value = true;
    appState.sessionError.value = null;
    if (error instanceof ServerClientError && error.code === "endpoint_unavailable") {
      appState.notice.value = friendlyError(code);
    }
    setRetryAction(
      "session-stream",
      () => void reconnectSession(endpointId, sessionId).catch(showError),
    );
    reconnect = true;
  } finally {
    if (eventStreamAbortController === controller) eventStreamAbortController = null;
  }
  if (reconnect && eventStreamKey === key && generation === navigationGeneration) {
    appState.connection.value = "Reconnecting";
    scheduleEventStreamReconnect(endpointId, sessionId, generation, key);
  }
}

async function routeFromLocation(loadData = true) {
  appState.homeEndpointSelection.value =
    location.pathname === "/" ? new URLSearchParams(location.search).get("endpoint") : null;
  const match = /^\/endpoints\/([^/]+)\/sessions\/([^/]+)$/.exec(location.pathname);
  if (match) {
    await openSession(decodeURIComponent(match[1]), decodeURIComponent(match[2]));
    return;
  }
  navigationGeneration += 1;
  activeSessionRequestGeneration += 1;
  closeEventStream();
  appState.activeSession.value = null;
  appState.activeEndpointId.value = null;
  appState.activeSessionId.value = null;
  appState.sessionError.value = null;
  appState.sessionRetryAvailable.value = false;
  appState.panel.value = null;
  appState.managementMenuOpen.value = false;
  appState.notice.value = null;
  clearRetryAction();
  if (location.pathname === "/endpoints") appState.view.value = "endpoints";
  else if (location.pathname === "/providers") appState.view.value = "providers";
  else if (location.pathname === "/settings") appState.view.value = "settings";
  else if (location.pathname === "/") appState.view.value = "sessions";
  else appState.view.value = "not_found";
  if (!loadData) return;
  if (appState.view.value === "providers") await refreshProviders();
  else if (appState.view.value === "sessions") await refreshSessions();
}

async function withBusy(operation: () => Promise<void>) {
  if (appState.busy.value) return;
  appState.busy.value = true;
  appState.notice.value = null;
  clearRetryAction("mutation");
  try {
    await operation();
  } catch (error) {
    showError(error);
    if (error instanceof ServerClientError && error.retryable) {
      setRetryAction("mutation", () => void withBusy(operation));
    }
  } finally {
    appState.busy.value = false;
  }
}

function showError(error: unknown) {
  if (error instanceof ServerClientError && error.status === 401) {
    if (accessReentryStarted) return;
    accessReentryStarted = true;
    closeEventStream();
    appState.activeSession.value = null;
    appState.system.value = null;
    window.location.assign(window.location.href);
    return;
  }
  appState.notice.value = friendlyErrorCode(error);
}

function friendlyErrorCode(error: unknown): string {
  const code = error instanceof ServerClientError ? error.code : "request_failed";
  return friendlyError(code);
}

function friendlyError(code: string) {
  if (/^http_5\d\d$/.test(code)) {
    return "The management Server is unavailable. Try again.";
  }
  const messages: Record<string, string> = {
    endpoint_unavailable:
      "The Endpoint is unavailable. Existing content is not an offline Server copy.",
    auth_replica_unavailable: "The selected profile is not installed on this Endpoint yet.",
    conflict:
      "This action conflicts with an earlier command. Review the current state and try again.",
    operation_conflict: "This action conflicts with an earlier management change.",
    network_error: "The Server could not be reached.",
    request_timeout: "The Server did not respond in time.",
    not_found: "The session could not be found on this Endpoint.",
    route_not_found: "The session event stream route is unavailable.",
    endpoint_unreachable: "The Endpoint is unreachable; its session state is not authoritative.",
    server_offline: "The management Server is offline.",
    capability_mismatch: "This Endpoint does not support the requested capability.",
    auth_profile_pending: "The selected auth profile is still being installed.",
    auth_profile_stale: "The selected auth profile is stale on this Endpoint.",
    provider_unavailable: "The provider is unavailable.",
    provider_auth_rejected: "The provider rejected the configured auth profile.",
    invalid_request: "Check the selected Endpoint, provider, model, and auth profile.",
    idempotency_conflict: "This action was already admitted with different values.",
    model_attempts_exhausted: "The model could not complete the requested activation.",
    tool_unknown_outcome:
      "Tool delivery has an unknown outcome; no safe action is currently available.",
    wait_timeout: "The session wait timed out.",
    session_stream_unavailable: "The session event stream is unavailable.",
  };
  return messages[code] ?? "The request could not be completed.";
}

async function initialize() {
  appState.bootstrapError.value = null;
  appState.bootstrapReady.value = false;
  appState.endpointInventoryError.value = null;
  appState.endpointsLoading.value = true;
  try {
    const system = await getSystem();
    appState.system.value = system;
    let endpointsError: string | null = null;
    try {
      appState.endpoints.value = await listEndpoints();
      appState.endpointInventoryError.value = null;
    } catch (error) {
      if (error instanceof ServerClientError && error.status === 401) {
        showError(error);
        return;
      }
      endpointsError = friendlyErrorCode(error);
      appState.endpointInventoryError.value = endpointsError;
    } finally {
      appState.endpointsLoading.value = false;
    }
    appState.providersLoading.value = true;
    appState.sessionsLoading.value = true;
    appState.bootstrapReady.value = true;
    appState.bootstrapError.value = null;
    await routeFromLocation(false).catch(showError);
    await Promise.all([refreshProviders().catch(showError), refreshSessions().catch(showError)]);
    if (endpointsError) {
      appState.notice.value = endpointsError;
      setRetryAction("bootstrap", () => void initialize());
    }
  } catch (error) {
    appState.endpointsLoading.value = false;
    appState.bootstrapReady.value = false;
    if (error instanceof ServerClientError && error.status === 401) showError(error);
    else appState.bootstrapError.value = friendlyErrorCode(error);
  }
}

createRoot(rootElement).render(<App />);
