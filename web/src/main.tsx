import "@phosphor-icons/web/regular";

import { Global } from "@emotion/react";
import { useSignals } from "@preact/signals-react/runtime";
import * as Dialog from "@radix-ui/react-dialog";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import * as Select from "@radix-ui/react-select";
import * as Slider from "@radix-ui/react-slider";
import { createContext, useEffect, useId, useRef, useState } from "react";
import { createRoot } from "react-dom/client";

import {
  application,
  type AuthProfile,
  type Endpoint,
  executionChoiceMatches,
  type ExecutionChoice,
  type ModelExecutionGroup,
  type OAuthAttempt,
  type Provider,
  type Session,
  type ToolCall,
  type TranscriptMessage,
  type View,
} from "./logic";
import { globalStyles } from "./styles";
import type { ElementType, FormEvent, MouseEvent, ReactNode, RefObject } from "react";

const rootElement = document.querySelector<HTMLDivElement>("#app");
if (!rootElement) throw new Error("application root is missing");

const viewPaths: Record<Exclude<View, "session" | "not_found">, string> = {
  sessions: "/",
  endpoints: "/endpoints",
  providers: "/providers",
  settings: "/settings",
};
const SidebarCollapsedContext = createContext(false);

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
  options: readonly SelectOption[];
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
  groups: readonly ModelExecutionGroup[];
  selected?: ExecutionChoice | null;
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
                        const profile = choice.profile.data.value;
                        const isSelected = executionChoiceMatches(
                          selected,
                          choice.provider.name,
                          choice.model,
                          profile.auth_profile_id,
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
                                const profile = choice.profile.data.value;
                                const isSelected = executionChoiceMatches(
                                  selected,
                                  choice.provider.name,
                                  choice.model,
                                  profile.auth_profile_id,
                                );
                                return (
                                  <DropdownMenu.Item
                                    className="model-menu-item"
                                    key={choice.key}
                                    data-zode-selected={String(isSelected)}
                                    onSelect={() => void onSelect(choice)}
                                  >
                                    <span>{choice.label}</span>
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

function Notice({ role }: { role?: "status" | "alert" } = {}) {
  useSignals();
  const value = application.notice.value;
  if (!value) return null;
  const resolvedRole = role ?? (application.noticeKind.value === "error" ? "alert" : "status");
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
    </div>
  );
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
    value.replaceAll("_", " ").replace(/\s+/g, " ").trim();
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

function navigate(path: string) {
  application.navigation.navigate(path);
}

function handleNavigation(event: MouseEvent<HTMLAnchorElement>, path: string) {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey)
    return;
  event.preventDefault();
  navigate(path);
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
  return `Tool call ${toolCallId}`;
}

function ToolActions({ tool }: { tool?: ToolCall }) {
  useSignals();
  if (!tool || tool.availableActions.value.length === 0) return null;
  const busy = tool.mutation.value === "submitting";
  return (
    <div className="tool-actions">
      {tool.availableActions.value.includes("cancel") ? (
        <button
          className="button button-quiet tool-action"
          type="button"
          aria-label="Cancel tool"
          disabled={busy}
          onClick={() => void tool.cancel().catch(() => undefined)}
        >
          <Icon name="x" />
          <span>Cancel</span>
        </button>
      ) : null}
      {tool.availableActions.value.includes("reconcile") ? (
        <button
          className="button button-quiet tool-action"
          type="button"
          aria-label="Reconcile tool outcome"
          disabled={busy}
          onClick={() => void tool.reconcileOutcome().catch(() => undefined)}
        >
          <Icon name="arrows-clockwise" />
          <span>Reconcile</span>
        </button>
      ) : null}
    </div>
  );
}

function ToolMessage({
  content,
  summary,
  status,
  toolCallId,
  tool,
}: {
  content: string;
  summary?: string;
  status?: string;
  toolCallId?: string;
  tool?: ToolCall;
}) {
  useSignals();
  const [expanded, setExpanded] = useState(false);
  const bodyId = `tool-activity-${useId().replaceAll(":", "")}`;
  const bodyRef = useRef<HTMLDivElement>(null);
  const label = tool?.name.value ?? toolIdentity(summary, toolCallId);
  const readableStatus = tool?.status.value ?? readableToolStatus(status);
  useEffect(() => {
    if (bodyRef.current) bodyRef.current.inert = !expanded;
  }, [expanded]);
  return (
    <div
      className="tool-disclosure"
      role="listitem"
      aria-label={`${label}${readableStatus ? `, ${readableStatus}` : ""}`}
      data-zode-tool-row="true"
      data-zode-tool-status={tool?.rawStatus.value ?? status}
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
      <ToolActions tool={tool} />
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

function transcriptRoleLabel(role: TranscriptMessage["role"]): string {
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

function InlineToolCalls({ message, session }: { message: TranscriptMessage; session: Session }) {
  if (!message.tool_calls || message.tool_calls.length === 0) return null;
  const durableToolMessageIds = new Set(
    (session.data.value?.transcript ?? [])
      .filter((candidate) => candidate.role === "tool" && candidate.tool_call_id)
      .map((candidate) => candidate.tool_call_id as string),
  );
  return (
    <div className="inline-tool-activity">
      {message.tool_calls
        .filter((call) => !durableToolMessageIds.has(call.tool_call_id))
        .map((call) => {
          const tool = session.toolCalls.value.find(
            (candidate) => candidate.id === call.tool_call_id,
          );
          const detail = tool?.description.value ?? "pending";
          return (
            <ToolMessage
              key={call.tool_call_id}
              content={detail}
              summary={call.tool_name}
              status={tool?.rawStatus.value}
              toolCallId={call.tool_call_id}
              tool={tool}
            />
          );
        })}
    </div>
  );
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
  view: Exclude<View, "session" | "not_found">;
  iconName: string;
}) {
  useSignals();
  const selected = application.navigation.route.value.view === view;
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

function ManagementContextItem({
  label,
  view,
  iconName,
}: {
  label: string;
  view: Exclude<View, "sessions" | "session" | "not_found">;
  iconName: string;
}) {
  return (
    <a
      className="nav-item is-selected management-context-item"
      data-zode-nav-row="true"
      data-zode-selected="true"
      data-zode-state="selected"
      href={viewPaths[view]}
      aria-current="page"
      onClick={(event) => handleNavigation(event, viewPaths[view])}
    >
      <Icon name={iconName} navIcon />
      <span>{label}</span>
    </a>
  );
}

function SidebarSectionTitle({ children }: { children: ReactNode }) {
  return (
    <div className="sidebar-section-title" data-zode-secondary-text="true">
      {children}
    </div>
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

function formatSessionRecency(timestampMs: number | undefined): string {
  if (!timestampMs || !Number.isFinite(timestampMs)) return "";
  const elapsed = Math.max(0, Date.now() - timestampMs);
  if (elapsed < 60_000) return "now";
  const minutes = Math.floor(elapsed / 60_000);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d`;
  return new Date(timestampMs).toLocaleDateString(undefined, { month: "numeric", day: "numeric" });
}

function SidebarSessionRow({ endpoint, session }: { endpoint: Endpoint; session: Session }) {
  useSignals();
  const summary = session.summary.value;
  const path = `/endpoints/${encodeURIComponent(endpoint.id)}/sessions/${encodeURIComponent(session.id)}`;
  const activeSession = application.activeSession.value;
  const selected = activeSession === session;
  const titleError = Boolean(session.error.value && !session.data.value);
  const title = titleError ? "Session details unavailable" : session.title.value;
  const accessibleName = session.sidebarAccessibleName.value;
  const stale = Boolean(endpoint.sessionsError.value);
  const statusState = stale ? "needs-resume" : sessionStatusState(summary.status);
  return (
    <a
      className={`sidebar-session-row${selected ? " is-selected" : ""}`}
      data-zode-nav-row="true"
      data-zode-selected={String(selected)}
      data-zode-state={selected ? "selected" : "idle"}
      data-zode-session-title-error={titleError ? "true" : undefined}
      data-zode-session-stale={stale ? "true" : undefined}
      aria-label={
        stale ? `${accessibleName}; cached while sessions are unavailable` : accessibleName
      }
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
          data-zode-session-status={summary.status.toLowerCase().replaceAll(" ", "-")}
          data-zode-session-state={statusState}
          aria-label={`Session status: ${summary.status}`}
          title={summary.status}
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
  const data = endpoint.data.value;
  return (
    <div className="sidebar-session-unavailable" role="status" aria-live="polite">
      <span className="sidebar-session-status sidebar-session-status-needs-resume">
        <Icon name="warning" className="sidebar-session-status-icon" />
      </span>
      <span className="sidebar-session-copy">
        <strong>{data.kind === "local" ? "This machine" : data.label}</strong>
        <span>Sessions unavailable</span>
      </span>
      <button
        className="sidebar-session-retry"
        type="button"
        aria-label={`Retry sessions for ${data.label}`}
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
  const recent = application.recentSessions.value;
  const endpoints = application.endpoints.value;
  const recentGroups = endpoints
    .map((endpoint) => ({
      endpoint,
      sessions: recent.filter((entry) => entry.endpoint === endpoint).map((entry) => entry.session),
    }))
    .filter((group) => group.sessions.length > 0);
  const recentLoading =
    application.endpointsState.value === "loading" || application.sessionsLoading.value;
  const endpointInventoryError = application.endpointError.value;
  const view = application.navigation.route.value.view;
  const newSessionSelected = view === "sessions";
  const [compact, setCompact] = useState(() => window.matchMedia("(max-width: 760px)").matches);
  const [collapsed, setCollapsed] = useState(compact);
  const [managementOpen, setManagementOpen] = useState(false);
  const appReady = application.ready.value && !application.bootstrapError.value;
  const collapseButtonRef = useRef<HTMLButtonElement>(null);
  const openButtonRef = useRef<HTMLButtonElement>(null);
  const managementTriggerRef = useRef<HTMLButtonElement>(null);
  const previousCollapsed = useRef(collapsed);
  const previousManagementOpen = useRef(managementOpen);
  const collapsedState = useRef(collapsed);
  const compactState = useRef(compact);
  const desktopCollapsePreference = useRef(compact ? false : collapsed);
  useEffect(() => {
    collapsedState.current = collapsed;
  }, [collapsed]);
  useEffect(() => {
    const mediaQuery = window.matchMedia("(max-width: 760px)");
    const handleViewportChange = () => {
      const nextCompact = mediaQuery.matches;
      if (nextCompact === compactState.current) return;
      if (nextCompact) {
        desktopCollapsePreference.current = collapsedState.current;
        setCollapsed(true);
      } else {
        setCollapsed(desktopCollapsePreference.current);
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
    <SidebarCollapsedContext.Provider value={collapsed}>
      <div className={`app-shell${collapsed ? " sidebar-collapsed" : ""}`} data-zode-shell="true">
        <aside className="sidebar" data-zode-shell-sidebar="true">
          <DropdownMenu.Root open={managementOpen} onOpenChange={setManagementOpen}>
            <div className="sidebar-toolbar">
              <IconButton
                label="Collapse sidebar"
                iconName="sidebar-simple"
                buttonRef={collapseButtonRef}
                onClick={() => setCollapsed(true)}
              />
              <IconButton
                label="Back"
                iconName="arrow-left"
                disabled={!application.navigation.canGoBack.value}
                onClick={() => application.navigation.back()}
              />
              <IconButton
                label="Forward"
                iconName="arrow-right"
                disabled={!application.navigation.canGoForward.value}
                onClick={() => application.navigation.forward()}
              />
            </div>
            {appReady ? (
              <DropdownMenu.Trigger asChild>
                <button
                  className="brand-button"
                  type="button"
                  aria-label="Zode"
                  title="Manage Zode"
                >
                  <span className="brand-name">Zode</span>
                  <Icon name="caret-down" />
                </button>
              </DropdownMenu.Trigger>
            ) : (
              <div className="brand-button" aria-label="Zode">
                <span className="brand-name">Zode</span>
              </div>
            )}
            {appReady ? (
              <>
                <nav className="primary-nav" aria-label="Primary">
                  <a
                    className={`new-session-button nav-item${newSessionSelected ? " is-selected" : ""}`}
                    data-zode-nav-row="true"
                    data-zode-selected={String(newSessionSelected)}
                    data-zode-state={newSessionSelected ? "selected" : "idle"}
                    href={viewPaths.sessions}
                    aria-current={newSessionSelected ? "page" : undefined}
                    onClick={(event) => {
                      handleNavigation(event, viewPaths.sessions);
                      queueMicrotask(() => document.getElementById("home-session-input")?.focus());
                    }}
                  >
                    <Icon name="note-pencil" navIcon />
                    <span>New session</span>
                  </a>
                </nav>
                {view === "endpoints" ? (
                  <div className="sidebar-management-context" aria-label="Current management page">
                    <ManagementContextItem label="Endpoints" view="endpoints" iconName="devices" />
                  </div>
                ) : view === "providers" ? (
                  <div className="sidebar-management-context" aria-label="Current management page">
                    <ManagementContextItem label="Providers" view="providers" iconName="key" />
                  </div>
                ) : view === "settings" ? (
                  <div className="sidebar-management-context" aria-label="Current management page">
                    <ManagementContextItem
                      label="Settings"
                      view="settings"
                      iconName="sliders-horizontal"
                    />
                  </div>
                ) : null}
                <div className="sidebar-recent">
                  {recentGroups.length > 0 ? (
                    recentGroups.map(({ endpoint, sessions }) => {
                      const headingId = `sidebar-environment-${endpoint.id.replaceAll(
                        /[^a-zA-Z0-9_-]/g,
                        "-",
                      )}`;
                      return (
                        <section
                          className="sidebar-environment-group"
                          aria-labelledby={headingId}
                          key={endpoint.id}
                        >
                          <div
                            className="sidebar-environment-heading"
                            id={headingId}
                            data-zode-secondary-text="true"
                          >
                            <Icon name="folder-simple" />
                            <span>{endpoint.environmentLabel.value}</span>
                          </div>
                          {sessions.map((session) => (
                            <SidebarSessionRow
                              key={`${endpoint.id}:${session.id}`}
                              endpoint={endpoint}
                              session={session}
                            />
                          ))}
                        </section>
                      );
                    })
                  ) : recentLoading ? (
                    <>
                      <SidebarSectionTitle>Recent</SidebarSectionTitle>
                      <p className="sidebar-empty" role="status">
                        Loading recent sessions…
                      </p>
                    </>
                  ) : endpoints.every((endpoint) => !endpoint.sessionsError.value) &&
                    !endpointInventoryError ? (
                    <>
                      <SidebarSectionTitle>Recent</SidebarSectionTitle>
                      <p className="sidebar-empty">No recent sessions</p>
                    </>
                  ) : endpointInventoryError ? (
                    <>
                      <SidebarSectionTitle>Recent</SidebarSectionTitle>
                      <p className="sidebar-empty sidebar-empty-error" role="status">
                        Endpoint inventory unavailable
                      </p>
                    </>
                  ) : null}
                  {endpoints
                    .filter((endpoint) => endpoint.sessionsError.value)
                    .map((endpoint) => (
                      <SidebarSessionUnavailableRow
                        key={`unavailable:${endpoint.id}`}
                        endpoint={endpoint}
                        onRetry={() => void endpoint.refreshSessions().catch(() => undefined)}
                      />
                    ))}
                </div>
              </>
            ) : null}
            <DropdownMenu.Portal>
              <DropdownMenu.Content
                className="management-menu"
                side="bottom"
                align="start"
                sideOffset={4}
              >
                <div className="management-menu-items">
                  <div className="management-menu-title">Manage</div>
                  <NavigationItem label="Endpoints" view="endpoints" iconName="devices" />
                  <NavigationItem label="Providers" view="providers" iconName="key" />
                  <NavigationItem label="Settings" view="settings" iconName="sliders-horizontal" />
                </div>
              </DropdownMenu.Content>
            </DropdownMenu.Portal>
          </DropdownMenu.Root>
        </aside>
        <main className="main-surface" aria-label="Main content" data-zode-shell-main="true">
          <header className="main-header" data-zode-shell-header="true">
            <div className="header-copy">
              {collapsed ? (
                <IconButton
                  label="Open sidebar"
                  iconName="sidebar-simple"
                  buttonRef={openButtonRef}
                  onClick={() => setCollapsed(false)}
                />
              ) : null}
              {headerIconName ? (
                <Icon name={headerIconName} className="header-context-icon" />
              ) : null}
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
    </SidebarCollapsedContext.Provider>
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
  const providers = application.providers.value;
  const [providerFormOpen, setProviderFormOpen] = useState(false);
  const [profilePanelProvider, setProfilePanelProvider] = useState<string | null>(null);
  const configureProviderButtonRef = useRef<HTMLButtonElement>(null);
  function closeProviderForm() {
    application.providerConfiguration.reset();
    setProviderFormOpen(false);
    queueMicrotask(() => {
      window.requestAnimationFrame(() => configureProviderButtonRef.current?.focus());
    });
  }
  const partialProfileFailure = providers.some((provider) => provider.error.value);
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
              application.clearNotice();
              application.providerConfiguration.reset();
              setProviderFormOpen(true);
            }}
          />
        </header>
        <Notice role={partialProfileFailure ? "status" : undefined} />
        {providerFormOpen ? <ProviderForm onClose={closeProviderForm} /> : null}
        {application.providersState.value === "loading" ? (
          <EmptyState
            iconName="spinner-gap"
            title="Loading providers"
            detail="Reading provider configuration from the management Server."
            role="status"
            state="loading"
          />
        ) : application.providerError.value ? (
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
          <ProviderCard
            key={provider.name}
            provider={provider}
            profilePanelOpen={profilePanelProvider === provider.name}
            onProfilePanelChange={(open) => {
              application.clearNotice();
              if (!open) provider.profileCreation.reset();
              setProfilePanelProvider(open ? provider.name : null);
            }}
          />
        ))}
      </section>
    </SettingsShell>
  );
}

function ProviderForm({ onClose }: { onClose: () => void }) {
  useSignals();
  const workflow = application.providerConfiguration;
  const busy = workflow.mutation.value === "submitting";
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      await workflow.submit();
      onClose();
    } catch {
      // The workflow retains the same command identity for an explicit retry.
    }
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
            value={workflow.provider.value}
            onChange={(value) => workflow.setProvider(value)}
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
            value={workflow.baseUrl.value}
            onChange={(value) => workflow.setBaseUrl(value)}
            required
          />
        </Field>
        <Field label="Models">
          <TextInput
            label="Models"
            placeholder="model-a, model-b"
            value={workflow.models.value}
            onChange={(value) => workflow.setModels(value)}
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

function ProviderCard({
  provider,
  profilePanelOpen,
  onProfilePanelChange,
}: {
  provider: Provider;
  profilePanelOpen: boolean;
  onProfilePanelChange: (open: boolean) => void;
}) {
  useSignals();
  const data = provider.data.value;
  const profiles = provider.profiles.value;
  const profileError = provider.error.value;
  const providerHeadingId = `provider-heading-${useId().replaceAll(":", "")}`;
  const profileEditorId = `profile-editor-${useId().replaceAll(":", "")}`;
  const profileEditorTitleId = `${profileEditorId}-title`;
  const oauthEditorId = `oauth-editor-${useId().replaceAll(":", "")}`;
  const oauthEditorTitleId = `${oauthEditorId}-title`;
  const addProfileButtonRef = useRef<HTMLButtonElement>(null);
  const addOAuthButtonRef = useRef<HTMLButtonElement>(null);
  const [oauthPanelOpen, setOauthPanelOpen] = useState(false);
  const oauthEnrollmentAvailable =
    provider.oauthAvailable.value &&
    !profiles.some((profile) => profile.data.value.refresh_state === "reauth_required");
  function closeProfileForm() {
    onProfilePanelChange(false);
    queueMicrotask(() => {
      window.requestAnimationFrame(() => addProfileButtonRef.current?.focus());
    });
  }
  function closeOAuthForm() {
    provider.oauthAttemptCreation.reset();
    setOauthPanelOpen(false);
    queueMicrotask(() => {
      window.requestAnimationFrame(() => addOAuthButtonRef.current?.focus());
    });
  }
  function openOAuthForm(profile?: AuthProfile) {
    onProfilePanelChange(false);
    if (profile) provider.oauthAttemptCreation.prepareReplacement(profile);
    else provider.oauthAttemptCreation.prepareNew();
    setOauthPanelOpen(true);
  }
  return (
    <article className="resource-card" aria-labelledby={providerHeadingId}>
      <div className="resource-heading">
        <div className="resource-heading-main">
          <Icon name="key" className="resource-heading-icon" />
          <div>
            <h2 id={providerHeadingId}>{provider.name}</h2>
            <p>{data.descriptor.base_url}</p>
          </div>
        </div>
        <StatusBadge value={data.auth_status} />
      </div>
      <dl className="facts">
        <Fact label="Adapter" value={data.descriptor.kind} />
        <Fact label="Revision" value={String(data.descriptor.revision)} />
        <Fact label="Models" value={data.descriptor.models.join(", ")} />
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
            setOauthPanelOpen(false);
            onProfilePanelChange(true);
          }}
        />
        {oauthEnrollmentAvailable ? (
          <ActionButton
            label="Add OAuth profile"
            iconName="sign-in"
            kind="quiet"
            buttonRef={addOAuthButtonRef}
            ariaExpanded={oauthPanelOpen}
            ariaControls={oauthEditorId}
            ariaDescribedBy={providerHeadingId}
            onClick={() => openOAuthForm()}
          />
        ) : null}
      </div>
      {profilePanelOpen ? (
        <ProfileForm
          provider={provider}
          id={profileEditorId}
          titleId={profileEditorTitleId}
          onClose={closeProfileForm}
        />
      ) : null}
      {oauthPanelOpen ? (
        <OAuthProfileForm
          provider={provider}
          id={oauthEditorId}
          titleId={oauthEditorTitleId}
          onClose={closeOAuthForm}
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
            disabled={provider.state.value === "loading"}
            onClick={() => void provider.refresh().catch(() => undefined)}
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
              key={profile.data.value.auth_profile_id}
              profile={profile}
              stale={Boolean(profileError)}
              onRelogin={() => openOAuthForm(profile)}
            />
          ))}
        </div>
      )}
      {provider.authAttempts.value.length > 0 ? (
        <div className="profile-list" aria-label="OAuth attempts">
          {provider.authAttempts.value.map((attempt) => (
            <OAuthAttemptRow key={attempt.id} attempt={attempt} />
          ))}
        </div>
      ) : null}
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
  const workflow = provider.profileCreation;
  const endpoints = application.endpoints.value;
  const busy = workflow.mutation.value === "submitting";
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      await workflow.submit();
      onClose();
    } catch {
      // A retry reuses the frozen command while the secret remains hidden.
    }
  }
  return (
    <form
      id={id}
      className="nested-editor"
      aria-labelledby={titleId}
      onSubmit={(event) => void submit(event)}
    >
      <h3 id={titleId}>
        Add API key profile<span className="sr-only"> for {provider.name}</span>
      </h3>
      <div className="form-grid">
        <Field label="Profile label">
          <TextInput
            label="Profile label"
            placeholder="Production key"
            value={workflow.label.value}
            onChange={(value) => workflow.setLabel(value)}
            required
          />
        </Field>
        <Field label="API key">
          <TextInput
            label="API key"
            type="password"
            value={workflow.apiKey.value}
            onChange={(value) => workflow.setApiKey(value)}
            required={workflow.mutation.value !== "unknown"}
          />
        </Field>
      </div>
      <label className="checkbox-row">
        <input
          type="checkbox"
          aria-label="Make this the default profile"
          checked={workflow.makeDefault.value}
          onChange={(event) => workflow.setMakeDefault(event.target.checked)}
        />
        <span>Make this the default profile</span>
      </label>
      <fieldset className="endpoint-choices">
        <legend>Share with Endpoints</legend>
        {endpoints.map((endpoint) => {
          const endpointData = endpoint.data.value;
          const labelText =
            endpointData.kind === "local"
              ? "Share with this machine"
              : `Share with ${endpointData.label}`;
          return (
            <label className="checkbox-row" key={endpoint.id}>
              <input
                type="checkbox"
                aria-label={labelText}
                checked={workflow.endpointIds.value.includes(endpoint.id)}
                onChange={(event) => workflow.setEndpoint(endpoint.id, event.target.checked)}
              />
              <span>{endpointData.kind === "local" ? "This machine" : endpointData.label}</span>
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

function OAuthProfileForm({
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
  const workflow = provider.oauthAttemptCreation;
  const endpoints = application.endpoints.value;
  const replacement = workflow.replacement.value;
  const busy = workflow.mutation.value === "submitting";
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      await workflow.submit();
      onClose();
    } catch {
      // The workflow retains the attempt and mutation identities for an explicit retry.
    }
  }
  return (
    <form
      id={id}
      className="nested-editor"
      aria-labelledby={titleId}
      onSubmit={(event) => void submit(event)}
    >
      <h3 id={titleId}>
        {replacement ? "Log in again" : "Add OAuth profile"}
        <span className="sr-only"> for {provider.name}</span>
      </h3>
      {replacement ? (
        <p>Replace credentials for this profile without changing its identity or sharing.</p>
      ) : null}
      <div className="form-grid">
        <Field label="Profile label">
          <TextInput
            label="Profile label"
            placeholder="Work account"
            value={workflow.label.value}
            onChange={(value) => workflow.setLabel(value)}
            required
          />
        </Field>
      </div>
      <label className="checkbox-row">
        <input
          type="checkbox"
          aria-label="Make this the default profile"
          checked={workflow.makeDefault.value}
          onChange={(event) => workflow.setMakeDefault(event.target.checked)}
        />
        <span>Make this the default profile</span>
      </label>
      <fieldset className="endpoint-choices">
        <legend>Share with Endpoints</legend>
        {endpoints.map((endpoint) => {
          const endpointData = endpoint.data.value;
          const labelText =
            endpointData.kind === "local"
              ? "Share with this machine"
              : `Share with ${endpointData.label}`;
          return (
            <label className="checkbox-row" key={endpoint.id}>
              <input
                type="checkbox"
                aria-label={labelText}
                checked={workflow.endpointIds.value.includes(endpoint.id)}
                onChange={(event) => workflow.setEndpoint(endpoint.id, event.target.checked)}
              />
              <span>{endpointData.kind === "local" ? "This machine" : endpointData.label}</span>
            </label>
          );
        })}
      </fieldset>
      <div className="panel-actions">
        <ActionButton label="Cancel" iconName="x" onClick={onClose} />
        <ActionButton
          label="Start OAuth"
          iconName="sign-in"
          type="submit"
          kind="primary"
          disabled={busy}
        />
      </div>
    </form>
  );
}

function OAuthAttemptRow({ attempt }: { attempt: OAuthAttempt }) {
  useSignals();
  const data = attempt.data.value;
  const busy = attempt.mutation.value === "submitting";
  const status =
    data.status === "succeeded"
      ? "OAuth success"
      : data.status === "cancelled"
        ? "OAuth cancelled"
        : data.status === "failed"
          ? "OAuth failed"
          : "OAuth authorization ready";
  return (
    <div className="profile-row">
      <div>
        <strong>{data.label}</strong>
        <span>{status}</span>
        {data.safe_code ? <span>{data.safe_code.replaceAll("_", " ")}</span> : null}
      </div>
      <StatusBadge value={data.status} />
      <div className="profile-actions">
        {data.allowed_actions.includes("authorize") ? (
          <ActionButton
            label="Continue to provider"
            iconName="arrow-square-out"
            kind="primary"
            onClick={() => void attempt.authorize().catch(() => undefined)}
            disabled={busy}
          />
        ) : null}
        {data.allowed_actions.includes("cancel") ? (
          <ActionButton
            label="Cancel OAuth"
            iconName="x"
            onClick={() => void attempt.cancel().catch(() => undefined)}
            disabled={busy}
          />
        ) : null}
      </div>
    </div>
  );
}

function ProfileRow({
  profile,
  stale,
  onRelogin,
}: {
  profile: AuthProfile;
  stale: boolean;
  onRelogin: () => void;
}) {
  useSignals();
  const data = profile.data.value;
  const refreshOperation = profile.refreshOperation.value;
  const refreshData = refreshOperation?.data.value;
  const reloginAvailable =
    data.allowed_actions.includes("relogin") ||
    refreshData?.allowed_actions.includes("relogin") === true;
  const endpoints = application.endpoints.value;
  const [rotationOpen, setRotationOpen] = useState(false);
  const [sharingOpen, setSharingOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const rotationButtonRef = useRef<HTMLButtonElement>(null);
  const sharingButtonRef = useRef<HTMLButtonElement>(null);
  const deleteButtonRef = useRef<HTMLButtonElement>(null);
  const targets = data.sharing.endpoint_ids
    .map((id) => application.endpoint(id)?.data.value.label ?? "Endpoint unavailable")
    .join(", ");
  const distribution = data.distribution
    .map((replica) => {
      const endpointLabel =
        application.endpoint(replica.endpoint_id)?.data.value.label ?? "Endpoint unavailable";
      return `${endpointLabel} · ${replica.status.replaceAll("_", " ")}`;
    })
    .join(", ");
  function closeDelete() {
    setDeleteOpen(false);
    profile.resetDelete();
    queueMicrotask(() => deleteButtonRef.current?.focus());
  }
  function closeRotation() {
    setRotationOpen(false);
    profile.apiKeyRotation.reset();
    queueMicrotask(() => rotationButtonRef.current?.focus());
  }
  function closeSharing() {
    setSharingOpen(false);
    profile.sharing.prepare();
    queueMicrotask(() => sharingButtonRef.current?.focus());
  }
  async function makeDefault() {
    await profile.setDefault().catch(() => undefined);
  }
  async function refreshCredential() {
    await profile.refreshCredential().catch(() => undefined);
  }
  async function replaceApiKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      await profile.apiKeyRotation.submit();
      closeRotation();
    } catch {
      // The frozen command and hidden secret remain available for an explicit retry.
    }
  }
  async function saveSharing(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      await profile.sharing.submit();
      closeSharing();
    } catch {
      // The workflow keeps the same command identity when delivery is unknown.
    }
  }
  async function confirmDelete() {
    try {
      await profile.delete();
      closeDelete();
    } catch {
      // The same deletion command remains available after explicit re-acknowledgement.
    }
  }
  return (
    <>
      <div className="profile-row">
        <div>
          <strong>{data.label}</strong>
          <span>{`${data.kind.replace("_", " ")} · revision ${data.revision}`}</span>
          {refreshData ? (
            <span role="status">
              {refreshData.status === "succeeded"
                ? "Credentials refreshed"
                : refreshData.status === "refresh_unknown"
                  ? "Relogin required — the provider may have consumed the previous refresh token"
                  : `Refresh ${refreshData.status.replaceAll("_", " ")}`}
            </span>
          ) : data.refresh_state === "reauth_required" ? (
            <span role="status">
              Relogin required — the provider may have consumed the previous refresh token
            </span>
          ) : null}
        </div>
        <span className="profile-default">
          {data.is_default ? "Default profile" : "Not default"}
        </span>
        <span className="profile-targets">
          {distribution || targets || "Not shared"}
          {stale ? <em className="profile-freshness">Cached while unavailable</em> : null}
        </span>
        <StatusBadge value={data.status} />
        <div className="profile-actions">
          {!data.is_default ? (
            <ActionButton
              label="Set as default"
              iconName="star"
              onClick={() => void makeDefault()}
              disabled={profile.mutation.value === "submitting" || stale}
            />
          ) : null}
          {data.allowed_actions.includes("refresh") ? (
            <ActionButton
              label="Refresh credentials"
              iconName="arrows-clockwise"
              onClick={() => void refreshCredential()}
              disabled={profile.refreshMutation.value === "submitting" || stale}
            />
          ) : null}
          {reloginAvailable ? (
            <ActionButton
              label="Log in again"
              iconName="sign-in"
              onClick={onRelogin}
              disabled={profile.mutation.value === "submitting" || stale}
            />
          ) : null}
          {data.kind === "api_key" ? (
            <ActionButton
              label="Rotate API key"
              iconName="key"
              buttonRef={rotationButtonRef}
              onClick={() => {
                profile.apiKeyRotation.reset();
                setRotationOpen(true);
              }}
              disabled={
                profile.apiKeyRotation.mutation.value === "submitting" ||
                data.status !== "ready" ||
                stale
              }
            />
          ) : null}
          <ActionButton
            label="Edit sharing"
            iconName="share-network"
            buttonRef={sharingButtonRef}
            onClick={() => {
              profile.sharing.prepare();
              setSharingOpen(true);
            }}
            disabled={profile.sharing.mutation.value === "submitting" || stale}
          />
          <ActionButton
            label="Delete profile"
            iconName="trash"
            kind="danger"
            buttonRef={deleteButtonRef}
            onClick={() => {
              profile.resetDelete();
              setDeleteOpen(true);
            }}
            disabled={profile.mutation.value === "submitting" || stale}
          />
        </div>
      </div>
      {rotationOpen ? (
        <form
          className="profile-delete-dialog"
          role="dialog"
          aria-modal="true"
          aria-label="Rotate API key"
          onSubmit={(event) => void replaceApiKey(event)}
        >
          <div className="panel-title">
            <div>
              <h3>Rotate API key</h3>
              <p>Replace credentials for this profile without changing its identity or sharing.</p>
            </div>
          </div>
          <Field label="New API key">
            <TextInput
              label="New API key"
              type="password"
              value={profile.apiKeyRotation.apiKey.value}
              onChange={(value) => profile.apiKeyRotation.setApiKey(value)}
              required={profile.apiKeyRotation.mutation.value !== "unknown"}
            />
          </Field>
          <div className="panel-actions">
            <ActionButton label="Cancel" iconName="x" onClick={closeRotation} />
            <ActionButton
              label="Save new API key"
              iconName="check"
              kind="primary"
              type="submit"
              disabled={profile.apiKeyRotation.mutation.value === "submitting"}
            />
          </div>
        </form>
      ) : null}
      {sharingOpen ? (
        <form
          className="profile-delete-dialog"
          role="dialog"
          aria-modal="true"
          aria-label="Edit sharing"
          onSubmit={(event) => void saveSharing(event)}
        >
          <div className="panel-title">
            <div>
              <h3>Edit sharing</h3>
              <p>Choose which Endpoints may receive this profile.</p>
            </div>
          </div>
          <fieldset className="endpoint-choices">
            <legend>Share with Endpoints</legend>
            {endpoints.map((endpoint) => {
              const endpointData = endpoint.data.value;
              const labelText =
                endpointData.kind === "local"
                  ? "Share with this machine"
                  : `Share with ${endpointData.label}`;
              return (
                <label className="checkbox-row" key={endpoint.id}>
                  <input
                    type="checkbox"
                    aria-label={labelText}
                    checked={profile.sharing.endpointIds.value.includes(endpoint.id)}
                    onChange={(event) =>
                      profile.sharing.setEndpoint(endpoint.id, event.target.checked)
                    }
                  />
                  <span>{endpointData.kind === "local" ? "This machine" : endpointData.label}</span>
                </label>
              );
            })}
          </fieldset>
          <div className="panel-actions">
            <ActionButton label="Cancel" iconName="x" onClick={closeSharing} />
            <ActionButton
              label="Save sharing"
              iconName="check"
              kind="primary"
              type="submit"
              disabled={
                !profile.sharing.dirty.value || profile.sharing.mutation.value === "submitting"
              }
            />
          </div>
        </form>
      ) : null}
      {deleteOpen ? (
        <div
          className="profile-delete-dialog"
          role="dialog"
          aria-modal="true"
          aria-label="Delete profile"
        >
          <div className="panel-title">
            <div>
              <h3>Delete profile</h3>
              <p>
                Removing the copied API key from an Endpoint is best-effort; provider-side
                revocation may require key rotation.
              </p>
            </div>
          </div>
          <label className="checkbox-row">
            <input
              type="checkbox"
              aria-label="I understand the revocation warning"
              checked={profile.deleteAcknowledged.value}
              onChange={(event) => profile.acknowledgeDelete(event.target.checked)}
            />
            <span>I understand that provider-side revocation may require key rotation.</span>
          </label>
          <div className="panel-actions">
            <ActionButton label="Cancel" iconName="x" onClick={closeDelete} />
            <ActionButton
              label="Delete profile permanently"
              iconName="trash"
              kind="danger"
              onClick={() => void confirmDelete()}
              disabled={
                !profile.deleteAcknowledged.value || profile.mutation.value === "submitting"
              }
            />
          </div>
        </div>
      ) : null}
    </>
  );
}

function EndpointsPage() {
  useSignals();
  const endpoints = application.endpoints.value;
  const [dialogOpen, setDialogOpen] = useState(false);
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
              application.clearNotice();
              application.endpointRegistration.reset();
              setDialogOpen(true);
            }}
          />
        </header>
        <Notice />
        <EndpointDialog open={dialogOpen} onClose={() => setDialogOpen(false)} />
        {application.endpointsState.value === "loading" ? (
          <EmptyState
            iconName="spinner-gap"
            title="Loading Endpoints"
            detail="Reading device inventory from the management Server."
            role="status"
            state="loading"
          />
        ) : application.endpointError.value ? (
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
          <EndpointCard key={endpoint.id} endpoint={endpoint} />
        ))}
      </section>
    </SettingsShell>
  );
}

function EndpointDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  useSignals();
  const workflow = application.endpointRegistration;
  const busy = workflow.mutation.value === "submitting";
  function close() {
    workflow.reset();
    onClose();
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      await workflow.submit();
      close();
    } catch {
      // An explicit retry reuses the same frozen registration command.
    }
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
              {workflow.progress.value ? (
                <p className="dialog-progress" role="status" aria-live="polite">
                  {workflow.progress.value}
                </p>
              ) : null}
              <div className="form-grid">
                <Field label="Endpoint label">
                  <TextInput
                    label="Endpoint label"
                    placeholder="Studio machine"
                    value={workflow.label.value}
                    onChange={(value) => workflow.setLabel(value)}
                    required
                  />
                </Field>
                <Field label="Endpoint URL">
                  <TextInput
                    label="Endpoint URL"
                    type="url"
                    placeholder="https://device.example"
                    value={workflow.baseUrl.value}
                    onChange={(value) => workflow.setBaseUrl(value)}
                    required
                  />
                </Field>
                <Field label="Controller credential">
                  <TextInput
                    label="Controller credential"
                    type="password"
                    value={workflow.controllerCredential.value}
                    onChange={(value) => workflow.setControllerCredential(value)}
                    required={workflow.mutation.value !== "unknown"}
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
  const data = endpoint.data.value;
  const endpointHeadingId = `endpoint-heading-${useId().replaceAll(":", "")}`;
  const endpointSessions = endpoint.sessions.value;
  const sessionListUnavailable = Boolean(endpoint.sessionsError.value);
  const sessionListLoading =
    endpoint.sessionsState.value === "loading" && endpointSessions.length === 0;
  const sessionCount =
    sessionListUnavailable || sessionListLoading ? undefined : endpointSessions.length;
  const installedProfiles = application.providers.value
    .flatMap((provider) => provider.profiles.value)
    .filter((profile) =>
      profile.data.value.distribution.some(
        (replica) => replica.endpoint_id === endpoint.id && replica.status === "ready",
      ),
    )
    .map((profile) => profile.data.value.label);
  return (
    <article className="resource-card" aria-labelledby={endpointHeadingId}>
      <div className="resource-heading">
        <div className="resource-heading-main">
          <Icon
            name={data.kind === "local" ? "desktop" : "globe"}
            className="resource-heading-icon"
          />
          <div>
            <h2 id={endpointHeadingId}>{data.label}</h2>
            <p>{data.kind === "local" ? "Built-in local Endpoint" : "Remote Endpoint"}</p>
          </div>
        </div>
        <StatusBadge value={data.status} />
      </div>
      <dl className="facts">
        <Fact label="Protocol" value={data.capabilities.protocol_version} />
        <Fact label="Providers" value={data.capabilities.providers.join(", ") || "None"} />
        <Fact label="Tools" value={data.capabilities.tools.join(", ") || "None"} />
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
            data.last_observed_at_ms
              ? new Date(data.last_observed_at_ms).toLocaleString()
              : "Unavailable"
          }
        />
        <Fact
          label="Auth replicas"
          value={`Ready ${data.auth_replica_summary.ready} · Pending ${data.auth_replica_summary.pending} · Stale ${data.auth_replica_summary.stale}`}
        />
        <Fact label="Installed profiles" value={installedProfiles.join(", ") || "None"} />
      </dl>
      <div className="endpoint-session-links">
        <span className="endpoint-session-links-label">Recent sessions</span>
        {sessionListUnavailable ? (
          <span className="endpoint-session-links-empty">Unavailable</span>
        ) : sessionListLoading ? (
          <span className="endpoint-session-links-empty" role="status">
            Loading…
          </span>
        ) : endpointSessions.length > 0 ? (
          endpointSessions.slice(0, 3).map((session) => {
            const titleError = Boolean(session.error.value && !session.data.value);
            const title = titleError ? "Session details unavailable" : session.title.value;
            const summary = session.summary.value;
            const path = `/endpoints/${encodeURIComponent(endpoint.id)}/sessions/${encodeURIComponent(session.id)}`;
            return (
              <a
                className="endpoint-session-link"
                data-zode-session-title-error={titleError ? "true" : undefined}
                href={path}
                key={session.id}
                onClick={(event) => handleNavigation(event, path)}
              >
                <span>{title}</span>
                <time
                  dateTime={new Date(summary.updated_at_ms ?? summary.created_at_ms).toISOString()}
                >
                  {formatSessionRecency(summary.updated_at_ms ?? summary.created_at_ms)}
                </time>
              </a>
            );
          })
        ) : (
          <span className="endpoint-session-links-empty">No sessions yet</span>
        )}
      </div>
      <div className="card-actions">
        <ActionButton
          label="Refresh Endpoint status"
          iconName="arrows-clockwise"
          ariaDescribedBy={endpointHeadingId}
          onClick={() => void endpoint.probe().catch(() => undefined)}
          disabled={endpoint.mutation.value === "submitting"}
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
  const workflow = application.newSession;
  const endpoints = application.endpoints.value;
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const endpointOptions = workflow.endpointOptions.value;
  const executionGroups = workflow.executionGroups.value;
  const selectedExecution = workflow.selectedExecution.value;
  const endpointId = workflow.currentEndpoint();
  const providerId = workflow.currentProvider();
  const modelId = workflow.currentModel();
  const profileId = workflow.currentProfile();
  const [reasoningEffort, setReasoningEffort] = useState<ReasoningEffort>("high");
  useEffect(() => {
    if (inputRef.current) resizeComposerInput(inputRef.current, 180, 44);
  }, [workflow.message.value]);
  const composerNeedsSetup = !workflow.ready.value;
  const setupHint = workflow.setupHint.value;
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (composerNeedsSetup) return;
    await workflow.submit().catch(() => undefined);
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
        tabIndex={0}
      >
        <textarea
          id="home-session-input"
          ref={inputRef}
          className="home-composer-input"
          rows={1}
          placeholder="Message"
          aria-label="New session message"
          aria-describedby={composerNeedsSetup ? "home-composer-empty" : undefined}
          value={workflow.message.value}
          onChange={(event) => workflow.setMessage(event.target.value)}
          onKeyDown={(event) => {
            if (!event.nativeEvent.isComposing && event.key === "Enter" && !event.shiftKey) {
              event.preventDefault();
              event.currentTarget.form?.requestSubmit();
            }
          }}
        />
        {composerNeedsSetup ? (
          <p id="home-composer-empty" className="home-composer-empty" role="status">
            {setupHint ?? "Session setup is unavailable."}
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
                onChange={(value) => workflow.setEndpoint(value)}
                disabled={endpoints.length === 0}
                placeholder="No environment available"
                className="select composer-select composer-environment-select"
              />
            </label>
            <ModelExecutionMenu
              groups={executionGroups}
              selected={selectedExecution}
              modelLabel={modelId || "Choose model"}
              reasoningEffort={reasoningEffort}
              onReasoningSelect={setReasoningEffort}
              ariaLabel="Choose model and reasoning"
              title="Choose model and reasoning"
              disabled={composerNeedsSetup || workflow.mutation.value === "submitting"}
              onSelect={(choice) => workflow.selectExecution(choice)}
            />
          </div>
          <button
            className="composer-submit"
            type="submit"
            aria-label="Start session"
            title="Start session"
            disabled={
              composerNeedsSetup ||
              workflow.mutation.value === "submitting" ||
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

function SessionPage() {
  useSignals();
  const route = application.navigation.route.value;
  const endpoint =
    application.activeEndpoint.value ??
    (route.endpointId ? application.endpoint(route.endpointId) : undefined);
  const session =
    application.activeSession.value ??
    (route.sessionId ? endpoint?.getSession(route.sessionId) : undefined);
  const snapshot = session?.data.value;
  if (!session || !endpoint || !snapshot) {
    const loading = !session || session.state.value === "idle" || session.state.value === "loading";
    return (
      <Shell title="Session">
        <section
          className="session-workspace"
          data-zode-thread-column="true"
          data-zode-session-state={loading ? undefined : "error"}
        >
          {loading ? (
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
                <p>{session?.error.value ?? "The Endpoint could not provide this session."}</p>
              </div>
              {route.endpointId && route.sessionId ? (
                <ActionButton
                  label="Retry"
                  iconName="arrows-clockwise"
                  onClick={() => void application.retryRoute()}
                />
              ) : null}
            </div>
          )}
        </section>
      </Shell>
    );
  }
  const endpointData = endpoint.data.value;
  const title = session.title.value;
  const state = session.visualState.value;
  const provisional = session.provisionalAssistant.value;
  return (
    <Shell title={title} headerIconName={endpointData.kind === "local" ? "desktop" : "globe"}>
      <section
        className="session-workspace"
        data-zode-thread-column="true"
        data-zode-session-state={state}
      >
        <Notice />
        <div
          className="session-identity"
          aria-label={`Endpoint ${session.environmentLabel.value}; provider ${snapshot.model?.provider ?? "unavailable"}; model ${session.modelLabel.value}; profile ${session.profileName.value}`}
          data-zode-session-identity="true"
        >
          <span>{session.environmentLabel.value}</span>
          <span aria-hidden="true">·</span>
          <span>{snapshot.model?.provider ?? "Provider unavailable"}</span>
          <span aria-hidden="true">·</span>
          <span>{session.modelLabel.value}</span>
          <span aria-hidden="true">·</span>
          <span>{session.profileName.value}</span>
        </div>
        <div className="sr-only" role="status" aria-live="polite" aria-atomic="true">
          {session.transcriptLength.value === 0
            ? "Session ready."
            : `${session.transcriptLength.value} messages. Latest from ${transcriptRoleLabel(snapshot.transcript.at(-1)?.role ?? "system")}.`}
        </div>
        <div className="transcript" aria-label="Conversation">
          {snapshot.transcript.length === 0 && !provisional ? (
            <div className="transcript-empty" role="status">
              <span>Ready when you are</span>
            </div>
          ) : null}
          {snapshot.transcript.map((message, index) => (
            <article
              className={`message message-${message.role}${
                index > 0 && snapshot.transcript[index - 1].role === message.role
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
                    ? session.toolCalls.value.find(
                        (candidate) => candidate.id === message.tool_call_id,
                      )
                    : undefined;
                  return (
                    <ToolMessage
                      content={message.content}
                      summary={tool?.name.value}
                      status={tool?.rawStatus.value}
                      toolCallId={message.tool_call_id ?? undefined}
                      tool={tool}
                    />
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
          {provisional ? (
            <article
              className="message message-assistant message-provisional"
              aria-label="Agent"
              aria-live="off"
              data-zode-provisional="true"
            >
              <MessageContent content={provisional} />
            </article>
          ) : null}
        </div>
        <RuntimeActivity session={session} />
        {session.connection.value !== "Live" ? (
          <div className="session-meta" data-zode-attention="true" role="status" aria-live="polite">
            <Icon name="wifi-slash" />
            <span>{session.connectionMessage.value}</span>
            {session.connection.value !== "Disconnected" || session.streamError.value ? (
              <button
                className="session-reconnect-button"
                type="button"
                onClick={() => session.toggleConnection()}
              >
                <Icon
                  name={
                    session.connection.value === "Connecting" ||
                    session.connection.value === "Reconnecting"
                      ? "stop"
                      : "arrows-clockwise"
                  }
                />
                <span>
                  {session.connection.value === "Connecting" ||
                  session.connection.value === "Reconnecting"
                    ? "Stop"
                    : "Reconnect"}
                </span>
              </button>
            ) : null}
          </div>
        ) : null}
        <SessionComposer session={session} />
      </section>
    </Shell>
  );
}

function RuntimeActivity({ session }: { session: Session }) {
  useSignals();
  const activityId = `runtime-activity-${useId().replaceAll(":", "")}`;
  const [open, setOpen] = useState(true);
  const lines = session.runtimeActivities.value;
  if (lines.length === 0) return null;
  return (
    <>
      <button
        className="activity-toggle"
        type="button"
        aria-controls={activityId}
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
      >
        <Icon name="pulse" />
        <span>Activity</span>
      </button>
      <aside
        id={activityId}
        className="runtime-activity"
        aria-label="Activity"
        data-zode-open={String(open)}
      >
        <div className="activity-list" role="list">
          {lines.map((line) => (
            <div
              className="status-line"
              role="listitem"
              aria-label={line.ariaLabel ?? `${line.title} ${line.detail}`}
              data-zode-attention={line.attention || line.title === "Waiting" ? "true" : undefined}
              key={line.key}
            >
              <Icon name={line.icon} />
              <div>
                <strong>{line.title}</strong>
                {line.alert ? (
                  <span role="alert" aria-live="assertive">
                    {line.detail}
                  </span>
                ) : (
                  <span role="status" aria-live="polite">
                    {line.detail}
                  </span>
                )}
              </div>
              <ToolActions tool={line.tool} />
            </div>
          ))}
        </div>
      </aside>
    </>
  );
}

function SessionExecutionMenu({
  session,
  reasoningEffort,
  onReasoningSelect,
}: {
  session: Session;
  reasoningEffort: ReasoningEffort;
  onReasoningSelect: (value: ReasoningEffort) => void;
}) {
  useSignals();
  const workflow = session.execution;
  const recovery = workflow.recoveryVisible.value;
  return (
    <ModelExecutionMenu
      groups={workflow.executionGroups.value}
      selected={workflow.selectedExecution.value}
      modelLabel={
        recovery ? "Choose execution" : (session.data.value?.model?.model ?? "Choose model")
      }
      reasoningEffort={reasoningEffort}
      onReasoningSelect={onReasoningSelect}
      ariaLabel={recovery ? "Choose execution" : "Choose model"}
      title={recovery ? "Choose a current execution" : "Choose model"}
      recovery={recovery}
      disabled={!workflow.interactionAvailable.value || workflow.mutation.value === "submitting"}
      onSelect={async (choice) => {
        workflow.selectExecution(choice);
        await workflow.apply().catch(() => undefined);
      }}
    />
  );
}

function SessionComposer({ session }: { session: Session }) {
  useSignals();
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const endpoint = session.endpoint.data.value;
  const busy = session.sendMutation.value === "submitting";
  const executionUnavailableForSending = session.executionUnavailableForSending.value;
  const [reasoningEffort, setReasoningEffort] = useState<ReasoningEffort>("high");
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
  }, [session.draft.value]);
  async function submit() {
    await session.send().catch(() => undefined);
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
        value={session.draft.value}
        onChange={(event) => session.setDraft(event.target.value)}
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
            {endpoint.kind === "local" ? "This machine" : endpoint.label}
          </span>
          <SessionExecutionMenu
            session={session}
            reasoningEffort={reasoningEffort}
            onReasoningSelect={setReasoningEffort}
          />
        </div>
        <span className="sr-only" role="status" aria-live="polite">
          {session.connection.value === "Live" ? "Connected to Endpoint" : session.connection.value}
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
            disabled={!session.canSend.value}
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
  const system = application.settings.data.value;
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
          <p>{application.bootstrapError.value}</p>
        </div>
        <ActionButton
          label="Retry"
          iconName="arrows-clockwise"
          onClick={() => void application.retryBootstrap()}
        />
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
  const view = application.navigation.route.value.view;
  const content = application.bootstrapError.value ? (
    <BootstrapError />
  ) : !application.settings.data.value || !application.ready.value ? (
    <Loading />
  ) : view === "providers" ? (
    <ProvidersPage />
  ) : view === "endpoints" ? (
    <EndpointsPage />
  ) : view === "settings" ? (
    <SettingsPage />
  ) : view === "session" ? (
    <SessionPage />
  ) : view === "not_found" ? (
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

createRoot(rootElement).render(<App />);
