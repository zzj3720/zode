import { css } from "@emotion/react";

export const globalStyles = css`
  :root {
    --zode-toolbar-height: 46px;
    --zode-sidebar-toolbar-height: 46px;
    --zode-sidebar-width: 275px;
    --zode-row-height: 30px;
    --zode-row-radius: 10px;
    --zode-sidebar: #27363b;
    --zode-selected-row: #38464b;
    --zode-button-secondary: rgba(255, 255, 255, 0.05);
    --zode-main: #181818;
    --zode-secondary-surface: #242424;
    --zode-composer: #2a2a2a;
    --zode-primary-text: #f5f6f6;
    --zode-secondary-text: #dfe1e1;
    --zode-muted-text: rgba(223, 225, 225, 0.72);
    --zode-subtle-text: rgba(223, 225, 225, 0.52);
    --zode-border: rgba(255, 255, 255, 0.08);
    --zode-border-heavy: rgba(255, 255, 255, 0.12);
    --zode-hover: rgba(255, 255, 255, 0.08);
    --zode-focus: rgba(51, 156, 255, 0.7);
    --zode-elevation-prominent:
      0 0 0 0.5px var(--zode-border-heavy), 0 3px 7.5px rgba(0, 0, 0, 0.04),
      0 0 20px rgba(0, 0, 0, 0.05);
    --zode-success: #40c977;
    --zode-attention: #f39c12;
    --zode-error: #ff6764;
    color: var(--zode-primary-text);
    background: var(--zode-main);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    font-size: 15px;
    line-height: 24px;
    font-synthesis: none;
    color-scheme: dark;
  }

  *,
  *::before,
  *::after {
    box-sizing: border-box;
  }

  html,
  body,
  #app {
    width: 100%;
    min-width: 320px;
    min-height: 100%;
    margin: 0;
  }

  body {
    min-height: 100vh;
    overflow: hidden;
    background: var(--zode-main);
  }

  button,
  a,
  input,
  select,
  textarea {
    font: inherit;
  }

  button,
  select {
    cursor: pointer;
  }

  button:focus-visible,
  a:focus-visible,
  select:focus-visible {
    outline: 2px solid var(--zode-focus);
    outline-offset: 1px;
  }

  input:focus-visible,
  textarea:focus-visible {
    outline: 2px solid var(--zode-focus);
    outline-offset: 1px;
  }

  .app-shell {
    display: grid;
    grid-template-columns: var(--zode-sidebar-width) minmax(0, 1fr);
    min-height: 100vh;
    background: var(--zode-main);
  }

  .sidebar {
    position: fixed;
    inset: 0 auto 0 0;
    z-index: 2;
    display: flex;
    width: var(--zode-sidebar-width);
    flex-direction: column;
    padding: 0;
    background: var(--zode-sidebar);
    color: var(--zode-secondary-text);
    transition:
      width 140ms ease,
      transform 140ms ease;
  }

  .sidebar::after {
    position: absolute;
    right: 0;
    bottom: 48px;
    left: 0;
    height: 1px;
    background: var(--zode-border-heavy);
    content: "";
    pointer-events: none;
  }

  .sidebar-content {
    display: flex;
    min-height: 0;
    flex: 1 1 auto;
    flex-direction: column;
    padding: 0;
    overflow: hidden;
  }

  .sidebar-toolbar {
    display: flex;
    height: var(--zode-sidebar-toolbar-height);
    min-height: var(--zode-sidebar-toolbar-height);
    align-items: center;
    gap: 4px;
    padding: 0 8px;
  }

  .icon-button {
    display: inline-flex;
    width: 28px;
    height: 28px;
    align-items: center;
    justify-content: center;
    padding: 0;
    border: 0;
    border-radius: 8px;
    color: var(--zode-secondary-text);
    background: transparent;
  }

  .icon-button:hover {
    color: var(--zode-primary-text);
    background: var(--zode-hover);
  }

  .icon-button:disabled {
    cursor: default;
    opacity: 0.42;
  }

  .icon-button i {
    font-size: 16px;
  }

  .brand {
    display: flex;
    height: 36px;
    align-items: center;
    gap: 4px;
    padding: 0 16px;
  }

  .brand-name {
    display: inline-flex;
    height: 32px;
    align-items: center;
    color: var(--zode-primary-text);
    font-size: 17px;
    font-weight: 500;
    line-height: 24px;
  }

  .brand-chevron {
    color: var(--zode-muted-text);
    font-size: 11px;
  }

  .primary-nav {
    display: grid;
    gap: 1px;
    margin-top: 8px;
    padding: 0 8px;
  }

  .new-session-button {
    width: 100%;
    min-height: var(--zode-row-height);
    height: var(--zode-row-height);
    justify-content: flex-start;
    padding: 5px 8px;
    border: 0;
    border-radius: var(--zode-row-radius);
    color: var(--zode-secondary-text);
    background: transparent;
    font-size: 14px;
    font-weight: 500;
    line-height: 20px;
  }

  .nav-item {
    display: flex;
    width: 100%;
    height: var(--zode-row-height);
    align-items: center;
    gap: 8px;
    padding: 5px 8px;
    border: 0;
    border-radius: var(--zode-row-radius);
    color: var(--zode-secondary-text);
    background: transparent;
    text-decoration: none;
    text-align: left;
    font-size: 14px;
    line-height: 20px;
  }

  .nav-item i {
    width: 16px;
    flex: 0 0 16px;
    font-size: 16px;
  }

  .nav-item:hover,
  .new-session-button:hover,
  .sidebar-session-row:hover,
  .sidebar-session-row:focus-visible {
    color: var(--zode-primary-text);
    background: var(--zode-hover);
  }

  .nav-item.is-selected,
  .sidebar-session-row.is-selected {
    color: var(--zode-primary-text);
    background: var(--zode-selected-row);
  }

  .sidebar-endpoint-groups {
    flex: 1 1 auto;
    min-height: 0;
    margin-top: 12px;
    padding: 0 8px 40px;
    overflow: auto;
    scrollbar-width: thin;
  }

  .sidebar-management-footer {
    display: flex;
    position: fixed;
    left: 8px;
    bottom: 8px;
    z-index: 3;
    height: 40px;
    width: calc(var(--zode-sidebar-width) - 16px);
    align-items: flex-end;
    margin: 0;
    padding: 0;
    pointer-events: none;
  }

  .sidebar-management-trigger {
    display: flex;
    width: 100%;
    height: var(--zode-row-height);
    min-height: var(--zode-row-height);
    align-items: center;
    gap: 8px;
    margin: 0;
    padding: 4px 8px;
    border: 0;
    border-radius: var(--zode-row-radius);
    color: var(--zode-muted-text);
    background: transparent;
    font-size: 15px;
    line-height: 24px;
    text-align: left;
    pointer-events: auto;
  }

  .sidebar-management-trigger:hover,
  .sidebar-management-trigger:focus-visible {
    color: var(--zode-primary-text);
  }

  .sidebar-management-trigger:hover {
    background: var(--zode-hover);
  }

  .sidebar-management-trigger > i:first-of-type {
    flex: 0 0 auto;
    font-size: 16px;
  }

  .sidebar-management-trigger > span {
    min-width: 0;
    flex: 1 1 auto;
  }

  .sidebar-environment-group + .sidebar-environment-group {
    margin-top: 10px;
  }

  .sidebar-environment-heading {
    display: flex;
    width: 100%;
    min-width: 0;
    min-height: 30px;
    align-items: center;
    gap: 8px;
    padding: 0 8px;
    border-radius: var(--zode-row-radius);
    color: var(--zode-muted-text);
    text-decoration: none;
    font-size: 14px;
    font-weight: 500;
    line-height: 20px;
  }

  .sidebar-environment-heading:hover,
  .sidebar-environment-heading:focus-visible {
    color: var(--zode-primary-text);
  }

  .sidebar-environment-heading > i {
    width: 16px;
    flex: 0 0 16px;
    color: var(--zode-subtle-text);
    font-size: 16px;
  }

  .sidebar-environment-heading > span {
    overflow: hidden;
    min-width: 0;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .sidebar-environment-group .sidebar-session-row {
    padding-left: 32px;
  }

  .sidebar-session-row {
    display: flex;
    min-width: 0;
    align-items: center;
    gap: 8px;
    min-height: var(--zode-row-height);
    height: var(--zode-row-height);
    padding: 0 8px;
    border-radius: var(--zode-row-radius);
    color: var(--zode-secondary-text);
    text-decoration: none;
    font-size: 14px;
  }

  .sidebar-session-copy {
    overflow: hidden;
    min-width: 0;
    flex: 1 1 auto;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 14px;
  }

  .sidebar-session-row[data-zode-session-title-error="true"] .sidebar-session-copy {
    color: var(--zode-error);
  }

  .sidebar-session-status {
    display: inline-flex;
    width: 16px;
    height: 16px;
    flex: 0 0 16px;
    align-items: center;
    justify-content: center;
    color: var(--zode-muted-text);
  }

  .sidebar-session-status-icon {
    color: var(--zode-muted-text);
    font-size: 12px;
  }

  .sidebar-session-status[data-zode-session-state="active"] .sidebar-session-status-icon {
    color: var(--zode-success);
    animation: zode-spin 1s linear infinite;
  }

  .sidebar-session-status[data-zode-session-state="needs-resume"] .sidebar-session-status-icon,
  .sidebar-session-status-needs-resume .sidebar-session-status-icon {
    color: var(--zode-error);
  }

  .sidebar-session-unavailable {
    display: flex;
    min-width: 0;
    min-height: 34px;
    align-items: center;
    gap: 8px;
    padding: 2px 8px;
    border-radius: 8px;
    color: var(--zode-muted-text);
    background: rgba(255, 103, 100, 0.06);
  }

  .sidebar-session-unavailable .sidebar-session-copy {
    display: flex;
    min-width: 0;
    flex-direction: column;
    font-size: 12px;
    line-height: 16px;
  }

  .sidebar-session-unavailable .sidebar-session-copy strong {
    overflow: hidden;
    color: var(--zode-secondary-text);
    font-size: 12px;
    font-weight: 500;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .sidebar-session-unavailable .sidebar-session-copy span {
    color: var(--zode-subtle-text);
    font-size: 11px;
  }

  .sidebar-session-retry {
    display: inline-flex;
    width: 24px;
    height: 24px;
    flex: 0 0 24px;
    align-items: center;
    justify-content: center;
    padding: 0;
    border: 0;
    border-radius: 7px;
    color: var(--zode-muted-text);
    background: transparent;
  }

  .sidebar-session-retry:hover,
  .sidebar-session-retry:focus-visible {
    color: var(--zode-primary-text);
    background: var(--zode-hover);
  }

  .status-line .ph-spinner-gap,
  .empty-state .ph-spinner-gap,
  .button .ph-spinner-gap {
    animation: zode-spin 1s linear infinite;
  }

  @keyframes zode-spin {
    to {
      transform: rotate(360deg);
    }
  }

  .sidebar-empty {
    margin: 4px 8px 0;
    color: var(--zode-subtle-text);
    font-size: 12px;
    line-height: 18px;
  }

  .sidebar-empty-error {
    color: var(--zode-error);
  }

  .management-menu {
    z-index: 5;
    width: 240px;
    padding: 6px;
    border: 1px solid var(--zode-border-heavy);
    border-radius: 12px;
    outline: 0;
    background: var(--zode-secondary-surface);
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.28);
    animation: menu-in 120ms ease-out;
  }

  .management-menu-items {
    display: grid;
    gap: 1px;
  }

  .management-menu-title {
    padding: 8px 10px 5px;
    color: var(--zode-muted-text);
    font-size: 12px;
  }

  .management-menu .nav-item {
    border-radius: 10px;
  }

  .model-menu-content {
    z-index: 20;
    width: 260px;
    min-width: 260px;
    max-width: min(260px, calc(100vw - 16px));
    padding: 5px;
    border: 1px solid var(--zode-border-heavy);
    border-radius: 10px;
    outline: 0;
    background: var(--zode-secondary-surface);
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.28);
  }

  .model-menu-subcontent {
    width: 260px;
    min-width: 260px;
  }

  .model-menu-model-subcontent {
    width: 280px;
    min-width: 280px;
    max-width: min(280px, calc(100vw - 16px));
  }

  .power-slider-container {
    display: flex;
    height: 32px;
    flex-direction: column;
    justify-content: center;
    margin: 0 2px;
    padding: 2px 6px;
    position: relative;
  }

  .power-slider-root {
    display: flex;
    width: 100%;
    height: 28px;
    align-items: center;
    position: relative;
    touch-action: none;
    outline: 0;
  }

  .power-slider-track {
    height: 24px;
    flex: 1 1 auto;
    overflow: hidden;
    border: 0;
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.1);
    box-shadow: inset 0 0 0 0.5px var(--zode-border);
    position: relative;
  }

  .power-slider-range {
    height: 100%;
    border-radius: 12px 0 0 12px;
    background: #339cff;
    position: absolute;
    inset: 0 auto 0 0;
  }

  .power-slider-ticks {
    position: absolute;
    inset: 0 14px;
    pointer-events: none;
  }

  .power-slider-tick {
    display: block;
    width: 4px;
    height: 4px;
    border-radius: 50%;
    background: rgba(255, 255, 255, 0.25);
    position: absolute;
    top: 50%;
    transform: translate(-50%, -50%);
  }

  .power-slider-tick[data-selected="true"] {
    background: rgba(255, 255, 255, 0.3);
  }

  .power-slider-thumb {
    display: block;
    width: 28px;
    height: 28px;
    border: 0.5px solid rgba(255, 255, 255, 0.16);
    border-radius: 50%;
    background: #fff;
    box-shadow: 0 0 2px rgba(0, 0, 0, 0.1);
    outline: 0;
    position: relative;
  }

  .power-slider-thumb:focus {
    outline: 0;
    box-shadow: none;
  }

  .power-slider-container[data-keyboard-focused="true"] .power-slider-thumb {
    outline: 2px solid var(--zode-focus);
    outline-offset: 0;
    box-shadow: none;
  }

  .power-view-controls {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 8px;
    min-height: 40px;
    padding: 0 8px;
    position: relative;
  }

  .power-view-controls[data-expanded="false"],
  .power-view-controls[data-expanded="true"] {
    min-height: 36px;
  }

  .power-view-controls[data-expanded="false"] .power-advanced-toggle {
    translate: 0 4px;
  }

  .power-view-controls[data-expanded="false"] .power-slider-endpoints {
    translate: 0 4px;
  }

  .power-slider-endpoints {
    display: flex;
    height: 32px;
    align-items: center;
    justify-content: space-between;
    padding: 0 8px;
    color: var(--zode-subtle-text);
    font-size: 14px;
    line-height: 20px;
    position: absolute;
    inset: 0;
    pointer-events: none;
    white-space: nowrap;
    opacity: 0;
    transition: opacity 120ms ease-out;
  }

  .power-slider-endpoints[data-visible="true"] {
    opacity: 1;
  }

  .power-view-controls .power-advanced-toggle {
    justify-content: flex-start;
    width: auto;
    min-height: 32px;
    gap: 4px;
    margin: 0 0 0 -8px;
    padding: 4px;
    border: 0;
    border-radius: 8px;
    color: var(--zode-muted-text);
    font-size: 14px;
    line-height: 20px;
    opacity: 1;
    transition: opacity 120ms ease-out;
  }

  .power-view-controls .power-advanced-toggle[data-visible="false"] {
    pointer-events: none;
    opacity: 0;
  }

  .power-advanced-toggle-content {
    display: flex;
    min-width: 0;
    align-items: center;
    gap: 4px;
    padding: 2px 4px;
    border-radius: 6px;
  }

  .power-advanced-toggle .advanced-toggle-icon {
    flex: 0 0 auto;
    color: var(--zode-muted-text);
    font-size: 12px;
    transition: transform 120ms ease-out;
  }

  .power-advanced-controls > .power-advanced-toggle {
    min-height: 32px;
    padding: 4px;
    border-radius: 8px;
    font-size: 14px;
    line-height: 20px;
  }

  .power-advanced-toggle.is-expanded .advanced-toggle-icon {
    transform: rotate(-90deg);
  }

  .power-advanced-controls {
    position: relative;
    padding-top: 4px;
  }

  .power-advanced-controls::before {
    position: absolute;
    inset: 0 6px auto;
    height: 1px;
    content: "";
    background: var(--zode-border);
  }

  .reasoning-menu-subcontent {
    width: 180px;
    min-width: 180px;
    max-width: min(180px, calc(100vw - 16px));
  }

  .model-menu-item {
    position: relative;
    display: flex;
    min-height: 32px;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 6px 9px;
    border-radius: 7px;
    color: var(--zode-primary-text);
    font-size: 13px;
    line-height: 20px;
    outline: 0;
    user-select: none;
  }

  .model-menu-item[data-highlighted] {
    color: var(--zode-primary-text);
    background: var(--zode-hover);
  }

  .model-menu-item[data-zode-selected="true"] {
    color: var(--zode-primary-text);
  }

  .model-menu-item > span {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .model-menu-item > i {
    flex: 0 0 auto;
    color: var(--zode-muted-text);
    font-size: 15px;
  }

  .model-menu-item[data-zode-selected="true"] > i {
    color: var(--zode-primary-text);
  }

  .intelligence-menu-row {
    gap: 12px;
  }

  .intelligence-menu-row > span:first-child {
    flex: 0 0 auto;
  }

  .intelligence-menu-row .intelligence-menu-value {
    min-width: 0;
    flex: 1 1 auto;
    color: var(--zode-muted-text);
    text-align: right;
  }

  .intelligence-menu-row > i {
    flex: 0 0 auto;
    color: var(--zode-muted-text);
    font-size: 13px;
  }

  .model-menu-subtrigger > i {
    color: var(--zode-muted-text);
    font-size: 13px;
  }

  @keyframes menu-in {
    from {
      opacity: 0;
      transform: translateY(-4px) scale(0.98);
    }
    to {
      opacity: 1;
      transform: translateY(0) scale(1);
    }
  }

  .settings-content-page {
    width: min(768px, calc(100% - 48px));
    margin: 0 auto;
    padding: 32px 0 64px;
  }

  .settings-page-header {
    display: flex;
    min-height: 55px;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 32px;
  }

  .settings-page-header > div {
    display: flex;
    min-width: 0;
    flex-direction: column;
    gap: 6px;
  }

  .settings-page-header h1 {
    margin: 0;
    color: var(--zode-primary-text);
    font-size: 24px;
    font-weight: 400;
    line-height: 29px;
  }

  .settings-page-header p,
  .settings-section-header p {
    margin: 0;
    color: var(--zode-muted-text);
    font-size: 14px;
    line-height: 20px;
  }

  .settings-section {
    margin-bottom: 40px;
  }

  .settings-section-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 12px;
  }

  .settings-section-header h2 {
    margin: 0;
    color: var(--zode-primary-text);
    font-size: 15px;
    font-weight: 500;
    line-height: 20px;
  }

  .settings-section-content {
    min-width: 0;
  }

  .settings-content-page > .resource-card {
    margin-bottom: 40px;
  }

  .settings-content-page > .resource-card .resource-heading {
    margin-bottom: 12px;
  }

  .settings-content-page > .resource-card .resource-heading h2 {
    font-size: 16px;
    font-weight: 500;
    line-height: 24px;
  }

  .resource-heading-main {
    display: flex;
    min-width: 0;
    align-items: flex-start;
    gap: 8px;
  }

  .resource-heading-icon {
    flex: 0 0 auto;
    margin-top: 3px;
    color: var(--zode-muted-text);
    font-size: 16px;
  }

  .settings-content-page > .resource-card .facts,
  .settings-section-content .facts {
    border-radius: 8px;
    background: var(--zode-secondary-surface);
  }

  .settings-content-page > .resource-card .fact-row,
  .settings-section-content .fact-row {
    min-height: 64px;
    padding: 12px;
  }

  .settings-content-page > .resource-card .resource-actions,
  .settings-content-page > .resource-card .card-actions {
    margin-top: 12px;
  }

  .settings-content-page .editor-panel {
    margin-bottom: 40px;
    border-radius: 8px;
  }

  .settings-content-page .profile-row {
    min-height: 64px;
    padding: 12px;
  }

  .main-surface {
    isolation: isolate;
    grid-column: 2;
    display: flex;
    position: relative;
    flex-direction: column;
    min-width: 0;
    min-height: 100vh;
    height: 100vh;
    overflow-y: auto;
    background: var(--zode-main);
  }

  .main-surface:has(> .session-workspace) {
    overflow: hidden;
  }

  .main-surface:has(> .session-workspace) > .session-workspace {
    display: flex;
    min-height: 0;
    flex: 1 1 auto;
    flex-direction: column;
    overflow: hidden;
  }

  .main-surface:has(> .session-workspace) > .session-workspace > .transcript {
    min-height: 0;
    flex: 1 1 auto;
    overflow-y: auto;
  }

  .main-header {
    position: sticky;
    top: 0;
    z-index: 1;
    display: flex;
    min-height: var(--zode-toolbar-height);
    height: var(--zode-toolbar-height);
    align-items: center;
    justify-content: space-between;
    padding: 0 16px;
    background: var(--zode-main);
  }

  .header-copy {
    display: flex;
    min-width: 0;
    align-items: baseline;
    gap: 10px;
  }

  .header-copy > .icon-button {
    flex: 0 0 auto;
    margin-right: 2px;
  }

  .header-context-icon {
    flex: 0 0 auto;
    align-self: center;
    color: var(--zode-secondary-text);
    font-size: 16px;
  }

  .header-copy h1 {
    overflow: hidden;
    margin: 0;
    color: var(--zode-primary-text);
    font-size: 15px;
    font-weight: 600;
    line-height: 20px;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .header-subtitle {
    overflow: hidden;
    margin: 0;
    color: var(--zode-muted-text);
    font-size: 12px;
    line-height: 18px;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .page-intro,
  .panel-title p,
  .resource-heading p,
  .profile-row span,
  .composer-hint,
  .status-line span {
    color: var(--zode-muted-text);
  }

  .content-page {
    width: min(768px, calc(100% - 48px));
    margin: 0 auto;
    padding: 32px 0 64px;
  }

  .page-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
    margin-bottom: 20px;
  }

  .page-intro {
    flex: 1 1 auto;
    max-width: 560px;
    margin: 0;
    line-height: 22px;
  }

  .button {
    display: inline-flex;
    min-height: 32px;
    align-items: center;
    justify-content: center;
    gap: 7px;
    padding: 0 12px;
    border: 1px solid var(--zode-border);
    border-radius: 8px;
    color: var(--zode-primary-text);
    background: var(--zode-secondary-surface);
    font-weight: 560;
    white-space: nowrap;
  }

  .button:hover {
    background: var(--zode-hover);
  }

  .button-primary {
    border-color: var(--zode-primary-text);
    color: var(--zode-main);
    background: var(--zode-primary-text);
  }

  .button-primary:hover {
    color: var(--zode-main);
    background: var(--zode-secondary-text);
  }

  .button-danger {
    border-color: rgba(255, 103, 100, 0.48);
    color: var(--zode-error);
  }

  .button:disabled,
  .composer-submit:disabled {
    cursor: not-allowed;
    opacity: 0.55;
  }

  .notice {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    margin: 0 0 16px;
    padding: 8px 8px 8px 12px;
    border: 1px solid var(--zode-border);
    border-inline-start: 3px solid var(--zode-border-heavy);
    border-radius: 16px;
    color: var(--zode-primary-text);
    background: var(--zode-secondary-surface);
    box-shadow: 0 1px 2px rgb(0 0 0 / 18%);
    font-size: 14px;
    line-height: 18px;
  }

  .notice > i {
    flex: 0 0 16px;
    margin-top: 1px;
    color: var(--zode-muted-text);
    font-size: 16px;
  }

  .notice-copy {
    display: flex;
    min-width: 0;
    flex: 1 1 auto;
    flex-direction: column;
    gap: 2px;
  }

  .notice-action {
    display: inline-flex;
    flex: 0 0 auto;
    align-items: center;
    gap: 5px;
    border: 0;
    border-radius: 7px;
    min-height: 28px;
    color: var(--zode-primary-text);
    background: var(--zode-button-secondary);
    font-size: 12px;
    line-height: 18px;
  }

  .notice-action {
    margin-left: auto;
    padding: 0 8px;
  }

  .notice-action:hover {
    background: rgba(255, 255, 255, 0.16);
  }

  .notice-alert {
    border-color: rgba(243, 156, 18, 0.28);
    border-inline-start-color: rgba(243, 156, 18, 0.72);
    background: rgba(243, 156, 18, 0.08);
  }

  .notice-alert > i {
    color: var(--zode-attention);
  }

  .inline-error {
    margin-top: 16px;
    margin-bottom: 0;
  }

  .editor-panel,
  .session-group {
    margin-bottom: 16px;
    border: 1px solid var(--zode-border);
    border-radius: 13px;
    background: var(--zode-secondary-surface);
  }

  .editor-panel {
    padding: 18px;
  }

  .resource-card {
    margin-bottom: 24px;
    background: transparent;
  }

  .panel-title,
  .resource-heading {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 16px;
  }

  .panel-title h2,
  .resource-heading h2,
  .resource-card > h2,
  .session-group h2,
  .nested-editor h3 {
    margin: 0;
    color: var(--zode-primary-text);
    font-size: 15px;
    font-weight: 620;
  }

  .panel-title p,
  .resource-heading p {
    margin: 4px 0 0;
    font-size: 14px;
  }

  .form-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px;
  }

  .field {
    display: grid;
    gap: 7px;
    min-width: 0;
  }

  .field-label,
  .endpoint-choices legend {
    color: var(--zode-primary-text);
    font-size: 13px;
    font-weight: 560;
  }

  .input,
  .select,
  .composer-input {
    width: 100%;
    border: 1px solid var(--zode-border);
    color: var(--zode-primary-text);
    background: var(--zode-composer);
  }

  .input,
  .select,
  .field-readonly {
    height: 38px;
    padding: 0 11px;
    border-radius: 8px;
  }

  .field-readonly {
    display: flex;
    align-items: center;
    overflow: hidden;
    border: 1px solid var(--zode-border);
    color: var(--zode-secondary-text);
    background: var(--zode-composer);
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .input::placeholder,
  .composer-input::placeholder {
    color: var(--zode-subtle-text);
  }

  .select {
    display: inline-flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    text-align: left;
  }

  .select > span:first-of-type {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .select > span:last-child {
    flex: 0 0 auto;
    color: var(--zode-muted-text);
  }

  .select-content {
    z-index: 20;
    min-width: var(--radix-select-trigger-width);
    overflow: hidden;
    padding: 5px;
    border: 1px solid var(--zode-border-heavy);
    border-radius: 10px;
    outline: 0;
    background: var(--zode-secondary-surface);
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.28);
  }

  .select-item {
    position: relative;
    display: flex;
    min-height: 30px;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 5px 8px;
    border-radius: 7px;
    color: var(--zode-primary-text);
    font-size: 13px;
    outline: 0;
    user-select: none;
  }

  .select-item[data-highlighted] {
    color: var(--zode-primary-text);
    background: var(--zode-hover);
  }

  .select-item[data-disabled] {
    pointer-events: none;
    opacity: 0.45;
  }

  .select-item > span:last-child {
    color: var(--zode-success);
  }

  .panel-actions,
  .resource-actions,
  .card-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 16px;
  }

  .facts {
    display: flex;
    flex-direction: column;
    overflow: hidden;
    margin: 0;
    border: 1px solid var(--zode-border);
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.02);
    font-size: 14px;
    line-height: 20px;
  }

  .fact-row {
    display: flex;
    min-height: 36px;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 8px 12px;
    border-top: 1px solid var(--zode-border);
  }

  .fact-row:first-of-type {
    border-top: 0;
  }

  .facts dt,
  .inline-empty,
  .empty-state,
  .session-row-id,
  .session-row-state {
    color: var(--zode-muted-text);
  }

  .facts dt {
    flex: 0 0 auto;
  }

  .facts dd {
    overflow-wrap: anywhere;
    margin: 0;
    max-width: 80%;
    color: var(--zode-primary-text);
    text-align: right;
  }

  .message-content ol {
    padding-left: 22px;
  }

  .message-content blockquote {
    margin: 0;
    padding-left: 14px;
    border-left: 2px solid var(--zode-border-heavy);
    color: var(--zode-muted-text);
  }

  .message-content hr {
    height: 1px;
    margin-right: 0;
    margin-left: 0;
    border: 0;
    background: var(--zode-border);
  }

  .message-table-container {
    max-width: 100%;
    overflow: hidden;
  }

  .message-table-scroller {
    max-width: 100%;
    overflow-x: auto;
    border: 1px solid var(--zode-border);
    border-radius: 10px;
  }

  .message-table-scroller:focus-visible,
  .message-content pre:focus-visible {
    outline: 2px solid var(--zode-focus);
    outline-offset: 2px;
  }

  .message-table-scroller table {
    min-width: 100%;
    border-collapse: collapse;
    font-size: 14px;
    line-height: 20px;
    text-align: left;
  }

  .message-table-scroller th,
  .message-table-scroller td {
    min-width: 112px;
    padding: 8px 10px;
    border-right: 1px solid var(--zode-border);
    border-bottom: 1px solid var(--zode-border);
    vertical-align: top;
  }

  .message-table-scroller th:last-child,
  .message-table-scroller td:last-child {
    border-right: 0;
  }

  .message-table-scroller tbody tr:last-child td {
    border-bottom: 0;
  }

  .message-table-scroller th {
    color: var(--zode-primary-text);
    background: rgba(255, 255, 255, 0.04);
    font-weight: 600;
  }

  .message-table-scroller td {
    color: var(--zode-secondary-text);
  }

  .profile-list {
    display: grid;
    gap: 0;
    overflow: hidden;
    margin-top: 16px;
    padding-top: 0;
    border: 1px solid var(--zode-border);
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.02);
  }

  .status-badge {
    display: inline-flex;
    min-height: 24px;
    flex: 0 0 auto;
    align-items: center;
    padding: 0 8px;
    border: 1px solid var(--zode-border);
    border-radius: 999px;
    color: var(--zode-muted-text);
    background: rgba(255, 255, 255, 0.06);
    font-size: 11px;
    font-weight: 600;
    text-transform: capitalize;
  }

  .status-ready,
  .status-online,
  .status-live {
    border-color: rgba(64, 201, 119, 0.34);
    color: var(--zode-success);
    background: rgba(64, 201, 119, 0.1);
  }

  .status-badge[data-zode-severity="pending"] {
    border-color: rgba(243, 156, 18, 0.42);
    color: var(--zode-attention);
    background: rgba(243, 156, 18, 0.1);
  }

  .status-badge[data-zode-severity="error"] {
    border-color: rgba(255, 103, 100, 0.42);
    color: var(--zode-error);
    background: rgba(255, 103, 100, 0.1);
  }

  .status-reconnecting,
  .status-pending,
  .status-waiting,
  .status-degraded,
  .status-warning {
    border-color: rgba(243, 156, 18, 0.42);
    color: var(--zode-attention);
    background: rgba(243, 156, 18, 0.1);
  }

  .profile-list[data-zode-stale="true"],
  .sidebar-session-row[data-zode-session-stale="true"] {
    border-color: rgba(243, 156, 18, 0.34);
  }

  .sidebar-session-row[data-zode-session-stale="true"] {
    background: rgba(243, 156, 18, 0.06);
  }

  .nested-editor {
    margin-top: 16px;
    padding: 16px;
    border: 1px solid var(--zode-border);
    border-radius: 10px;
    background: rgba(0, 0, 0, 0.12);
  }

  .nested-editor h3 {
    margin-bottom: 14px;
  }

  .endpoint-choices {
    display: grid;
    gap: 7px;
    margin: 14px 0 0;
    padding: 0;
    border: 0;
  }

  .endpoint-choices legend {
    margin-bottom: 7px;
  }

  .checkbox-row {
    display: flex;
    min-height: 32px;
    align-items: center;
    gap: 9px;
    color: var(--zode-secondary-text);
  }

  .checkbox-row input {
    width: 16px;
    height: 16px;
    accent-color: var(--zode-attention);
  }

  .profile-row {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(120px, auto) minmax(120px, auto) auto auto;
    align-items: center;
    gap: 14px;
    min-height: 44px;
    padding: 8px 12px;
    border-top: 1px solid var(--zode-border);
  }

  .profile-row:first-of-type {
    border-top: 0;
  }

  .profile-row > div {
    display: grid;
    gap: 3px;
  }

  .profile-row strong {
    color: var(--zode-primary-text);
    font-size: 13px;
  }

  .profile-row span {
    font-size: 12px;
  }

  .profile-actions {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 6px;
  }

  .profile-actions .button {
    min-height: 28px;
    padding: 0 8px;
    font-size: 11px;
  }

  .profile-delete-dialog {
    position: fixed;
    top: 50%;
    left: 50%;
    z-index: 10;
    width: min(460px, calc(100vw - 32px));
    max-height: calc(100dvh - 32px);
    overflow: auto;
    display: grid;
    gap: 14px;
    padding: 16px;
    border: 1px solid var(--zode-border-heavy);
    border-radius: 12px;
    outline: 0;
    background: var(--zode-secondary-surface);
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.28);
    transform: translate(-50%, -50%);
  }

  .profile-delete-dialog .panel-title {
    margin: 0;
  }

  .profile-delete-dialog .panel-title h3 {
    margin: 0;
    color: var(--zode-primary-text);
    font-size: 14px;
  }

  .profile-delete-dialog .panel-title p {
    max-width: 560px;
    margin: 5px 0 0;
    color: var(--zode-muted-text);
    font-size: 12px;
    line-height: 18px;
  }

  .profile-freshness {
    display: block;
    margin-top: 3px;
    color: var(--zode-attention);
    font-size: 11px;
    font-style: normal;
  }

  .inline-empty {
    margin: 16px 0 0;
    padding-top: 14px;
    border-top: 1px solid var(--zode-border);
    font-size: 13px;
  }

  .empty-state {
    display: flex;
    min-height: 62px;
    align-items: flex-start;
    gap: 10px;
    padding: 12px;
    border: 1px solid var(--zode-border);
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.02);
    text-align: left;
  }

  .empty-state > i {
    flex: 0 0 auto;
    margin-top: 2px;
    color: var(--zode-subtle-text);
    font-size: 16px;
  }

  .empty-state-copy {
    min-width: 0;
  }

  .empty-state h2 {
    margin: 0;
    color: var(--zode-primary-text);
    font-size: 14px;
    font-weight: 600;
    line-height: 20px;
  }

  .empty-state p {
    max-width: 420px;
    margin: 2px 0 0;
    line-height: 20px;
  }

  .empty-state-loading > i {
    color: var(--zode-attention);
  }

  .empty-state-error > i {
    color: var(--zode-attention);
  }

  .empty-state-error {
    border-color: rgba(243, 156, 18, 0.38);
    border-radius: 6px;
  }

  .session-error-state {
    display: flex;
    min-height: calc(100vh - var(--zode-toolbar-height));
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 16px;
    padding: 24px;
    text-align: center;
  }

  .session-error-state > i {
    color: var(--zode-attention);
    font-size: 24px;
  }

  .session-error-copy {
    display: flex;
    max-width: 520px;
    flex-direction: column;
    gap: 4px;
  }

  .session-error-copy h2 {
    margin: 0;
    color: var(--zode-primary-text);
    font-size: 15px;
    font-weight: 600;
    line-height: 20px;
  }

  .session-error-copy p {
    margin: 0;
    color: var(--zode-muted-text);
    font-size: 14px;
    line-height: 20px;
  }

  .bootstrap-state {
    display: flex;
    min-height: 220px;
    align-items: center;
    gap: 12px;
    color: var(--zode-muted-text);
  }

  .bootstrap-state-error {
    min-height: calc(100vh - var(--zode-toolbar-height));
    flex-direction: column;
    justify-content: center;
    gap: 16px;
    padding: 24px;
    text-align: center;
  }

  .bootstrap-state-error > div {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .bootstrap-state-error > i {
    font-size: 24px;
  }

  .bootstrap-state > i {
    flex: 0 0 auto;
    color: var(--zode-attention);
    font-size: 20px;
  }

  .bootstrap-state h1 {
    margin: 0;
    color: var(--zode-primary-text);
    font-size: 16px;
    font-weight: 600;
    line-height: 24px;
  }

  .bootstrap-state p {
    margin: 2px 0 0;
    color: var(--zode-muted-text);
    font-size: 14px;
  }

  .bootstrap-state .button {
    margin: 0;
  }

  .dialog-overlay {
    position: fixed;
    inset: 0;
    z-index: 9;
    background: rgba(0, 0, 0, 0.58);
  }

  .dialog-panel {
    position: fixed;
    top: 50%;
    left: 50%;
    z-index: 10;
    width: min(480px, 92vw);
    max-height: calc(100dvh - 32px);
    overflow: auto;
    transform: translate(-50%, -50%);
    outline: 0;
  }

  .dialog-panel .editor-panel {
    margin: 0;
    padding: 20px;
    border-radius: 16px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.28);
  }

  .home-page {
    display: flex;
    flex-direction: column;
    width: min(736px, calc(100% - 32px));
    min-height: calc(100vh - var(--zode-toolbar-height));
    margin: 0 auto;
    padding: 0 0 152px;
  }

  .home-intro {
    display: flex;
    min-height: calc((100vh - var(--zode-toolbar-height) + 24px) / 2);
    flex-direction: column;
    align-items: center;
    justify-content: flex-end;
    padding-top: 24px;
    padding-bottom: 48px;
    text-align: center;
  }

  .home-intro h1 {
    margin: 0;
    color: var(--zode-primary-text);
    font-size: 28px;
    font-weight: 400;
    line-height: 1.2;
  }

  .home-hero {
    position: relative;
    width: 100%;
    min-width: 0;
    text-align: center;
    user-select: none;
  }

  .home-hero-placeholder {
    visibility: hidden;
  }

  .home-hero > h1:not(.home-hero-placeholder) {
    position: absolute;
    right: 0;
    bottom: 0;
    left: 0;
    animation: home-hero-in 200ms ease-in-out both;
  }

  @keyframes home-hero-in {
    from {
      opacity: 0;
      transform: translateY(-4px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  .home-composer {
    position: fixed;
    right: max(16px, calc((100vw - var(--zode-sidebar-width) - 736px) / 2));
    bottom: 16px;
    z-index: 1;
    display: flex;
    width: min(736px, calc(100vw - var(--zode-sidebar-width) - 32px));
    flex-direction: column;
    overflow: visible;
  }

  .home-composer-context-bar {
    position: relative;
    z-index: 1;
    top: 0;
    display: flex;
    min-height: 36px;
    align-items: center;
    gap: 8px;
    margin: 0 12px;
    padding: 6px;
    border-radius: 16px 16px 0 0;
    color: var(--zode-muted-text);
    background: color-mix(in oklab, var(--zode-primary-text) 2.5%, transparent);
  }

  .home-composer-context-bar .composer-context-field {
    width: 100%;
  }

  .home-composer-context-bar .composer-select {
    width: auto;
    max-width: 224px;
    height: 24px;
    min-height: 24px;
    padding-inline: 6px;
    font-size: 14px;
    line-height: 20px;
  }

  .home-composer-context-bar .composer-select > i {
    flex: 0 0 auto;
    color: var(--zode-muted-text);
    font-size: 16px;
  }

  .home-composer-context-bar .composer-select > span:last-child {
    display: none;
  }

  .composer-context-field {
    display: inline-flex;
    min-width: 0;
    align-items: center;
    gap: 4px;
    color: var(--zode-muted-text);
  }

  .composer-context-readonly {
    display: inline-flex;
    min-width: 0;
    max-width: 220px;
    height: 20px;
    min-height: 20px;
    align-items: center;
    gap: 4px;
    overflow: hidden;
    padding: 0 6px;
    border: 0;
    border-radius: 9999px;
    color: var(--zode-muted-text);
    background: transparent;
    font-size: 14px;
    line-height: 18px;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .composer-context-readonly > i {
    flex: 0 0 auto;
    color: var(--zode-muted-text);
    font-size: 16px;
  }

  .composer-model-context {
    max-width: 420px;
    color: var(--zode-muted-text);
  }

  .composer-execution-trigger {
    display: inline-flex;
    min-width: 0;
    max-width: 192px;
    height: 28px;
    align-items: center;
    gap: 4px;
    overflow: hidden;
    padding: 0 8px;
    border: 0;
    border-radius: 9999px;
    color: var(--zode-muted-text);
    background: transparent;
    font-size: 14px;
    line-height: 18px;
    text-align: left;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .composer-execution-trigger-content {
    display: block;
    min-width: 0;
    flex: 1 1 auto;
    overflow: hidden;
    text-align: center;
    transition: inline-size 320ms cubic-bezier(0.23, 1, 0.32, 1);
  }

  .composer-execution-trigger-wrapper {
    display: flex;
    min-width: 0;
    align-items: center;
  }

  .composer-execution-trigger-label {
    display: inline-flex;
    position: relative;
    min-width: 0;
    max-width: 100%;
    align-items: center;
    gap: 4px;
  }

  .composer-execution-model {
    min-width: 0;
    max-width: 110px;
    flex: 0 1 auto;
    color: var(--zode-primary-text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .composer-execution-effort {
    flex: 0 0 auto;
    color: var(--zode-subtle-text);
    font-size: inherit;
  }

  .composer-execution-trigger > i {
    flex: 0 0 auto;
    color: currentColor;
    font-size: 13px;
  }

  .composer-execution-trigger:hover,
  .composer-execution-trigger:focus-visible,
  .composer-execution-trigger[data-state="open"] {
    color: var(--zode-primary-text);
    background: var(--zode-hover);
  }

  .composer-execution-trigger[data-zode-execution-state="needs-recovery"] {
    color: var(--zode-attention);
  }

  .composer-execution-trigger[data-zode-execution-state="needs-recovery"]:hover,
  .composer-execution-trigger[data-zode-execution-state="needs-recovery"]:focus-visible,
  .composer-execution-trigger[data-zode-execution-state="needs-recovery"][data-state="open"] {
    color: var(--zode-primary-text);
    background: rgba(243, 156, 18, 0.14);
  }

  .composer-execution-trigger:disabled {
    cursor: not-allowed;
    opacity: 0.55;
  }

  .composer-context-readonly:focus-visible,
  .composer-execution-trigger:focus-visible,
  .composer-select:focus-visible,
  .composer-submit:focus-visible {
    outline: 0;
    outline-offset: 0;
  }

  .composer-context-field > i {
    flex: 0 0 auto;
    font-size: 16px;
  }

  .composer-select {
    min-width: 0;
    max-width: 224px;
    height: 20px;
    padding: 0 6px;
    border: 0;
    border-radius: 9999px;
    color: var(--zode-muted-text);
    background: transparent;
    font-size: 13px;
    font-weight: 400;
    line-height: 18px;
    outline: 0;
  }

  .composer-select:hover {
    color: var(--zode-primary-text);
    background: var(--zode-hover);
  }

  .composer-select[data-state="open"] {
    color: var(--zode-primary-text);
    background: var(--zode-hover);
  }

  .composer-select > span:last-child {
    display: inline-flex;
    flex: 0 0 auto;
    color: var(--zode-subtle-text);
  }

  .composer-context-field .composer-select {
    max-width: 224px;
  }

  .composer-utility-bar {
    display: flex;
    min-width: 0;
    align-items: center;
    gap: 4px;
  }

  .reasoning-menu-label {
    display: block;
    padding: 5px 9px 4px;
    color: var(--zode-muted-text);
    font-size: 12px;
    line-height: 18px;
  }

  .reasoning-menu-item {
    min-height: 30px;
  }

  .composer-environment-select {
    max-width: 192px;
  }

  .composer-model-select {
    max-width: 192px;
  }

  .composer-context-field .composer-model-select {
    max-width: 192px;
  }

  .composer-profile-select {
    max-width: 224px;
  }

  .composer-select:disabled {
    cursor: default;
    color: var(--zode-subtle-text);
  }

  .home-composer-body {
    position: relative;
    z-index: 1;
    display: flex;
    width: 100%;
    height: auto;
    flex-direction: column;
    min-height: 99px;
    padding: 14px 0 8px;
    border: 0;
    border-radius: 20px;
    background: var(--zode-composer);
    box-shadow: var(--zode-elevation-prominent);
  }

  .home-composer-input {
    width: 100%;
    flex: 1 1 auto;
    min-height: 44px;
    max-height: 180px;
    overflow-y: hidden;
    resize: none;
    padding: 0 16px;
    border: 0;
    color: var(--zode-primary-text);
    background: transparent;
    font-size: 16px;
    line-height: 24px;
    outline: 0;
  }

  .home-composer-input:focus-visible,
  .composer-input:focus-visible {
    outline: 0;
  }

  .home-composer-input::placeholder {
    color: var(--zode-subtle-text);
  }

  .home-composer-empty {
    flex: 0 0 auto;
    margin: 0;
    overflow: hidden;
    color: var(--zode-subtle-text);
    font-size: 11px;
    line-height: 18px;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .home-composer-footer {
    display: grid;
    flex: 0 0 28px;
    height: 28px;
    min-height: 28px;
    container: composer-footer / inline-size;
    align-items: center;
    grid-template-columns: minmax(0, 1fr) auto auto;
    column-gap: 5px;
    margin: 0;
    padding-inline: 12px;
  }

  .composer-options {
    display: flex;
    min-width: 0;
    flex: 0 0 auto;
    align-items: center;
    gap: 8px;
    margin-left: 0;
  }

  .home-composer-footer > .composer-utility-bar {
    grid-column: 2;
    min-width: 0;
    align-items: center;
    justify-self: end;
    overflow-x: auto;
    scrollbar-width: none;
  }

  .home-composer-footer > .composer-utility-bar::-webkit-scrollbar {
    display: none;
  }

  .home-composer-footer > .composer-submit {
    grid-column: 3;
    justify-self: end;
  }

  .composer-submit {
    display: inline-flex;
    width: 28px;
    height: 28px;
    flex: 0 0 28px;
    align-items: center;
    justify-content: center;
    padding: 2px;
    border: 0;
    border-radius: 9999px;
    color: var(--zode-main);
    background: var(--zode-primary-text);
  }

  .composer-submit:hover {
    color: var(--zode-main);
    background: var(--zode-secondary-text);
  }

  .composer-submit i {
    font-size: 16px;
  }

  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    clip-path: inset(50%);
    white-space: nowrap;
  }

  .session-workspace {
    position: relative;
    width: min(736px, calc(100% - 32px));
    min-height: calc(100vh - var(--zode-toolbar-height));
    margin: 0 auto;
    padding: 18px 0 260px;
  }

  .session-meta {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 7px;
    min-height: 24px;
    padding: 4px 16px 8px;
    color: var(--zode-muted-text);
    font-size: 14px;
  }

  .session-reconnect-button {
    display: inline-flex;
    min-height: 24px;
    align-items: center;
    gap: 5px;
    margin-left: 4px;
    padding: 0 8px;
    border: 1px solid rgba(243, 156, 18, 0.38);
    border-radius: 7px;
    color: var(--zode-primary-text);
    background: transparent;
    font-size: 12px;
    line-height: 20px;
  }

  .session-reconnect-button:hover {
    background: rgba(243, 156, 18, 0.12);
  }

  .session-reconnect-button:disabled {
    cursor: not-allowed;
    opacity: 0.55;
  }

  .transcript {
    display: flex;
    flex-direction: column;
    gap: 16px;
    padding: 24px 0;
  }

  .transcript-empty {
    display: flex;
    min-height: 180px;
    align-items: center;
    justify-content: center;
    color: var(--zode-subtle-text);
    font-size: 14px;
    line-height: 20px;
  }

  .message {
    min-width: 0;
    max-width: 100%;
    color: var(--zode-primary-text);
    font-size: 15px;
    line-height: 24px;
  }

  .message-user {
    display: flex;
    align-self: flex-end;
    width: fit-content;
    max-width: 100%;
    align-items: center;
    gap: 8px;
    padding: 6px 12px;
    border: 1px solid rgb(255 255 255 / 12%);
    border-radius: 24px;
    background: var(--zode-secondary-surface);
  }

  .message.is-grouped {
    margin-top: -12px;
  }

  .message-assistant {
    max-width: 100%;
    padding: 0 2px;
  }

  .message-tool {
    max-width: 100%;
    padding: 0 2px;
  }

  .tool-disclosure {
    display: flex;
    min-width: 0;
    flex-direction: column;
    color: var(--zode-muted-text);
  }

  .inline-tool-activity {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-top: 8px;
  }

  .inline-tool-activity.is-standalone {
    margin-top: 0;
  }

  .inline-tool-activity .tool-disclosure {
    position: relative;
  }

  .tool-disclosure-header {
    display: inline-flex;
    width: fit-content;
    max-width: 100%;
    min-width: 0;
    min-height: 28px;
    align-items: center;
    gap: 6px;
    align-self: flex-start;
    padding: 2px 4px;
    border: 0;
    border-radius: 6px;
    color: var(--zode-muted-text);
    background: transparent;
    font-size: 14px;
    line-height: 24px;
    cursor: pointer;
    text-align: left;
  }

  .tool-disclosure-header:hover,
  .tool-disclosure-header:focus-visible {
    color: var(--zode-primary-text);
  }

  .tool-disclosure-icon {
    flex: 0 0 auto;
    color: var(--zode-subtle-text);
    font-size: 14px;
  }

  .tool-disclosure-summary {
    flex: 0 1 auto;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--zode-secondary-text);
    font-weight: 500;
  }

  .tool-disclosure-status {
    flex: 0 0 auto;
    color: var(--zode-subtle-text);
    font-size: 12px;
    white-space: nowrap;
  }

  .tool-disclosure-chevron {
    color: var(--zode-subtle-text);
    font-size: 12px;
    opacity: 0.62;
    transform: rotate(0deg);
    transition:
      opacity 100ms ease,
      transform 100ms ease;
  }

  .tool-disclosure-header:hover .tool-disclosure-chevron,
  .tool-disclosure-header:focus-visible .tool-disclosure-chevron,
  .tool-disclosure-chevron.is-expanded {
    opacity: 1;
  }

  .tool-disclosure-chevron.is-expanded {
    transform: rotate(90deg);
  }

  .tool-disclosure-body {
    display: grid;
    grid-template-rows: 0fr;
    margin: 4px 0 0 16px;
    opacity: 0;
    color: var(--zode-secondary-text);
    pointer-events: none;
    transition:
      grid-template-rows 120ms ease,
      opacity 120ms ease;
  }

  .tool-disclosure-body.is-expanded {
    grid-template-rows: 1fr;
    opacity: 1;
    pointer-events: auto;
  }

  .tool-disclosure-body-inner {
    min-height: 0;
    overflow: hidden;
  }

  .message-role {
    display: none;
  }

  .message p {
    margin: 0;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }

  .message-content {
    min-width: 0;
  }

  .message-content li,
  .message-content blockquote,
  .message-content h1,
  .message-content h2,
  .message-content h3,
  .message-content h4,
  .message-content h5,
  .message-content h6 {
    overflow-wrap: anywhere;
  }

  .message-content p,
  .message-content ul,
  .message-content ol,
  .message-content pre,
  .message-content h1,
  .message-content h2,
  .message-content h3,
  .message-content h4,
  .message-content h5,
  .message-content h6 {
    margin: 0;
  }

  .message-content + .message-content,
  .message-content > * + *,
  .message-content p + p,
  .message-content p + ul,
  .message-content p + ol,
  .message-content ul + p,
  .message-content ol + p,
  .message-content pre + p,
  .message-content p + pre,
  .message-content p + .message-table-container,
  .message-content .message-table-container + p,
  .message-content ol + .message-table-container,
  .message-content .message-table-container + ol {
    margin-top: 12px;
  }

  .message-content ul {
    padding-left: 22px;
  }

  .message-content .task-list-item {
    list-style: none;
    margin-left: -22px;
  }

  .message-content .task-list-item input {
    width: 13px;
    height: 13px;
    margin: 0 7px 0 0;
    vertical-align: -2px;
    accent-color: var(--zode-focus);
  }

  .message-content h3 {
    font-size: 16px;
    font-weight: 600;
    line-height: 24px;
  }

  .message-content h1,
  .message-content h2,
  .message-content h4,
  .message-content h5,
  .message-content h6 {
    color: var(--zode-primary-text);
    font-weight: 600;
    line-height: 24px;
  }

  .message-content h1 {
    font-size: 20px;
  }

  .message-content h2 {
    font-size: 18px;
  }

  .message-content h4,
  .message-content h5,
  .message-content h6 {
    font-size: 14px;
  }

  .message-content pre {
    overflow: auto;
    padding: 12px 14px;
    border: 1px solid var(--zode-border);
    border-radius: 10px;
    background: rgba(0, 0, 0, 0.24);
  }

  .message-content code {
    padding: 1px 4px;
    border-radius: 4px;
    background: rgba(255, 255, 255, 0.08);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.92em;
  }

  .message-content pre code {
    padding: 0;
    background: transparent;
  }

  .message-content a {
    color: var(--zode-secondary-text);
    text-decoration: underline;
    text-underline-offset: 2px;
  }

  .message-content em {
    font-style: italic;
  }

  .message-content del {
    text-decoration: line-through;
  }

  .runtime-activity {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin: 0 0 12px;
    padding: 0;
  }

  .activity-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .status-line {
    display: flex;
    min-height: 24px;
    align-items: flex-start;
    gap: 8px;
    padding: 3px 0;
    color: var(--zode-muted-text);
  }

  .status-line[data-zode-alert="true"] {
    min-height: 24px;
    align-items: flex-start;
    gap: 8px;
    padding: 3px 0;
    border: 0;
    border-radius: 0;
    color: var(--zode-muted-text);
    background: transparent;
    box-shadow: none;
    font-size: inherit;
  }

  .status-line > i {
    flex: 0 0 auto;
    margin-top: 1px;
    color: var(--zode-muted-text);
    font-size: 16px;
  }

  .status-line[data-zode-attention="true"] > i {
    color: var(--zode-attention);
  }

  .status-line > div {
    display: grid;
    flex: 1 1 auto;
    grid-template-columns: minmax(0, 1fr) auto;
    min-width: 0;
    align-items: baseline;
    column-gap: 8px;
    row-gap: 1px;
  }

  .status-line > div > span {
    min-width: 0;
  }

  .status-line strong {
    min-width: 0;
    color: var(--zode-primary-text);
    font-size: 13px;
    font-weight: 500;
    overflow-wrap: anywhere;
  }

  .status-line[data-zode-alert="true"] strong {
    color: var(--zode-primary-text);
    font-size: 13px;
    font-weight: 500;
    line-height: normal;
  }

  .status-line[data-zode-alert="true"] > i {
    color: var(--zode-attention);
  }

  .turn-error-line[data-zode-alert="true"] > i {
    color: var(--zode-attention);
  }

  .status-line.turn-error-line {
    flex: 0 0 auto;
    align-items: center;
    gap: 12px;
    min-height: 0;
    margin-bottom: 16px;
    padding: 8px 8px 8px 12px;
    overflow: hidden;
    border: 1px solid var(--zode-border);
    border-radius: 16px;
    color: var(--zode-primary-text);
    background: var(--zode-secondary-surface);
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.12);
    font-size: 14px;
    line-height: 20px;
  }

  .status-line.turn-error-line > i {
    margin-top: 0;
    font-size: 16px;
  }

  .status-line.turn-error-line > .turn-error-copy {
    display: flex;
    min-width: 0;
    flex: 1 1 auto;
    flex-direction: column;
    align-items: flex-start;
    gap: 2px;
  }

  .status-line.turn-error-line .turn-error-copy > strong {
    color: var(--zode-primary-text);
    font-size: 15px;
    font-weight: 500;
    line-height: 20px;
  }

  .status-line.turn-error-line .turn-error-message {
    color: var(--zode-muted-text) !important;
    font-size: 14px !important;
    line-height: 20px !important;
  }

  .status-line span {
    font-size: 12px;
  }

  .status-line-state {
    color: var(--zode-subtle-text);
    white-space: nowrap;
  }

  .status-line-detail {
    grid-column: 1 / -1;
    color: var(--zode-muted-text);
    line-height: 17px;
    overflow-wrap: anywhere;
  }

  .status-line[data-zode-alert="true"] .status-line-detail {
    color: var(--zode-muted-text);
  }

  .composer {
    position: fixed;
    right: max(16px, calc((100vw - var(--zode-sidebar-width) - 736px) / 2));
    bottom: 16px;
    z-index: 1;
    display: flex;
    width: min(736px, calc(100vw - var(--zode-sidebar-width) - 32px));
    flex-direction: column;
    padding: 7px 14px 10px;
    border: 0;
    border-radius: 20px;
    background: var(--zode-composer);
    box-shadow: var(--zode-elevation-prominent);
  }

  .composer-input {
    height: auto;
    min-height: 46px;
    max-height: 180px;
    overflow-y: hidden;
    resize: none;
    padding: 0;
    border: 0;
    outline: 0;
    background: transparent;
    line-height: 28px;
    position: relative;
    z-index: 1;
  }

  .composer-input:focus-visible,
  .home-composer-input:focus-visible {
    outline: 0;
  }

  .composer-footer {
    display: grid;
    align-items: center;
    grid-template-columns: minmax(0, auto) auto minmax(0, 1fr);
    column-gap: 5px;
    margin-bottom: 8px;
    padding-inline: 8px;
    position: relative;
    z-index: 1;
  }

  .composer-footer > .composer-utility-bar {
    grid-column: 1;
    align-items: center;
  }

  .composer-footer > .composer-hint {
    grid-column: 2;
  }

  .composer-footer > .composer-options {
    grid-column: 3;
    justify-self: end;
  }

  .composer-hint {
    font-size: 11px;
  }

  @media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
      scroll-behavior: auto !important;
      transition-duration: 0.01ms !important;
    }
  }

  .composer .button {
    min-width: 34px;
    height: 34px;
    padding: 0 10px;
    border-radius: 17px;
  }

  .center-state {
    display: flex;
    min-height: 100vh;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 12px;
    color: var(--zode-primary-text);
    background: var(--zode-main);
  }

  .center-state i {
    color: var(--zode-attention);
    font-size: 24px;
  }

  .center-state h1 {
    margin: 0;
    font-size: 16px;
  }

  [data-zode-primary-text] {
    color: var(--zode-primary-text);
  }

  [data-zode-secondary-text] {
    color: var(--zode-secondary-text);
  }

  [data-zode-attention] {
    color: var(--zode-attention);
  }

  [data-zode-session-state="connecting"] .session-meta,
  [data-zode-session-state="disconnected"] .session-meta,
  [data-zode-session-state="reconnecting"] .session-meta,
  [data-zode-session-state="waiting"] .session-meta,
  [data-zode-session-state="tool"] .session-meta {
    color: var(--zode-attention);
  }

  @media (max-width: 760px) {
    body {
      overflow: hidden;
    }

    :root {
      --zode-sidebar-toolbar-height: 36px;
    }

    .app-shell {
      grid-template-columns: minmax(0, 1fr);
    }

    .sidebar {
      position: fixed;
      inset: 0 auto 0 0;
      width: min(var(--zode-sidebar-width), calc(100vw - 32px));
      height: 100vh;
      max-height: none;
      padding: 0;
      border-bottom: 0;
      overflow: hidden;
      box-shadow: 8px 0 24px rgb(0 0 0 / 24%);
    }

    .sidebar-endpoint-groups {
      flex: 1 1 auto;
      max-height: none;
      margin-top: 12px;
    }

    .primary-nav {
      grid-template-columns: 1fr;
    }

    .nav-item {
      justify-content: flex-start;
      padding: 5px 8px;
    }

    .main-surface {
      grid-column: 1;
      height: 100vh;
      min-height: 100vh;
    }

    .content-page,
    .session-workspace {
      width: calc(100% - 28px);
    }

    .settings-content-page {
      width: calc(100% - 28px);
      padding: 24px 0 48px;
    }

    .settings-page-header {
      align-items: stretch;
      flex-direction: column;
      gap: 16px;
      margin-bottom: 24px;
    }

    .page-toolbar,
    .resource-heading {
      align-items: stretch;
      flex-direction: column;
    }

    .form-grid {
      grid-template-columns: 1fr;
    }

    .profile-row {
      grid-template-columns: 1fr auto;
    }

    .profile-targets {
      grid-column: 1 / -1;
    }

    .profile-row .profile-actions {
      grid-column: 1 / -1;
      justify-content: flex-start;
    }

    .profile-delete-dialog .panel-actions {
      flex-wrap: wrap;
    }

    .profile-delete-dialog .button {
      max-width: 100%;
      min-height: 36px;
      padding: 6px 10px;
      line-height: 18px;
      white-space: normal;
    }

    .composer,
    .home-composer {
      right: 14px;
      width: calc(100vw - 28px);
    }

    .home-composer-footer {
      position: relative;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto auto;
      gap: 4px;
      column-gap: 5px;
      overflow: visible;
    }

    .home-composer-footer > .composer-utility-bar {
      grid-column: 2;
      grid-row: 1;
      gap: 4px;
      min-width: 0;
      justify-self: end;
      overflow: visible;
    }

    .home-composer-footer::after {
      display: none;
    }

    .home-composer-footer > .composer-submit {
      position: static;
      z-index: 1;
      grid-column: 3;
      grid-row: 1;
    }

    @media (max-width: 340px) {
      .home-intro {
        padding-bottom: 48px;
      }

      .home-page:has(.home-composer-empty) .home-intro {
        padding-bottom: 64px;
      }
    }

    .main-surface > .session-workspace {
      padding-bottom: 14px;
    }

    .session-workspace > .composer {
      position: static;
      right: auto;
      bottom: auto;
      width: 100%;
      flex: 0 0 auto;
      margin-top: 8px;
    }

    .composer-footer {
      grid-template-columns: minmax(0, 1fr) auto;
      row-gap: 4px;
    }

    .composer-footer > .composer-utility-bar {
      grid-column: 1;
      grid-row: 1;
      max-width: 100%;
      overflow-x: auto;
      scrollbar-width: none;
    }

    .composer-footer
      > .composer-utility-bar:has(
        .composer-execution-trigger[data-zode-execution-state="needs-recovery"]
      ) {
      overflow: visible;
    }

    .composer-footer
      > .composer-utility-bar:has(
        .composer-execution-trigger[data-zode-execution-state="needs-recovery"]
      )
      .composer-context-readonly {
      display: none;
    }

    .composer-footer > .composer-utility-bar::-webkit-scrollbar {
      display: none;
    }

    .composer-footer > .composer-hint {
      grid-column: 1;
      grid-row: 2;
    }

    .composer-footer > .composer-options {
      grid-column: 2;
      grid-row: 1 / span 2;
    }

    .composer-footer .composer-context-readonly,
    .composer-footer .composer-execution-trigger {
      flex: 0 0 auto;
    }

    .composer-footer .composer-context-readonly {
      max-width: min(46vw, 220px);
    }

    .composer-footer .composer-execution-trigger {
      max-width: min(46vw, 192px);
    }

    .composer-footer .composer-execution-trigger[data-zode-execution-state="needs-recovery"] {
      width: max-content;
      max-width: none;
      overflow: visible;
    }

    .composer-footer
      .composer-execution-trigger[data-zode-execution-state="needs-recovery"]
      .composer-execution-trigger-content {
      overflow: visible;
      text-overflow: clip;
    }

    .home-composer-empty {
      overflow: visible;
      line-height: 15px;
      text-overflow: clip;
      white-space: normal;
    }
  }

  @media (max-width: 760px) and (max-height: 560px) {
    .session-workspace > .transcript {
      padding: 12px 0;
    }

    .home-intro {
      padding-bottom: 48px;
    }

    .home-page:has(.home-composer-empty) .home-intro {
      padding-bottom: 64px;
    }
  }

  @media (max-width: 768px) {
    .runtime-activity {
      margin: 0 0 12px;
      padding: 0;
      border: 0;
      border-radius: 0;
      background: transparent;
    }
  }

  .app-shell.sidebar-collapsed {
    grid-template-columns: 0 minmax(0, 1fr);
  }

  .app-shell.sidebar-collapsed .sidebar {
    width: 0;
    padding: 0;
    transform: translateX(-100%);
    overflow: hidden;
  }

  .app-shell.sidebar-collapsed .sidebar-management-footer {
    display: none;
  }

  @media (max-width: 760px) {
    .app-shell.sidebar-collapsed .sidebar {
      height: 0;
      min-height: 0;
      max-height: 0;
      border-bottom: 0;
    }

    .app-shell.sidebar-collapsed .main-surface {
      height: 100vh;
      min-height: 100vh;
    }
  }

  .app-shell.sidebar-collapsed .main-surface {
    grid-column: 1 / -1;
  }

  .app-shell.sidebar-collapsed .home-composer,
  .app-shell.sidebar-collapsed .composer {
    right: max(16px, calc((100vw - 736px) / 2));
    width: min(736px, calc(100vw - 32px));
  }
`;
